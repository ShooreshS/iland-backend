import { describe, expect, it } from "bun:test";

import type { Groth16ArtifactManifest } from "./groth16ArtifactManifestService";
import {
  createGroth16TallyProverService,
  type Groth16TallyProverRunProof,
} from "./groth16TallyProverService";
import {
  CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
  type Groth16TallyVerifierConfig,
} from "./groth16TallyProofVerifierService";
import { encodeGroth16PublicField } from "./groth16SnarkjsVerifierEngine";
import { poseidonHashHex64 } from "./poseidonBn254Service";
import type { PollOptionRow, PollRow } from "../types/db";
import type { JsonValue } from "../types/json";

const FIXED_TIME = "2026-07-12T12:00:00.000Z";
const POLL_POLICY_HASH = "1".repeat(64);
const CREDENTIAL_SCHEMA_HASH = "2".repeat(64);
const OPTION_SET_HASH = "3".repeat(64);
const VERIFIER_KEY_HASH = "4".repeat(64);
const MANIFEST_HASH = "5".repeat(64);
const TRANSCRIPT_HASH = "6".repeat(64);

const manifest: Groth16ArtifactManifest = {
  version: "civicos-groth16-artifact-manifest-v1",
  artifactKind: "tally",
  circuitId: "civicos-groth16-tally-circuit-v1",
  proofSystem: "groth16",
  protocol: "groth16",
  curve: "bn254",
  hashSuite: "poseidon-bn254-v1",
  publicInputSchemaVersion: CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
  trustedSetupTranscriptHash: TRANSCRIPT_HASH,
  verifierKeyHash: VERIFIER_KEY_HASH,
  provingKeyHash: "7".repeat(64),
  wasmOrNativeArtifactHash: "8".repeat(64),
  circuitParameters: {
    tallyBatchSize: 64,
    maxOptions: 8,
  },
  artifacts: [],
};

const config: Groth16TallyVerifierConfig = {
  tallyVerifierEnabled: true,
  tallyCircuitId: manifest.circuitId,
  tallyVerifierKeyHash: VERIFIER_KEY_HASH,
  tallyPublicInputSchemaVersion: CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
  tallyTrustedSetupTranscriptHash: TRANSCRIPT_HASH,
  tallyArtifactManifestPath: "/tmp/encrypted_choice_tally.manifest.json",
  tallyArtifactManifestHash: MANIFEST_HASH,
  tallyArtifactManifest: manifest,
  tallyArtifactManifestStatus: "loaded",
  tallyArtifactManifestError: null,
  tallyVerifierKeyRegistryRecord: {
    version: "civicos-groth16-verifier-key-registry-v1",
    artifactKind: "tally",
    proofSystem: "groth16",
    protocol: "groth16",
    curve: "bn254",
    hashSuite: "poseidon-bn254-v1",
    circuitId: manifest.circuitId,
    verifierKeyHash: VERIFIER_KEY_HASH,
    publicInputSchemaVersion: CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
    trustedSetupTranscriptHash: TRANSCRIPT_HASH,
    artifactManifestHash: MANIFEST_HASH,
  },
};

const createPoll = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "poll-1",
  slug: "poll-1",
  created_by_user_id: "owner-1",
  title: "Tally Poll",
  description: null,
  status: "closed",
  jurisdiction_type: "global",
  jurisdiction_country_code: null,
  jurisdiction_area_ids: [],
  jurisdiction_land_ids: [],
  requires_verified_identity: true,
  allowed_document_country_codes: [],
  allowed_home_area_ids: [],
  allowed_land_ids: [],
  minimum_age: null,
  starts_at: null,
  ends_at: "2026-07-12T11:00:00.000Z",
  poll_policy_hash: POLL_POLICY_HASH,
  credential_schema_hash: CREDENTIAL_SCHEMA_HASH,
  vote_privacy_mode: "zk_secret_ballot_v1",
  option_set_hash: OPTION_SET_HASH,
  poll_encryption_key_id: "poll-key-1",
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createOption = (overrides: Partial<PollOptionRow> = {}): PollOptionRow => ({
  id: "option-1",
  poll_id: "poll-1",
  label: "Yes",
  description: null,
  color: null,
  display_order: 0,
  is_active: true,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

describe("groth16TallyProverService", () => {
  it("builds a production tally proof envelope from decrypted vote openings", async () => {
    const poll = createPoll();
    const optionA = createOption({ id: "option-a", label: "Yes", display_order: 0 });
    const optionB = createOption({ id: "option-b", label: "No", display_order: 1 });
    const nullifier = "9".repeat(64);
    const encryptedVoteRandomness = "a".repeat(64);
    const voteRandomness = "b".repeat(64);
    const optionSetField = encodeGroth16PublicField(
      "optionSetHash",
      OPTION_SET_HASH,
    );
    const encryptedVoteCommitment = await poseidonHashHex64([
      1001,
      1,
      encryptedVoteRandomness,
      optionSetField,
    ]);
    const voteCommitment = await poseidonHashHex64([
      nullifier,
      encryptedVoteCommitment,
      optionSetField,
      voteRandomness,
    ]);
    let capturedPublicSignals: readonly string[] = [];
    const runProof: Groth16TallyProverRunProof = async (input) => {
      capturedPublicSignals = input.expectedPublicSignals;
      return {
        proof: { pi_a: ["1", "2", "1"] } as unknown as JsonValue,
        publicSignals: [...input.expectedPublicSignals],
      };
    };
    const service = createGroth16TallyProverService({
      config,
      encryptedTallyService: {
        getFinalizationBatch: async () => ({
          success: true,
          votes: [
            {
              id: "vote-1",
              nullifier,
              voteCommitment,
              encryptedVoteCommitment,
              encryptedVoteRandomness,
              voteRandomness,
              optionId: optionB.id,
              optionIndex: 1,
              acceptedAt: FIXED_TIME,
            },
          ],
          countsByOptionId: {
            [optionA.id]: 0,
            [optionB.id]: 1,
          },
          totalVotes: 1,
          updatedAt: FIXED_TIME,
        }),
      },
      runProof,
    });

    const result = await service.generateProofForPoll({
      poll,
      options: [optionB, optionA],
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      throw new Error(result.message);
    }
    expect(result.acceptedVoteCount).toBe(1);
    expect(result.proof.circuitId).toBe(manifest.circuitId);
    expect(result.proof.verifierKeyHash).toBe(VERIFIER_KEY_HASH);
    expect(result.proof.publicInputs.optionResults).toEqual([
      { optionId: optionA.id, count: 0 },
      { optionId: optionB.id, count: 1 },
    ]);
    expect(result.proof.publicInputs.acceptedVoteCount).toBe(1);
    expect(result.proof.publicInputs.nullifierRoot).toMatch(/^[0-9a-f]{64}$/);
    expect(capturedPublicSignals).toHaveLength(10);
  });
});
