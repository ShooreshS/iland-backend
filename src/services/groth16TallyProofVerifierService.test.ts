import { readFileSync } from "node:fs";

import { describe, expect, it } from "bun:test";

import type { PollRow } from "../types/db";
import {
  GROTH16_ARTIFACT_MANIFEST_VERSION,
  buildGroth16VerifierKeyRegistryRecord,
  hashGroth16ArtifactManifest,
  type Groth16ArtifactManifest,
} from "./groth16ArtifactManifestService";
import {
  CIVIC_PRODUCTION_HASH_SUITE,
  CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
  CIVIC_PRODUCTION_PROOF_PROTOCOL,
  CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
} from "./groth16ProofVerifierService";
import {
  CIVIC_TALLY_PROOF_ENVELOPE_VERSION,
  CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
  encodeGroth16TallyPublicSignals,
  hashGroth16TallyOptionCounts,
  hashGroth16TallyPublicInputs,
  isGroth16TallyVerifierConfigured,
  type Groth16TallyProofEnvelopeDto,
  type Groth16TallyPublicInputsDto,
  type Groth16TallyVerifierConfig,
  verifyGroth16TallyProofForPoll,
} from "./groth16TallyProofVerifierService";

const FIXED_TIME = "2026-07-07T12:00:00.000Z";
const POLL_POLICY_HASH = "1".repeat(64);
const CREDENTIAL_SCHEMA_HASH = "2".repeat(64);
const OPTION_SET_HASH = "3".repeat(64);
const OPTION_COUNT = 2;
const NULLIFIER_ROOT = "4".repeat(64);
const VOTE_COMMITMENT_ROOT = "5".repeat(64);
const ENCRYPTED_VOTE_ROOT = "6".repeat(64);
const VERIFIER_KEY_HASH = "7".repeat(64);
const TRUSTED_SETUP_TRANSCRIPT_HASH = "8".repeat(64);
const PROVING_KEY_HASH = "9".repeat(64);
const PROVER_ARTIFACT_HASH = "a".repeat(64);
const TALLY_CIRCUIT_ID = "civicos-groth16-tally-circuit-v1";
const fixtureUrl = new URL("./__fixtures__/groth16-tally/", import.meta.url);
const fixtureManifestPath = new URL("encrypted_choice_tally.manifest.json", fixtureUrl);
const fixtureManifest = JSON.parse(
  readFileSync(fixtureManifestPath, "utf8"),
) as Groth16ArtifactManifest;
const fixtureManifestHash = readFileSync(
  new URL("encrypted_choice_tally.manifest-hash.txt", fixtureUrl),
  "utf8",
).trim();
const fixtureEnvelope = JSON.parse(
  readFileSync(new URL("encrypted_choice_tally.envelope.json", fixtureUrl), "utf8"),
) as Groth16TallyProofEnvelopeDto;
const createPoll = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "poll-1",
  slug: "poll-1",
  created_by_user_id: "owner-1",
  title: "Production ZKP poll",
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
  ends_at: null,
  poll_policy_json: null,
  poll_policy_hash: POLL_POLICY_HASH,
  credential_schema_json: null,
  credential_schema_hash: CREDENTIAL_SCHEMA_HASH,
  vote_privacy_mode: "zk_secret_ballot_v1",
  option_set_hash: OPTION_SET_HASH,
  poll_encryption_key_id: "poll-key-1",
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createArtifactManifest = (
  overrides: Partial<Groth16ArtifactManifest> = {},
): Groth16ArtifactManifest => ({
  version: GROTH16_ARTIFACT_MANIFEST_VERSION,
  artifactKind: "tally",
  circuitId: TALLY_CIRCUIT_ID,
  proofSystem: "groth16",
  protocol: "groth16",
  curve: "bn254",
  hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
  publicInputSchemaVersion: CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
  trustedSetupTranscriptHash: TRUSTED_SETUP_TRANSCRIPT_HASH,
  verifierKeyHash: VERIFIER_KEY_HASH,
  provingKeyHash: PROVING_KEY_HASH,
  wasmOrNativeArtifactHash: PROVER_ARTIFACT_HASH,
  circuitParameters: {
    tallyBatchSize: 64,
    maxOptions: 8,
  },
  artifacts: [
    {
      role: "verification_key",
      path: "tally.vkey.json",
      sha256: VERIFIER_KEY_HASH,
      format: "snarkjs-vkey-json",
    },
    {
      role: "proving_key",
      path: "tally.zkey",
      sha256: PROVING_KEY_HASH,
      format: "zkey",
    },
    {
      role: "witness_wasm",
      path: "tally.wasm",
      sha256: PROVER_ARTIFACT_HASH,
      format: "wasm",
    },
  ],
  ...overrides,
});

const artifactManifest = createArtifactManifest();
const artifactManifestHash = hashGroth16ArtifactManifest(artifactManifest);
const configuredVerifier: Groth16TallyVerifierConfig = {
  tallyVerifierEnabled: true,
  tallyCircuitId: TALLY_CIRCUIT_ID,
  tallyVerifierKeyHash: VERIFIER_KEY_HASH,
  tallyPublicInputSchemaVersion: CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
  tallyTrustedSetupTranscriptHash: TRUSTED_SETUP_TRANSCRIPT_HASH,
  tallyArtifactManifestPath: "/zkp/tally.manifest.json",
  tallyArtifactManifestHash: artifactManifestHash,
  tallyArtifactManifest: artifactManifest,
  tallyArtifactManifestStatus: "loaded",
  tallyArtifactManifestError: null,
  tallyVerifierKeyRegistryRecord: buildGroth16VerifierKeyRegistryRecord(
    artifactManifest,
    artifactManifestHash,
  ),
};

const createProof = async (
  overrides: Partial<Groth16TallyPublicInputsDto> & {
    publicInputsHash?: string;
  } = {},
): Promise<Groth16TallyProofEnvelopeDto> => {
  const optionResults = overrides.optionResults ?? [
    { optionId: "option-a", count: 1 },
    { optionId: "option-b", count: 1 },
  ];
  const optionCountsHash =
    overrides.optionCountsHash ??
    (await hashGroth16TallyOptionCounts(optionResults));
  const publicInputs: Groth16TallyPublicInputsDto = {
    version:
      overrides.version ?? CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
    pollId: overrides.pollId ?? "poll-1",
    pollPolicyHash: overrides.pollPolicyHash ?? POLL_POLICY_HASH,
    credentialSchemaHash:
      overrides.credentialSchemaHash ?? CREDENTIAL_SCHEMA_HASH,
    optionSetHash: overrides.optionSetHash ?? OPTION_SET_HASH,
    optionCount: overrides.optionCount ?? OPTION_COUNT,
    nullifierRoot: overrides.nullifierRoot ?? NULLIFIER_ROOT,
    voteCommitmentRoot:
      overrides.voteCommitmentRoot ?? VOTE_COMMITMENT_ROOT,
    encryptedVoteRoot:
      overrides.encryptedVoteRoot ?? ENCRYPTED_VOTE_ROOT,
    acceptedVoteCount: overrides.acceptedVoteCount ?? 2,
    optionResults,
    optionCountsHash,
    proofSystemVersion:
      overrides.proofSystemVersion ?? CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
    hashSuite: overrides.hashSuite ?? CIVIC_PRODUCTION_HASH_SUITE,
    circuitId: overrides.circuitId ?? TALLY_CIRCUIT_ID,
    verifierKeyHash: overrides.verifierKeyHash ?? VERIFIER_KEY_HASH,
    publicInputSchemaVersion:
      overrides.publicInputSchemaVersion ??
      CIVIC_TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
  };

  return {
    version: CIVIC_TALLY_PROOF_ENVELOPE_VERSION,
    protocol: CIVIC_PRODUCTION_PROOF_PROTOCOL,
    proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
    status: CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
    hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
    circuitId: publicInputs.circuitId,
    verifierKeyHash: publicInputs.verifierKeyHash,
    publicInputSchemaVersion: publicInputs.publicInputSchemaVersion,
    proof: {
      pi_a: ["1", "2", "1"],
      pi_b: [
        ["3", "4"],
        ["5", "6"],
        ["1", "0"],
      ],
      pi_c: ["7", "8", "1"],
    },
    publicInputs,
    publicInputsHash:
      overrides.publicInputsHash ?? hashGroth16TallyPublicInputs(publicInputs),
  };
};

describe("groth16TallyProofVerifierService", () => {
  it("reports tally verifier configuration readiness", () => {
    expect(isGroth16TallyVerifierConfigured(configuredVerifier)).toBe(true);
    expect(
      isGroth16TallyVerifierConfigured({
        ...configuredVerifier,
        tallyVerifierKeyHash: null,
      }),
    ).toBe(false);
  });

  it("accepts a configured tally verifier result", async () => {
    const proof = await createProof();
    const result = await verifyGroth16TallyProofForPoll(
      {
        poll: createPoll(),
        proof,
        nullifierRoot: NULLIFIER_ROOT,
        voteCommitmentRoot: VOTE_COMMITMENT_ROOT,
        encryptedVoteRoot: ENCRYPTED_VOTE_ROOT,
        acceptedVoteCount: 2,
        expectedOptionIds: ["option-a", "option-b"],
      },
      {
        config: configuredVerifier,
        verifyProof: async (input) => {
          expect(input.publicSignals).toEqual(
            encodeGroth16TallyPublicSignals(proof.publicInputs),
          );
          return true;
        },
      },
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.auditMaterial).toMatchObject({
        tallyPublicInputsHash: proof.publicInputsHash,
        tallyVerifierKeyHash: VERIFIER_KEY_HASH,
        tallyCircuitId: TALLY_CIRCUIT_ID,
        nullifierRoot: NULLIFIER_ROOT,
        voteCommitmentRoot: VOTE_COMMITMENT_ROOT,
        encryptedVoteRoot: ENCRYPTED_VOTE_ROOT,
        acceptedCount: 2,
      });
      expect(result.auditMaterial.tallyProofHash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("encodes the regenerated frozen tally fixture public signals", () => {
    const publicSignals = encodeGroth16TallyPublicSignals(
      fixtureEnvelope.publicInputs,
    );

    expect(publicSignals).toEqual(
      JSON.parse(
        readFileSync(
          new URL("encrypted_choice_tally.public.json", fixtureUrl),
          "utf8",
        ),
      ),
    );
  });

  it("accepts the regenerated EncryptedChoiceTally fixture through the current padded tally contract", async () => {
    const registryRecord = buildGroth16VerifierKeyRegistryRecord(
      fixtureManifest,
      fixtureManifestHash,
    );
    const fixtureConfig: Groth16TallyVerifierConfig = {
      tallyVerifierEnabled: true,
      tallyCircuitId: fixtureManifest.circuitId,
      tallyVerifierKeyHash: fixtureManifest.verifierKeyHash,
      tallyPublicInputSchemaVersion: fixtureManifest.publicInputSchemaVersion,
      tallyTrustedSetupTranscriptHash: fixtureManifest.trustedSetupTranscriptHash,
      tallyArtifactManifestPath: fixtureManifestPath.pathname,
      tallyArtifactManifestHash: fixtureManifestHash,
      tallyArtifactManifest: fixtureManifest,
      tallyArtifactManifestStatus: "loaded",
      tallyArtifactManifestError: null,
      tallyVerifierKeyRegistryRecord: registryRecord,
    };

    const result = await verifyGroth16TallyProofForPoll(
      {
        poll: createPoll({
          id: fixtureEnvelope.publicInputs.pollId,
          poll_policy_hash: fixtureEnvelope.publicInputs.pollPolicyHash,
          credential_schema_hash:
            fixtureEnvelope.publicInputs.credentialSchemaHash,
          option_set_hash: fixtureEnvelope.publicInputs.optionSetHash,
        }),
        proof: fixtureEnvelope,
        nullifierRoot: fixtureEnvelope.publicInputs.nullifierRoot,
        voteCommitmentRoot: fixtureEnvelope.publicInputs.voteCommitmentRoot,
        encryptedVoteRoot: fixtureEnvelope.publicInputs.encryptedVoteRoot,
        acceptedVoteCount: fixtureEnvelope.publicInputs.acceptedVoteCount,
        expectedOptionIds: fixtureEnvelope.publicInputs.optionResults.map(
          (entry) => entry.optionId,
        ),
      },
      { config: fixtureConfig },
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.auditMaterial).toMatchObject({
        tallyCircuitId: fixtureManifest.circuitId,
        tallyVerifierKeyHash: fixtureManifest.verifierKeyHash,
        nullifierRoot: fixtureEnvelope.publicInputs.nullifierRoot,
        voteCommitmentRoot: fixtureEnvelope.publicInputs.voteCommitmentRoot,
        encryptedVoteRoot: fixtureEnvelope.publicInputs.encryptedVoteRoot,
        acceptedCount: fixtureEnvelope.publicInputs.acceptedVoteCount,
      });
    }
  });

  it("rejects mismatched roots before verifier execution", async () => {
    let verifierCalled = false;
    const result = await verifyGroth16TallyProofForPoll(
      {
        poll: createPoll(),
        proof: await createProof({ encryptedVoteRoot: "b".repeat(64) }),
        nullifierRoot: NULLIFIER_ROOT,
        voteCommitmentRoot: VOTE_COMMITMENT_ROOT,
        encryptedVoteRoot: ENCRYPTED_VOTE_ROOT,
        acceptedVoteCount: 2,
        expectedOptionIds: ["option-a", "option-b"],
      },
      {
        config: configuredVerifier,
        verifyProof: () => {
          verifierCalled = true;
          return true;
        },
      },
    );

    expect(result.ok).toBe(false);
    expect(verifierCalled).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("ROOT_MISMATCH");
    }
  });

  it("rejects public counts that do not sum to accepted count", async () => {
    const result = await verifyGroth16TallyProofForPoll(
      {
        poll: createPoll(),
        proof: await createProof({
          optionResults: [
            { optionId: "option-a", count: 1 },
            { optionId: "option-b", count: 0 },
          ],
        }),
        nullifierRoot: NULLIFIER_ROOT,
        voteCommitmentRoot: VOTE_COMMITMENT_ROOT,
        encryptedVoteRoot: ENCRYPTED_VOTE_ROOT,
        acceptedVoteCount: 2,
        expectedOptionIds: ["option-a", "option-b"],
      },
      {
        config: configuredVerifier,
        verifyProof: () => true,
      },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("PROOF_INVALID");
    }
  });
});
