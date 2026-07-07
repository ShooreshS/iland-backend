import { describe, expect, it } from "bun:test";

import type { PollRow } from "../types/db";
import {
  CIVIC_PRODUCTION_HASH_SUITE,
  CIVIC_PRODUCTION_PROOF_ENVELOPE_VERSION,
  CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
  CIVIC_PRODUCTION_PROOF_PROTOCOL,
  CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
  CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
  hashGroth16VotePublicInputs,
  isGroth16VoteVerifierConfigured,
  type Groth16VerifierConfig,
  type Groth16VoteProofEnvelopeDto,
  type Groth16VotePublicInputsDto,
  verifyGroth16VoteProofForPoll,
} from "./groth16ProofVerifierService";

const FIXED_TIME = "2026-07-07T12:00:00.000Z";
const POLL_POLICY_HASH = "1".repeat(64);
const CREDENTIAL_SCHEMA_HASH = "2".repeat(64);
const OPTION_SET_HASH = "3".repeat(64);
const CREDENTIAL_ROOT = "4".repeat(64);
const NULLIFIER = "5".repeat(64);
const VOTE_COMMITMENT = "6".repeat(64);
const ENCRYPTED_VOTE_HASH = "7".repeat(64);
const VERIFIER_KEY_HASH = "8".repeat(64);
const TRUSTED_SETUP_TRANSCRIPT_HASH = "9".repeat(64);
const CIRCUIT_ID = "civicos-groth16-vote-circuit-v1";

const configuredVerifier: Groth16VerifierConfig = {
  voteVerifierEnabled: true,
  voteCircuitId: CIRCUIT_ID,
  voteVerifierKeyHash: VERIFIER_KEY_HASH,
  publicInputSchemaVersion: CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
  trustedSetupTranscriptHash: TRUSTED_SETUP_TRANSCRIPT_HASH,
};

const disabledVerifier: Groth16VerifierConfig = {
  ...configuredVerifier,
  voteVerifierEnabled: false,
};

const createPoll = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "poll-1",
  slug: "poll-1",
  created_by_user_id: null,
  title: "Production ZKP poll",
  description: null,
  status: "active",
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

const createProof = (
  overrides: Partial<Groth16VotePublicInputsDto> & {
    publicInputsHash?: string;
    verifierKeyHash?: string;
    circuitId?: string;
  } = {},
): Groth16VoteProofEnvelopeDto => {
  const publicInputs: Groth16VotePublicInputsDto = {
    version: CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
    pollId: overrides.pollId ?? "poll-1",
    pollPolicyHash: overrides.pollPolicyHash ?? POLL_POLICY_HASH,
    credentialSchemaHash:
      overrides.credentialSchemaHash ?? CREDENTIAL_SCHEMA_HASH,
    optionSetHash: overrides.optionSetHash ?? OPTION_SET_HASH,
    credentialRoot: overrides.credentialRoot ?? CREDENTIAL_ROOT,
    nullifier: overrides.nullifier ?? NULLIFIER,
    voteCommitment: overrides.voteCommitment ?? VOTE_COMMITMENT,
    encryptedVoteHash: overrides.encryptedVoteHash ?? ENCRYPTED_VOTE_HASH,
    verificationMethodVersion:
      overrides.verificationMethodVersion ??
      "civicos-mobile-verification-v1",
    proofSystemVersion:
      overrides.proofSystemVersion ?? CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
    hashSuite: overrides.hashSuite ?? CIVIC_PRODUCTION_HASH_SUITE,
    circuitId: overrides.circuitId ?? CIRCUIT_ID,
    verifierKeyHash: overrides.verifierKeyHash ?? VERIFIER_KEY_HASH,
    publicInputSchemaVersion:
      overrides.publicInputSchemaVersion ??
      CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
  };

  return {
    version: CIVIC_PRODUCTION_PROOF_ENVELOPE_VERSION,
    protocol: CIVIC_PRODUCTION_PROOF_PROTOCOL,
    proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
    status: CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
    hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
    circuitId: overrides.circuitId ?? CIRCUIT_ID,
    verifierKeyHash: overrides.verifierKeyHash ?? VERIFIER_KEY_HASH,
    publicInputSchemaVersion: CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
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
      overrides.publicInputsHash ?? hashGroth16VotePublicInputs(publicInputs),
  };
};

describe("groth16ProofVerifierService", () => {
  it("reports verifier configuration readiness", () => {
    expect(isGroth16VoteVerifierConfigured(disabledVerifier)).toBe(false);
    expect(isGroth16VoteVerifierConfigured(configuredVerifier)).toBe(true);
    expect(
      isGroth16VoteVerifierConfigured({
        ...configuredVerifier,
        voteVerifierKeyHash: null,
      }),
    ).toBe(false);
  });

  it("fails closed when production ZKP poll verification is disabled", async () => {
    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll(),
        proof: createProof(),
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
        expectedVoteCommitment: VOTE_COMMITMENT,
      },
      {
        config: disabledVerifier,
        verifyProof: () => true,
      },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("VERIFIER_DISABLED");
    }
  });

  it("fails closed when artifacts are configured but no verifier engine exists", async () => {
    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll(),
        proof: createProof(),
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
      },
      {
        config: configuredVerifier,
      },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("VERIFIER_UNAVAILABLE");
    }
  });

  it("accepts a configured verifier engine result and returns anonymous audit material", async () => {
    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll(),
        proof: createProof(),
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
        expectedVoteCommitment: VOTE_COMMITMENT,
      },
      {
        config: configuredVerifier,
        verifyProof: async (input) => {
          expect(input.circuitId).toBe(CIRCUIT_ID);
          expect(input.verifierKeyHash).toBe(VERIFIER_KEY_HASH);
          expect(input.trustedSetupTranscriptHash).toBe(
            TRUSTED_SETUP_TRANSCRIPT_HASH,
          );
          return true;
        },
      },
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.auditMaterial).toMatchObject({
        nullifier: NULLIFIER,
        voteCommitment: VOTE_COMMITMENT,
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
        proofSystemVersion: "civicos-zk-proof-v1",
        proofVerificationStatus: "verified",
        verifierKeyHash: VERIFIER_KEY_HASH,
        circuitId: CIRCUIT_ID,
      });
      expect(result.auditMaterial?.proofHash).toMatch(/^[0-9a-f]{64}$/);
      expect(result.auditMaterial?.proofEnvelopeHash).toBe(
        result.auditMaterial?.proofHash,
      );
    }
  });

  it("rejects public input hash mismatch before calling the verifier engine", async () => {
    let verifierCalled = false;
    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll(),
        proof: createProof({ publicInputsHash: "a".repeat(64) }),
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
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
      expect(result.reason).toBe("PROOF_INVALID");
    }
  });

  it("rejects mixed pre-prover status in a production envelope", async () => {
    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll(),
        proof: {
          ...createProof(),
          status: "not_generated",
        },
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
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

  it("rejects pre-prover proof-system values in production public inputs", async () => {
    const proof = createProof({
      proofSystemVersion: "civicos-zk-proof-v1-preprover",
    });

    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll(),
        proof,
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
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

  it("rejects verifier rejection", async () => {
    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll(),
        proof: createProof(),
        encryptedVoteHash: ENCRYPTED_VOTE_HASH,
      },
      {
        config: configuredVerifier,
        verifyProof: () => false,
      },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("VERIFIER_REJECTED");
    }
  });

  it("keeps non-production polls out of the Groth16 verifier path", async () => {
    const result = await verifyGroth16VoteProofForPoll(
      {
        poll: createPoll({ vote_privacy_mode: "zk_preprover_audit" }),
        proof: null,
      },
      {
        config: configuredVerifier,
      },
    );

    expect(result).toEqual({ ok: true, auditMaterial: null });
  });
});
