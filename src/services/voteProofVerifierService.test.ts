import { describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import { canonicalizeJson } from "./pollPolicyService";
import {
  buildVoteCommitment,
  hashVoteProofEnvelope,
  verifyVoteProofForPoll,
} from "./voteProofVerifierService";
import type { PollRow } from "../types/db";
import type {
  PreproverVotePrivacyPayloadDto,
  VotePrivacyPayloadDto,
} from "../types/contracts";

const FIXED_TIME = "2026-07-04T12:00:00.000Z";
const POLL_POLICY_HASH = "1".repeat(64);
const CREDENTIAL_SCHEMA_HASH = "2".repeat(64);
const NULLIFIER = "3".repeat(64);

const sha256Hex = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

const createPoll = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "poll-1",
  slug: "poll-1",
  created_by_user_id: null,
  title: "Test Poll",
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
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createPrivacy = (
  overrides: {
    pollId?: string;
    pollPolicyHash?: string;
    credentialSchemaHash?: string;
    nullifier?: string;
    publicInputsHash?: string | null;
  } = {},
): PreproverVotePrivacyPayloadDto => {
  const publicInputs = {
    pollId: overrides.pollId ?? "poll-1",
    pollPolicyHash: overrides.pollPolicyHash ?? POLL_POLICY_HASH,
    credentialSchemaHash:
      overrides.credentialSchemaHash ?? CREDENTIAL_SCHEMA_HASH,
    nullifier: overrides.nullifier ?? NULLIFIER,
    verificationMethodVersion: "civicos-mobile-verification-v1",
    proofSystemVersion: "civicos-zk-proof-v1-preprover",
  };

  return {
    version: "civicos-vote-privacy-v1",
    hashSuite: "sha256-sha512-preposeidon-v1",
    nullifier: publicInputs.nullifier,
    proof: {
      version: "civicos-proof-envelope-v1",
      proofSystemVersion: "civicos-zk-proof-v1-preprover",
      status: "not_generated",
      reason: "prover_not_integrated",
      publicInputs,
      publicInputsHash:
        overrides.publicInputsHash === undefined
          ? sha256Hex(
              `org.civicos.identity|proof-public-inputs|${canonicalizeJson(publicInputs)}`,
            )
          : overrides.publicInputsHash,
    },
  };
};

describe("voteProofVerifierService", () => {
  it("accepts a Phase 3 pre-prover envelope and derives audit material", () => {
    const privacy = createPrivacy();
    const proofHash = hashVoteProofEnvelope(privacy.proof);
    const expectedVoteCommitment = buildVoteCommitment({
      pollId: "poll-1",
      optionId: "option-1",
      nullifier: NULLIFIER,
      proofHash,
    });
    const result = verifyVoteProofForPoll({
      poll: createPoll(),
      optionId: "option-1",
      privacy,
      expectedVoteCommitment,
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.auditMaterial?.nullifier).toBe(NULLIFIER);
      expect(result.auditMaterial?.proofHash).toMatch(/^[0-9a-f]{64}$/);
      expect(result.auditMaterial?.voteCommitment).toMatch(/^[0-9a-f]{64}$/);
      expect(result.auditMaterial?.proofVerificationStatus).toBe(
        "preprover_accepted",
      );
    }
  });

  it("rejects a supplied vote commitment that does not match proof material", () => {
    const result = verifyVoteProofForPoll({
      poll: createPoll(),
      optionId: "option-1",
      privacy: createPrivacy(),
      expectedVoteCommitment: "9".repeat(64),
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("VOTE_COMMITMENT_MISMATCH");
      expect(result.message).toContain("Vote commitment");
    }
  });

  it("requires proof metadata for verified polls with frozen policy hashes", () => {
    const result = verifyVoteProofForPoll({
      poll: createPoll(),
      optionId: "option-1",
      privacy: null,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("PROOF_REQUIRED");
    }
  });

  it("rejects public input hash mismatch", () => {
    const result = verifyVoteProofForPoll({
      poll: createPoll(),
      optionId: "option-1",
      privacy: createPrivacy({
        publicInputsHash: "9".repeat(64),
      }),
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("PROOF_INVALID");
      expect(result.message).toContain("public input hash");
    }
  });

  it("rejects poll policy hash mismatch", () => {
    const result = verifyVoteProofForPoll({
      poll: createPoll(),
      optionId: "option-1",
      privacy: createPrivacy({
        pollPolicyHash: "9".repeat(64),
      }),
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("POLL_POLICY_HASH_MISMATCH");
    }
  });

  it("rejects production Groth16 envelopes on the pre-prover verifier path", () => {
    const privacy = {
      version: "civicos-vote-privacy-v1",
      hashSuite: "poseidon-bn254-v1",
      nullifier: NULLIFIER,
      proof: {
        version: "civicos-groth16-vote-proof-envelope-v1",
        protocol: "groth16",
        proofSystemVersion: "civicos-zk-proof-v1",
        status: "generated",
        hashSuite: "poseidon-bn254-v1",
        circuitId: "civicos-groth16-vote-circuit-v1",
        verifierKeyHash: "8".repeat(64),
        publicInputSchemaVersion: "civicos-groth16-vote-public-inputs-v1",
        proof: {},
        publicInputs: {
          pollId: "poll-1",
          pollPolicyHash: POLL_POLICY_HASH,
          credentialSchemaHash: CREDENTIAL_SCHEMA_HASH,
          nullifier: NULLIFIER,
          verificationMethodVersion: "civicos-mobile-verification-v1",
          proofSystemVersion: "civicos-zk-proof-v1",
        },
        publicInputsHash: null,
      },
    } as unknown as VotePrivacyPayloadDto;

    const result = verifyVoteProofForPoll({
      poll: createPoll(),
      optionId: "option-1",
      privacy,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("PROOF_INVALID");
    }
  });

  it("keeps legacy non-proof polls optional", () => {
    const result = verifyVoteProofForPoll({
      poll: createPoll({
        requires_verified_identity: false,
        poll_policy_hash: null,
        credential_schema_hash: null,
      }),
      optionId: "option-1",
      privacy: null,
    });

    expect(result).toEqual({
      ok: true,
      auditMaterial: null,
    });
  });

  it("ignores supplied proof metadata for legacy polls without frozen hashes", () => {
    const result = verifyVoteProofForPoll({
      poll: createPoll({
        poll_policy_hash: null,
        credential_schema_hash: null,
      }),
      optionId: "option-1",
      privacy: createPrivacy(),
    });

    expect(result).toEqual({
      ok: true,
      auditMaterial: null,
    });
  });
});
