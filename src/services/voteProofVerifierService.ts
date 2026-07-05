import { createHash } from "node:crypto";
import type {
  VotePrivacyPayloadDto,
  VoteProofEnvelopeDto,
  VoteProofPublicInputsDto,
} from "../types/contracts";
import type { PollRow } from "../types/db";
import { canonicalizeJson } from "./pollPolicyService";

export const CIVIC_VOTE_PRIVACY_VERSION = "civicos-vote-privacy-v1" as const;
export const CIVIC_IDENTITY_HASH_SUITE = "sha256-sha512-preposeidon-v1" as const;
export const CIVIC_PROOF_ENVELOPE_VERSION = "civicos-proof-envelope-v1" as const;
export const CIVIC_PROOF_SYSTEM_VERSION = "civicos-zk-proof-v1-preprover" as const;
export const CIVIC_VERIFICATION_METHOD_VERSION =
  "civicos-mobile-verification-v1" as const;
export const CIVIC_PROOF_NOT_GENERATED_STATUS = "not_generated" as const;
export const CIVIC_PROOF_NOT_GENERATED_REASON = "prover_not_integrated" as const;
export const CIVIC_VOTE_PROOF_VERIFICATION_STATUS =
  "preprover_accepted" as const;

const CIVIC_IDENTITY_DOMAIN = "org.civicos.identity" as const;
const HEX_64_PATTERN = /^[0-9a-f]{64}$/;

export type VerifiedVoteProofAuditMaterial = {
  nullifier: string;
  voteCommitment: string;
  proofHash: string;
  proofSystemVersion: string;
  verificationMethodVersion: string;
  proofVerificationStatus: typeof CIVIC_VOTE_PROOF_VERIFICATION_STATUS;
  proofPublicInputsJson: VoteProofPublicInputsDto;
  proofEnvelopeJson: VoteProofEnvelopeDto;
};

export type VoteProofVerificationResult =
  | {
      ok: true;
      auditMaterial: VerifiedVoteProofAuditMaterial | null;
    }
  | {
      ok: false;
      reason:
        | "PROOF_REQUIRED"
        | "PROOF_INVALID"
        | "POLL_POLICY_HASH_MISMATCH"
        | "CREDENTIAL_SCHEMA_HASH_MISMATCH"
        | "NULLIFIER_MISMATCH"
        | "VOTE_COMMITMENT_MISMATCH";
      message: string;
    };

type VoteProofEnvelopeShapeResult =
  | {
      ok: true;
      proof: VoteProofEnvelopeDto;
    }
  | Extract<VoteProofVerificationResult, { ok: false }>;

const sha256Hex = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

const normalizeHex64 = (value: string | null | undefined): string | null => {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  return HEX_64_PATTERN.test(normalized) ? normalized : null;
};

const hashProofPublicInputs = (publicInputs: VoteProofPublicInputsDto): string =>
  sha256Hex(
    `${CIVIC_IDENTITY_DOMAIN}|proof-public-inputs|${canonicalizeJson(publicInputs)}`,
  );

export const hashVoteProofEnvelope = (proof: VoteProofEnvelopeDto): string =>
  sha256Hex(
    `${CIVIC_IDENTITY_DOMAIN}|proof-envelope|${canonicalizeJson(proof)}`,
  );

export const buildVoteCommitment = (input: {
  pollId: string;
  optionId: string;
  nullifier: string;
  proofHash: string;
}): string =>
  sha256Hex(
    [
      CIVIC_IDENTITY_DOMAIN,
      "vote-commitment-v1",
      input.pollId,
      input.optionId,
      input.nullifier,
      input.proofHash,
    ].join("|"),
  );

const pollHasFrozenProofMaterial = (
  poll: Pick<PollRow, "requires_verified_identity" | "poll_policy_hash" | "credential_schema_hash">,
): boolean =>
  Boolean(
    poll.requires_verified_identity &&
      normalizeHex64(poll.poll_policy_hash) &&
      normalizeHex64(poll.credential_schema_hash),
  );

const validateProofEnvelopeShape = (
  privacy: VotePrivacyPayloadDto,
): VoteProofEnvelopeShapeResult => {
  if (
    privacy.version !== CIVIC_VOTE_PRIVACY_VERSION ||
    privacy.hashSuite !== CIVIC_IDENTITY_HASH_SUITE
  ) {
    return {
      ok: false,
      reason: "PROOF_INVALID",
      message: "Vote proof privacy metadata uses an unsupported version.",
    };
  }

  const proof = privacy.proof;
  if (
    proof.version !== CIVIC_PROOF_ENVELOPE_VERSION ||
    proof.proofSystemVersion !== CIVIC_PROOF_SYSTEM_VERSION ||
    proof.status !== CIVIC_PROOF_NOT_GENERATED_STATUS ||
    proof.reason !== CIVIC_PROOF_NOT_GENERATED_REASON
  ) {
    return {
      ok: false,
      reason: "PROOF_INVALID",
      message: "Vote proof envelope uses an unsupported proof status or version.",
    };
  }

  const publicInputs = proof.publicInputs;
  if (
    publicInputs.proofSystemVersion !== CIVIC_PROOF_SYSTEM_VERSION ||
    publicInputs.verificationMethodVersion !== CIVIC_VERIFICATION_METHOD_VERSION
  ) {
    return {
      ok: false,
      reason: "PROOF_INVALID",
      message: "Vote proof public inputs use an unsupported verifier version.",
    };
  }

  if (privacy.nullifier !== publicInputs.nullifier) {
    return {
      ok: false,
      reason: "NULLIFIER_MISMATCH",
      message: "Vote proof nullifier does not match the vote privacy payload.",
    };
  }

  if (
    proof.publicInputsHash &&
    proof.publicInputsHash !== hashProofPublicInputs(publicInputs)
  ) {
    return {
      ok: false,
      reason: "PROOF_INVALID",
      message: "Vote proof public input hash does not match the public inputs.",
    };
  }

  return { ok: true, proof };
};

export const verifyVoteProofForPoll = (params: {
  poll: PollRow;
  optionId: string;
  privacy?: VotePrivacyPayloadDto | null;
  expectedVoteCommitment?: string | null;
}): VoteProofVerificationResult => {
  const { poll, optionId, privacy } = params;
  const proofRequired = pollHasFrozenProofMaterial(poll);

  if (!proofRequired) {
    return { ok: true, auditMaterial: null };
  }

  if (!privacy) {
    return {
      ok: false,
      reason: "PROOF_REQUIRED",
      message: "This poll requires vote proof metadata.",
    };
  }

  const shapeResult = validateProofEnvelopeShape(privacy);
  if (!shapeResult.ok) {
    return shapeResult;
  }

  const { proof } = shapeResult;
  const publicInputs = proof.publicInputs;
  const pollPolicyHash = normalizeHex64(poll.poll_policy_hash);
  const credentialSchemaHash = normalizeHex64(poll.credential_schema_hash);

  if (publicInputs.pollId !== poll.id) {
    return {
      ok: false,
      reason: "PROOF_INVALID",
      message: "Vote proof poll id does not match the requested poll.",
    };
  }

  if (!pollPolicyHash || publicInputs.pollPolicyHash !== pollPolicyHash) {
    return {
      ok: false,
      reason: "POLL_POLICY_HASH_MISMATCH",
      message: "Vote proof poll policy hash does not match the registered poll policy.",
    };
  }

  if (!credentialSchemaHash || publicInputs.credentialSchemaHash !== credentialSchemaHash) {
    return {
      ok: false,
      reason: "CREDENTIAL_SCHEMA_HASH_MISMATCH",
      message:
        "Vote proof credential schema hash does not match the registered poll schema.",
    };
  }

  const proofHash = hashVoteProofEnvelope(proof);
  const voteCommitment = buildVoteCommitment({
    pollId: poll.id,
    optionId,
    nullifier: publicInputs.nullifier,
    proofHash,
  });
  const expectedVoteCommitment = normalizeHex64(params.expectedVoteCommitment);
  if (expectedVoteCommitment && expectedVoteCommitment !== voteCommitment) {
    return {
      ok: false,
      reason: "VOTE_COMMITMENT_MISMATCH",
      message: "Vote commitment does not match the submitted proof material.",
    };
  }

  return {
    ok: true,
    auditMaterial: {
      nullifier: publicInputs.nullifier,
      voteCommitment,
      proofHash,
      proofSystemVersion: publicInputs.proofSystemVersion,
      verificationMethodVersion: publicInputs.verificationMethodVersion,
      proofVerificationStatus: CIVIC_VOTE_PROOF_VERIFICATION_STATUS,
      proofPublicInputsJson: publicInputs,
      proofEnvelopeJson: proof,
    },
  };
};

export default {
  buildVoteCommitment,
  hashVoteProofEnvelope,
  verifyVoteProofForPoll,
};
