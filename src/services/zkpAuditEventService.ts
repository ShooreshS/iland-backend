import { createHash } from "node:crypto";

import backendAuditEventRepository, {
  type AppendBackendAuditEventResult,
} from "../repositories/backendAuditEventRepository";
import type { BackendAuditEventDecision } from "../types/db";
import type { JsonValue } from "../types/json";

export const ZKP_AUDIT_EVENT_CONTRACT_VERSION =
  "civicos-zkp-backend-audit-events-v1" as const;
export const ZKP_AUDIT_STREAM_PREFIX = "zkp:poll" as const;
const ZKP_AUDIT_IDENTIFIER_HASH_DOMAIN =
  "org.civicos.zkp.audit:identifier-hash:v1" as const;

export const ZKP_AUDIT_EVENT_TYPES = Object.freeze({
  voteAccepted: "zkp.vote.accepted",
  voteRejected: "zkp.vote.rejected",
  tallyAccepted: "zkp.tally.accepted",
  tallyRejected: "zkp.tally.rejected",
  rootPublished: "zkp.audit.root_published",
  finalized: "zkp.audit.finalized",
  publicationRejected: "zkp.audit.publication_rejected",
} as const);

export type ZkpAuditEventType =
  (typeof ZKP_AUDIT_EVENT_TYPES)[keyof typeof ZKP_AUDIT_EVENT_TYPES];

export const ZKP_AUDIT_REJECTION_REASON_CODES = Object.freeze({
  pollNotActive: "poll_not_active",
  optionNotFound: "option_not_found",
  optionNotInPoll: "option_not_in_poll",
  optionInactive: "option_inactive",
  tooManyOptions: "too_many_options",
  verifiedIdentityRequired: "verified_identity_required",
  productionIdentityRequired: "production_identity_required",
  identityProfileRequired: "identity_profile_required",
  homeLocationRequired: "home_location_required",
  eligibilityFailed: "eligibility_failed",
  encryptedVoteRequired: "encrypted_vote_required",
  proofMetadataRequired: "proof_metadata_required",
  ciphertextCommitmentMismatch: "ciphertext_commitment_mismatch",
  pollEncryptionKeyUnavailable: "poll_encryption_key_unavailable",
  pollEncryptionKeyMismatch: "poll_encryption_key_mismatch",
  encryptedVoteHashMismatch: "encrypted_vote_hash_mismatch",
  proofRequired: "proof_required",
  preproverEnvelopeOnProductionPoll: "preprover_envelope_on_production_poll",
  proofInvalid: "proof_invalid",
  nonRegistryCredentialRoot: "non_registry_credential_root",
  staleCredentialRoot: "stale_credential_root",
  unknownVerifierKey: "unknown_verifier_key",
  verifierDisabled: "verifier_disabled",
  verifierUnconfigured: "verifier_unconfigured",
  verifierUnavailable: "verifier_unavailable",
  verifierRejected: "verifier_rejected",
  duplicateNullifier: "duplicate_nullifier",
  auditMaterialMissing: "audit_material_missing",
  noAcceptedAuditVotes: "no_accepted_audit_votes",
  tallyBatchLimitExceeded: "tally_batch_limit_exceeded",
  tallyProofInvalid: "tally_proof_invalid",
  transactionsDisabled: "transactions_disabled",
  publicationFailed: "publication_failed",
  pollNotOwned: "poll_not_owned",
  pollNotProductionZkp: "poll_not_production_zkp",
} as const);

export type ZkpAuditRejectionReasonCode =
  (typeof ZKP_AUDIT_REJECTION_REASON_CODES)[keyof typeof ZKP_AUDIT_REJECTION_REASON_CODES];

const FORBIDDEN_AUDIT_PAYLOAD_KEYS = new Set(
  [
    "user_id",
    "userid",
    "userId",
    "viewer_user_id",
    "viewerUserId",
    "verified_identity_id",
    "verifiedIdentityId",
    "identity_profile_id",
    "identityProfileId",
    "ip",
    "ip_address",
    "ipAddress",
    "remote_address",
    "remoteAddress",
    "x_forwarded_for",
    "xForwardedFor",
    "user_agent",
    "userAgent",
    "raw_document",
    "rawDocument",
    "document_number",
    "documentNumber",
    "document_image",
    "documentImage",
    "document_scan",
    "documentScan",
    "passport_number",
    "passportNumber",
    "national_id",
    "nationalId",
    "mrz",
    "date_of_birth",
    "dateOfBirth",
    "birth_date",
    "birthDate",
    "dob",
    "witness",
    "private_witness",
    "privateWitness",
    "witness_json",
    "witnessJson",
    "credential_secret",
    "credentialSecret",
    "identity_secret",
    "identitySecret",
    "nullifier_secret",
    "nullifierSecret",
    "secret",
    "seed_phrase",
    "seedPhrase",
    "private_key",
    "privateKey",
    "latitude",
    "longitude",
    "home_area_id",
    "homeAreaId",
    "location",
    "location_snapshot",
    "locationSnapshot",
    "vote_latitude_l0",
    "voteLatitudeL0",
    "vote_longitude_l0",
    "voteLongitudeL0",
    "vote_location_snapshot_at",
    "voteLocationSnapshotAt",
  ].map((key) => key.toLowerCase()),
);

const sha256Hex = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const isForbiddenAuditPayloadKey = (key: string): boolean =>
  FORBIDDEN_AUDIT_PAYLOAD_KEYS.has(key.trim().toLowerCase());

export const hashZkpAuditIdentifier = (
  value: string | null | undefined,
): string | null => {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (!normalized) {
    return null;
  }

  return sha256Hex(`${ZKP_AUDIT_IDENTIFIER_HASH_DOMAIN}|${normalized}`);
};

export const assertZkpAuditPayloadIsSafe = (
  value: JsonValue,
  path = "$",
): void => {
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      assertZkpAuditPayloadIsSafe(entry, `${path}[${index}]`),
    );
    return;
  }

  if (!isRecord(value)) {
    return;
  }

  Object.entries(value).forEach(([key, child]) => {
    const childPath = `${path}.${key}`;
    if (isForbiddenAuditPayloadKey(key)) {
      throw new Error(
        `Unsafe ZKP audit payload key "${childPath}" would leak identity, witness, network, or location material.`,
      );
    }
    assertZkpAuditPayloadIsSafe(child as JsonValue, childPath);
  });
};

type ZkpAuditEventRepositoryLike = Pick<
  typeof backendAuditEventRepository,
  "append"
>;

type AppendZkpAuditEventInput = Readonly<{
  pollId: string;
  eventType: ZkpAuditEventType;
  decision: BackendAuditEventDecision;
  payload: JsonValue;
  occurredAt?: string | null;
}>;

const appendZkpAuditEvent = async (
  repository: ZkpAuditEventRepositoryLike,
  input: AppendZkpAuditEventInput,
): Promise<AppendBackendAuditEventResult | null> => {
  const payload = {
    version: ZKP_AUDIT_EVENT_CONTRACT_VERSION,
    ...((isRecord(input.payload) ? input.payload : { value: input.payload }) as {
      [key: string]: JsonValue;
    }),
    pollId: input.pollId,
  } satisfies JsonValue;
  assertZkpAuditPayloadIsSafe(payload);

  return repository.append({
    streamId: `${ZKP_AUDIT_STREAM_PREFIX}:${input.pollId}`,
    eventType: input.eventType,
    decision: input.decision,
    subjectType: "poll",
    subjectId: input.pollId,
    payload,
    occurredAt: input.occurredAt ?? undefined,
  });
};

export const createZkpAuditEventService = (
  repository: ZkpAuditEventRepositoryLike = backendAuditEventRepository,
) => ({
  appendVoteAccepted(input: {
    pollId: string;
    voteId?: string | null;
    nullifier: string;
    voteCommitment: string;
    encryptedVoteHash: string;
    encryptedVoteCommitment: string;
    proofHash: string;
    proofEnvelopeHash: string;
    proofVerificationStatus: string;
    verifierKeyHash: string;
    circuitId: string;
    occurredAt?: string | null;
  }) {
    return appendZkpAuditEvent(repository, {
      pollId: input.pollId,
      eventType: ZKP_AUDIT_EVENT_TYPES.voteAccepted,
      decision: "accepted",
      occurredAt: input.occurredAt,
      payload: {
        voteId: input.voteId ?? null,
        nullifierHash: hashZkpAuditIdentifier(input.nullifier),
        voteCommitment: input.voteCommitment,
        encryptedVoteHash: input.encryptedVoteHash,
        encryptedVoteCommitment: input.encryptedVoteCommitment,
        proofHash: input.proofHash,
        proofEnvelopeHash: input.proofEnvelopeHash,
        proofVerificationStatus: input.proofVerificationStatus,
        verifierKeyHash: input.verifierKeyHash,
        circuitId: input.circuitId,
      },
    });
  },

  appendVoteRejected(input: {
    pollId: string;
    reasonCode: ZkpAuditRejectionReasonCode;
    errorCode: string;
    verifierReason?: string | null;
    nullifier?: string | null;
    proofHash?: string | null;
    proofEnvelopeHash?: string | null;
    proofPublicInputsHash?: string | null;
    credentialRoot?: string | null;
    encryptedVoteHash?: string | null;
    encryptedVoteCommitment?: string | null;
    verifierKeyHash?: string | null;
    circuitId?: string | null;
    occurredAt?: string | null;
  }) {
    return appendZkpAuditEvent(repository, {
      pollId: input.pollId,
      eventType: ZKP_AUDIT_EVENT_TYPES.voteRejected,
      decision: "rejected",
      occurredAt: input.occurredAt,
      payload: {
        reasonCode: input.reasonCode,
        errorCode: input.errorCode,
        verifierReason: input.verifierReason ?? null,
        nullifierHash: hashZkpAuditIdentifier(input.nullifier),
        proofHash: input.proofHash ?? null,
        proofEnvelopeHash: input.proofEnvelopeHash ?? null,
        proofPublicInputsHash: input.proofPublicInputsHash ?? null,
        credentialRoot: input.credentialRoot ?? null,
        encryptedVoteHash: input.encryptedVoteHash ?? null,
        encryptedVoteCommitment: input.encryptedVoteCommitment ?? null,
        verifierKeyHash: input.verifierKeyHash ?? null,
        circuitId: input.circuitId ?? null,
      },
    });
  },

  appendTallyAccepted(input: {
    pollId: string;
    resultHash: string;
    tallyProofHash: string;
    tallyPublicInputsHash: string;
    tallyVerifierKeyHash: string;
    tallyCircuitId: string;
    nullifierRoot: string;
    voteCommitmentRoot: string;
    encryptedVoteRoot: string;
    acceptedCount: number;
    occurredAt?: string | null;
  }) {
    return appendZkpAuditEvent(repository, {
      pollId: input.pollId,
      eventType: ZKP_AUDIT_EVENT_TYPES.tallyAccepted,
      decision: "accepted",
      occurredAt: input.occurredAt,
      payload: {
        resultHash: input.resultHash,
        tallyProofHash: input.tallyProofHash,
        tallyPublicInputsHash: input.tallyPublicInputsHash,
        tallyVerifierKeyHash: input.tallyVerifierKeyHash,
        tallyCircuitId: input.tallyCircuitId,
        nullifierRoot: input.nullifierRoot,
        voteCommitmentRoot: input.voteCommitmentRoot,
        encryptedVoteRoot: input.encryptedVoteRoot,
        acceptedCount: input.acceptedCount,
      },
    });
  },

  appendTallyRejected(input: {
    pollId: string;
    reasonCode: ZkpAuditRejectionReasonCode;
    errorCode: string;
    verifierReason?: string | null;
    nullifierRoot?: string | null;
    voteCommitmentRoot?: string | null;
    encryptedVoteRoot?: string | null;
    acceptedCount?: number | null;
    tallyProofHash?: string | null;
    tallyPublicInputsHash?: string | null;
    tallyVerifierKeyHash?: string | null;
    tallyCircuitId?: string | null;
    occurredAt?: string | null;
  }) {
    return appendZkpAuditEvent(repository, {
      pollId: input.pollId,
      eventType: ZKP_AUDIT_EVENT_TYPES.tallyRejected,
      decision: "rejected",
      occurredAt: input.occurredAt,
      payload: {
        reasonCode: input.reasonCode,
        errorCode: input.errorCode,
        verifierReason: input.verifierReason ?? null,
        nullifierRoot: input.nullifierRoot ?? null,
        voteCommitmentRoot: input.voteCommitmentRoot ?? null,
        encryptedVoteRoot: input.encryptedVoteRoot ?? null,
        acceptedCount: input.acceptedCount ?? null,
        tallyProofHash: input.tallyProofHash ?? null,
        tallyPublicInputsHash: input.tallyPublicInputsHash ?? null,
        tallyVerifierKeyHash: input.tallyVerifierKeyHash ?? null,
        tallyCircuitId: input.tallyCircuitId ?? null,
      },
    });
  },

  appendRootPublished(input: {
    pollId: string;
    batchIndex: number;
    batchId: string;
    acceptedCount: number;
    cumulativeAcceptedCount: number;
    resultHash: string;
    nullifierRoot: string;
    voteCommitmentRoot: string;
    encryptedVoteRoot: string;
    tallyProofHash?: string | null;
    tallyPublicInputsHash?: string | null;
    solanaTxSignature: string;
    pollAddress?: string | null;
    rootAddress?: string | null;
    occurredAt?: string | null;
  }) {
    return appendZkpAuditEvent(repository, {
      pollId: input.pollId,
      eventType: ZKP_AUDIT_EVENT_TYPES.rootPublished,
      decision: "published",
      occurredAt: input.occurredAt,
      payload: {
        batchIndex: input.batchIndex,
        batchId: input.batchId,
        acceptedCount: input.acceptedCount,
        cumulativeAcceptedCount: input.cumulativeAcceptedCount,
        resultHash: input.resultHash,
        nullifierRoot: input.nullifierRoot,
        voteCommitmentRoot: input.voteCommitmentRoot,
        encryptedVoteRoot: input.encryptedVoteRoot,
        tallyProofHash: input.tallyProofHash ?? null,
        tallyPublicInputsHash: input.tallyPublicInputsHash ?? null,
        solanaTxSignature: input.solanaTxSignature,
        pollAddress: input.pollAddress ?? null,
        rootAddress: input.rootAddress ?? null,
      },
    });
  },

  appendFinalized(input: {
    pollId: string;
    resultHash: string;
    acceptedVoteCount: number;
    nullifierRoot: string;
    voteCommitmentRoot: string;
    encryptedVoteRoot: string;
    tallyProofHash?: string | null;
    tallyPublicInputsHash?: string | null;
    solanaTxSignature: string;
    finalResultAddress?: string | null;
    occurredAt?: string | null;
  }) {
    return appendZkpAuditEvent(repository, {
      pollId: input.pollId,
      eventType: ZKP_AUDIT_EVENT_TYPES.finalized,
      decision: "published",
      occurredAt: input.occurredAt,
      payload: {
        resultHash: input.resultHash,
        acceptedVoteCount: input.acceptedVoteCount,
        nullifierRoot: input.nullifierRoot,
        voteCommitmentRoot: input.voteCommitmentRoot,
        encryptedVoteRoot: input.encryptedVoteRoot,
        tallyProofHash: input.tallyProofHash ?? null,
        tallyPublicInputsHash: input.tallyPublicInputsHash ?? null,
        solanaTxSignature: input.solanaTxSignature,
        finalResultAddress: input.finalResultAddress ?? null,
      },
    });
  },

  appendPublicationRejected(input: {
    pollId: string;
    reasonCode: ZkpAuditRejectionReasonCode;
    errorCode: string;
    acceptedVoteCount?: number | null;
    resultHash?: string | null;
    occurredAt?: string | null;
  }) {
    return appendZkpAuditEvent(repository, {
      pollId: input.pollId,
      eventType: ZKP_AUDIT_EVENT_TYPES.publicationRejected,
      decision: "rejected",
      occurredAt: input.occurredAt,
      payload: {
        reasonCode: input.reasonCode,
        errorCode: input.errorCode,
        acceptedVoteCount: input.acceptedVoteCount ?? null,
        resultHash: input.resultHash ?? null,
      },
    });
  },
});

export const zkpAuditEventService = createZkpAuditEventService();

export default zkpAuditEventService;
