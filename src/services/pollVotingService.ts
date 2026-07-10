import identityProfileRepository from "../repositories/identityProfileRepository";
import pollMapRefreshQueueRepository from "../repositories/pollMapRefreshQueueRepository";
import pollRepository from "../repositories/pollRepository";
import pollZkVoteRepository from "../repositories/pollZkVoteRepository";
import verifiedIdentityRepository from "../repositories/verifiedIdentityRepository";
import voteRepository from "../repositories/voteRepository";
import {
  CIVIC_PRODUCTION_ENCRYPTED_VOTE_VERSION,
  CIVIC_PRODUCTION_HASH_SUITE,
  CIVIC_PRODUCTION_VOTE_PRIVACY_MODE,
  hashEncryptedVotePayload,
  verifyGroth16VoteProofForPoll,
  type Groth16VoteProofEnvelopeDto,
} from "./groth16ProofVerifierService";
import {
  normalizeCountryCode,
  resolveCivicPollPolicy,
  type CivicPollPolicy,
} from "./pollPolicyService";
import pollEncryptionKeyService, {
  CIVIC_ENCRYPTED_VOTE_ALGORITHM,
  CIVIC_ENCRYPTED_VOTE_CIPHER,
  CIVIC_ENCRYPTED_VOTE_KEY_AGREEMENT,
  CIVIC_ENCRYPTED_VOTE_KDF,
} from "./pollEncryptionKeyService";
import {
  hashPublicAuditLeaf,
  hashPublicAuditLeafForPoll,
} from "./pollPublicAuditService";
import { verifyVoteProofForPoll } from "./voteProofVerifierService";
import zkpAuditEventService, {
  ZKP_AUDIT_REJECTION_REASON_CODES,
  type ZkpAuditRejectionReasonCode,
} from "./zkpAuditEventService";
import type {
  PollDetailsDto,
  PollDto,
  PollOptionDto,
  PollResultsSummaryDto,
  PollSummaryDto,
  VotePrivacyPayloadDto,
  VoteReceiptDto,
  VoteSubmissionErrorCode,
  VoteSubmissionFailureDto,
  VoteSubmissionResultDto,
  PollVotePrivacyMode,
} from "../types/contracts";
import type { PollOptionRow, PollRow, UserRow } from "../types/db";
import type { JsonValue } from "../types/json";

const POLL_STATUS_SORT_ORDER: Record<PollDto["status"], number> = {
  active: 0,
  scheduled: 1,
  closed: 2,
  archived: 3,
  draft: 4,
};

const toArray = (value: string[] | null | undefined): string[] =>
  Array.isArray(value) ? value : [];

const normalizeVotePrivacyMode = (
  value: PollRow["vote_privacy_mode"],
): PollVotePrivacyMode => {
  if (
    value === "legacy_identity_linked" ||
    value === "zk_preprover_audit" ||
    value === "zk_secret_ballot_v1"
  ) {
    return value;
  }

  return "zk_preprover_audit";
};

const mapPoll = (row: PollRow): PollDto => {
  const allowedDocumentCountryCodes = toArray(row.allowed_document_country_codes);
  const allowedHomeAreaIds = toArray(row.allowed_home_area_ids);
  const allowedLandIds = toArray(row.allowed_land_ids);

  return {
    id: row.id,
    slug: row.slug,
    createdByUserId: row.created_by_user_id,
    title: row.title,
    description: row.description,
    status: row.status,
    jurisdictionType: row.jurisdiction_type,
    jurisdictionCountryCode: row.jurisdiction_country_code,
    jurisdictionAreaIds: toArray(row.jurisdiction_area_ids),
    jurisdictionLandIds: toArray(row.jurisdiction_land_ids),
    eligibilityRule: {
      requiresVerifiedIdentity: row.requires_verified_identity,
      ...(allowedDocumentCountryCodes.length > 0
        ? { allowedDocumentCountryCodes }
        : null),
      ...(allowedHomeAreaIds.length > 0 ? { allowedHomeAreaIds } : null),
      ...(allowedLandIds.length > 0 ? { allowedLandIds } : null),
      minimumAge: row.minimum_age,
    },
    pollPolicyHash: row.poll_policy_hash ?? null,
    credentialSchemaHash: row.credential_schema_hash ?? null,
    votePrivacyMode: normalizeVotePrivacyMode(row.vote_privacy_mode),
    optionSetHash: row.option_set_hash ?? null,
    pollEncryptionKeyId: row.poll_encryption_key_id ?? null,
    startsAt: row.starts_at,
    endsAt: row.ends_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
};

const mapOption = (row: PollOptionRow): PollOptionDto => ({
  id: row.id,
  pollId: row.poll_id,
  label: row.label,
  description: row.description,
  color: row.color,
  order: row.display_order,
  isActive: row.is_active,
  createdAt: row.created_at,
});

const buildFailure = (
  errorCode: VoteSubmissionErrorCode,
  message: string,
  reasonCode?: string | null,
): VoteSubmissionFailureDto => ({
  success: false,
  errorCode,
  ...(reasonCode ? { reasonCode } : null),
  message,
});

const DUPLICATE_USER_VOTE_MESSAGE =
  "Only one vote per user and poll is allowed.";
const DUPLICATE_VERIFIED_IDENTITY_VOTE_MESSAGE =
  "Only one vote per verified identity and poll is allowed.";
const DUPLICATE_NULLIFIER_VOTE_MESSAGE =
  "Only one vote per proof nullifier and poll is allowed.";
const VERIFIED_IDENTITY_REQUIRED_MESSAGE =
  "This poll requires a linked verified identity.";
const PRODUCTION_ZKP_ENCRYPTED_VOTE_REQUIRED_MESSAGE =
  "This poll requires an encrypted vote payload.";

type ProductionEncryptedVotePayload = {
  version: typeof CIVIC_PRODUCTION_ENCRYPTED_VOTE_VERSION;
  pollEncryptionKeyId: string;
  pollEncryptionKeyHash: string;
  encryptedVoteCommitment: string;
  ciphertext: string;
  nonce: string;
  authTag: string;
  algorithm: string;
  keyAgreement: string;
  kdf: string;
  cipher: string;
  ephemeralPublicKey: string;
  optionSetHash: string;
};

type PollVotingServiceDependencies = {
  verifyGroth16VoteProofForPoll?: typeof verifyGroth16VoteProofForPoll;
  hashEncryptedVotePayload?: typeof hashEncryptedVotePayload;
  getPollEncryptionKeyForPoll?: typeof pollEncryptionKeyService.getOrCreatePublicKeyForPoll;
  zkpAuditEventService?: Pick<
    typeof zkpAuditEventService,
    "appendVoteAccepted" | "appendVoteRejected"
  >;
};

type VoteRejectedAuditFields = Partial<
  Omit<
    Parameters<typeof zkpAuditEventService.appendVoteRejected>[0],
    "pollId" | "reasonCode" | "errorCode" | "occurredAt"
  >
>;

const buildVoteReceipt = (input: {
  pollId: string;
  optionId: string;
  voteCommitment: string;
  voteCommitmentLeafHash?: string;
  proofHash: string;
  acceptedAt: string;
}): VoteReceiptDto => ({
  version: "civicos-vote-receipt-v1",
  pollId: input.pollId,
  optionId: input.optionId,
  voteCommitment: input.voteCommitment,
  voteCommitmentLeafHash:
    input.voteCommitmentLeafHash ??
    hashPublicAuditLeaf("vote_commitment", input.voteCommitment),
  proofHash: input.proofHash,
  batchStatus: "pending",
  batchId: null,
  solanaRootTransaction: null,
  acceptedAt: input.acceptedAt,
  auditUrl: `/polls/${encodeURIComponent(input.pollId)}/audit`,
});

const isUniqueViolation = (error: unknown): boolean => {
  if (!error || typeof error !== "object") {
    return false;
  }

  const maybeCode = (error as { code?: unknown }).code;
  return maybeCode === "23505";
};

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const toStringOrEmpty = (value: unknown): string =>
  typeof value === "string" ? value.trim() : "";

const HEX_64_PATTERN = /^[0-9a-f]{64}$/;

const normalizeHex64 = (value: unknown): string | null => {
  const normalized = toStringOrEmpty(value).toLowerCase();
  return HEX_64_PATTERN.test(normalized) ? normalized : null;
};

const isProductionZkpPoll = (poll: PollRow): boolean =>
  normalizeVotePrivacyMode(poll.vote_privacy_mode) ===
  CIVIC_PRODUCTION_VOTE_PRIVACY_MODE;

const getOrderedActivePollOptions = (
  options: readonly PollOptionRow[],
): PollOptionRow[] =>
  [...options]
    .filter((option) => option.is_active)
    .sort((left, right) => left.display_order - right.display_order);

const normalizeProductionEncryptedVotePayload = (
  encryptedVote: unknown,
  poll: PollRow,
): ProductionEncryptedVotePayload | null => {
  if (!isPlainObject(encryptedVote)) {
    return null;
  }

  const allowedKeys = new Set([
    "version",
    "pollEncryptionKeyId",
    "pollEncryptionKeyHash",
    "encryptedVoteCommitment",
    "ciphertext",
    "nonce",
    "authTag",
    "algorithm",
    "keyAgreement",
    "kdf",
    "cipher",
    "ephemeralPublicKey",
    "optionSetHash",
  ]);
  if (Object.keys(encryptedVote).some((key) => !allowedKeys.has(key))) {
    return null;
  }

  const optionSetHash = normalizeHex64(encryptedVote.optionSetHash);
  const pollEncryptionKeyHash = normalizeHex64(
    encryptedVote.pollEncryptionKeyHash,
  );
  const encryptedVoteCommitment = normalizeHex64(
    encryptedVote.encryptedVoteCommitment,
  );
  const normalized = {
    version: toStringOrEmpty(encryptedVote.version),
    pollEncryptionKeyId: toStringOrEmpty(encryptedVote.pollEncryptionKeyId),
    pollEncryptionKeyHash,
    encryptedVoteCommitment,
    ciphertext: toStringOrEmpty(encryptedVote.ciphertext),
    nonce: toStringOrEmpty(encryptedVote.nonce),
    authTag: toStringOrEmpty(encryptedVote.authTag),
    algorithm: toStringOrEmpty(encryptedVote.algorithm),
    keyAgreement: toStringOrEmpty(encryptedVote.keyAgreement),
    kdf: toStringOrEmpty(encryptedVote.kdf),
    cipher: toStringOrEmpty(encryptedVote.cipher),
    ephemeralPublicKey: toStringOrEmpty(encryptedVote.ephemeralPublicKey),
    optionSetHash,
  };

  if (
    normalized.version !== CIVIC_PRODUCTION_ENCRYPTED_VOTE_VERSION ||
    !normalized.pollEncryptionKeyId ||
    !normalized.pollEncryptionKeyHash ||
    !normalized.encryptedVoteCommitment ||
    !normalized.ciphertext ||
    !normalized.nonce ||
    !normalized.authTag ||
    normalized.algorithm !== CIVIC_ENCRYPTED_VOTE_ALGORITHM ||
    normalized.keyAgreement !== CIVIC_ENCRYPTED_VOTE_KEY_AGREEMENT ||
    normalized.kdf !== CIVIC_ENCRYPTED_VOTE_KDF ||
    normalized.cipher !== CIVIC_ENCRYPTED_VOTE_CIPHER ||
    !normalized.ephemeralPublicKey ||
    !normalized.optionSetHash
  ) {
    return null;
  }

  if (
    poll.poll_encryption_key_id &&
    normalized.pollEncryptionKeyId !== poll.poll_encryption_key_id
  ) {
    return null;
  }

  const pollOptionSetHash = normalizeHex64(poll.option_set_hash);
  if (!pollOptionSetHash || normalized.optionSetHash !== pollOptionSetHash) {
    return null;
  }

  return normalized as ProductionEncryptedVotePayload;
};

const normalizeProductionPrivacyPayload = (
  privacy: VotePrivacyPayloadDto | null | undefined,
): {
  proof: Groth16VoteProofEnvelopeDto;
  voteCommitment: string;
  encryptedVoteHash: string;
  encryptedVoteCommitment: string;
} | null => {
  const candidate = privacy as
    | (VotePrivacyPayloadDto & {
        votePrivacyMode?: unknown;
        voteCommitment?: unknown;
        encryptedVoteHash?: unknown;
        encryptedVoteCommitment?: unknown;
        proof?: unknown;
      })
    | null
    | undefined;

  if (!candidate || !isPlainObject(candidate.proof)) {
    return null;
  }

  const nullifier = normalizeHex64(candidate.nullifier);
  const proofPublicInputs = (candidate.proof as { publicInputs?: unknown })
    .publicInputs;
  if (!isPlainObject(proofPublicInputs)) {
    return null;
  }

  const proofNullifier = normalizeHex64(proofPublicInputs.nullifier);
  const voteCommitment =
    normalizeHex64(candidate.voteCommitment) ||
    normalizeHex64(proofPublicInputs.voteCommitment);
  const encryptedVoteHash =
    normalizeHex64(candidate.encryptedVoteHash) ||
    normalizeHex64(proofPublicInputs.encryptedVoteHash);
  const encryptedVoteCommitment =
    normalizeHex64(candidate.encryptedVoteCommitment) ||
    normalizeHex64(proofPublicInputs.encryptedVoteCommitment);

  if (
    toStringOrEmpty(candidate.version) !== "civicos-vote-privacy-v1" ||
    toStringOrEmpty(candidate.votePrivacyMode) !== CIVIC_PRODUCTION_VOTE_PRIVACY_MODE ||
    toStringOrEmpty(candidate.hashSuite) !== CIVIC_PRODUCTION_HASH_SUITE ||
    !nullifier ||
    !proofNullifier ||
    nullifier !== proofNullifier ||
    !voteCommitment ||
    !encryptedVoteHash ||
    !encryptedVoteCommitment
  ) {
    return null;
  }

  return {
    proof: candidate.proof as Groth16VoteProofEnvelopeDto,
    voteCommitment,
    encryptedVoteHash,
    encryptedVoteCommitment,
  };
};

const isPreproverVotePrivacyPayload = (
  privacy: VotePrivacyPayloadDto | null | undefined,
): boolean => {
  if (!privacy || !isPlainObject(privacy)) {
    return false;
  }

  const proof = privacy.proof;
  if (!isPlainObject(proof)) {
    return false;
  }

  return (
    toStringOrEmpty(proof.version) === "civicos-proof-envelope-v1" ||
    toStringOrEmpty(proof.proofSystemVersion) ===
      "civicos-zk-proof-v1-preprover" ||
    toStringOrEmpty(proof.status) === "not_generated"
  );
};

const mapVoteVerifierReasonToAuditReasonCode = (
  reason: string,
): ZkpAuditRejectionReasonCode => {
  switch (reason) {
    case "PROOF_REQUIRED":
      return ZKP_AUDIT_REJECTION_REASON_CODES.proofRequired;
    case "CREDENTIAL_ROOT_UNKNOWN":
      return ZKP_AUDIT_REJECTION_REASON_CODES.nonRegistryCredentialRoot;
    case "VERIFIER_KEY_MISMATCH":
      return ZKP_AUDIT_REJECTION_REASON_CODES.unknownVerifierKey;
    case "VERIFIER_DISABLED":
      return ZKP_AUDIT_REJECTION_REASON_CODES.verifierDisabled;
    case "VERIFIER_UNCONFIGURED":
      return ZKP_AUDIT_REJECTION_REASON_CODES.verifierUnconfigured;
    case "VERIFIER_UNAVAILABLE":
      return ZKP_AUDIT_REJECTION_REASON_CODES.verifierUnavailable;
    case "VERIFIER_REJECTED":
      return ZKP_AUDIT_REJECTION_REASON_CODES.verifierRejected;
    default:
      return ZKP_AUDIT_REJECTION_REASON_CODES.proofInvalid;
  }
};

const buildProductionVoteAuditHints = (
  productionPrivacy:
    | ReturnType<typeof normalizeProductionPrivacyPayload>
    | null
    | undefined,
): {
  nullifier?: string | null;
  proofPublicInputsHash?: string | null;
  credentialRoot?: string | null;
  encryptedVoteHash?: string | null;
  encryptedVoteCommitment?: string | null;
  verifierKeyHash?: string | null;
  circuitId?: string | null;
} => {
  const proof = productionPrivacy?.proof;
  const publicInputs = proof?.publicInputs;

  return {
    nullifier: publicInputs?.nullifier ?? null,
    proofPublicInputsHash: proof?.publicInputsHash ?? null,
    credentialRoot: publicInputs?.credentialRoot ?? null,
    encryptedVoteHash:
      productionPrivacy?.encryptedVoteHash ??
      publicInputs?.encryptedVoteHash ??
      null,
    encryptedVoteCommitment:
      productionPrivacy?.encryptedVoteCommitment ??
      publicInputs?.encryptedVoteCommitment ??
      null,
    verifierKeyHash: proof?.verifierKeyHash ?? publicInputs?.verifierKeyHash ?? null,
    circuitId: proof?.circuitId ?? publicInputs?.circuitId ?? null,
  };
};

const sortSummaries = (summaries: PollSummaryDto[]): PollSummaryDto[] =>
  [...summaries].sort((left, right) => {
    const statusDelta =
      POLL_STATUS_SORT_ORDER[left.poll.status] -
      POLL_STATUS_SORT_ORDER[right.poll.status];

    if (statusDelta !== 0) {
      return statusDelta;
    }

    return right.poll.createdAt.localeCompare(left.poll.createdAt);
  });

const isPollVisibleToViewer = (poll: PollRow, viewerUserId: string): boolean =>
  poll.status !== "draft" || poll.created_by_user_id === viewerUserId;

const buildResults = (
  poll: PollDto,
  options: PollOptionDto[],
  params: {
    countsByOptionId: Record<string, number>;
    totalVotes: number;
    latestSubmittedAt: string | null;
  },
): PollResultsSummaryDto => {
  const { countsByOptionId, totalVotes, latestSubmittedAt } = params;

  const orderedOptions = [...options].sort((left, right) => left.order - right.order);
  const normalizedTotalVotes = Number.isFinite(totalVotes)
    ? Math.max(0, Math.trunc(totalVotes))
    : 0;

  const optionResults = orderedOptions.map((option) => {
    const count = countsByOptionId[option.id] || 0;
    return {
      optionId: option.id,
      label: option.label,
      count,
      percentage: normalizedTotalVotes > 0 ? (count / normalizedTotalVotes) * 100 : 0,
    };
  });

  const winningOption =
    normalizedTotalVotes > 0 && optionResults.some((entry) => entry.count > 0)
      ? optionResults.reduce<typeof optionResults[number] | null>((winner, candidate) => {
          if (!winner || candidate.count > winner.count) {
            return candidate;
          }

          return winner;
        }, null)
      : null;

  return {
    pollId: poll.id,
    totalVotes: normalizedTotalVotes,
    optionResults,
    winningOptionId: winningOption?.optionId ?? null,
    winningOptionLabel: winningOption?.label ?? null,
    updatedAt: latestSubmittedAt || poll.updatedAt,
  };
};

const resolvePolicyForPoll = (poll: PollRow): CivicPollPolicy =>
  resolveCivicPollPolicy(poll.poll_policy_json, {
    pollId: poll.id,
    jurisdictionType: poll.jurisdiction_type,
    jurisdictionCountryCode: poll.jurisdiction_country_code,
    jurisdictionAreaIds: poll.jurisdiction_area_ids,
    jurisdictionLandIds: poll.jurisdiction_land_ids,
    requiresVerifiedIdentity: poll.requires_verified_identity,
    allowedDocumentCountryCodes: poll.allowed_document_country_codes,
    allowedHomeAreaIds: poll.allowed_home_area_ids,
    allowedLandIds: poll.allowed_land_ids,
    minimumAge: poll.minimum_age,
    startsAt: poll.starts_at,
    endsAt: poll.ends_at,
  });

const isTimestampAfter = (left: string, right: string): boolean => {
  const leftMs = Date.parse(left);
  const rightMs = Date.parse(right);
  return Number.isFinite(leftMs) && Number.isFinite(rightMs) && leftMs > rightMs;
};

const isTimestampOnOrBefore = (left: string, right: string): boolean => {
  const leftMs = Date.parse(left);
  const rightMs = Date.parse(right);
  return Number.isFinite(leftMs) && Number.isFinite(rightMs) && leftMs <= rightMs;
};

const isPollVotingWindowOpen = (poll: PollRow, nowIso: string): boolean => {
  if (poll.starts_at && isTimestampAfter(poll.starts_at, nowIso)) {
    return false;
  }

  if (poll.ends_at && isTimestampOnOrBefore(poll.ends_at, nowIso)) {
    return false;
  }

  return true;
};

const evaluateEligibility = (
  policy: CivicPollPolicy,
  user: Pick<UserRow, "selected_land_id">,
  hasLinkedVerifiedIdentity: boolean,
  identityProfile: { document_country_code: string | null; home_area_id: string | null },
): VoteSubmissionFailureDto | null => {
  const { eligibilityRules } = policy;

  if (eligibilityRules.requiresVerifiedIdentity && !hasLinkedVerifiedIdentity) {
    return buildFailure(
      "ELIGIBILITY_FAILED",
      VERIFIED_IDENTITY_REQUIRED_MESSAGE,
    );
  }

  const allowedDocumentCountryCodes =
    eligibilityRules.acceptedDocumentCountryCodes;
  if (allowedDocumentCountryCodes.length > 0) {
    const documentCountryCode = normalizeCountryCode(
      identityProfile.document_country_code,
    );
    if (
      !documentCountryCode ||
      !allowedDocumentCountryCodes.includes(documentCountryCode)
    ) {
      return buildFailure(
        "ELIGIBILITY_FAILED",
        "This poll is restricted to specific document countries.",
      );
    }
  }

  const allowedHomeAreaIds = eligibilityRules.acceptedHomeAreaIds;
  if (allowedHomeAreaIds.length > 0) {
    const homeAreaId = identityProfile.home_area_id?.trim() || null;
    if (!homeAreaId || !allowedHomeAreaIds.includes(homeAreaId)) {
      return buildFailure(
        "ELIGIBILITY_FAILED",
        "This poll is restricted to specific home areas.",
      );
    }
  }

  const allowedLandIds = eligibilityRules.acceptedLandIds;
  if (allowedLandIds.length > 0) {
    const selectedLandId = user.selected_land_id?.trim() || null;
    if (!selectedLandId || !allowedLandIds.includes(selectedLandId)) {
      return buildFailure(
        "ELIGIBILITY_FAILED",
        "This poll is restricted to specific lands.",
      );
    }
  }

  // minimum_age is intentionally deferred until age data is available.
  return null;
};

const pollRequiresIdentityProfile = (policy: CivicPollPolicy): boolean =>
  policy.eligibilityRules.requiresVerifiedIdentity ||
  policy.eligibilityRules.acceptedDocumentCountryCodes.length > 0 ||
  policy.eligibilityRules.acceptedHomeAreaIds.length > 0;

const pollRequiresHomeArea = (policy: CivicPollPolicy): boolean =>
  policy.eligibilityRules.acceptedHomeAreaIds.length > 0;

const canonicalizeNegativeZero = (value: number): number =>
  Object.is(value, -0) ? 0 : value;

const roundToTwoDecimals = (value: number): number =>
  canonicalizeNegativeZero(Math.round(value * 100) / 100);

const resolveSnapshotCoordinate = (
  value: number | null,
  bounds: { min: number; max: number },
): number | null => {
  if (!Number.isFinite(value)) {
    return null;
  }

  const numericValue = Number(value);
  if (numericValue < bounds.min || numericValue > bounds.max) {
    return null;
  }

  return roundToTwoDecimals(numericValue);
};

const resolveVoteLocationSnapshot = (
  identityProfile: {
    home_approx_latitude: number | null;
    home_approx_longitude: number | null;
  } | null,
  snapshotAt: string,
):
  | {
      vote_latitude_l0: number;
      vote_longitude_l0: number;
      vote_location_snapshot_at: string;
      vote_location_snapshot_version: number;
    }
  | {
      vote_latitude_l0: null;
      vote_longitude_l0: null;
      vote_location_snapshot_at: null;
      vote_location_snapshot_version: number;
    } => {
  const latitude = resolveSnapshotCoordinate(identityProfile?.home_approx_latitude ?? null, {
    min: -90,
    max: 90,
  });
  const longitude = resolveSnapshotCoordinate(
    identityProfile?.home_approx_longitude ?? null,
    {
      min: -180,
      max: 180,
    },
  );

  if (latitude === null || longitude === null) {
    return {
      vote_latitude_l0: null,
      vote_longitude_l0: null,
      vote_location_snapshot_at: null,
      vote_location_snapshot_version: 1,
    };
  }

  return {
    vote_latitude_l0: latitude,
    vote_longitude_l0: longitude,
    vote_location_snapshot_at: snapshotAt,
    vote_location_snapshot_version: 1,
  };
};

export const createPollVotingService = (
  dependencies: PollVotingServiceDependencies = {},
) => {
  const verifyProductionVoteProof =
    dependencies.verifyGroth16VoteProofForPoll ?? verifyGroth16VoteProofForPoll;
  const hashProductionEncryptedVote =
    dependencies.hashEncryptedVotePayload ?? hashEncryptedVotePayload;
  const getPollEncryptionKeyForPoll =
    dependencies.getPollEncryptionKeyForPoll ??
    pollEncryptionKeyService.getOrCreatePublicKeyForPoll;
  const zkpAuditEvents =
    dependencies.zkpAuditEventService ?? zkpAuditEventService;

  return {
  async getPollSummaries(viewerUserId: string): Promise<PollSummaryDto[]> {
    const polls = (await pollRepository.listAll()).filter((poll) =>
      isPollVisibleToViewer(poll, viewerUserId),
    );
    if (polls.length === 0) {
      return [];
    }

    const pollIds = polls.map((poll) => poll.id);

    const productionPollIds = new Set(
      polls.filter(isProductionZkpPoll).map((poll) => poll.id),
    );

    const [options, viewerVotes, totalValidVotesByPoll] = await Promise.all([
      pollRepository.getOptionsByPollIds(pollIds),
      voteRepository.getViewerVotesByPollIds(viewerUserId, pollIds),
      Promise.all(
        polls.map(
          async (poll) =>
            [
              poll.id,
              productionPollIds.has(poll.id)
                ? await pollZkVoteRepository.countAcceptedByPollId(poll.id)
                : await voteRepository.countValidByPollId(poll.id),
            ] as const,
        ),
      ),
    ]);

    const optionCountByPollId = options.reduce<Record<string, number>>((acc, option) => {
      acc[option.poll_id] = (acc[option.poll_id] || 0) + 1;
      return acc;
    }, {});

    const voteCountByPollId = totalValidVotesByPoll.reduce<Record<string, number>>(
      (acc, [pollId, totalVotes]) => {
        acc[pollId] = totalVotes;
        return acc;
      },
      {},
    );

    const viewerVotedPollIds = new Set(
      viewerVotes
        .filter((vote) => !productionPollIds.has(vote.poll_id))
        .map((vote) => vote.poll_id),
    );

    const summaries = polls.map((poll) => ({
      poll: mapPoll(poll),
      optionCount: optionCountByPollId[poll.id] || 0,
      totalVotes: voteCountByPollId[poll.id] || 0,
      hasViewerVoted: viewerVotedPollIds.has(poll.id),
    }));

    return sortSummaries(summaries);
  },

  async getPollDetails(pollId: string, viewerUserId: string): Promise<PollDetailsDto | null> {
    const pollRow = await pollRepository.getById(pollId);
    if (!pollRow) {
      return null;
    }
    if (!isPollVisibleToViewer(pollRow, viewerUserId)) {
      return null;
    }

    const productionPoll = isProductionZkpPoll(pollRow);
    const [optionRows, viewerVote, exactTotalVotes, latestSubmittedAt] = await Promise.all([
      pollRepository.getOptionsByPollId(pollId),
      productionPoll
        ? Promise.resolve(null)
        : voteRepository.getByUserIdAndPollId(viewerUserId, pollId),
      productionPoll
        ? pollZkVoteRepository.countAcceptedByPollId(pollId)
        : voteRepository.countValidByPollId(pollId),
      productionPoll
        ? Promise.resolve(null)
        : voteRepository.getLatestValidSubmittedAtByPollId(pollId),
    ]);

    const optionCountEntries = productionPoll
      ? optionRows.map((option) => [option.id, 0] as const)
      : await Promise.all(
          optionRows.map(async (option) => [
            option.id,
            await voteRepository.countValidByPollIdAndOptionId(pollId, option.id),
          ] as const),
        );
    const countsByOptionId = optionCountEntries.reduce<Record<string, number>>(
      (acc, [optionId, count]) => {
        acc[optionId] = count;
        return acc;
      },
      {},
    );

    const poll = mapPoll(pollRow);
    const options = optionRows.map(mapOption);
    const results = buildResults(poll, options, {
      countsByOptionId,
      totalVotes: exactTotalVotes,
      latestSubmittedAt,
    });

    return {
      poll,
      options,
      viewerVote: viewerVote
        ? {
            pollId: viewerVote.poll_id,
            optionId: viewerVote.option_id,
            submittedAt: viewerVote.submitted_at,
          }
        : null,
      totalVotes: results.totalVotes,
      results,
    };
  },

  async submitVote(params: {
    pollId: string;
    optionId: string;
    viewer: UserRow;
    privacy?: VotePrivacyPayloadDto | null;
    expectedVoteCommitment?: string | null;
    encryptedVote?: unknown;
  }): Promise<VoteSubmissionResultDto> {
    const { pollId, optionId, viewer, privacy } = params;

    const poll = await pollRepository.getById(pollId);
    if (!poll) {
      return buildFailure("POLL_NOT_FOUND", "The requested poll does not exist.");
    }

    const submittedAt = new Date().toISOString();
    const productionZkpPoll = isProductionZkpPoll(poll);
    const rejectProductionVote = async (
      reasonCode: ZkpAuditRejectionReasonCode,
      errorCode: VoteSubmissionErrorCode,
      message: string,
      auditPayload: VoteRejectedAuditFields = {},
    ): Promise<VoteSubmissionFailureDto> => {
      if (productionZkpPoll) {
        await zkpAuditEvents.appendVoteRejected({
          pollId: poll.id,
          reasonCode,
          errorCode,
          occurredAt: submittedAt,
          ...auditPayload,
        });
      }

      return buildFailure(
        errorCode,
        message,
        productionZkpPoll ? reasonCode : null,
      );
    };

    if (poll.status !== "active") {
      return rejectProductionVote(
        ZKP_AUDIT_REJECTION_REASON_CODES.pollNotActive,
        "POLL_NOT_ACTIVE",
        "Only active polls can accept new votes in this phase.",
      );
    }

    if (!isPollVotingWindowOpen(poll, submittedAt)) {
      return rejectProductionVote(
        ZKP_AUDIT_REJECTION_REASON_CODES.pollNotActive,
        "POLL_NOT_ACTIVE",
        "The poll voting window is not open.",
      );
    }

    const pollPolicy = resolvePolicyForPoll(poll);
    const requiresVerifiedIdentity =
      pollPolicy.eligibilityRules.requiresVerifiedIdentity;

    const optionInPoll = await pollRepository.getOptionByIdForPoll(pollId, optionId);
    if (!optionInPoll) {
      const option = await pollRepository.getOptionById(optionId);
      if (!option) {
        return rejectProductionVote(
          ZKP_AUDIT_REJECTION_REASON_CODES.optionNotFound,
          "OPTION_NOT_FOUND",
          "The requested poll option does not exist.",
        );
      }

      return rejectProductionVote(
        ZKP_AUDIT_REJECTION_REASON_CODES.optionNotInPoll,
        "OPTION_NOT_IN_POLL",
        "The requested option does not belong to the poll.",
      );
    }

    if (!optionInPoll.is_active) {
      return rejectProductionVote(
        ZKP_AUDIT_REJECTION_REASON_CODES.optionInactive,
        "OPTION_NOT_FOUND",
        "The requested poll option is not active.",
      );
    }

    const productionOptionCount = productionZkpPoll
      ? getOrderedActivePollOptions(
          await pollRepository.getOptionsByPollId(pollId),
        ).length
      : 0;
    if (productionZkpPoll && productionOptionCount > 8) {
      return rejectProductionVote(
        ZKP_AUDIT_REJECTION_REASON_CODES.tooManyOptions,
        "PROOF_INVALID",
        "Production ZKP v1 polls support at most 8 active options.",
      );
    }

    let verifiedIdentityId: string | null = null;
    if (requiresVerifiedIdentity) {
      const verifiedIdentity = await verifiedIdentityRepository.getByUserId(viewer.id);
      if (!verifiedIdentity) {
        return rejectProductionVote(
          ZKP_AUDIT_REJECTION_REASON_CODES.verifiedIdentityRequired,
          "ELIGIBILITY_FAILED",
          VERIFIED_IDENTITY_REQUIRED_MESSAGE,
        );
      }

      verifiedIdentityId = verifiedIdentity.id;
      if (!productionZkpPoll) {
        const existingVote = await voteRepository.getByVerifiedIdentityIdAndPollId(
          verifiedIdentity.id,
          pollId,
        );
        if (existingVote) {
          return buildFailure("ALREADY_VOTED", DUPLICATE_VERIFIED_IDENTITY_VOTE_MESSAGE);
        }
      }
    } else {
      if (productionZkpPoll) {
        return rejectProductionVote(
          ZKP_AUDIT_REJECTION_REASON_CODES.productionIdentityRequired,
          "ELIGIBILITY_FAILED",
          "Production ZKP polls require verified identity eligibility.",
        );
      }

      const existingVote = await voteRepository.getByUserIdAndPollId(viewer.id, pollId);
      if (existingVote) {
        return buildFailure("ALREADY_VOTED", DUPLICATE_USER_VOTE_MESSAGE);
      }
    }

    const identityProfile = await identityProfileRepository.getByUserId(viewer.id);
    const requiresIdentityProfile = pollRequiresIdentityProfile(pollPolicy);

    if (!identityProfile && requiresIdentityProfile) {
      return rejectProductionVote(
        ZKP_AUDIT_REJECTION_REASON_CODES.identityProfileRequired,
        "IDENTITY_PROFILE_NOT_FOUND",
        "This poll requires identity profile data before voting.",
      );
    }

    if (pollRequiresHomeArea(pollPolicy) && !identityProfile?.home_area_id) {
      return rejectProductionVote(
        ZKP_AUDIT_REJECTION_REASON_CODES.homeLocationRequired,
        "HOME_LOCATION_MISSING",
        "A home location area is required for this poll.",
      );
    }

    const eligibilityFailure = evaluateEligibility(
      pollPolicy,
      viewer,
      Boolean(verifiedIdentityId),
      {
        document_country_code: identityProfile?.document_country_code || null,
        home_area_id: identityProfile?.home_area_id || null,
      },
    );
    if (eligibilityFailure) {
      if (productionZkpPoll) {
        return rejectProductionVote(
          ZKP_AUDIT_REJECTION_REASON_CODES.eligibilityFailed,
          eligibilityFailure.errorCode,
          eligibilityFailure.message,
        );
      }
      return eligibilityFailure;
    }

    if (productionZkpPoll) {
      const normalizedEncryptedVote = normalizeProductionEncryptedVotePayload(
        params.encryptedVote,
        poll,
      );
      if (!normalizedEncryptedVote) {
        return rejectProductionVote(
          ZKP_AUDIT_REJECTION_REASON_CODES.encryptedVoteRequired,
          "PROOF_REQUIRED",
          PRODUCTION_ZKP_ENCRYPTED_VOTE_REQUIRED_MESSAGE,
        );
      }

      const productionPrivacy = normalizeProductionPrivacyPayload(privacy);
      if (!productionPrivacy) {
        return rejectProductionVote(
          isPreproverVotePrivacyPayload(privacy)
            ? ZKP_AUDIT_REJECTION_REASON_CODES.preproverEnvelopeOnProductionPoll
            : ZKP_AUDIT_REJECTION_REASON_CODES.proofMetadataRequired,
          "PROOF_REQUIRED",
          "This poll requires production Groth16 vote proof metadata.",
        );
      }
      const proofAuditHints = buildProductionVoteAuditHints(productionPrivacy);

      if (
        normalizedEncryptedVote.encryptedVoteCommitment !==
        productionPrivacy.encryptedVoteCommitment
      ) {
        return rejectProductionVote(
          ZKP_AUDIT_REJECTION_REASON_CODES.ciphertextCommitmentMismatch,
          "PROOF_INVALID",
          "Encrypted vote commitment does not match the submitted proof envelope.",
          proofAuditHints,
        );
      }

      const pollEncryptionKey = await getPollEncryptionKeyForPoll(pollId);
      if (!pollEncryptionKey.success) {
        return rejectProductionVote(
          ZKP_AUDIT_REJECTION_REASON_CODES.pollEncryptionKeyUnavailable,
          "PROOF_REQUIRED",
          pollEncryptionKey.message,
          proofAuditHints,
        );
      }
      if (
        pollEncryptionKey.key.publicKeyHash !==
        normalizedEncryptedVote.pollEncryptionKeyHash
      ) {
        return rejectProductionVote(
          ZKP_AUDIT_REJECTION_REASON_CODES.pollEncryptionKeyMismatch,
          "PROOF_INVALID",
          "Encrypted vote payload was not encrypted for the registered poll key.",
          proofAuditHints,
        );
      }

      const encryptedVoteJson = normalizedEncryptedVote as JsonValue;
      const encryptedVoteHash = hashProductionEncryptedVote(encryptedVoteJson);
      if (productionPrivacy.encryptedVoteHash !== encryptedVoteHash) {
        return rejectProductionVote(
          ZKP_AUDIT_REJECTION_REASON_CODES.encryptedVoteHashMismatch,
          "PROOF_INVALID",
          "Encrypted vote hash does not match the submitted encrypted vote payload.",
          {
            ...proofAuditHints,
            encryptedVoteHash,
            encryptedVoteCommitment:
              normalizedEncryptedVote.encryptedVoteCommitment,
          },
        );
      }

      const proofVerification = await verifyProductionVoteProof({
        poll,
        proof: productionPrivacy.proof,
        encryptedVoteHash,
        expectedVoteCommitment:
          params.expectedVoteCommitment || productionPrivacy.voteCommitment,
        expectedOptionCount: productionOptionCount,
      });
      if (!proofVerification.ok) {
        if (proofVerification.reason.startsWith("VERIFIER_")) {
          console.error("[zkp] production vote verifier rejected before proof acceptance", {
            pollId,
            reason: proofVerification.reason,
            message: proofVerification.message,
            circuitId: productionPrivacy.proof.circuitId,
            verifierKeyHash: productionPrivacy.proof.verifierKeyHash,
          });
        }

        return rejectProductionVote(
          mapVoteVerifierReasonToAuditReasonCode(proofVerification.reason),
          proofVerification.reason === "PROOF_REQUIRED"
            ? "PROOF_REQUIRED"
            : "PROOF_INVALID",
          proofVerification.message,
          {
            ...proofAuditHints,
            verifierReason: proofVerification.reason,
            encryptedVoteHash,
            encryptedVoteCommitment:
              normalizedEncryptedVote.encryptedVoteCommitment,
          },
        );
      }

      const proofAuditMaterial = proofVerification.auditMaterial;
      if (!proofAuditMaterial) {
        return rejectProductionVote(
          ZKP_AUDIT_REJECTION_REASON_CODES.auditMaterialMissing,
          "PROOF_INVALID",
          "Production ZKP vote proof did not produce audit material.",
          {
            ...proofAuditHints,
            encryptedVoteHash,
            encryptedVoteCommitment:
              normalizedEncryptedVote.encryptedVoteCommitment,
          },
        );
      }

      const existingNullifierVote =
        await pollZkVoteRepository.getByPollIdAndNullifier(
          pollId,
          proofAuditMaterial.nullifier,
        );
      if (existingNullifierVote) {
        return rejectProductionVote(
          ZKP_AUDIT_REJECTION_REASON_CODES.duplicateNullifier,
          "ALREADY_VOTED",
          DUPLICATE_NULLIFIER_VOTE_MESSAGE,
          {
            ...proofAuditHints,
            nullifier: proofAuditMaterial.nullifier,
            proofHash: proofAuditMaterial.proofHash,
            proofEnvelopeHash: proofAuditMaterial.proofEnvelopeHash,
            encryptedVoteHash: proofAuditMaterial.encryptedVoteHash,
            encryptedVoteCommitment: proofAuditMaterial.encryptedVoteCommitment,
            verifierKeyHash: proofAuditMaterial.verifierKeyHash,
            circuitId: proofAuditMaterial.circuitId,
          },
        );
      }

      try {
        const insertedVote = await pollZkVoteRepository.insertVerified({
          poll_id: pollId,
          nullifier: proofAuditMaterial.nullifier,
          vote_commitment: proofAuditMaterial.voteCommitment,
          encrypted_vote: encryptedVoteJson,
          encrypted_vote_hash: proofAuditMaterial.encryptedVoteHash,
          encrypted_vote_commitment: proofAuditMaterial.encryptedVoteCommitment,
          proof_hash: proofAuditMaterial.proofHash,
          proof_system_version: proofAuditMaterial.proofSystemVersion,
          verification_method_version:
            proofAuditMaterial.verificationMethodVersion,
          proof_verification_status: proofAuditMaterial.proofVerificationStatus,
          proof_public_inputs_json:
            proofAuditMaterial.proofPublicInputsJson as unknown as JsonValue,
          proof_envelope_hash: proofAuditMaterial.proofEnvelopeHash,
          verifier_key_hash: proofAuditMaterial.verifierKeyHash,
          circuit_id: proofAuditMaterial.circuitId,
          accepted_at: submittedAt,
          batch_id: null,
        });

        await zkpAuditEvents.appendVoteAccepted({
          pollId: insertedVote.poll_id,
          voteId: insertedVote.id,
          nullifier: insertedVote.nullifier,
          voteCommitment: insertedVote.vote_commitment,
          encryptedVoteHash: insertedVote.encrypted_vote_hash,
          encryptedVoteCommitment: insertedVote.encrypted_vote_commitment,
          proofHash: insertedVote.proof_hash,
          proofEnvelopeHash: insertedVote.proof_envelope_hash,
          proofVerificationStatus: insertedVote.proof_verification_status,
          verifierKeyHash: insertedVote.verifier_key_hash,
          circuitId: insertedVote.circuit_id,
          occurredAt: insertedVote.accepted_at,
        });

        return {
          success: true,
          viewerVote: {
            pollId: insertedVote.poll_id,
            optionId,
            submittedAt: insertedVote.accepted_at,
          },
          receipt: buildVoteReceipt({
            pollId: insertedVote.poll_id,
            optionId,
            voteCommitment: insertedVote.vote_commitment,
            voteCommitmentLeafHash: await hashPublicAuditLeafForPoll(
              poll,
              "vote_commitment",
              insertedVote.vote_commitment,
            ),
            proofHash: insertedVote.proof_hash,
            acceptedAt: insertedVote.accepted_at,
          }),
        };
      } catch (error) {
        if (isUniqueViolation(error)) {
          return rejectProductionVote(
            ZKP_AUDIT_REJECTION_REASON_CODES.duplicateNullifier,
            "ALREADY_VOTED",
            DUPLICATE_NULLIFIER_VOTE_MESSAGE,
            {
              ...proofAuditHints,
              nullifier: proofAuditMaterial.nullifier,
              proofHash: proofAuditMaterial.proofHash,
              proofEnvelopeHash: proofAuditMaterial.proofEnvelopeHash,
              encryptedVoteHash: proofAuditMaterial.encryptedVoteHash,
              encryptedVoteCommitment:
                proofAuditMaterial.encryptedVoteCommitment,
              verifierKeyHash: proofAuditMaterial.verifierKeyHash,
              circuitId: proofAuditMaterial.circuitId,
            },
          );
        }

        throw error;
      }
    }

    const proofVerification = verifyVoteProofForPoll({
      poll,
      optionId,
      privacy,
      expectedVoteCommitment: params.expectedVoteCommitment,
    });
    if (!proofVerification.ok) {
      return buildFailure(
        proofVerification.reason === "PROOF_REQUIRED"
          ? "PROOF_REQUIRED"
          : "PROOF_INVALID",
        proofVerification.message,
      );
    }

    const proofAuditMaterial = proofVerification.auditMaterial;
    if (proofAuditMaterial?.nullifier) {
      const existingNullifierVote = await voteRepository.getByPollIdAndNullifier(
        pollId,
        proofAuditMaterial.nullifier,
      );
      if (existingNullifierVote) {
        return buildFailure("ALREADY_VOTED", DUPLICATE_NULLIFIER_VOTE_MESSAGE);
      }
    }

    const locationSnapshot = resolveVoteLocationSnapshot(
      identityProfile
        ? {
            home_approx_latitude: identityProfile.home_approx_latitude,
            home_approx_longitude: identityProfile.home_approx_longitude,
          }
        : null,
      submittedAt,
    );

    try {
      const insertedVote = await voteRepository.insert({
        poll_id: pollId,
        option_id: optionId,
        user_id: viewer.id,
        verified_identity_id: verifiedIdentityId,
        nullifier: proofAuditMaterial?.nullifier ?? null,
        vote_commitment: proofAuditMaterial?.voteCommitment ?? null,
        encrypted_vote: null,
        proof_hash: proofAuditMaterial?.proofHash ?? null,
        proof_system_version: proofAuditMaterial?.proofSystemVersion ?? null,
        verification_method_version:
          proofAuditMaterial?.verificationMethodVersion ?? null,
        proof_verification_status:
          proofAuditMaterial?.proofVerificationStatus ?? null,
        proof_public_inputs_json:
          proofAuditMaterial?.proofPublicInputsJson ?? null,
        proof_envelope_json: proofAuditMaterial?.proofEnvelopeJson ?? null,
        accepted_at: proofAuditMaterial ? submittedAt : null,
        batch_id: null,
        vote_latitude_l0: locationSnapshot.vote_latitude_l0,
        vote_longitude_l0: locationSnapshot.vote_longitude_l0,
        vote_location_snapshot_at: locationSnapshot.vote_location_snapshot_at,
        vote_location_snapshot_version: locationSnapshot.vote_location_snapshot_version,
        submitted_at: submittedAt,
        is_valid: true,
        invalid_reason: null,
      });

      try {
        await pollMapRefreshQueueRepository.enqueuePoll(pollId);
      } catch (enqueueError) {
        console.error("[pollVotingService] failed to enqueue poll map refresh", {
          pollId,
          error: enqueueError,
        });
      }

      return {
        success: true,
        viewerVote: {
          pollId: insertedVote.poll_id,
          optionId: insertedVote.option_id,
          submittedAt: insertedVote.submitted_at,
        },
        receipt:
          proofAuditMaterial && insertedVote.vote_commitment && insertedVote.proof_hash
            ? buildVoteReceipt({
                pollId: insertedVote.poll_id,
                optionId: insertedVote.option_id,
                voteCommitment: insertedVote.vote_commitment,
                proofHash: insertedVote.proof_hash,
                acceptedAt: insertedVote.accepted_at || insertedVote.submitted_at,
              })
            : null,
      };
    } catch (error) {
      if (isUniqueViolation(error)) {
        return buildFailure(
          "ALREADY_VOTED",
          requiresVerifiedIdentity
            ? DUPLICATE_VERIFIED_IDENTITY_VOTE_MESSAGE
            : DUPLICATE_USER_VOTE_MESSAGE,
        );
      }

      throw error;
    }
  },
  };
};

export const pollVotingService = createPollVotingService();

export default pollVotingService;
