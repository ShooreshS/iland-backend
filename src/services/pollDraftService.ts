import { randomUUID } from "node:crypto";
import pollRepository from "../repositories/pollRepository";
import voteRepository from "../repositories/voteRepository";
import {
  buildPollAuditMaterial,
  hashPollOptionSet,
} from "./pollPolicyService";
import type {
  CreatePollRequestDto,
  CreatePollResultDto,
  DraftPollEditorResultDto,
  PollDto,
  PollEditabilityResultDto,
  PollEligibilityRule,
  PollManagementErrorCode,
  PollOptionDto,
  PollOptionInputDto,
  PollStatus,
  PollVotePrivacyMode,
  PublishDraftPollResultDto,
  UpdateDraftPollRequestDto,
  UpdateDraftPollResultDto,
} from "../types/contracts";
import type {
  NewPollOptionRow,
  NewPollRow,
  PollOptionRow,
  PollRow,
} from "../types/db";

const OPTION_COLOR_PALETTE = [
  "#3B82F6",
  "#EF4444",
  "#10B981",
  "#F59E0B",
  "#8B5CF6",
  "#14B8A6",
];
const MIN_PUBLISHABLE_ACTIVE_OPTIONS = 2;
const PRODUCTION_ZKP_MAX_OPTIONS = 8;
const DEFAULT_VOTE_PRIVACY_MODE = "zk_preprover_audit" as const;
const PRODUCTION_ZKP_VOTE_PRIVACY_MODE = "zk_secret_ballot_v1" as const;
const KNOWN_VOTE_PRIVACY_MODES = new Set<PollVotePrivacyMode>([
  "legacy_identity_linked",
  "zk_preprover_audit",
  "zk_secret_ballot_v1",
]);

type NormalizedPollMutationInput = {
  title: string;
  description: string | null;
  options: Array<{
    id?: string;
    label: string;
    description: string | null;
    color: string | null;
  }>;
  jurisdictionType: PollDto["jurisdictionType"];
  jurisdictionCountryCode: string | null;
  jurisdictionAreaIds: string[];
  jurisdictionLandIds: string[];
  status: PollStatus;
  eligibilityRule: PollEligibilityRule;
  votePrivacyMode: PollVotePrivacyMode;
  pollEncryptionKeyId: string | null;
};

const slugify = (value: string): string =>
  value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");

const isUuid = (value: string): boolean =>
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);

const toArray = (value: string[] | null | undefined): string[] =>
  Array.isArray(value) ? value : [];

const normalizeOptionalString = (value: string | null | undefined): string | null => {
  const normalized = typeof value === "string" ? value.trim() : "";
  return normalized.length > 0 ? normalized : null;
};

const normalizeVotePrivacyMode = (
  value: PollVotePrivacyMode | string | null | undefined,
): PollVotePrivacyMode =>
  typeof value === "string" &&
  KNOWN_VOTE_PRIVACY_MODES.has(value as PollVotePrivacyMode)
    ? (value as PollVotePrivacyMode)
    : DEFAULT_VOTE_PRIVACY_MODE;

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

const createFailureResult = (
  errorCode: PollManagementErrorCode,
  message: string,
): CreatePollResultDto => ({
  success: false,
  errorCode,
  message,
});

const getFallbackOptionColor = (optionIndex: number): string =>
  OPTION_COLOR_PALETTE[optionIndex % OPTION_COLOR_PALETTE.length];

const normalizeOptions = (options: PollOptionInputDto[]) =>
  options
    .map((option) =>
      typeof option === "string"
        ? { label: option.trim(), description: null, color: null }
        : {
            id: typeof option?.id === "string" ? option.id.trim() : undefined,
            label: typeof option?.label === "string" ? option.label.trim() : "",
            description:
              typeof option?.description === "string" ? option.description.trim() : null,
            color: typeof option?.color === "string" ? option.color.trim() : null,
          },
    )
    .filter((option) => option.label.length > 0)
    .map((option) => ({
      id: option.id,
      label: option.label,
      description: option.description || null,
      color: option.color || null,
    }));

const buildEligibilityRule = (
  input: Partial<PollEligibilityRule> | null | undefined,
): PollEligibilityRule => ({
  requiresVerifiedIdentity: Boolean(input?.requiresVerifiedIdentity),
  allowedDocumentCountryCodes: input?.allowedDocumentCountryCodes?.length
    ? [...input.allowedDocumentCountryCodes]
    : undefined,
  allowedHomeAreaIds: input?.allowedHomeAreaIds?.length
    ? [...input.allowedHomeAreaIds]
    : undefined,
  allowedLandIds: input?.allowedLandIds?.length
    ? [...input.allowedLandIds]
    : undefined,
  minimumAge: typeof input?.minimumAge === "number" ? input.minimumAge : null,
});

const normalizeMutationInput = (
  input: CreatePollRequestDto | UpdateDraftPollRequestDto,
): { data?: NormalizedPollMutationInput; error?: CreatePollResultDto } => {
  const title = typeof input.title === "string" ? input.title.trim() : "";
  const normalizedOptions = normalizeOptions(input.options || []);
  const jurisdictionType = input.jurisdictionType ?? "global";
  const jurisdictionCountryCode = input.jurisdictionCountryCode ?? null;
  const jurisdictionAreaIds = (input.jurisdictionAreaIds || []).filter(Boolean);
  const jurisdictionLandIds = (input.jurisdictionLandIds || []).filter(Boolean);

  if (!title) {
    return {
      error: createFailureResult("VALIDATION_FAILED", "A poll title is required."),
    };
  }

  if (normalizedOptions.length < 2) {
    return {
      error: createFailureResult(
        "VALIDATION_FAILED",
        "At least two non-empty options are required.",
      ),
    };
  }

  if (jurisdictionType === "real_country" && !jurisdictionCountryCode) {
    return {
      error: createFailureResult(
        "VALIDATION_FAILED",
        "A country must be selected for country-scoped polls.",
      ),
    };
  }

  if (jurisdictionType === "real_area" && jurisdictionAreaIds.length === 0) {
    return {
      error: createFailureResult(
        "VALIDATION_FAILED",
        "At least one home area must be selected for area-scoped polls.",
      ),
    };
  }

  if (jurisdictionType === "land" && jurisdictionLandIds.length === 0) {
    return {
      error: createFailureResult(
        "VALIDATION_FAILED",
        "A land must be selected for land-scoped polls.",
      ),
    };
  }

  const minimumAge = input.eligibilityRule?.minimumAge;
  if (
    typeof minimumAge === "number" &&
    (!Number.isFinite(minimumAge) || !Number.isInteger(minimumAge) || minimumAge < 0)
  ) {
    return {
      error: createFailureResult(
        "VALIDATION_FAILED",
        "Minimum age must be a non-negative whole number.",
      ),
    };
  }

  const eligibilityRule = buildEligibilityRule(input.eligibilityRule);

  if (jurisdictionType === "real_country" && jurisdictionCountryCode) {
    eligibilityRule.requiresVerifiedIdentity = true;
    eligibilityRule.allowedDocumentCountryCodes = [jurisdictionCountryCode];
  }

  if (jurisdictionType === "real_area" && jurisdictionAreaIds.length > 0) {
    eligibilityRule.requiresVerifiedIdentity = true;
    eligibilityRule.allowedHomeAreaIds = [...jurisdictionAreaIds];
  }

  if (jurisdictionType === "land" && jurisdictionLandIds.length > 0) {
    eligibilityRule.allowedLandIds = [...jurisdictionLandIds];
  }

  const votePrivacyMode = normalizeVotePrivacyMode(input.votePrivacyMode);
  const pollEncryptionKeyId = normalizeOptionalString(input.pollEncryptionKeyId);

  if (
    votePrivacyMode === PRODUCTION_ZKP_VOTE_PRIVACY_MODE &&
    normalizedOptions.length > PRODUCTION_ZKP_MAX_OPTIONS
  ) {
    return {
      error: createFailureResult(
        "VALIDATION_FAILED",
        `Production ZKP polls support at most ${PRODUCTION_ZKP_MAX_OPTIONS} options.`,
      ),
    };
  }

  if (
    votePrivacyMode === PRODUCTION_ZKP_VOTE_PRIVACY_MODE &&
    !eligibilityRule.requiresVerifiedIdentity
  ) {
    return {
      error: createFailureResult(
        "VALIDATION_FAILED",
        "Production ZKP polls require verified identity eligibility.",
      ),
    };
  }

  if (
    votePrivacyMode === PRODUCTION_ZKP_VOTE_PRIVACY_MODE &&
    !pollEncryptionKeyId
  ) {
    return {
      error: createFailureResult(
        "VALIDATION_FAILED",
        "Production ZKP polls require a poll encryption key id.",
      ),
    };
  }

  return {
    data: {
      title,
      description:
        typeof input.description === "string" ? input.description.trim() || null : null,
      options: normalizedOptions,
      jurisdictionType,
      jurisdictionCountryCode,
      jurisdictionAreaIds,
      jurisdictionLandIds,
      status: (input.status || "active") as PollStatus,
      eligibilityRule,
      votePrivacyMode,
      pollEncryptionKeyId,
    },
  };
};

const buildOptionRows = ({
  pollId,
  options,
  existingOptions,
  createdAt,
}: {
  pollId: string;
  options: NormalizedPollMutationInput["options"];
  existingOptions: PollOptionRow[];
  createdAt: string;
}): NewPollOptionRow[] => {
  const existingById = new Map(existingOptions.map((option) => [option.id, option]));

  return options.map((option, index) => {
    const existingOption =
      option.id && existingById.has(option.id)
        ? existingById.get(option.id) || null
        : null;

    const explicitId = option.id && isUuid(option.id) ? option.id : undefined;
    const optionId = existingOption?.id || explicitId || randomUUID();

    return {
      id: optionId,
      poll_id: pollId,
      label: option.label,
      description: option.description ?? null,
      color: existingOption?.color || option.color || getFallbackOptionColor(index),
      display_order: index + 1,
      is_active: true,
      created_at: existingOption?.created_at || createdAt,
    };
  });
};

const createEditabilityResult = (
  poll: PollRow | null,
  voteCount: number,
  viewerUserId: string,
): PollEditabilityResultDto => {
  if (!poll) {
    return {
      editable: false,
      errorCode: "POLL_NOT_FOUND",
      message: "The poll could not be found.",
      voteCount: 0,
    };
  }

  if (poll.created_by_user_id !== viewerUserId) {
    return {
      editable: false,
      errorCode: "POLL_NOT_OWNED",
      message: "Only the poll creator can edit this draft poll.",
      voteCount,
    };
  }

  if (poll.status !== "draft") {
    return {
      editable: false,
      errorCode: "POLL_NOT_EDITABLE",
      message: "Only polls in draft state can be edited.",
      voteCount,
    };
  }

  if (voteCount > 0) {
    return {
      editable: false,
      errorCode: "POLL_ALREADY_HAS_VOTES",
      message: "This poll already has votes and can no longer be edited.",
      voteCount,
    };
  }

  return {
    editable: true,
    voteCount: 0,
  };
};

const buildOptionSetHashFromRows = (
  pollId: string,
  options: Array<
    Pick<
      NewPollOptionRow,
      "id" | "label" | "description" | "color" | "display_order" | "is_active"
    >
  >,
): string =>
  hashPollOptionSet({
    pollId,
    options: options.map((option) => ({
      id: option.id ?? "",
      label: option.label,
      description: option.description,
      color: option.color,
      displayOrder: option.display_order,
      isActive: option.is_active,
    })),
  });

const validateProductionPollContract = (input: {
  votePrivacyMode: PollVotePrivacyMode;
  requiresVerifiedIdentity: boolean;
  pollEncryptionKeyId: string | null | undefined;
  optionSetHash: string | null | undefined;
}): CreatePollResultDto | null => {
  if (input.votePrivacyMode !== PRODUCTION_ZKP_VOTE_PRIVACY_MODE) {
    return null;
  }

  if (!input.requiresVerifiedIdentity) {
    return createFailureResult(
      "VALIDATION_FAILED",
      "Production ZKP polls require verified identity eligibility.",
    );
  }

  if (!normalizeOptionalString(input.pollEncryptionKeyId)) {
    return createFailureResult(
      "VALIDATION_FAILED",
      "Production ZKP polls require a poll encryption key id.",
    );
  }

  if (!input.optionSetHash) {
    return createFailureResult(
      "VALIDATION_FAILED",
      "Production ZKP polls require a frozen option set hash.",
    );
  }

  return null;
};

const buildPollInsertPayload = (
  pollId: string,
  data: NormalizedPollMutationInput,
  createdByUserId: string,
  slug: string,
  startsAt: string | null,
  endsAt: string | null,
  optionSetHash: string,
): NewPollRow => {
  const auditMaterial = buildPollAuditMaterial({
    pollId,
    jurisdictionType: data.jurisdictionType,
    jurisdictionCountryCode: data.jurisdictionCountryCode,
    jurisdictionAreaIds: data.jurisdictionAreaIds,
    jurisdictionLandIds: data.jurisdictionLandIds,
    requiresVerifiedIdentity: data.eligibilityRule.requiresVerifiedIdentity,
    allowedDocumentCountryCodes: data.eligibilityRule.allowedDocumentCountryCodes || [],
    allowedHomeAreaIds: data.eligibilityRule.allowedHomeAreaIds || [],
    allowedLandIds: data.eligibilityRule.allowedLandIds || [],
    minimumAge: data.eligibilityRule.minimumAge ?? null,
    startsAt,
    endsAt,
  });
  const { pollPolicy, pollPolicyHash, credentialSchema, credentialSchemaHash } =
    auditMaterial;

  return {
    id: pollId,
    slug,
    created_by_user_id: createdByUserId,
    title: data.title,
    description: data.description,
    status: data.status,
    jurisdiction_type: pollPolicy.jurisdiction.type,
    jurisdiction_country_code: pollPolicy.jurisdiction.countryCode,
    jurisdiction_area_ids: pollPolicy.jurisdiction.areaIds,
    jurisdiction_land_ids: pollPolicy.jurisdiction.landIds,
    requires_verified_identity: pollPolicy.eligibilityRules.requiresVerifiedIdentity,
    allowed_document_country_codes:
      pollPolicy.eligibilityRules.acceptedDocumentCountryCodes,
    allowed_home_area_ids: pollPolicy.eligibilityRules.acceptedHomeAreaIds,
    allowed_land_ids: pollPolicy.eligibilityRules.acceptedLandIds,
    minimum_age: pollPolicy.eligibilityRules.minimumAge,
    starts_at: pollPolicy.votingWindow.opensAt,
    ends_at: pollPolicy.votingWindow.closesAt,
    poll_policy_json: pollPolicy,
    poll_policy_hash: pollPolicyHash,
    credential_schema_json: credentialSchema,
    credential_schema_hash: credentialSchemaHash,
    vote_privacy_mode: data.votePrivacyMode,
    option_set_hash: optionSetHash,
    poll_encryption_key_id: data.pollEncryptionKeyId,
  };
};

const buildCreateSlug = (title: string): string => {
  const base = slugify(title) || "poll";
  const suffix = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  return `${base}-${suffix}`;
};

const countPublishableOptions = (options: PollOptionRow[]): number =>
  options.filter(
    (option) => option.is_active && option.label.trim().length > 0,
  ).length;

const createDraftFailure = (
  editability: PollEditabilityResultDto,
  poll: PollRow | null,
  options: PollOptionRow[],
): DraftPollEditorResultDto => {
  const shouldIncludeDraftData =
    editability.errorCode !== "POLL_NOT_OWNED" && editability.errorCode !== "USER_NOT_FOUND";

  return {
    success: false,
    editable: false,
    ...(shouldIncludeDraftData && poll
      ? {
          poll: mapPoll(poll),
          options: options.map(mapOption),
        }
      : null),
    errorCode: editability.errorCode,
    message: editability.message,
    voteCount: editability.voteCount,
  };
};

export const pollDraftService = {
  async createPoll(input: CreatePollRequestDto, viewerUserId: string): Promise<CreatePollResultDto> {
    const normalized = normalizeMutationInput(input);
    if (!normalized.data || normalized.error) {
      return normalized.error as CreatePollResultDto;
    }

    const now = new Date().toISOString();
    const pollId = randomUUID();
    const optionRows = buildOptionRows({
      pollId,
      options: normalized.data.options,
      existingOptions: [],
      createdAt: now,
    });
    const optionSetHash = buildOptionSetHashFromRows(pollId, optionRows);
    const contractFailure = validateProductionPollContract({
      votePrivacyMode: normalized.data.votePrivacyMode,
      requiresVerifiedIdentity:
        normalized.data.eligibilityRule.requiresVerifiedIdentity,
      pollEncryptionKeyId: normalized.data.pollEncryptionKeyId,
      optionSetHash,
    });
    if (contractFailure) {
      return contractFailure;
    }

    const createdPoll = await pollRepository.insert(
      buildPollInsertPayload(
        pollId,
        normalized.data,
        viewerUserId,
        buildCreateSlug(normalized.data.title),
        now,
        null,
        optionSetHash,
      ),
    );

    const createdOptions = await pollRepository.insertOptions(optionRows);

    return {
      success: true,
      poll: mapPoll(createdPoll),
      options: createdOptions.map(mapOption),
    };
  },

  async canEditPoll(pollId: string, viewerUserId: string): Promise<PollEditabilityResultDto> {
    const [poll, voteCount] = await Promise.all([
      pollRepository.getById(pollId),
      voteRepository.countByPollId(pollId),
    ]);

    return createEditabilityResult(poll, voteCount, viewerUserId);
  },

  async getDraftPollForEditing(
    pollId: string,
    viewerUserId: string,
  ): Promise<DraftPollEditorResultDto> {
    const [poll, options, editability] = await Promise.all([
      pollRepository.getById(pollId),
      pollRepository.getOptionsByPollId(pollId),
      this.canEditPoll(pollId, viewerUserId),
    ]);

    if (!poll) {
      return {
        success: false,
        editable: false,
        errorCode: "POLL_NOT_FOUND",
        message: "The draft poll could not be loaded.",
        voteCount: 0,
      };
    }

    if (!editability.editable) {
      return createDraftFailure(editability, poll, options);
    }

    return {
      success: true,
      editable: true,
      poll: mapPoll(poll),
      options: options.map(mapOption),
      voteCount: 0,
    };
  },

  async updateDraftPoll(
    input: UpdateDraftPollRequestDto,
    viewerUserId: string,
  ): Promise<UpdateDraftPollResultDto> {
    const pollId = input.pollId;
    const [existingPoll, existingOptions, editability] = await Promise.all([
      pollRepository.getById(pollId),
      pollRepository.getOptionsByPollId(pollId),
      this.canEditPoll(pollId, viewerUserId),
    ]);

    if (!existingPoll) {
      return {
        success: false,
        errorCode: "POLL_NOT_FOUND",
        message: "The draft poll could not be found.",
      };
    }

    if (!editability.editable) {
      return {
        success: false,
        errorCode: editability.errorCode,
        message: editability.message,
      };
    }

    const normalized = normalizeMutationInput({
      ...input,
      votePrivacyMode:
        input.votePrivacyMode ??
        existingPoll.vote_privacy_mode ??
        DEFAULT_VOTE_PRIVACY_MODE,
      pollEncryptionKeyId:
        input.pollEncryptionKeyId === undefined
          ? existingPoll.poll_encryption_key_id ?? null
          : input.pollEncryptionKeyId,
    });
    if (!normalized.data || normalized.error) {
      return normalized.error as UpdateDraftPollResultDto;
    }

    const now = new Date().toISOString();
    const optionRows = buildOptionRows({
      pollId: existingPoll.id,
      options: normalized.data.options,
      existingOptions,
      createdAt: now,
    });
    const optionSetHash = buildOptionSetHashFromRows(existingPoll.id, optionRows);
    const contractFailure = validateProductionPollContract({
      votePrivacyMode: normalized.data.votePrivacyMode,
      requiresVerifiedIdentity:
        normalized.data.eligibilityRule.requiresVerifiedIdentity,
      pollEncryptionKeyId: normalized.data.pollEncryptionKeyId,
      optionSetHash,
    });
    if (contractFailure) {
      return contractFailure as UpdateDraftPollResultDto;
    }

    const updatedPoll = await pollRepository.updateById(
      existingPoll.id,
      buildPollInsertPayload(
        existingPoll.id,
        normalized.data,
        existingPoll.created_by_user_id || viewerUserId,
        existingPoll.slug,
        existingPoll.starts_at,
        existingPoll.ends_at,
        optionSetHash,
      ),
    );

    if (!updatedPoll) {
      return {
        success: false,
        errorCode: "POLL_NOT_FOUND",
        message: "The draft poll could not be updated.",
      };
    }

    const updatedOptions = await pollRepository.replaceOptions(
      existingPoll.id,
      optionRows,
    );

    return {
      success: true,
      poll: mapPoll(updatedPoll),
      options: updatedOptions.map(mapOption),
    };
  },

  async publishDraftPoll(
    pollId: string,
    viewerUserId: string,
  ): Promise<PublishDraftPollResultDto> {
    const [existingPoll, existingOptions, editability] = await Promise.all([
      pollRepository.getById(pollId),
      pollRepository.getOptionsByPollId(pollId),
      this.canEditPoll(pollId, viewerUserId),
    ]);

    if (!existingPoll) {
      return {
        success: false,
        errorCode: "POLL_NOT_FOUND",
        message: "The draft poll could not be found.",
      };
    }

    if (!editability.editable) {
      return {
        success: false,
        errorCode: editability.errorCode,
        message: editability.message,
      };
    }

    if (countPublishableOptions(existingOptions) < MIN_PUBLISHABLE_ACTIVE_OPTIONS) {
      return {
        success: false,
        errorCode: "VALIDATION_FAILED",
        message: "At least two active options are required to publish this draft poll.",
      };
    }

    const now = new Date().toISOString();
    const votePrivacyMode = normalizeVotePrivacyMode(existingPoll.vote_privacy_mode);
    const pollEncryptionKeyId = normalizeOptionalString(
      existingPoll.poll_encryption_key_id,
    );
    const optionSetHash = buildOptionSetHashFromRows(
      existingPoll.id,
      existingOptions,
    );
    const contractFailure = validateProductionPollContract({
      votePrivacyMode,
      requiresVerifiedIdentity: existingPoll.requires_verified_identity,
      pollEncryptionKeyId,
      optionSetHash,
    });
    if (contractFailure) {
      return contractFailure as PublishDraftPollResultDto;
    }

    const publishedPoll = await pollRepository.updateById(
      existingPoll.id,
      buildPollInsertPayload(
        existingPoll.id,
        {
          title: existingPoll.title,
          description: existingPoll.description,
          options: [],
          jurisdictionType: existingPoll.jurisdiction_type,
          jurisdictionCountryCode: existingPoll.jurisdiction_country_code,
          jurisdictionAreaIds: existingPoll.jurisdiction_area_ids || [],
          jurisdictionLandIds: existingPoll.jurisdiction_land_ids || [],
          status: "active",
          eligibilityRule: {
            requiresVerifiedIdentity: existingPoll.requires_verified_identity,
            allowedDocumentCountryCodes:
              existingPoll.allowed_document_country_codes || [],
            allowedHomeAreaIds: existingPoll.allowed_home_area_ids || [],
            allowedLandIds: existingPoll.allowed_land_ids || [],
            minimumAge: existingPoll.minimum_age,
          },
          votePrivacyMode,
          pollEncryptionKeyId,
        },
        existingPoll.created_by_user_id || viewerUserId,
        existingPoll.slug,
        existingPoll.starts_at || now,
        existingPoll.ends_at,
        optionSetHash,
      ),
    );

    if (!publishedPoll) {
      return {
        success: false,
        errorCode: "POLL_NOT_FOUND",
        message: "The draft poll could not be published.",
      };
    }

    return {
      success: true,
      poll: mapPoll(publishedPoll),
      options: existingOptions.map(mapOption),
    };
  },
};

export default pollDraftService;
