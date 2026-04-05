import pollRepository from "../repositories/pollRepository";
import voteRepository from "../repositories/voteRepository";
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

    return {
      ...(existingOption?.id
        ? { id: existingOption.id }
        : explicitId
          ? { id: explicitId }
          : null),
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

const buildPollInsertPayload = (
  data: NormalizedPollMutationInput,
  createdByUserId: string,
  slug: string,
  startsAt: string | null,
  endsAt: string | null,
): NewPollRow => ({
  slug,
  created_by_user_id: createdByUserId,
  title: data.title,
  description: data.description,
  status: data.status,
  jurisdiction_type: data.jurisdictionType,
  jurisdiction_country_code: data.jurisdictionCountryCode,
  jurisdiction_area_ids: data.jurisdictionAreaIds,
  jurisdiction_land_ids: data.jurisdictionLandIds,
  requires_verified_identity: data.eligibilityRule.requiresVerifiedIdentity,
  allowed_document_country_codes: data.eligibilityRule.allowedDocumentCountryCodes || [],
  allowed_home_area_ids: data.eligibilityRule.allowedHomeAreaIds || [],
  allowed_land_ids: data.eligibilityRule.allowedLandIds || [],
  minimum_age: data.eligibilityRule.minimumAge ?? null,
  starts_at: startsAt,
  ends_at: endsAt,
});

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
    const createdPoll = await pollRepository.insert(
      buildPollInsertPayload(
        normalized.data,
        viewerUserId,
        buildCreateSlug(normalized.data.title),
        now,
        null,
      ),
    );

    const optionRows = buildOptionRows({
      pollId: createdPoll.id,
      options: normalized.data.options,
      existingOptions: [],
      createdAt: now,
    });

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

    const normalized = normalizeMutationInput(input);
    if (!normalized.data || normalized.error) {
      return normalized.error as UpdateDraftPollResultDto;
    }

    const now = new Date().toISOString();
    const updatedPoll = await pollRepository.updateById(
      existingPoll.id,
      buildPollInsertPayload(
        normalized.data,
        existingPoll.created_by_user_id || viewerUserId,
        existingPoll.slug,
        existingPoll.starts_at,
        existingPoll.ends_at,
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
      buildOptionRows({
        pollId: existingPoll.id,
        options: normalized.data.options,
        existingOptions,
        createdAt: now,
      }),
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
    const publishedPoll = await pollRepository.updateById(existingPoll.id, {
      slug: existingPoll.slug,
      created_by_user_id: existingPoll.created_by_user_id || viewerUserId,
      title: existingPoll.title,
      description: existingPoll.description,
      status: "active",
      jurisdiction_type: existingPoll.jurisdiction_type,
      jurisdiction_country_code: existingPoll.jurisdiction_country_code,
      jurisdiction_area_ids: existingPoll.jurisdiction_area_ids || [],
      jurisdiction_land_ids: existingPoll.jurisdiction_land_ids || [],
      requires_verified_identity: existingPoll.requires_verified_identity,
      allowed_document_country_codes: existingPoll.allowed_document_country_codes || [],
      allowed_home_area_ids: existingPoll.allowed_home_area_ids || [],
      allowed_land_ids: existingPoll.allowed_land_ids || [],
      minimum_age: existingPoll.minimum_age,
      starts_at: existingPoll.starts_at || now,
      ends_at: existingPoll.ends_at,
    });

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
