import identityProfileRepository from "../repositories/identityProfileRepository";
import pollMapRefreshQueueRepository from "../repositories/pollMapRefreshQueueRepository";
import pollRepository from "../repositories/pollRepository";
import verifiedIdentityRepository from "../repositories/verifiedIdentityRepository";
import voteRepository from "../repositories/voteRepository";
import type {
  PollDetailsDto,
  PollDto,
  PollOptionDto,
  PollResultsSummaryDto,
  PollSummaryDto,
  VoteSubmissionErrorCode,
  VoteSubmissionFailureDto,
  VoteSubmissionResultDto,
} from "../types/contracts";
import type { PollOptionRow, PollRow, UserRow, VoteRow } from "../types/db";

const POLL_STATUS_SORT_ORDER: Record<PollDto["status"], number> = {
  active: 0,
  scheduled: 1,
  closed: 2,
  archived: 3,
  draft: 4,
};

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

const buildFailure = (
  errorCode: VoteSubmissionErrorCode,
  message: string,
): VoteSubmissionFailureDto => ({
  success: false,
  errorCode,
  message,
});

const DUPLICATE_USER_VOTE_MESSAGE =
  "Only one vote per user and poll is allowed.";
const DUPLICATE_VERIFIED_IDENTITY_VOTE_MESSAGE =
  "Only one vote per verified identity and poll is allowed.";
const VERIFIED_IDENTITY_REQUIRED_MESSAGE =
  "This poll requires a linked verified identity.";

const isUniqueViolation = (error: unknown): boolean => {
  if (!error || typeof error !== "object") {
    return false;
  }

  const maybeCode = (error as { code?: unknown }).code;
  return maybeCode === "23505";
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

const buildResults = (
  poll: PollDto,
  options: PollOptionDto[],
  validVotes: VoteRow[],
  exactTotalVotes?: number,
): PollResultsSummaryDto => {
  const countsByOptionId = validVotes.reduce<Record<string, number>>((acc, vote) => {
    acc[vote.option_id] = (acc[vote.option_id] || 0) + 1;
    return acc;
  }, {});

  const orderedOptions = [...options].sort((left, right) => left.order - right.order);
  const sampledVoteCount = validVotes.length;
  const totalVotes =
    typeof exactTotalVotes === "number" && Number.isFinite(exactTotalVotes)
      ? Math.max(0, Math.trunc(exactTotalVotes))
      : sampledVoteCount;

  const optionResults = orderedOptions.map((option) => {
    const count = countsByOptionId[option.id] || 0;
    return {
      optionId: option.id,
      label: option.label,
      count,
      percentage: sampledVoteCount > 0 ? (count / sampledVoteCount) * 100 : 0,
    };
  });

  const winningOption =
    sampledVoteCount > 0
      ? optionResults.reduce<typeof optionResults[number] | null>((winner, candidate) => {
          if (!winner || candidate.count > winner.count) {
            return candidate;
          }

          return winner;
        }, null)
      : null;

  const latestSubmittedAt =
    validVotes.reduce<string | null>((latest, vote) => {
      if (!latest || vote.submitted_at > latest) {
        return vote.submitted_at;
      }

      return latest;
    }, null) || poll.updatedAt;

  return {
    pollId: poll.id,
    totalVotes,
    optionResults,
    winningOptionId: winningOption?.optionId ?? null,
    winningOptionLabel: winningOption?.label ?? null,
    updatedAt: latestSubmittedAt,
  };
};

const evaluateEligibility = (
  poll: PollRow,
  user: Pick<UserRow, "selected_land_id">,
  hasLinkedVerifiedIdentity: boolean,
  identityProfile: { document_country_code: string | null; home_area_id: string | null },
): VoteSubmissionFailureDto | null => {
  if (poll.requires_verified_identity && !hasLinkedVerifiedIdentity) {
    return buildFailure(
      "ELIGIBILITY_FAILED",
      VERIFIED_IDENTITY_REQUIRED_MESSAGE,
    );
  }

  const allowedDocumentCountryCodes = toArray(poll.allowed_document_country_codes);
  if (allowedDocumentCountryCodes.length > 0) {
    const documentCountryCode = identityProfile.document_country_code;
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

  const allowedHomeAreaIds = toArray(poll.allowed_home_area_ids);
  if (allowedHomeAreaIds.length > 0) {
    const homeAreaId = identityProfile.home_area_id;
    if (!homeAreaId || !allowedHomeAreaIds.includes(homeAreaId)) {
      return buildFailure(
        "ELIGIBILITY_FAILED",
        "This poll is restricted to specific home areas.",
      );
    }
  }

  const allowedLandIds = toArray(poll.allowed_land_ids);
  if (allowedLandIds.length > 0) {
    const selectedLandId = user.selected_land_id;
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

const pollRequiresIdentityProfile = (poll: PollRow): boolean =>
  poll.requires_verified_identity ||
  toArray(poll.allowed_document_country_codes).length > 0 ||
  toArray(poll.allowed_home_area_ids).length > 0;

const pollRequiresHomeArea = (poll: PollRow): boolean =>
  toArray(poll.allowed_home_area_ids).length > 0;

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

export const pollVotingService = {
  async getPollSummaries(viewerUserId: string): Promise<PollSummaryDto[]> {
    const polls = await pollRepository.listAll();
    if (polls.length === 0) {
      return [];
    }

    const pollIds = polls.map((poll) => poll.id);

    const [options, viewerVotes, totalValidVotesByPoll] = await Promise.all([
      pollRepository.getOptionsByPollIds(pollIds),
      voteRepository.getViewerVotesByPollIds(viewerUserId, pollIds),
      Promise.all(
        pollIds.map(
          async (pollId) =>
            [pollId, await voteRepository.countValidByPollId(pollId)] as const,
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

    const viewerVotedPollIds = new Set(viewerVotes.map((vote) => vote.poll_id));

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

    const [optionRows, validVotes, viewerVote, exactTotalVotes] = await Promise.all([
      pollRepository.getOptionsByPollId(pollId),
      voteRepository.getValidByPollId(pollId),
      voteRepository.getByUserIdAndPollId(viewerUserId, pollId),
      voteRepository.countValidByPollId(pollId),
    ]);

    const poll = mapPoll(pollRow);
    const options = optionRows.map(mapOption);
    const results = buildResults(poll, options, validVotes, exactTotalVotes);

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
  }): Promise<VoteSubmissionResultDto> {
    const { pollId, optionId, viewer } = params;

    const poll = await pollRepository.getById(pollId);
    if (!poll) {
      return buildFailure("POLL_NOT_FOUND", "The requested poll does not exist.");
    }

    if (poll.status !== "active") {
      return buildFailure(
        "POLL_NOT_ACTIVE",
        "Only active polls can accept new votes in this phase.",
      );
    }

    const optionInPoll = await pollRepository.getOptionByIdForPoll(pollId, optionId);
    if (!optionInPoll) {
      const option = await pollRepository.getOptionById(optionId);
      if (!option) {
        return buildFailure(
          "OPTION_NOT_FOUND",
          "The requested poll option does not exist.",
        );
      }

      return buildFailure(
        "OPTION_NOT_IN_POLL",
        "The requested option does not belong to the poll.",
      );
    }

    if (!optionInPoll.is_active) {
      return buildFailure(
        "OPTION_NOT_FOUND",
        "The requested poll option is not active.",
      );
    }

    let verifiedIdentityId: string | null = null;
    if (poll.requires_verified_identity) {
      const verifiedIdentity = await verifiedIdentityRepository.getByUserId(viewer.id);
      if (!verifiedIdentity) {
        return buildFailure(
          "ELIGIBILITY_FAILED",
          VERIFIED_IDENTITY_REQUIRED_MESSAGE,
        );
      }

      verifiedIdentityId = verifiedIdentity.id;
      const existingVote = await voteRepository.getByVerifiedIdentityIdAndPollId(
        verifiedIdentity.id,
        pollId,
      );
      if (existingVote) {
        return buildFailure("ALREADY_VOTED", DUPLICATE_VERIFIED_IDENTITY_VOTE_MESSAGE);
      }
    } else {
      const existingVote = await voteRepository.getByUserIdAndPollId(viewer.id, pollId);
      if (existingVote) {
        return buildFailure("ALREADY_VOTED", DUPLICATE_USER_VOTE_MESSAGE);
      }
    }

    const identityProfile = await identityProfileRepository.getByUserId(viewer.id);
    const requiresIdentityProfile = pollRequiresIdentityProfile(poll);

    if (!identityProfile && requiresIdentityProfile) {
      return buildFailure(
        "IDENTITY_PROFILE_NOT_FOUND",
        "This poll requires identity profile data before voting.",
      );
    }

    if (pollRequiresHomeArea(poll) && !identityProfile?.home_area_id) {
      return buildFailure(
        "HOME_LOCATION_MISSING",
        "A home location area is required for this poll.",
      );
    }

    const eligibilityFailure = evaluateEligibility(
      poll,
      viewer,
      Boolean(verifiedIdentityId),
      {
        document_country_code: identityProfile?.document_country_code || null,
        home_area_id: identityProfile?.home_area_id || null,
      },
    );
    if (eligibilityFailure) {
      return eligibilityFailure;
    }

    const submittedAt = new Date().toISOString();
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
      };
    } catch (error) {
      if (isUniqueViolation(error)) {
        return buildFailure(
          "ALREADY_VOTED",
          poll.requires_verified_identity
            ? DUPLICATE_VERIFIED_IDENTITY_VOTE_MESSAGE
            : DUPLICATE_USER_VOTE_MESSAGE,
        );
      }

      throw error;
    }
  },
};

export default pollVotingService;
