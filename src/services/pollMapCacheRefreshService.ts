import pollMapMarkerCacheRepository from "../repositories/pollMapMarkerCacheRepository";
import pollRepository from "../repositories/pollRepository";
import voteRepository from "../repositories/voteRepository";
import type { PollMapRebuildVoteRow } from "../repositories/voteRepository";
import type { NewPollMapMarkerCacheRow, PollOptionRow } from "../types/db";

const POLL_MAP_CACHE_SCHEMA_VERSION = 1;
const DEFAULT_VOTE_PAGE_SIZE = 5000;

type PollMapCacheRefreshDependencies = {
  pollRepositoryLike?: Pick<typeof pollRepository, "getById" | "getOptionsByPollId">;
  voteRepositoryLike?: Pick<
    typeof voteRepository,
    "getValidWithSnapshotByPollIdKeysetPage"
  >;
  pollMapMarkerCacheRepositoryLike?: Pick<
    typeof pollMapMarkerCacheRepository,
    "upsertCacheRow"
  >;
  nowIsoFn?: () => string;
  votePageSize?: number;
};

export type PollMapMarkerOptionBreakdown = {
  optionId: string;
  label: string;
  color: string | null;
  count: number;
  percentageWithinArea: number;
};

export type PollMapLevel1Marker = {
  id: string;
  bucketLat1: number;
  bucketLng1: number;
  parentBucketId: string;
  parentLatInt: number;
  parentLngInt: number;
  latitude: number;
  longitude: number;
  totalVotes: number;
  optionBreakdown: PollMapMarkerOptionBreakdown[];
  leadingOptionId: string | null;
  updatedAt: string;
};

export type PollMapCacheRebuildResult = {
  pollId: string;
  pollFound: boolean;
  scannedVotes: number;
  includedVotes: number;
  ignoredVotesMissingSnapshot: number;
  markerCount: number;
  totalVotes: number;
  lastVoteSubmittedAt: string | null;
  refreshedAt: string;
  markers: PollMapLevel1Marker[];
};

type BucketAccumulator = {
  id: string;
  bucketLat1: number;
  bucketLng1: number;
  parentBucketId: string;
  parentLatInt: number;
  parentLngInt: number;
  sumLat: number;
  sumLng: number;
  totalVotes: number;
  countsByOptionId: Record<string, number>;
  updatedAt: string | null;
};

type PollMapCacheRefreshErrorStage =
  | "load_poll"
  | "load_poll_options"
  | "load_vote_page"
  | "upsert_cache_row";

type PollMapCacheRefreshErrorContext = {
  pollId: string;
  stage: PollMapCacheRefreshErrorStage;
  votePageSize: number;
  pageFrom?: number;
  pageTo?: number;
  pageAfterVoteId?: string | null;
  scannedVotes: number;
  includedVotes: number;
  ignoredVotesMissingSnapshot: number;
  markerCount?: number;
};

type ErrorLike = {
  code?: unknown;
  message?: unknown;
  details?: unknown;
  hint?: unknown;
};

export class PollMapCacheRefreshError extends Error {
  readonly context: PollMapCacheRefreshErrorContext;
  readonly rawError: unknown;

  constructor(params: {
    message: string;
    context: PollMapCacheRefreshErrorContext;
    rawError: unknown;
  }) {
    super(params.message);
    this.name = "PollMapCacheRefreshError";
    this.context = params.context;
    this.rawError = params.rawError;
  }
}

const canonicalizeNegativeZero = (value: number): number =>
  Object.is(value, -0) ? 0 : value;

const roundToDecimals = (value: number, decimals: number): number => {
  const scale = 10 ** decimals;
  return canonicalizeNegativeZero(Math.round(value * scale) / scale);
};

const isValidCoordinate = (
  value: number | null,
  bounds: { min: number; max: number },
): value is number =>
  typeof value === "number" &&
  Number.isFinite(value) &&
  value >= bounds.min &&
  value <= bounds.max;

// Negative values use floor-based bucketing (not truncation), which gives stable
// half-open intervals: [n/10, (n+1)/10). Example: -0.01 and -0.10 both map to -0.1.
const toTenthsBucket = (value: number): number =>
  canonicalizeNegativeZero(Math.floor(value * 10) / 10);

const toTenthsBucketString = (value: number): string =>
  canonicalizeNegativeZero(value).toFixed(1);

const buildMarkerOptionBreakdown = (params: {
  countsByOptionId: Record<string, number>;
  totalVotes: number;
  pollOptions: PollOptionRow[];
}): PollMapMarkerOptionBreakdown[] => {
  const { countsByOptionId, totalVotes, pollOptions } = params;

  if (pollOptions.length === 0) {
    return Object.entries(countsByOptionId)
      .map(([optionId, count]) => ({
        optionId,
        label: optionId,
        color: null,
        count,
        percentageWithinArea: totalVotes > 0 ? count / totalVotes : 0,
      }))
      .sort((left, right) => {
        if (right.count !== left.count) {
          return right.count - left.count;
        }

        return left.optionId.localeCompare(right.optionId);
      });
  }

  const displayOrderById = new Map(
    pollOptions.map((option) => [option.id, option.display_order]),
  );

  return pollOptions
    .map((option) => {
      const count = countsByOptionId[option.id] || 0;
      return {
        optionId: option.id,
        label: option.label,
        color: option.color ?? null,
        count,
        percentageWithinArea: totalVotes > 0 ? count / totalVotes : 0,
      };
    })
    .sort((left, right) => {
      if (right.count !== left.count) {
        return right.count - left.count;
      }

      const leftOrder =
        displayOrderById.get(left.optionId) ?? Number.MAX_SAFE_INTEGER;
      const rightOrder =
        displayOrderById.get(right.optionId) ?? Number.MAX_SAFE_INTEGER;
      if (leftOrder !== rightOrder) {
        return leftOrder - rightOrder;
      }

      return left.optionId.localeCompare(right.optionId);
    });
};

const selectLeadingOptionId = (
  optionBreakdown: PollMapMarkerOptionBreakdown[],
): string | null => optionBreakdown.find((entry) => entry.count > 0)?.optionId || null;

const createEmptyResult = (pollId: string, refreshedAt: string): PollMapCacheRebuildResult => ({
  pollId,
  pollFound: true,
  scannedVotes: 0,
  includedVotes: 0,
  ignoredVotesMissingSnapshot: 0,
  markerCount: 0,
  totalVotes: 0,
  lastVoteSubmittedAt: null,
  refreshedAt,
  markers: [],
});

const normalizeText = (value: unknown): string | null => {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
};

const extractErrorMessage = (error: unknown): string => {
  if (error instanceof Error) {
    return normalizeText(error.message) || error.name;
  }

  if (error && typeof error === "object") {
    const errorLike = error as ErrorLike;
    const code = normalizeText(errorLike.code);
    const message = normalizeText(errorLike.message);
    const details = normalizeText(errorLike.details);
    const hint = normalizeText(errorLike.hint);

    const parts = [
      code ? `[${code}]` : null,
      message,
      details ? `details=${details}` : null,
      hint ? `hint=${hint}` : null,
    ].filter(Boolean);

    if (parts.length > 0) {
      return parts.join(" ");
    }

    try {
      return JSON.stringify(error);
    } catch {
      return String(error);
    }
  }

  return String(error);
};

const createPollMapCacheRefreshError = (params: {
  pollId: string;
  stage: PollMapCacheRefreshErrorStage;
  votePageSize: number;
  scannedVotes: number;
  includedVotes: number;
  ignoredVotesMissingSnapshot: number;
  pageFrom?: number;
  pageTo?: number;
  pageAfterVoteId?: string | null;
  markerCount?: number;
  rawError: unknown;
}): PollMapCacheRefreshError => {
  const {
    pollId,
    stage,
    votePageSize,
    scannedVotes,
    includedVotes,
    ignoredVotesMissingSnapshot,
    pageFrom,
    pageTo,
    pageAfterVoteId,
    markerCount,
    rawError,
  } = params;

  const context: PollMapCacheRefreshErrorContext = {
    pollId,
    stage,
    votePageSize,
    scannedVotes,
    includedVotes,
    ignoredVotesMissingSnapshot,
    ...(pageFrom !== undefined ? { pageFrom } : null),
    ...(pageTo !== undefined ? { pageTo } : null),
    ...(pageAfterVoteId !== undefined ? { pageAfterVoteId } : null),
    ...(markerCount !== undefined ? { markerCount } : null),
  };

  const batchContext =
    pageFrom !== undefined && pageTo !== undefined
      ? ` page=${pageFrom}-${pageTo}`
      : "";
  const cursorContext =
    pageAfterVoteId !== undefined
      ? ` afterVoteId=${pageAfterVoteId || "null"}`
      : "";
  const message = `[pollMapCacheRefreshService] rebuild failed stage=${stage} pollId=${pollId}${batchContext}${cursorContext}: ${extractErrorMessage(rawError)}`;

  const wrapped = new PollMapCacheRefreshError({
    message,
    context,
    rawError,
  });

  if (rawError instanceof Error && rawError.stack) {
    wrapped.stack = `${wrapped.name}: ${wrapped.message}\nCaused by: ${rawError.stack}`;
  }

  return wrapped;
};

export const createPollMapCacheRefreshService = (
  dependencies: PollMapCacheRefreshDependencies = {},
) => {
  const pollRepositoryLike = dependencies.pollRepositoryLike || pollRepository;
  const voteRepositoryLike = dependencies.voteRepositoryLike || voteRepository;
  const pollMapMarkerCacheRepositoryLike =
    dependencies.pollMapMarkerCacheRepositoryLike || pollMapMarkerCacheRepository;
  const nowIsoFn = dependencies.nowIsoFn || (() => new Date().toISOString());
  const votePageSize =
    dependencies.votePageSize && dependencies.votePageSize > 0
      ? Math.trunc(dependencies.votePageSize)
      : DEFAULT_VOTE_PAGE_SIZE;

  return {
    async rebuildPollMapCache(pollId: string): Promise<PollMapCacheRebuildResult> {
      const normalizedPollId = pollId.trim();
      const refreshedAt = nowIsoFn();

      if (!normalizedPollId) {
        return {
          ...createEmptyResult(normalizedPollId, refreshedAt),
          pollFound: false,
        };
      }

      let poll: Awaited<ReturnType<typeof pollRepositoryLike.getById>>;
      try {
        poll = await pollRepositoryLike.getById(normalizedPollId);
      } catch (error) {
        throw createPollMapCacheRefreshError({
          pollId: normalizedPollId,
          stage: "load_poll",
          votePageSize,
          scannedVotes: 0,
          includedVotes: 0,
          ignoredVotesMissingSnapshot: 0,
          rawError: error,
        });
      }

      if (!poll) {
        return {
          ...createEmptyResult(normalizedPollId, refreshedAt),
          pollFound: false,
        };
      }

      const bucketsById = new Map<string, BucketAccumulator>();
      let scannedVotes = 0;
      let includedVotes = 0;
      let ignoredVotesMissingSnapshot = 0;
      let lastVoteSubmittedAt: string | null = null;
      let pollOptions: PollOptionRow[] = [];

      try {
        pollOptions = await pollRepositoryLike.getOptionsByPollId(normalizedPollId);
      } catch (error) {
        throw createPollMapCacheRefreshError({
          pollId: normalizedPollId,
          stage: "load_poll_options",
          votePageSize,
          scannedVotes,
          includedVotes,
          ignoredVotesMissingSnapshot,
          rawError: error,
        });
      }

      console.info("[pollMapCacheRefreshService] starting vote page scan", {
        pollId: normalizedPollId,
        pageSize: votePageSize,
        pagination: "keyset",
        orderBy: "id asc",
        cursorField: "id",
        selectedColumns: [
          "id",
          "option_id",
          "submitted_at",
          "vote_latitude_l0",
          "vote_longitude_l0",
        ],
        usesCountQuery: false,
      });

      let pageFrom = 0;
      let afterVoteId: string | null = null;

      for (;;) {
        const pageTo = pageFrom + votePageSize - 1;
        let votes: PollMapRebuildVoteRow[];
        try {
          votes = await voteRepositoryLike.getValidWithSnapshotByPollIdKeysetPage(
            normalizedPollId,
            afterVoteId,
            votePageSize,
          );
        } catch (error) {
          throw createPollMapCacheRefreshError({
            pollId: normalizedPollId,
            stage: "load_vote_page",
            votePageSize,
            scannedVotes,
            includedVotes,
            ignoredVotesMissingSnapshot,
            pageFrom,
            pageTo,
            pageAfterVoteId: afterVoteId,
            rawError: error,
          });
        }

        if (votes.length === 0) {
          break;
        }

        for (const vote of votes) {
          scannedVotes += 1;

          const latitude = vote.vote_latitude_l0;
          const longitude = vote.vote_longitude_l0;
          if (
            !isValidCoordinate(latitude, { min: -90, max: 90 }) ||
            !isValidCoordinate(longitude, { min: -180, max: 180 })
          ) {
            ignoredVotesMissingSnapshot += 1;
            continue;
          }

          const latL0 = roundToDecimals(latitude, 2);
          const lngL0 = roundToDecimals(longitude, 2);
          const bucketLat1 = toTenthsBucket(latL0);
          const bucketLng1 = toTenthsBucket(lngL0);
          const parentLatInt = Math.floor(bucketLat1);
          const parentLngInt = Math.floor(bucketLng1);

          const bucketId = `l1:${toTenthsBucketString(bucketLat1)}:${toTenthsBucketString(bucketLng1)}`;
          const existing = bucketsById.get(bucketId);
          if (!existing) {
            bucketsById.set(bucketId, {
              id: bucketId,
              bucketLat1,
              bucketLng1,
              parentBucketId: `l2:${parentLatInt}:${parentLngInt}`,
              parentLatInt,
              parentLngInt,
              sumLat: latL0,
              sumLng: lngL0,
              totalVotes: 1,
              countsByOptionId: { [vote.option_id]: 1 },
              updatedAt: vote.submitted_at,
            });
          } else {
            existing.sumLat += latL0;
            existing.sumLng += lngL0;
            existing.totalVotes += 1;
            existing.countsByOptionId[vote.option_id] =
              (existing.countsByOptionId[vote.option_id] || 0) + 1;
            if (!existing.updatedAt || vote.submitted_at > existing.updatedAt) {
              existing.updatedAt = vote.submitted_at;
            }
          }

          includedVotes += 1;
          if (!lastVoteSubmittedAt || vote.submitted_at > lastVoteSubmittedAt) {
            lastVoteSubmittedAt = vote.submitted_at;
          }
        }

        pageFrom += votes.length;
        afterVoteId = votes[votes.length - 1]?.id || afterVoteId;
      }

      const markers = Array.from(bucketsById.values())
        .map((bucket): PollMapLevel1Marker => {
          const optionBreakdown = buildMarkerOptionBreakdown({
            countsByOptionId: bucket.countsByOptionId,
            totalVotes: bucket.totalVotes,
            pollOptions,
          });

          return {
            id: bucket.id,
            bucketLat1: bucket.bucketLat1,
            bucketLng1: bucket.bucketLng1,
            parentBucketId: bucket.parentBucketId,
            parentLatInt: bucket.parentLatInt,
            parentLngInt: bucket.parentLngInt,
            latitude: roundToDecimals(bucket.sumLat / bucket.totalVotes, 6),
            longitude: roundToDecimals(bucket.sumLng / bucket.totalVotes, 6),
            totalVotes: bucket.totalVotes,
            optionBreakdown,
            leadingOptionId: selectLeadingOptionId(optionBreakdown),
            updatedAt: bucket.updatedAt || refreshedAt,
          };
        })
        .sort((left, right) => {
          if (right.totalVotes !== left.totalVotes) {
            return right.totalVotes - left.totalVotes;
          }

          return left.id.localeCompare(right.id);
        });

      const cachePayload: NewPollMapMarkerCacheRow = {
        poll_id: normalizedPollId,
        markers_level1_json: markers as Record<string, unknown>[],
        schema_version: POLL_MAP_CACHE_SCHEMA_VERSION,
        marker_count: markers.length,
        total_votes: includedVotes,
        last_vote_submitted_at: lastVoteSubmittedAt,
        refreshed_at: refreshedAt,
      };
      try {
        await pollMapMarkerCacheRepositoryLike.upsertCacheRow(cachePayload);
      } catch (error) {
        throw createPollMapCacheRefreshError({
          pollId: normalizedPollId,
          stage: "upsert_cache_row",
          votePageSize,
          scannedVotes,
          includedVotes,
          ignoredVotesMissingSnapshot,
          markerCount: markers.length,
          rawError: error,
        });
      }

      return {
        pollId: normalizedPollId,
        pollFound: true,
        scannedVotes,
        includedVotes,
        ignoredVotesMissingSnapshot,
        markerCount: markers.length,
        totalVotes: includedVotes,
        lastVoteSubmittedAt,
        refreshedAt,
        markers,
      };
    },
  };
};

export const pollMapCacheRefreshService = createPollMapCacheRefreshService();

export default pollMapCacheRefreshService;
