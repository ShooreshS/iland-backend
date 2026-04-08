import pollMapMarkerCacheRepository from "../repositories/pollMapMarkerCacheRepository";
import pollRepository from "../repositories/pollRepository";
import voteRepository from "../repositories/voteRepository";
import type { NewPollMapMarkerCacheRow, PollOptionRow, VoteRow } from "../types/db";

const POLL_MAP_CACHE_SCHEMA_VERSION = 1;
const DEFAULT_VOTE_PAGE_SIZE = 5000;

type PollMapCacheRefreshDependencies = {
  pollRepositoryLike?: Pick<typeof pollRepository, "getById" | "getOptionsByPollId">;
  voteRepositoryLike?: Pick<
    typeof voteRepository,
    "countValidByPollId" | "getValidByPollIdPage"
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

      const poll = await pollRepositoryLike.getById(normalizedPollId);
      if (!poll) {
        return {
          ...createEmptyResult(normalizedPollId, refreshedAt),
          pollFound: false,
        };
      }

      const [pollOptions, totalValidVotes] = await Promise.all([
        pollRepositoryLike.getOptionsByPollId(normalizedPollId),
        voteRepositoryLike.countValidByPollId(normalizedPollId),
      ]);

      const bucketsById = new Map<string, BucketAccumulator>();
      let scannedVotes = 0;
      let includedVotes = 0;
      let ignoredVotesMissingSnapshot = 0;
      let lastVoteSubmittedAt: string | null = null;

      for (let offset = 0; offset < totalValidVotes; offset += votePageSize) {
        const votes = await voteRepositoryLike.getValidByPollIdPage(
          normalizedPollId,
          offset,
          offset + votePageSize - 1,
        );

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
      await pollMapMarkerCacheRepositoryLike.upsertCacheRow(cachePayload);

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
