import { describe, expect, it } from "bun:test";
import { createPollMapCacheRefreshService } from "./pollMapCacheRefreshService";
import type {
  NewPollMapMarkerCacheRow,
  PollMapMarkerCacheRow,
  PollOptionRow,
  PollRow,
  VoteRow,
} from "../types/db";

const FIXED_TIME = "2026-04-08T12:00:00.000Z";

const createPoll = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "poll-1",
  slug: "poll-1",
  created_by_user_id: "owner-1",
  title: "Poll",
  description: null,
  status: "active",
  jurisdiction_type: "global",
  jurisdiction_country_code: null,
  jurisdiction_area_ids: [],
  jurisdiction_land_ids: [],
  requires_verified_identity: false,
  allowed_document_country_codes: [],
  allowed_home_area_ids: [],
  allowed_land_ids: [],
  minimum_age: null,
  starts_at: null,
  ends_at: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createOption = (overrides: Partial<PollOptionRow> = {}): PollOptionRow => ({
  id: "option-1",
  poll_id: "poll-1",
  label: "Option 1",
  description: null,
  color: null,
  display_order: 0,
  is_active: true,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createVote = (overrides: Partial<VoteRow> = {}): VoteRow => ({
  id: "vote-1",
  poll_id: "poll-1",
  option_id: "option-1",
  user_id: "user-1",
  verified_identity_id: null,
  vote_latitude_l0: 35.71,
  vote_longitude_l0: 51.42,
  vote_location_snapshot_at: FIXED_TIME,
  vote_location_snapshot_version: 1,
  submitted_at: FIXED_TIME,
  is_valid: true,
  invalid_reason: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createCacheRepositoryDouble = () => {
  const upsertCalls: NewPollMapMarkerCacheRow[] = [];

  return {
    upsertCalls,
    repository: {
      async upsertCacheRow(
        input: NewPollMapMarkerCacheRow,
      ): Promise<PollMapMarkerCacheRow> {
        upsertCalls.push(input);

        return {
          poll_id: input.poll_id,
          markers_level1_json:
            (input.markers_level1_json as Record<string, unknown>[]) || [],
          schema_version: input.schema_version ?? 1,
          marker_count: input.marker_count ?? 0,
          total_votes: input.total_votes ?? 0,
          last_vote_submitted_at: input.last_vote_submitted_at ?? null,
          refreshed_at: input.refreshed_at || FIXED_TIME,
          created_at: FIXED_TIME,
          updated_at: FIXED_TIME,
        };
      },
    },
  };
};

const createService = (params: {
  poll: PollRow | null;
  options: PollOptionRow[];
  votes: VoteRow[];
}) => {
  const cacheDouble = createCacheRepositoryDouble();

  const service = createPollMapCacheRefreshService({
    pollRepositoryLike: {
      getById: async () => params.poll,
      getOptionsByPollId: async () => params.options,
    },
    voteRepositoryLike: {
      countValidByPollId: async () => params.votes.length,
      getValidByPollIdPage: async (_pollId, fromInclusive, toInclusive) =>
        params.votes.slice(fromInclusive, toInclusive + 1),
    },
    pollMapMarkerCacheRepositoryLike: cacheDouble.repository,
    nowIsoFn: () => FIXED_TIME,
    votePageSize: 2,
  });

  return {
    service,
    upsertCalls: cacheDouble.upsertCalls,
  };
};

describe("pollMapCacheRefreshService.rebuildPollMapCache", () => {
  it("writes empty payload when poll has votes but none have snapshot coordinates", async () => {
    const poll = createPoll();
    const option = createOption();
    const votes = [
      createVote({
        id: "vote-1",
        vote_latitude_l0: null,
        vote_longitude_l0: 51.4,
      }),
      createVote({
        id: "vote-2",
        vote_latitude_l0: 35.7,
        vote_longitude_l0: null,
      }),
    ];

    const { service, upsertCalls } = createService({
      poll,
      options: [option],
      votes,
    });

    const result = await service.rebuildPollMapCache(poll.id);

    expect(result.pollFound).toBe(true);
    expect(result.scannedVotes).toBe(2);
    expect(result.includedVotes).toBe(0);
    expect(result.ignoredVotesMissingSnapshot).toBe(2);
    expect(result.markerCount).toBe(0);
    expect(result.totalVotes).toBe(0);
    expect(result.lastVoteSubmittedAt).toBeNull();

    expect(upsertCalls.length).toBe(1);
    expect(upsertCalls[0]).toMatchObject({
      poll_id: poll.id,
      marker_count: 0,
      total_votes: 0,
      markers_level1_json: [],
      last_vote_submitted_at: null,
      refreshed_at: FIXED_TIME,
    });
  });

  it("aggregates same level-1 bucket into one marker with arithmetic mean coordinates", async () => {
    const poll = createPoll();
    const optionA = createOption({
      id: "option-a",
      label: "Option A",
      display_order: 0,
    });
    const optionB = createOption({
      id: "option-b",
      label: "Option B",
      display_order: 1,
    });

    const votes = [
      createVote({
        id: "vote-1",
        option_id: "option-a",
        vote_latitude_l0: 35.71,
        vote_longitude_l0: 51.42,
        submitted_at: "2026-04-08T11:00:00.000Z",
      }),
      createVote({
        id: "vote-2",
        option_id: "option-a",
        vote_latitude_l0: 35.79,
        vote_longitude_l0: 51.49,
        submitted_at: "2026-04-08T12:00:00.000Z",
      }),
      createVote({
        id: "vote-3",
        option_id: "option-b",
        vote_latitude_l0: 35.75,
        vote_longitude_l0: 51.41,
        submitted_at: "2026-04-08T10:00:00.000Z",
      }),
    ];

    const { service, upsertCalls } = createService({
      poll,
      options: [optionA, optionB],
      votes,
    });

    const result = await service.rebuildPollMapCache(poll.id);
    expect(result.markerCount).toBe(1);
    expect(result.totalVotes).toBe(3);
    expect(result.lastVoteSubmittedAt).toBe("2026-04-08T12:00:00.000Z");

    const marker = result.markers[0];
    expect(marker.id).toBe("l1:35.7:51.4");
    expect(marker.bucketLat1).toBe(35.7);
    expect(marker.bucketLng1).toBe(51.4);
    expect(marker.parentBucketId).toBe("l2:35:51");
    expect(marker.parentLatInt).toBe(35);
    expect(marker.parentLngInt).toBe(51);
    expect(marker.totalVotes).toBe(3);
    expect(marker.latitude).toBeCloseTo(35.75, 6);
    expect(marker.longitude).toBeCloseTo(51.44, 6);
    expect(marker.leadingOptionId).toBe("option-a");
    expect(marker.updatedAt).toBe("2026-04-08T12:00:00.000Z");

    expect(marker.optionBreakdown).toEqual([
      {
        optionId: "option-a",
        label: "Option A",
        color: null,
        count: 2,
        percentageWithinArea: 2 / 3,
      },
      {
        optionId: "option-b",
        label: "Option B",
        color: null,
        count: 1,
        percentageWithinArea: 1 / 3,
      },
    ]);

    expect(upsertCalls.length).toBe(1);
    expect(upsertCalls[0]).toMatchObject({
      poll_id: poll.id,
      marker_count: 1,
      total_votes: 3,
      last_vote_submitted_at: "2026-04-08T12:00:00.000Z",
    });
  });

  it("creates multiple markers when votes fall into different level-1 buckets", async () => {
    const poll = createPoll();
    const option = createOption();
    const votes = [
      createVote({
        id: "vote-1",
        vote_latitude_l0: 35.71,
        vote_longitude_l0: 51.42,
      }),
      createVote({
        id: "vote-2",
        vote_latitude_l0: 35.81,
        vote_longitude_l0: 51.52,
      }),
    ];

    const { service } = createService({
      poll,
      options: [option],
      votes,
    });

    const result = await service.rebuildPollMapCache(poll.id);
    expect(result.markerCount).toBe(2);
    expect(result.markers.map((marker) => marker.id)).toEqual([
      "l1:35.7:51.4",
      "l1:35.8:51.5",
    ]);
  });

  it("uses floor-based negative bucketing consistently for level-1 and parent buckets", async () => {
    const poll = createPoll();
    const option = createOption();
    const votes = [
      createVote({
        id: "vote-1",
        vote_latitude_l0: -0.01,
        vote_longitude_l0: -0.01,
      }),
      createVote({
        id: "vote-2",
        vote_latitude_l0: -0.1,
        vote_longitude_l0: -0.1,
      }),
      createVote({
        id: "vote-3",
        vote_latitude_l0: -1.21,
        vote_longitude_l0: -1.29,
      }),
    ];

    const { service } = createService({
      poll,
      options: [option],
      votes,
    });

    const result = await service.rebuildPollMapCache(poll.id);
    expect(result.markerCount).toBe(2);

    const markerById = new Map(result.markers.map((marker) => [marker.id, marker]));
    const nearZeroMarker = markerById.get("l1:-0.1:-0.1");
    const minusOneMarker = markerById.get("l1:-1.3:-1.3");

    expect(nearZeroMarker?.totalVotes).toBe(2);
    expect(nearZeroMarker?.parentBucketId).toBe("l2:-1:-1");
    expect(nearZeroMarker?.parentLatInt).toBe(-1);
    expect(nearZeroMarker?.parentLngInt).toBe(-1);

    expect(minusOneMarker?.totalVotes).toBe(1);
    expect(minusOneMarker?.parentBucketId).toBe("l2:-2:-2");
    expect(minusOneMarker?.parentLatInt).toBe(-2);
    expect(minusOneMarker?.parentLngInt).toBe(-2);
  });
});
