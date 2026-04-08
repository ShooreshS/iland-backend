import { describe, expect, it } from "bun:test";
import identityProfileRepository from "../repositories/identityProfileRepository";
import pollMapMarkerCacheRepository from "../repositories/pollMapMarkerCacheRepository";
import pollRepository from "../repositories/pollRepository";
import voteRepository from "../repositories/voteRepository";
import mapMarkerService from "./mapMarkerService";
import type { PollMapMarkerCacheRow, PollRow } from "../types/db";

const FIXED_TIME = "2026-04-08T12:00:00.000Z";

const createPoll = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "poll-1",
  slug: "poll-1",
  created_by_user_id: "owner-1",
  title: "Map Test Poll",
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

const createCacheRow = (
  overrides: Partial<PollMapMarkerCacheRow> = {},
): PollMapMarkerCacheRow => ({
  poll_id: "poll-1",
  markers_level1_json: [
    {
      id: "l1:35.7:51.4",
      bucketLat1: 35.7,
      bucketLng1: 51.4,
      parentBucketId: "l2:35:51",
      parentLatInt: 35,
      parentLngInt: 51,
      latitude: 35.75,
      longitude: 51.44,
      totalVotes: 3,
      optionBreakdown: [
        {
          optionId: "option-a",
          label: "Option A",
          color: "#22c55e",
          count: 2,
        },
        {
          optionId: "option-b",
          label: "Option B",
          color: "#ef4444",
          count: 1,
        },
      ],
      leadingOptionId: "option-a",
      updatedAt: FIXED_TIME,
    },
  ],
  schema_version: 1,
  marker_count: 1,
  total_votes: 3,
  last_vote_submitted_at: FIXED_TIME,
  refreshed_at: FIXED_TIME,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const patchMethod = <T extends object, K extends keyof T>(
  target: T,
  key: K,
  implementation: T[K],
): (() => void) => {
  const original = target[key];
  target[key] = implementation;

  return () => {
    target[key] = original;
  };
};

describe("mapMarkerService", () => {
  it("returns empty markers when no poll is selected", async () => {
    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => {
        throw new Error("no-poll request should not query poll repository");
      }),
    ];

    try {
      const markers = await mapMarkerService.getPollVoteMarkers({
        pollId: "",
      });
      expect(markers).toEqual([]);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("treats all_polls as debug-only and returns empty markers by default", async () => {
    const restoreFns = [
      patchMethod(pollRepository, "listAll", async () => {
        throw new Error("all_polls raw aggregation path should not run by default");
      }),
      patchMethod(voteRepository, "getValidByPollIds", async () => {
        throw new Error("all_polls raw vote read should not run by default");
      }),
      patchMethod(pollRepository, "getOptionsByPollIds", async () => {
        throw new Error("all_polls raw option read should not run by default");
      }),
    ];

    try {
      const markers = await mapMarkerService.getPollVoteMarkers({
        pollId: "all_polls",
      });

      expect(markers).toEqual([]);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("uses poll_map_marker_cache for single-poll reads and skips raw vote aggregation", async () => {
    const poll = createPoll();
    const cacheRow = createCacheRow();

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollMapMarkerCacheRepository, "getByPollId", async () => cacheRow),
      patchMethod(voteRepository, "countValidByPollId", async () => {
        throw new Error("single-poll cache path should not count raw votes");
      }),
      patchMethod(voteRepository, "getValidByPollIdPage", async () => {
        throw new Error("single-poll cache path should not page raw votes");
      }),
      patchMethod(identityProfileRepository, "listMapSeedByUserIds", async () => {
        throw new Error("single-poll cache path should not read identity profiles");
      }),
    ];

    try {
      const markers = await mapMarkerService.getPollVoteMarkers({
        pollId: poll.id,
        areaLevel: "city",
      });

      expect(markers.length).toBe(1);
      expect(markers[0]).toMatchObject({
        id: "marker_poll-1_l1:35.7:51.4",
        pollId: poll.id,
        areaId: "l1:35.7:51.4",
        areaLevel: "city",
        parentAreaId: "l2:35:51",
        latitude: 35.75,
        longitude: 51.44,
        totalVotes: 3,
        leadingOptionId: "option-a",
      });
      expect(markers[0]?.optionBreakdown).toEqual([
        {
          optionId: "option-a",
          label: "Option A",
          count: 2,
          color: "#22c55e",
          percentageWithinArea: 2 / 3,
        },
        {
          optionId: "option-b",
          label: "Option B",
          count: 1,
          color: "#ef4444",
          percentageWithinArea: 1 / 3,
        },
      ]);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("returns empty markers on single-poll cache miss without raw fallback", async () => {
    const poll = createPoll();

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollMapMarkerCacheRepository, "getByPollId", async () => null),
      patchMethod(voteRepository, "countValidByPollId", async () => {
        throw new Error("single-poll cache miss should not fallback to raw count");
      }),
      patchMethod(voteRepository, "getValidByPollIdPage", async () => {
        throw new Error("single-poll cache miss should not fallback to raw paging");
      }),
    ];

    try {
      const markers = await mapMarkerService.getPollVoteMarkers({
        pollId: poll.id,
        areaLevel: "city",
      });

      expect(markers).toEqual([]);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("falls back to legacy raw vote aggregation when cache table is missing in schema cache", async () => {
    const poll = createPoll();

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollMapMarkerCacheRepository, "getByPollId", async () => {
        throw {
          code: "PGRST205",
          message:
            "Could not find the table 'public.poll_map_marker_cache' in the schema cache",
        };
      }),
      patchMethod(pollRepository, "getOptionsByPollId", async () => [
        {
          id: "option-a",
          poll_id: poll.id,
          label: "Option A",
          description: null,
          color: "#22c55e",
          display_order: 1,
          is_active: true,
          created_at: FIXED_TIME,
          updated_at: FIXED_TIME,
        },
      ]),
      patchMethod(voteRepository, "getValidByPollId", async () => [
        {
          id: "vote-1",
          poll_id: poll.id,
          option_id: "option-a",
          user_id: "user-1",
          verified_identity_id: null,
          vote_latitude_l0: null,
          vote_longitude_l0: null,
          vote_location_snapshot_at: null,
          vote_location_snapshot_version: 1,
          submitted_at: FIXED_TIME,
          is_valid: true,
          invalid_reason: null,
          created_at: FIXED_TIME,
          updated_at: FIXED_TIME,
        },
        {
          id: "vote-2",
          poll_id: poll.id,
          option_id: "option-a",
          user_id: "user-2",
          verified_identity_id: null,
          vote_latitude_l0: null,
          vote_longitude_l0: null,
          vote_location_snapshot_at: null,
          vote_location_snapshot_version: 1,
          submitted_at: FIXED_TIME,
          is_valid: true,
          invalid_reason: null,
          created_at: FIXED_TIME,
          updated_at: FIXED_TIME,
        },
        {
          id: "vote-3",
          poll_id: poll.id,
          option_id: "option-a",
          user_id: "user-3",
          verified_identity_id: null,
          vote_latitude_l0: null,
          vote_longitude_l0: null,
          vote_location_snapshot_at: null,
          vote_location_snapshot_version: 1,
          submitted_at: FIXED_TIME,
          is_valid: true,
          invalid_reason: null,
          created_at: FIXED_TIME,
          updated_at: FIXED_TIME,
        },
      ]),
      patchMethod(identityProfileRepository, "listMapSeedByUserIds", async () => [
        {
          user_id: "user-1",
          home_area_id: "geo_city_ir_tehran",
          home_country_code: "IR",
          home_approx_latitude: 35.6892,
          home_approx_longitude: 51.389,
        },
        {
          user_id: "user-2",
          home_area_id: "geo_city_ir_tehran",
          home_country_code: "IR",
          home_approx_latitude: 35.6892,
          home_approx_longitude: 51.389,
        },
        {
          user_id: "user-3",
          home_area_id: "geo_city_ir_tehran",
          home_country_code: "IR",
          home_approx_latitude: 35.6892,
          home_approx_longitude: 51.389,
        },
      ]),
      patchMethod(voteRepository, "countValidByPollId", async () => {
        throw new Error("legacy fallback should not require countValidByPollId");
      }),
      patchMethod(voteRepository, "getValidByPollIdPage", async () => {
        throw new Error("legacy fallback should not require paged vote reads");
      }),
    ];

    try {
      const markers = await mapMarkerService.getPollVoteMarkers({
        pollId: poll.id,
        areaLevel: "city",
      });

      expect(markers.length).toBeGreaterThan(0);
      expect(markers[0]).toMatchObject({
        pollId: poll.id,
        areaLevel: "city",
        totalVotes: 3,
      });
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("derives areaLevel=country markers from cached level-1 markers for poll-map compatibility", async () => {
    const poll = createPoll();
    const cacheRow = createCacheRow({
      markers_level1_json: [
        {
          id: "l1:35.7:51.4",
          bucketLat1: 35.7,
          bucketLng1: 51.4,
          parentBucketId: "l2:35:51",
          parentLatInt: 35,
          parentLngInt: 51,
          latitude: 35.75,
          longitude: 51.44,
          totalVotes: 3,
          optionBreakdown: [
            { optionId: "option-a", label: "Option A", color: null, count: 2 },
            { optionId: "option-b", label: "Option B", color: null, count: 1 },
          ],
          leadingOptionId: "option-a",
          updatedAt: "2026-04-08T12:00:00.000Z",
        },
        {
          id: "l1:35.8:51.5",
          bucketLat1: 35.8,
          bucketLng1: 51.5,
          parentBucketId: "l2:35:51",
          parentLatInt: 35,
          parentLngInt: 51,
          latitude: 35.82,
          longitude: 51.53,
          totalVotes: 4,
          optionBreakdown: [
            { optionId: "option-a", label: "Option A", color: null, count: 1 },
            { optionId: "option-b", label: "Option B", color: null, count: 3 },
          ],
          leadingOptionId: "option-b",
          updatedAt: "2026-04-08T12:10:00.000Z",
        },
      ],
      marker_count: 2,
      total_votes: 7,
    });

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollMapMarkerCacheRepository, "getByPollId", async () => cacheRow),
    ];

    try {
      const markers = await mapMarkerService.getPollVoteMarkers({
        pollId: poll.id,
        areaLevel: "country",
      });

      expect(markers.length).toBe(1);
      expect(markers[0]).toMatchObject({
        pollId: poll.id,
        areaId: "l2:35:51",
        areaLevel: "country",
        parentAreaId: null,
        totalVotes: 7,
        leadingOptionId: "option-b",
      });
      expect(markers[0]?.optionBreakdown).toEqual([
        {
          optionId: "option-b",
          label: "Option B",
          count: 4,
          color: null,
          percentageWithinArea: 4 / 7,
        },
        {
          optionId: "option-a",
          label: "Option A",
          count: 3,
          color: null,
          percentageWithinArea: 3 / 7,
        },
      ]);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });
});
