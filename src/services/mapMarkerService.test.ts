import { describe, expect, it } from "bun:test";
import identityProfileRepository from "../repositories/identityProfileRepository";
import pollRepository from "../repositories/pollRepository";
import voteRepository from "../repositories/voteRepository";
import mapMarkerService from "./mapMarkerService";
import type { IdentityProfileMapSeedRow, PollOptionRow, PollRow, VoteRow } from "../types/db";

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

const createOption = (overrides: Partial<PollOptionRow> = {}): PollOptionRow => ({
  id: "option-1",
  poll_id: "poll-1",
  label: "Option A",
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
  submitted_at: FIXED_TIME,
  is_valid: true,
  invalid_reason: null,
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
  it("aggregates poll map markers across paged vote reads (not capped at first page)", async () => {
    const poll = createPoll();
    const option = createOption();
    const votes = Array.from({ length: 7000 }, (_, index) =>
      createVote({
        id: `vote-${index}`,
        user_id: `user-${index}`,
      }),
    );

    const votePageRanges: Array<[number, number]> = [];
    const chunkSizes: number[] = [];

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionsByPollId", async () => [option]),
      patchMethod(voteRepository, "countValidByPollId", async () => votes.length),
      patchMethod(
        voteRepository,
        "getValidByPollIdPage",
        async (_pollId: string, fromInclusive: number, toInclusive: number) => {
          votePageRanges.push([fromInclusive, toInclusive]);
          return votes.slice(fromInclusive, toInclusive + 1);
        },
      ),
      patchMethod(
        identityProfileRepository,
        "listMapSeedByUserIds",
        async (userIds: string[]): Promise<IdentityProfileMapSeedRow[]> => {
          chunkSizes.push(userIds.length);

          return userIds.map((userId) => ({
            user_id: userId,
            home_area_id: "geo_city_ir_tehran",
            home_country_code: "IR",
            home_approx_latitude: 35.6892,
            home_approx_longitude: 51.389,
          }));
        },
      ),
    ];

    try {
      const markers = await mapMarkerService.getPollVoteMarkers({
        pollId: poll.id,
        areaLevel: "city",
      });

      expect(markers.length).toBeGreaterThan(0);
      expect(votePageRanges).toEqual([
        [0, 4999],
        [5000, 9999],
      ]);
      expect(chunkSizes.length).toBeGreaterThan(2);
      expect(chunkSizes.reduce((sum, size) => sum + size, 0)).toBe(7000);
      expect(Math.max(...chunkSizes)).toBeLessThanOrEqual(500);
      expect(markers[0]?.totalVotes).toBe(7000);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("prefers stored profile coordinates for city markers when available", async () => {
    const poll = createPoll();
    const option = createOption();
    const votes = [
      createVote({
        id: "vote-1",
        user_id: "user-1",
      }),
      createVote({
        id: "vote-2",
        user_id: "user-2",
      }),
      createVote({
        id: "vote-3",
        user_id: "user-3",
      }),
    ];

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionsByPollId", async () => [option]),
      patchMethod(voteRepository, "countValidByPollId", async () => votes.length),
      patchMethod(voteRepository, "getValidByPollIdPage", async () => votes),
      patchMethod(
        identityProfileRepository,
        "listMapSeedByUserIds",
        async (userIds: string[]): Promise<IdentityProfileMapSeedRow[]> =>
          userIds.map((userId) => ({
            user_id: userId,
            home_area_id: "geo_city_ir_tehran",
            home_country_code: "IR",
            home_approx_latitude: 35.6892,
            home_approx_longitude: 51.389,
          })),
      ),
    ];

    try {
      const markers = await mapMarkerService.getPollVoteMarkers({
        pollId: poll.id,
        areaLevel: "city",
      });

      expect(markers.length).toBe(1);
      expect(markers[0]?.areaId).toBe("city:IR:geo_city_ir_tehran");
      expect(markers[0]?.latitude).toBe(35.6892);
      expect(markers[0]?.longitude).toBe(51.389);
      expect(markers[0]?.totalVotes).toBe(3);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });
});
