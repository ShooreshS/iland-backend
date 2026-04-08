import { describe, expect, it } from "bun:test";
import { createPollMapMarkerCacheRepository } from "./pollMapMarkerCacheRepository";
import type { PollMapMarkerCacheRow } from "../types/db";

const FIXED_TIME = "2026-04-08T12:00:00.000Z";

const createMockCacheClient = () => {
  const rows = new Map<string, PollMapMarkerCacheRow>();

  return {
    from(table: string) {
      if (table !== "poll_map_marker_cache") {
        throw new Error(`Unexpected table: ${table}`);
      }

      return {
        select() {
          return {
            eq(_column: string, pollId: string) {
              return {
                async maybeSingle<T>() {
                  return {
                    data: (rows.get(pollId) || null) as T | null,
                    error: null,
                  };
                },
              };
            },
            in(_column: string, pollIds: string[]) {
              const data = pollIds
                .map((pollId) => rows.get(pollId) || null)
                .filter((row): row is PollMapMarkerCacheRow => Boolean(row));

              return {
                data,
                error: null,
              };
            },
          };
        },

        upsert(payload: Record<string, unknown>) {
          const pollId = String(payload.poll_id);
          const previous = rows.get(pollId);

          const nextRow: PollMapMarkerCacheRow = {
            poll_id: pollId,
            markers_level1_json: (payload.markers_level1_json as Record<string, unknown>[]) ||
              previous?.markers_level1_json ||
              [],
            schema_version:
              typeof payload.schema_version === "number"
                ? payload.schema_version
                : (previous?.schema_version ?? 1),
            marker_count:
              typeof payload.marker_count === "number"
                ? payload.marker_count
                : (previous?.marker_count ?? 0),
            total_votes:
              typeof payload.total_votes === "number"
                ? payload.total_votes
                : (previous?.total_votes ?? 0),
            last_vote_submitted_at:
              payload.last_vote_submitted_at !== undefined
                ? (payload.last_vote_submitted_at as string | null)
                : (previous?.last_vote_submitted_at ?? null),
            refreshed_at:
              (payload.refreshed_at as string | undefined) ||
              previous?.refreshed_at ||
              FIXED_TIME,
            created_at: previous?.created_at || FIXED_TIME,
            updated_at: FIXED_TIME,
          };

          rows.set(pollId, nextRow);

          return {
            select() {
              return {
                async single<T>() {
                  return {
                    data: nextRow as T,
                    error: null,
                  };
                },
              };
            },
          };
        },

        delete() {
          return {
            async eq(_column: string, pollId: string) {
              rows.delete(pollId);
              return {
                error: null,
              };
            },
          };
        },
      };
    },
  };
};

describe("pollMapMarkerCacheRepository", () => {
  it("upserts and reads a cache row by poll id", async () => {
    const mockClient = createMockCacheClient();
    const repository = createPollMapMarkerCacheRepository({
      getSupabaseAdminClient: () =>
        mockClient as unknown as ReturnType<
          typeof import("../db/supabaseClient").requireSupabaseAdminClient
        >,
    });

    const upserted = await repository.upsertCacheRow({
      poll_id: "poll-1",
      markers_level1_json: [
        {
          id: "l1:35.7:51.4",
          totalVotes: 12,
        },
      ],
      marker_count: 1,
      total_votes: 12,
      refreshed_at: FIXED_TIME,
    });

    expect(upserted.poll_id).toBe("poll-1");
    expect(upserted.marker_count).toBe(1);
    expect(upserted.total_votes).toBe(12);
    expect(upserted.markers_level1_json.length).toBe(1);

    const fetched = await repository.getByPollId("poll-1");
    expect(fetched).toEqual(upserted);
  });
});
