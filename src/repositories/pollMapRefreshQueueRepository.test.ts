import { describe, expect, it } from "bun:test";
import { createPollMapRefreshQueueRepository } from "./pollMapRefreshQueueRepository";
import type { PollMapRefreshQueueRow } from "../types/db";

const FIXED_TIME = "2026-04-08T12:00:00.000Z";

const createMockQueueClient = () => {
  const rows = new Map<string, PollMapRefreshQueueRow>();

  const ensureRow = (pollId: string): PollMapRefreshQueueRow => {
    const existing = rows.get(pollId);
    if (existing) {
      return existing;
    }

    const created: PollMapRefreshQueueRow = {
      poll_id: pollId,
      pending_vote_events: 0,
      first_enqueued_at: FIXED_TIME,
      last_enqueued_at: FIXED_TIME,
      last_processed_at: null,
      last_error: null,
      created_at: FIXED_TIME,
      updated_at: FIXED_TIME,
    };

    rows.set(pollId, created);
    return created;
  };

  return {
    async rpc(fnName: string, params: Record<string, unknown>) {
      if (fnName !== "enqueue_poll_map_refresh") {
        throw new Error(`Unexpected function: ${fnName}`);
      }

      const pollId = String(params.p_poll_id || "").trim();
      if (!pollId) {
        return {
          data: null,
          error: new Error("p_poll_id is required"),
        };
      }

      const row = ensureRow(pollId);
      const next: PollMapRefreshQueueRow = {
        ...row,
        pending_vote_events: row.pending_vote_events + 1,
        last_enqueued_at: FIXED_TIME,
        last_error: null,
        updated_at: FIXED_TIME,
      };
      rows.set(pollId, next);

      return {
        data: null,
        error: null,
      };
    },

    from(table: string) {
      if (table !== "poll_map_refresh_queue") {
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
          };
        },
      };
    },
  };
};

describe("pollMapRefreshQueueRepository", () => {
  it("increments pending_vote_events for repeated enqueue calls", async () => {
    const mockClient = createMockQueueClient();
    const repository = createPollMapRefreshQueueRepository({
      getSupabaseAdminClient: () =>
        mockClient as unknown as ReturnType<
          typeof import("../db/supabaseClient").requireSupabaseAdminClient
        >,
    });

    const first = await repository.enqueuePoll("poll-1");
    expect(first.pending_vote_events).toBe(1);

    const second = await repository.enqueuePoll("poll-1");
    expect(second.pending_vote_events).toBe(2);

    const fetched = await repository.getByPollId("poll-1");
    expect(fetched?.pending_vote_events).toBe(2);
  });
});
