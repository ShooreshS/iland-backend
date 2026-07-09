import { describe, expect, it } from "bun:test";

import {
  createBackendAuditEventRepository,
  type AppendBackendAuditEventInput,
} from "./backendAuditEventRepository";
import type { BackendAuditEventRow } from "../types/db";

const FIXED_TIME = "2026-07-05T12:00:00.000Z";

const createMockSupabaseClient = () => {
  let capturedRpcName: string | null = null;
  let capturedRpcParams: Record<string, unknown> | null = null;
  const rows: BackendAuditEventRow[] = [];

  return {
    getCapturedRpcName: () => capturedRpcName,
    getCapturedRpcParams: () => capturedRpcParams,
    from(tableName: string) {
      expect(tableName).toBe("backend_audit_events");
      return {
        select(columns: string) {
          expect(columns).toBe("event_hash");
          return {
            eq(column: string, value: string) {
              expect(column).toBe("stream_id");
              return {
                order(columnName: string, options: { ascending: boolean }) {
                  expect(columnName).toBe("sequence");
                  expect(options.ascending).toBe(false);
                  return {
                    limit(limitCount: number) {
                      expect(limitCount).toBe(1);
                      return {
                        async maybeSingle<T>() {
                          const row = rows
                            .filter((entry) => entry.stream_id === value)
                            .sort((left, right) => right.sequence - left.sequence)[0];
                          return {
                            data: row
                              ? ({ event_hash: row.event_hash } as T)
                              : null,
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
        },
      };
    },
    rpc(rpcName: string, params: Record<string, unknown>) {
      capturedRpcName = rpcName;
      capturedRpcParams = params;

      return {
        select(columns: string) {
          expect(columns).toContain("event_hash");
          return {
            async single<T>() {
              const streamRows = rows.filter(
                (entry) => entry.stream_id === String(params.p_stream_id),
              );
              const row: BackendAuditEventRow = {
                id: `event-${rows.length + 1}`,
                stream_id: String(params.p_stream_id),
                sequence: streamRows.length,
                previous_event_hash: String(params.p_previous_event_hash),
                event_hash: String(params.p_event_hash),
                event_type: String(params.p_event_type),
                decision: params.p_decision as BackendAuditEventRow["decision"],
                subject_type: params.p_subject_type
                  ? String(params.p_subject_type)
                  : null,
                subject_id: params.p_subject_id
                  ? String(params.p_subject_id)
                  : null,
                event_payload_json:
                  params.p_event_payload_json as BackendAuditEventRow["event_payload_json"],
                occurred_at: String(params.p_occurred_at),
                anchored_at: null,
                anchor_cluster: null,
                anchor_tx_signature: null,
                created_at: FIXED_TIME,
              };
              rows.push(row);

              return {
                data: row as T,
                error: null,
              };
            },
          };
        },
      };
    },
  };
};

describe("backendAuditEventRepository", () => {
  it("appends hash-linked events through the Supabase RPC", async () => {
    const mockClient = createMockSupabaseClient();
    const repository = createBackendAuditEventRepository({
      getSupabaseAdminClient: () =>
        mockClient as unknown as ReturnType<
          typeof import("../db/supabaseClient").getSupabaseAdminClient
        >,
    });
    const input: AppendBackendAuditEventInput = {
      streamId: "poll:poll-1",
      eventType: "vote.accepted",
      decision: "accepted",
      subjectType: "poll",
      subjectId: "poll-1",
      occurredAt: FIXED_TIME,
      payload: {
        voteCommitment: "1".repeat(64),
      },
    };

    const result = await repository.append(input);

    expect(result?.row.event_hash).toBe(result?.hashedEvent.eventHash);
    expect(result?.row.previous_event_hash).toBe(
      result?.hashedEvent.previousEventHash,
    );
    expect(mockClient.getCapturedRpcName()).toBe("append_backend_audit_event");
    expect(mockClient.getCapturedRpcParams()).toMatchObject({
      p_stream_id: "poll:poll-1",
      p_event_hash: result?.hashedEvent.eventHash,
      p_event_type: "vote.accepted",
      p_decision: "accepted",
      p_subject_type: "poll",
      p_subject_id: "poll-1",
      p_occurred_at: FIXED_TIME,
    });
  });

  it("uses the current stream tail when appending later events", async () => {
    const mockClient = createMockSupabaseClient();
    const repository = createBackendAuditEventRepository({
      getSupabaseAdminClient: () =>
        mockClient as unknown as ReturnType<
          typeof import("../db/supabaseClient").getSupabaseAdminClient
        >,
    });

    const first = await repository.append({
      streamId: "poll:poll-1",
      eventType: "vote.accepted",
      decision: "accepted",
      occurredAt: FIXED_TIME,
      payload: { voteCommitment: "1".repeat(64) },
    });
    const second = await repository.append({
      streamId: "poll:poll-1",
      eventType: "tally.accepted",
      decision: "accepted",
      occurredAt: "2026-07-05T12:01:00.000Z",
      payload: { tallyProofHash: "2".repeat(64) },
    });

    expect(second?.row.sequence).toBe(1);
    expect(second?.row.previous_event_hash).toBe(first?.row.event_hash);
  });

  it("returns null when Supabase is not configured", async () => {
    const repository = createBackendAuditEventRepository({
      getSupabaseAdminClient: () => null,
    });

    await expect(
      repository.append({
        eventType: "vote.accepted",
        decision: "accepted",
        occurredAt: FIXED_TIME,
      }),
    ).resolves.toBeNull();
  });
});
