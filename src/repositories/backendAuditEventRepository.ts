import { getSupabaseAdminClient } from "../db/supabaseClient";
import {
  buildBackendAuditEventHash,
  GENESIS_BACKEND_AUDIT_EVENT_HASH,
  type HashedBackendAuditEvent,
} from "../services/backendAuditHashChainService";
import type {
  BackendAuditEventDecision,
  BackendAuditEventRow,
} from "../types/db";
import type { JsonValue } from "../types/json";

const BACKEND_AUDIT_EVENT_COLUMNS =
  "id,stream_id,sequence,previous_event_hash,event_hash,event_type,decision,subject_type,subject_id,event_payload_json,occurred_at,anchored_at,anchor_cluster,anchor_tx_signature,created_at";

export type AppendBackendAuditEventInput = Readonly<{
  streamId?: string | null;
  previousEventHash?: string | null;
  eventType: string;
  decision: BackendAuditEventDecision;
  subjectType?: string | null;
  subjectId?: string | null;
  payload?: JsonValue | null;
  occurredAt?: string | null;
}>;

export type AppendBackendAuditEventResult = Readonly<{
  row: BackendAuditEventRow;
  hashedEvent: HashedBackendAuditEvent;
}>;

type BackendAuditEventRepositoryDependencies = {
  getSupabaseAdminClient?: typeof getSupabaseAdminClient;
};

export const createBackendAuditEventRepository = (
  dependencies: BackendAuditEventRepositoryDependencies = {},
) => {
  const resolveSupabase =
    dependencies.getSupabaseAdminClient || getSupabaseAdminClient;

  return {
    async append(
      input: AppendBackendAuditEventInput,
    ): Promise<AppendBackendAuditEventResult | null> {
      const supabase = resolveSupabase();
      if (!supabase) {
        return null;
      }

      const streamId = input.streamId ?? "global";
      const occurredAt = input.occurredAt ?? new Date().toISOString();

      const readPreviousEventHash = async (): Promise<string> => {
        if (input.previousEventHash) {
          return input.previousEventHash;
        }

        const { data, error } = await supabase
          .from("backend_audit_events")
          .select("event_hash")
          .eq("stream_id", streamId)
          .order("sequence", { ascending: false })
          .limit(1)
          .maybeSingle<Pick<BackendAuditEventRow, "event_hash">>();

        if (error) {
          throw error;
        }

        return data?.event_hash ?? GENESIS_BACKEND_AUDIT_EVENT_HASH;
      };

      let lastError: unknown = null;
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const hashedEvent = buildBackendAuditEventHash({
          previousEventHash: await readPreviousEventHash(),
          eventType: input.eventType,
          decision: input.decision,
          subjectType: input.subjectType,
          subjectId: input.subjectId,
          occurredAt,
          payload: input.payload ?? {},
        });

        const { data, error } = await supabase
          .rpc("append_backend_audit_event", {
            p_stream_id: streamId,
            p_previous_event_hash: hashedEvent.previousEventHash,
            p_event_hash: hashedEvent.eventHash,
            p_event_type: hashedEvent.eventPayload.eventType,
            p_decision: hashedEvent.eventPayload.decision,
            p_subject_type: hashedEvent.eventPayload.subject.type,
            p_subject_id: hashedEvent.eventPayload.subject.id,
            p_event_payload_json: hashedEvent.eventPayload,
            p_occurred_at: hashedEvent.eventPayload.occurredAt,
          })
          .select(BACKEND_AUDIT_EVENT_COLUMNS)
          .single<BackendAuditEventRow>();

        if (!error) {
          return Object.freeze({
            row: data,
            hashedEvent,
          });
        }

        lastError = error;
        const message =
          typeof error === "object" &&
          error !== null &&
          "message" in error &&
          typeof error.message === "string"
            ? error.message
            : "";
        if (
          input.previousEventHash ||
          !message.includes("previous event hash does not match")
        ) {
          throw error;
        }
      }

      throw lastError;
    },
  };
};

export const backendAuditEventRepository =
  createBackendAuditEventRepository();

export default backendAuditEventRepository;
