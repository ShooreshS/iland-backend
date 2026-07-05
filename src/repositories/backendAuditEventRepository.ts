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

      const hashedEvent = buildBackendAuditEventHash({
        previousEventHash:
          input.previousEventHash ?? GENESIS_BACKEND_AUDIT_EVENT_HASH,
        eventType: input.eventType,
        decision: input.decision,
        subjectType: input.subjectType,
        subjectId: input.subjectId,
        occurredAt: input.occurredAt ?? new Date().toISOString(),
        payload: input.payload ?? {},
      });

      const { data, error } = await supabase
        .rpc("append_backend_audit_event", {
          p_stream_id: input.streamId ?? "global",
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

      if (error) {
        throw error;
      }

      return Object.freeze({
        row: data,
        hashedEvent,
      });
    },
  };
};

export const backendAuditEventRepository =
  createBackendAuditEventRepository();

export default backendAuditEventRepository;
