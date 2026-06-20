import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  AuthAuditEventRow,
  NewAuthAuditEventRow,
} from "../types/db";

const AUTH_AUDIT_EVENT_COLUMNS =
  "id,user_id,auth_credential_id,session_id,event_type,platform,metadata,occurred_at";

export const authAuditEventRepository = {
  async insert(input: NewAuthAuditEventRow): Promise<AuthAuditEventRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("auth_audit_events")
      .insert({
        user_id: input.user_id ?? null,
        auth_credential_id: input.auth_credential_id ?? null,
        session_id: input.session_id ?? null,
        event_type: input.event_type,
        platform: input.platform ?? null,
        metadata: input.metadata ?? {},
        occurred_at: input.occurred_at ?? new Date().toISOString(),
      })
      .select(AUTH_AUDIT_EVENT_COLUMNS)
      .single<AuthAuditEventRow>();

    if (error) {
      throw error;
    }

    return data;
  },
};

export default authAuditEventRepository;
