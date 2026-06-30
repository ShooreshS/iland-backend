import { getSupabaseAdminClient } from "../db/supabaseClient";

export type NewOidcAuditEventRow = {
  user_id?: string | null;
  client_id?: string | null;
  auth_session_id?: string | null;
  authorization_request_id?: string | null;
  grant_id?: string | null;
  event_type: string;
  ip_hash?: string | null;
  user_agent_hash?: string | null;
  metadata?: Record<string, unknown>;
  occurred_at?: string;
};

export type OidcAuditEventRow = NewOidcAuditEventRow & {
  id: string;
  user_id: string | null;
  client_id: string | null;
  auth_session_id: string | null;
  authorization_request_id: string | null;
  grant_id: string | null;
  ip_hash: string | null;
  user_agent_hash: string | null;
  metadata: Record<string, unknown>;
  occurred_at: string;
};

const OIDC_AUDIT_EVENT_COLUMNS =
  "id,user_id,client_id,auth_session_id,authorization_request_id,grant_id,event_type,ip_hash,user_agent_hash,metadata,occurred_at";

export const oidcAuditEventRepository = {
  async insert(input: NewOidcAuditEventRow): Promise<OidcAuditEventRow | null> {
    if (
      process.env.NODE_ENV === "test" &&
      process.env.OIDC_AUDIT_ENABLE_IN_TESTS !== "true"
    ) {
      return null;
    }

    const supabase = getSupabaseAdminClient();
    if (!supabase) {
      return null;
    }

    const { data, error } = await supabase
      .from("oidc_audit_events")
      .insert({
        user_id: input.user_id ?? null,
        client_id: input.client_id ?? null,
        auth_session_id: input.auth_session_id ?? null,
        authorization_request_id: input.authorization_request_id ?? null,
        grant_id: input.grant_id ?? null,
        event_type: input.event_type,
        ip_hash: input.ip_hash ?? null,
        user_agent_hash: input.user_agent_hash ?? null,
        metadata: input.metadata ?? {},
        occurred_at: input.occurred_at ?? new Date().toISOString(),
      })
      .select(OIDC_AUDIT_EVENT_COLUMNS)
      .single<OidcAuditEventRow>();

    if (error) {
      throw error;
    }

    return data;
  },
};

export default oidcAuditEventRepository;
