import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  AuthSessionRow,
  NewAuthSessionRow,
} from "../types/db";

const AUTH_SESSION_COLUMNS =
  "id,user_id,auth_credential_id,status,auth_generation,attestation_verified_at,last_seen_at,expires_at,revoked_at,revocation_reason,created_at,updated_at";

export const authSessionRepository = {
  async insert(input: NewAuthSessionRow): Promise<AuthSessionRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("auth_sessions")
      .insert({
        user_id: input.user_id,
        auth_credential_id: input.auth_credential_id,
        status: input.status ?? "active",
        auth_generation: input.auth_generation,
        attestation_verified_at: input.attestation_verified_at,
        last_seen_at: input.last_seen_at ?? new Date().toISOString(),
        expires_at: input.expires_at,
      })
      .select(AUTH_SESSION_COLUMNS)
      .single<AuthSessionRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async listByUserId(userId: string): Promise<AuthSessionRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("auth_sessions")
      .select(AUTH_SESSION_COLUMNS)
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .returns<AuthSessionRow[]>();

    if (error) {
      throw error;
    }

    return data || [];
  },

  async getById(sessionId: string): Promise<AuthSessionRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("auth_sessions")
      .select(AUTH_SESSION_COLUMNS)
      .eq("id", sessionId)
      .maybeSingle<AuthSessionRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async revokeById(
    sessionId: string,
    revocationReason: string,
  ): Promise<AuthSessionRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("auth_sessions")
      .update({
        status: "revoked",
        revoked_at: new Date().toISOString(),
        revocation_reason: revocationReason,
      })
      .eq("id", sessionId)
      .select(AUTH_SESSION_COLUMNS)
      .maybeSingle<AuthSessionRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },
};

export default authSessionRepository;
