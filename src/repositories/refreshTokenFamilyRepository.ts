import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  NewRefreshTokenFamilyRow,
  RefreshTokenFamilyRow,
} from "../types/db";

const REFRESH_TOKEN_FAMILY_COLUMNS =
  "id,session_id,user_id,status,current_token_hash,previous_token_hash,rotation_counter,last_rotated_at,last_used_at,expires_at,revoked_at,revocation_reason,created_at,updated_at";

export const refreshTokenFamilyRepository = {
  async insert(input: NewRefreshTokenFamilyRow): Promise<RefreshTokenFamilyRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("refresh_token_families")
      .insert({
        session_id: input.session_id,
        user_id: input.user_id,
        status: input.status ?? "active",
        current_token_hash: input.current_token_hash,
        previous_token_hash: input.previous_token_hash ?? null,
        rotation_counter: input.rotation_counter ?? 0,
        last_rotated_at: input.last_rotated_at ?? new Date().toISOString(),
        expires_at: input.expires_at,
      })
      .select(REFRESH_TOKEN_FAMILY_COLUMNS)
      .single<RefreshTokenFamilyRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async getBySessionId(sessionId: string): Promise<RefreshTokenFamilyRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("refresh_token_families")
      .select(REFRESH_TOKEN_FAMILY_COLUMNS)
      .eq("session_id", sessionId)
      .maybeSingle<RefreshTokenFamilyRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getByCurrentTokenHash(
    tokenHash: string,
  ): Promise<RefreshTokenFamilyRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("refresh_token_families")
      .select(REFRESH_TOKEN_FAMILY_COLUMNS)
      .eq("current_token_hash", tokenHash)
      .maybeSingle<RefreshTokenFamilyRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getByPreviousTokenHash(
    tokenHash: string,
  ): Promise<RefreshTokenFamilyRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("refresh_token_families")
      .select(REFRESH_TOKEN_FAMILY_COLUMNS)
      .eq("previous_token_hash", tokenHash)
      .maybeSingle<RefreshTokenFamilyRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async rotateCurrentToken(
    familyId: string,
    input: {
      previousTokenHash: string;
      currentTokenHash: string;
      expiresAt: string;
      rotationCounter: number;
    },
  ): Promise<RefreshTokenFamilyRow | null> {
    const supabase = requireSupabaseAdminClient();

    const now = new Date().toISOString();
    const { data, error } = await supabase
      .from("refresh_token_families")
      .update({
        previous_token_hash: input.previousTokenHash,
        current_token_hash: input.currentTokenHash,
        expires_at: input.expiresAt,
        rotation_counter: input.rotationCounter,
        last_rotated_at: now,
        last_used_at: now,
      })
      .eq("id", familyId)
      .select(REFRESH_TOKEN_FAMILY_COLUMNS)
      .maybeSingle<RefreshTokenFamilyRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async revokeById(
    familyId: string,
    input: {
      status: "revoked" | "reused" | "expired";
      revocationReason: string;
    },
  ): Promise<RefreshTokenFamilyRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("refresh_token_families")
      .update({
        status: input.status,
        revoked_at: new Date().toISOString(),
        revocation_reason: input.revocationReason,
      })
      .eq("id", familyId)
      .select(REFRESH_TOKEN_FAMILY_COLUMNS)
      .maybeSingle<RefreshTokenFamilyRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },
};

export default refreshTokenFamilyRepository;
