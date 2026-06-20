import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  AuthChallengeRow,
  NewAuthChallengeRow,
} from "../types/db";

const AUTH_CHALLENGE_COLUMNS =
  "id,purpose,platform,challenge_hash,credential_id_hint,expires_at,consumed_at,metadata,created_at";

export const authChallengeRepository = {
  async insert(input: NewAuthChallengeRow): Promise<AuthChallengeRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("auth_challenges")
      .insert({
        purpose: input.purpose,
        platform: input.platform,
        challenge_hash: input.challenge_hash,
        credential_id_hint: input.credential_id_hint ?? null,
        expires_at: input.expires_at,
        metadata: input.metadata ?? {},
      })
      .select(AUTH_CHALLENGE_COLUMNS)
      .single<AuthChallengeRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async getById(challengeId: string): Promise<AuthChallengeRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("auth_challenges")
      .select(AUTH_CHALLENGE_COLUMNS)
      .eq("id", challengeId)
      .maybeSingle<AuthChallengeRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async markConsumed(challengeId: string): Promise<AuthChallengeRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("auth_challenges")
      .update({
        consumed_at: new Date().toISOString(),
      })
      .eq("id", challengeId)
      .is("consumed_at", null)
      .select(AUTH_CHALLENGE_COLUMNS)
      .maybeSingle<AuthChallengeRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },
};

export default authChallengeRepository;
