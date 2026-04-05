import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type { NewVerifiedIdentityRow, VerifiedIdentityRow } from "../types/db";

const VERIFIED_IDENTITY_COLUMNS =
  "id,user_id,canonical_identity_key,normalization_version,verification_method,verified_at,created_at,updated_at";

export const verifiedIdentityRepository = {
  async getByUserId(userId: string): Promise<VerifiedIdentityRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("verified_identities")
      .select(VERIFIED_IDENTITY_COLUMNS)
      .eq("user_id", userId)
      .maybeSingle<VerifiedIdentityRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getByCanonicalIdentityKey(
    canonicalIdentityKey: string,
  ): Promise<VerifiedIdentityRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("verified_identities")
      .select(VERIFIED_IDENTITY_COLUMNS)
      .eq("canonical_identity_key", canonicalIdentityKey)
      .maybeSingle<VerifiedIdentityRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insert(input: NewVerifiedIdentityRow): Promise<VerifiedIdentityRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("verified_identities")
      .insert({
        user_id: input.user_id,
        canonical_identity_key: input.canonical_identity_key,
        normalization_version: input.normalization_version,
        verification_method: input.verification_method,
        verified_at: input.verified_at,
      })
      .select(VERIFIED_IDENTITY_COLUMNS)
      .single<VerifiedIdentityRow>();

    if (error) {
      throw error;
    }

    return data;
  },
};

export default verifiedIdentityRepository;
