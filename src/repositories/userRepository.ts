import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type { UserRow } from "../types/db";

const USER_COLUMNS =
  "id,username,display_name,onboarding_status,verification_level,has_wallet,wallet_credential_id,selected_land_id,preferred_language,created_at,updated_at";

export const userRepository = {
  async getById(userId: string): Promise<UserRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("users")
      .select(USER_COLUMNS)
      .eq("id", userId)
      .maybeSingle<UserRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },
};

export default userRepository;
