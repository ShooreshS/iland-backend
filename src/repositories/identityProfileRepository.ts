import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type { IdentityProfileRow } from "../types/db";

const IDENTITY_PROFILE_COLUMNS =
  "id,user_id,passport_scan_completed,passport_nfc_completed,national_id_scan_completed,face_scan_completed,face_bound_to_identity,document_country_code,issuing_country_code,home_country_code,home_area_id,home_approx_latitude,home_approx_longitude,home_location_source,home_location_updated_at,created_at,updated_at";

export const identityProfileRepository = {
  async getByUserId(userId: string): Promise<IdentityProfileRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("identity_profiles")
      .select(IDENTITY_PROFILE_COLUMNS)
      .eq("user_id", userId)
      .maybeSingle<IdentityProfileRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },
};

export default identityProfileRepository;
