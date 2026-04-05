import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type { IdentityProfileRow, NewIdentityProfileRow } from "../types/db";

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

  async insert(input: NewIdentityProfileRow): Promise<IdentityProfileRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("identity_profiles")
      .insert({
        user_id: input.user_id,
        passport_scan_completed: input.passport_scan_completed,
        passport_nfc_completed: input.passport_nfc_completed,
        national_id_scan_completed: input.national_id_scan_completed,
        face_scan_completed: input.face_scan_completed,
        face_bound_to_identity: input.face_bound_to_identity,
        document_country_code: input.document_country_code,
        issuing_country_code: input.issuing_country_code,
        home_country_code: input.home_country_code,
        home_area_id: input.home_area_id,
        home_approx_latitude: input.home_approx_latitude,
        home_approx_longitude: input.home_approx_longitude,
        home_location_source: input.home_location_source,
        home_location_updated_at: input.home_location_updated_at,
      })
      .select(IDENTITY_PROFILE_COLUMNS)
      .single<IdentityProfileRow>();

    if (error) {
      throw error;
    }

    return data;
  },
};

export default identityProfileRepository;
