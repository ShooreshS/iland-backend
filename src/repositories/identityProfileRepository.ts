import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  IdentityProfileMapSeedRow,
  IdentityProfileReferenceRow,
  IdentityProfileRow,
  NewIdentityProfileRow,
} from "../types/db";

const IDENTITY_PROFILE_COLUMNS =
  "id,user_id,passport_scan_completed,passport_nfc_completed,national_id_scan_completed,face_scan_completed,face_bound_to_identity,passport_verified_at,national_id_verified_at,face_verified_at,document_country_code,issuing_country_code,home_country_code,home_area_id,home_approx_latitude,home_approx_longitude,home_location_source,home_location_updated_at,created_at,updated_at";

export const normalizeIdentityProfileRepositoryError = (
  error: unknown,
  contextMessage: string,
): Error => {
  if (error instanceof Error) {
    return error;
  }

  if (
    error &&
    typeof error === "object" &&
    "message" in error &&
    typeof (error as { message?: unknown }).message === "string"
  ) {
    return new Error(
      `${contextMessage}: ${(error as { message: string }).message}`,
    );
  }

  return new Error(`${contextMessage}: ${String(error)}`);
};

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
        passport_verified_at: input.passport_verified_at,
        national_id_verified_at: input.national_id_verified_at,
        face_verified_at: input.face_verified_at,
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

  async updateHomeLocationByUserId(
    userId: string,
    input: {
      home_country_code: string;
      home_area_id: string;
      home_approx_latitude: number;
      home_approx_longitude: number;
      home_location_source: string;
      home_location_updated_at: string;
    },
  ): Promise<IdentityProfileRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("identity_profiles")
      .update({
        home_country_code: input.home_country_code,
        home_area_id: input.home_area_id,
        home_approx_latitude: input.home_approx_latitude,
        home_approx_longitude: input.home_approx_longitude,
        home_location_source: input.home_location_source,
        home_location_updated_at: input.home_location_updated_at,
      })
      .eq("user_id", userId)
      .select(IDENTITY_PROFILE_COLUMNS)
      .maybeSingle<IdentityProfileRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async updateVerificationStateByUserId(
    userId: string,
    input: {
      passport_scan_completed?: boolean;
      passport_nfc_completed?: boolean;
      national_id_scan_completed?: boolean;
      face_scan_completed?: boolean;
      face_bound_to_identity?: boolean;
      passport_verified_at?: string | null;
      national_id_verified_at?: string | null;
      face_verified_at?: string | null;
    },
  ): Promise<IdentityProfileRow | null> {
    const supabase = requireSupabaseAdminClient();

    // Backend-authoritative method badges must come from these persisted fields,
    // not from device-local progress state. This update path is called only when
    // the backend has accepted a verification step as complete.
    const { data, error } = await supabase
      .from("identity_profiles")
      .update({
        ...(input.passport_scan_completed !== undefined
          ? { passport_scan_completed: input.passport_scan_completed }
          : {}),
        ...(input.passport_nfc_completed !== undefined
          ? { passport_nfc_completed: input.passport_nfc_completed }
          : {}),
        ...(input.national_id_scan_completed !== undefined
          ? { national_id_scan_completed: input.national_id_scan_completed }
          : {}),
        ...(input.face_scan_completed !== undefined
          ? { face_scan_completed: input.face_scan_completed }
          : {}),
        ...(input.face_bound_to_identity !== undefined
          ? { face_bound_to_identity: input.face_bound_to_identity }
          : {}),
        ...(input.passport_verified_at !== undefined
          ? { passport_verified_at: input.passport_verified_at }
          : {}),
        ...(input.national_id_verified_at !== undefined
          ? { national_id_verified_at: input.national_id_verified_at }
          : {}),
        ...(input.face_verified_at !== undefined
          ? { face_verified_at: input.face_verified_at }
          : {}),
      })
      .eq("user_id", userId)
      .select(IDENTITY_PROFILE_COLUMNS)
      .maybeSingle<IdentityProfileRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async listReferenceRows(): Promise<IdentityProfileReferenceRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("identity_profiles")
      .select(
        "home_area_id,home_country_code,document_country_code,issuing_country_code",
      );

    if (error) {
      throw error;
    }

    return (data || []) as IdentityProfileReferenceRow[];
  },

  async listMapSeedByUserIds(
    userIds: string[],
  ): Promise<IdentityProfileMapSeedRow[]> {
    if (userIds.length === 0) {
      return [];
    }

    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("identity_profiles")
      .select(
        "user_id,home_area_id,home_country_code,home_approx_latitude,home_approx_longitude",
      )
      .in("user_id", userIds);

    if (error) {
      throw normalizeIdentityProfileRepositoryError(
        error,
        "identity_profiles map seed lookup failed",
      );
    }

    return (data || []) as IdentityProfileMapSeedRow[];
  },
};

export default identityProfileRepository;
