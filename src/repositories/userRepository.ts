import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type { NewUserRow, UserRow } from "../types/db";

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

  async insert(input: NewUserRow): Promise<UserRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("users")
      .insert({
        username: input.username,
        display_name: input.display_name,
        onboarding_status: input.onboarding_status,
        verification_level: input.verification_level,
        has_wallet: input.has_wallet,
        wallet_credential_id: input.wallet_credential_id,
        selected_land_id: input.selected_land_id,
        preferred_language: input.preferred_language,
      })
      .select(USER_COLUMNS)
      .single<UserRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async updateSelectedLandId(
    userId: string,
    selectedLandId: string | null,
  ): Promise<UserRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("users")
      .update({
        selected_land_id: selectedLandId,
      })
      .eq("id", userId)
      .select(USER_COLUMNS)
      .maybeSingle<UserRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async updateWalletCredentialLink(
    userId: string,
    params: {
      hasWallet: boolean;
      walletCredentialId: string | null;
    },
  ): Promise<UserRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("users")
      .update({
        has_wallet: params.hasWallet,
        wallet_credential_id: params.walletCredentialId,
      })
      .eq("id", userId)
      .select(USER_COLUMNS)
      .maybeSingle<UserRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async updateVerificationState(
    userId: string,
    params: {
      verificationLevel?: string;
      onboardingStatus?: string;
    },
  ): Promise<UserRow | null> {
    const supabase = requireSupabaseAdminClient();

    const updatePayload: Record<string, unknown> = {};
    if (typeof params.verificationLevel === "string") {
      updatePayload.verification_level = params.verificationLevel;
    }

    if (typeof params.onboardingStatus === "string") {
      updatePayload.onboarding_status = params.onboardingStatus;
    }

    if (Object.keys(updatePayload).length === 0) {
      return this.getById(userId);
    }

    const { data, error } = await supabase
      .from("users")
      .update(updatePayload)
      .eq("id", userId)
      .select(USER_COLUMNS)
      .maybeSingle<UserRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },
};

export default userRepository;
