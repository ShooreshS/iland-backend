import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type { NewUserRow, UserRow } from "../types/db";

const USER_COLUMNS =
  "id,username,display_name,public_nickname,onboarding_status,verification_level,has_wallet,wallet_credential_id,selected_land_id,preferred_language,auth_generation,account_status,created_at,updated_at";

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

  async listByIds(userIds: string[]): Promise<UserRow[]> {
    if (userIds.length === 0) {
      return [];
    }

    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("users")
      .select(USER_COLUMNS)
      .in("id", userIds);

    if (error) {
      throw error;
    }

    return data || [];
  },

  async insert(input: NewUserRow): Promise<UserRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("users")
      .insert({
        username: input.username,
        display_name: input.display_name,
        public_nickname: input.public_nickname ?? null,
        onboarding_status: input.onboarding_status,
        verification_level: input.verification_level,
        has_wallet: input.has_wallet,
        wallet_credential_id: input.wallet_credential_id,
        selected_land_id: input.selected_land_id,
        preferred_language: input.preferred_language,
        auth_generation: input.auth_generation ?? 1,
        account_status: input.account_status ?? "active",
      })
      .select(USER_COLUMNS)
      .single<UserRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async getByPublicNickname(publicNickname: string): Promise<UserRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("users")
      .select(USER_COLUMNS)
      .ilike("public_nickname", publicNickname)
      .maybeSingle<UserRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async updatePublicNickname(
    userId: string,
    publicNickname: string,
  ): Promise<UserRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("users")
      .update({
        public_nickname: publicNickname,
      })
      .eq("id", userId)
      .select(USER_COLUMNS)
      .maybeSingle<UserRow>();

    if (error) {
      throw error;
    }

    return data || null;
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

  async incrementAuthGeneration(userId: string): Promise<UserRow | null> {
    const current = await this.getById(userId);
    if (!current) {
      return null;
    }

    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("users")
      .update({
        auth_generation: current.auth_generation + 1,
      })
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
