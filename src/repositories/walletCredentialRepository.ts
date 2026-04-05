import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  NewWalletCredentialRegistrationRow,
  WalletCredentialRow,
  WalletCredentialStatus,
} from "../types/db";

const WALLET_CREDENTIAL_COLUMNS =
  "id,user_id,wallet_public_id,holder_id,wallet_public_key,issuance_status,issued_at,revoked_at,revocation_reason,credential_payload,created_at,updated_at";

export const walletCredentialRepository = {
  async getByUserId(userId: string): Promise<WalletCredentialRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("wallet_credentials")
      .select(WALLET_CREDENTIAL_COLUMNS)
      .eq("user_id", userId)
      .maybeSingle<WalletCredentialRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async upsertPublicMaterial(
    input: NewWalletCredentialRegistrationRow,
  ): Promise<WalletCredentialRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("wallet_credentials")
      .upsert(
        {
          user_id: input.user_id,
          wallet_public_id: input.wallet_public_id,
          holder_id: input.holder_id,
          wallet_public_key: input.wallet_public_key,
        },
        {
          onConflict: "user_id",
        },
      )
      .select(WALLET_CREDENTIAL_COLUMNS)
      .single<WalletCredentialRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async updateByUserId(
    userId: string,
    input: {
      issuance_status?: WalletCredentialStatus;
      issued_at?: string | null;
      revoked_at?: string | null;
      revocation_reason?: string | null;
      credential_payload?: Record<string, unknown> | null;
    },
  ): Promise<WalletCredentialRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("wallet_credentials")
      .update(input)
      .eq("user_id", userId)
      .select(WALLET_CREDENTIAL_COLUMNS)
      .maybeSingle<WalletCredentialRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },
};

export default walletCredentialRepository;
