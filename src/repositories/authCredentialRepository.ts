import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  AuthCredentialRow,
  NewAuthCredentialRow,
} from "../types/db";

const AUTH_CREDENTIAL_COLUMNS =
  "id,user_id,platform,algorithm,credential_id,public_key_pem,status,device_label,last_authenticated_at,superseded_by_auth_credential_id,revoked_at,revocation_reason,created_at,updated_at";

export const authCredentialRepository = {
  async insert(input: NewAuthCredentialRow): Promise<AuthCredentialRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("auth_credentials")
      .insert({
        user_id: input.user_id,
        platform: input.platform,
        algorithm: input.algorithm,
        credential_id: input.credential_id,
        public_key_pem: input.public_key_pem,
        device_label: input.device_label ?? null,
      })
      .select(AUTH_CREDENTIAL_COLUMNS)
      .single<AuthCredentialRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async getByCredentialId(credentialId: string): Promise<AuthCredentialRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("auth_credentials")
      .select(AUTH_CREDENTIAL_COLUMNS)
      .eq("credential_id", credentialId)
      .maybeSingle<AuthCredentialRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async listByUserId(userId: string): Promise<AuthCredentialRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("auth_credentials")
      .select(AUTH_CREDENTIAL_COLUMNS)
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .returns<AuthCredentialRow[]>();

    if (error) {
      throw error;
    }

    return data || [];
  },
};

export default authCredentialRepository;
