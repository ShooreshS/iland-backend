import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  AppAttestationCredentialRow,
  NewAppAttestationCredentialRow,
} from "../types/db";

const APP_ATTESTATION_CREDENTIAL_COLUMNS =
  "id,user_id,auth_credential_id,platform,attestation_provider,environment,attestation_key_id,app_identifier,package_name,signing_cert_digest,status,last_counter,last_asserted_at,last_assertion_nonce_hash,revoked_at,revocation_reason,created_at,updated_at";

export const appAttestationCredentialRepository = {
  async insert(
    input: NewAppAttestationCredentialRow,
  ): Promise<AppAttestationCredentialRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("app_attestation_credentials")
      .insert({
        user_id: input.user_id,
        auth_credential_id: input.auth_credential_id,
        platform: input.platform,
        attestation_provider: input.attestation_provider,
        environment: input.environment,
        attestation_key_id: input.attestation_key_id ?? null,
        app_identifier: input.app_identifier ?? null,
        package_name: input.package_name ?? null,
        signing_cert_digest: input.signing_cert_digest ?? null,
        status: input.status ?? "verified",
      })
      .select(APP_ATTESTATION_CREDENTIAL_COLUMNS)
      .single<AppAttestationCredentialRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async getByAuthCredentialId(
    authCredentialId: string,
  ): Promise<AppAttestationCredentialRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("app_attestation_credentials")
      .select(APP_ATTESTATION_CREDENTIAL_COLUMNS)
      .eq("auth_credential_id", authCredentialId)
      .maybeSingle<AppAttestationCredentialRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async recordAssertion(
    authCredentialId: string,
    input: {
      lastAssertionNonceHash: string | null;
      lastCounter?: number | null;
    },
  ): Promise<AppAttestationCredentialRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("app_attestation_credentials")
      .update({
        last_asserted_at: new Date().toISOString(),
        last_assertion_nonce_hash: input.lastAssertionNonceHash,
        last_counter: input.lastCounter ?? null,
      })
      .eq("auth_credential_id", authCredentialId)
      .select(APP_ATTESTATION_CREDENTIAL_COLUMNS)
      .maybeSingle<AppAttestationCredentialRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },
};

export default appAttestationCredentialRepository;
