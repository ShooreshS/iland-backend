import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  AppAttestationCredentialRow,
  NewAppAttestationCredentialRow,
} from "../types/db";

const APP_ATTESTATION_CREDENTIAL_COLUMNS =
  "id,user_id,auth_credential_id,platform,attestation_provider,environment,attestation_key_id,public_key_pem,app_identifier,package_name,signing_cert_digest,status,last_counter,last_asserted_at,last_assertion_nonce_hash,revoked_at,revocation_reason,created_at,updated_at";

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
        public_key_pem: input.public_key_pem ?? null,
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

  async updateByAuthCredentialId(
    authCredentialId: string,
    input: {
      attestationProvider: AppAttestationCredentialRow["attestation_provider"];
      environment: AppAttestationCredentialRow["environment"];
      attestationKeyId: string | null;
      publicKeyPem: string | null;
      appIdentifier: string | null;
      packageName: string | null;
      signingCertDigest: string | null;
      status: AppAttestationCredentialRow["status"];
      resetAssertionState?: boolean;
    },
  ): Promise<AppAttestationCredentialRow | null> {
    const supabase = requireSupabaseAdminClient();
    const nextValues: Record<string, unknown> = {
      attestation_provider: input.attestationProvider,
      environment: input.environment,
      attestation_key_id: input.attestationKeyId,
      public_key_pem: input.publicKeyPem,
      app_identifier: input.appIdentifier,
      package_name: input.packageName,
      signing_cert_digest: input.signingCertDigest,
      status: input.status,
    };

    if (input.resetAssertionState === true) {
      nextValues.last_asserted_at = null;
      nextValues.last_assertion_nonce_hash = null;
      nextValues.last_counter = null;
    }

    const { data, error } = await supabase
      .from("app_attestation_credentials")
      .update(nextValues)
      .eq("auth_credential_id", authCredentialId)
      .select(APP_ATTESTATION_CREDENTIAL_COLUMNS)
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

  async revokeActiveByUserId(
    userId: string,
    input: {
      revocationReason: string;
      excludeAuthCredentialId?: string | null;
    },
  ): Promise<AppAttestationCredentialRow[]> {
    const supabase = requireSupabaseAdminClient();

    let query = supabase
      .from("app_attestation_credentials")
      .update({
        status: "revoked",
        revoked_at: new Date().toISOString(),
        revocation_reason: input.revocationReason,
      })
      .eq("user_id", userId)
      .eq("status", "verified");

    if (input.excludeAuthCredentialId) {
      query = query.neq("auth_credential_id", input.excludeAuthCredentialId);
    }

    const { data, error } = await query
      .select(APP_ATTESTATION_CREDENTIAL_COLUMNS)
      .returns<AppAttestationCredentialRow[]>();

    if (error) {
      throw error;
    }

    return data || [];
  },
};

export default appAttestationCredentialRepository;
