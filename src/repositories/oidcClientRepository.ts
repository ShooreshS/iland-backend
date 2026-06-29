import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  OidcClientApplicationType,
  OidcClientRedirectUriRow,
  OidcClientRedirectUriUsage,
  OidcClientRow,
  OidcClientSecretRow,
  OidcClientType,
} from "../types/db";

const OIDC_CLIENT_COLUMNS =
  "id,client_id,client_name,client_type,application_type,status,client_uri,logo_uri,tos_uri,policy_uri,sector_identifier,allowed_scopes,default_scopes,require_pkce,pkce_required_method,id_token_signed_response_alg,access_token_ttl_seconds,authorization_code_ttl_seconds,refresh_token_ttl_days,created_at,updated_at";

const OIDC_CLIENT_SECRET_COLUMNS =
  "id,client_id,secret_hash,label,status,last_used_at,expires_at,revoked_at,revocation_reason,created_at,updated_at";

const OIDC_CLIENT_REDIRECT_URI_COLUMNS =
  "id,client_id,usage,redirect_uri,created_at";

export type UpsertOidcClientInput = {
  client_id: string;
  client_name: string;
  client_type: OidcClientType;
  application_type: OidcClientApplicationType;
  status?: "active";
  client_uri?: string | null;
  logo_uri?: string | null;
  tos_uri?: string | null;
  policy_uri?: string | null;
  sector_identifier: string;
  allowed_scopes: string[];
  default_scopes: string[];
  require_pkce?: boolean;
  pkce_required_method?: "S256";
  id_token_signed_response_alg?: "RS256";
  access_token_ttl_seconds?: number;
  authorization_code_ttl_seconds?: number;
  refresh_token_ttl_days?: number;
};

export const oidcClientRepository = {
  async upsertClient(input: UpsertOidcClientInput): Promise<OidcClientRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_clients")
      .upsert(
        {
          client_id: input.client_id,
          client_name: input.client_name,
          client_type: input.client_type,
          application_type: input.application_type,
          status: input.status ?? "active",
          client_uri: input.client_uri ?? null,
          logo_uri: input.logo_uri ?? null,
          tos_uri: input.tos_uri ?? null,
          policy_uri: input.policy_uri ?? null,
          sector_identifier: input.sector_identifier,
          allowed_scopes: input.allowed_scopes,
          default_scopes: input.default_scopes,
          require_pkce: input.require_pkce ?? true,
          pkce_required_method: input.pkce_required_method ?? "S256",
          id_token_signed_response_alg:
            input.id_token_signed_response_alg ?? "RS256",
          access_token_ttl_seconds: input.access_token_ttl_seconds ?? 900,
          authorization_code_ttl_seconds:
            input.authorization_code_ttl_seconds ?? 300,
          refresh_token_ttl_days: input.refresh_token_ttl_days ?? 30,
        },
        {
          onConflict: "client_id",
        },
      )
      .select(OIDC_CLIENT_COLUMNS)
      .single<OidcClientRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async replaceRedirectUris(
    clientDbId: string,
    input: Array<{
      usage: OidcClientRedirectUriUsage;
      redirect_uri: string;
    }>,
  ): Promise<OidcClientRedirectUriRow[]> {
    const supabase = requireSupabaseAdminClient();

    const deleteResult = await supabase
      .from("oidc_client_redirect_uris")
      .delete()
      .eq("client_id", clientDbId);

    if (deleteResult.error) {
      throw deleteResult.error;
    }

    if (input.length === 0) {
      return [];
    }

    const { data, error } = await supabase
      .from("oidc_client_redirect_uris")
      .insert(
        input.map((row) => ({
          client_id: clientDbId,
          usage: row.usage,
          redirect_uri: row.redirect_uri,
        })),
      )
      .select(OIDC_CLIENT_REDIRECT_URI_COLUMNS)
      .returns<OidcClientRedirectUriRow[]>();

    if (error) {
      throw error;
    }

    return data || [];
  },

  async listActiveSecrets(clientDbId: string): Promise<OidcClientSecretRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_client_secrets")
      .select(OIDC_CLIENT_SECRET_COLUMNS)
      .eq("client_id", clientDbId)
      .eq("status", "active")
      .order("created_at", { ascending: false })
      .returns<OidcClientSecretRow[]>();

    if (error) {
      throw error;
    }

    return data || [];
  },

  async insertSecret(input: {
    clientDbId: string;
    secretHash: string;
    label?: string | null;
  }): Promise<OidcClientSecretRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_client_secrets")
      .insert({
        client_id: input.clientDbId,
        secret_hash: input.secretHash,
        label: input.label ?? null,
        status: "active",
      })
      .select(OIDC_CLIENT_SECRET_COLUMNS)
      .single<OidcClientSecretRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async revokeActiveSecrets(
    clientDbId: string,
    revocationReason: string,
  ): Promise<OidcClientSecretRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_client_secrets")
      .update({
        status: "revoked",
        revoked_at: new Date().toISOString(),
        revocation_reason: revocationReason,
      })
      .eq("client_id", clientDbId)
      .eq("status", "active")
      .select(OIDC_CLIENT_SECRET_COLUMNS)
      .returns<OidcClientSecretRow[]>();

    if (error) {
      throw error;
    }

    return data || [];
  },
};

export default oidcClientRepository;
