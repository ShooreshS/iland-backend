import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type { OidcSigningKeyRow } from "../types/db";

const OIDC_SIGNING_KEY_COLUMNS =
  "id,kid,key_use,algorithm,status,public_jwk,private_key_ref,not_before,not_after,activated_at,retired_at,revoked_at,created_at,updated_at";

export type NewOidcSigningKeyRow = {
  kid: string;
  key_use: "sig";
  algorithm: "RS256";
  status: "active" | "retiring";
  public_jwk: Record<string, unknown>;
  private_key_ref: string;
  not_before: string;
  not_after?: string | null;
  activated_at?: string | null;
};

export const oidcSigningKeyRepository = {
  async listPublicSigningKeys(): Promise<OidcSigningKeyRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_signing_keys")
      .select(OIDC_SIGNING_KEY_COLUMNS)
      .eq("key_use", "sig")
      .eq("algorithm", "RS256")
      .in("status", ["active", "retiring"])
      .order("created_at", { ascending: false })
      .returns<OidcSigningKeyRow[]>();

    if (error) {
      throw error;
    }

    return data || [];
  },

  async listAllSigningKeys(): Promise<OidcSigningKeyRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_signing_keys")
      .select(OIDC_SIGNING_KEY_COLUMNS)
      .order("created_at", { ascending: false })
      .returns<OidcSigningKeyRow[]>();

    if (error) {
      throw error;
    }

    return data || [];
  },

  async insert(input: NewOidcSigningKeyRow): Promise<OidcSigningKeyRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_signing_keys")
      .insert({
        kid: input.kid,
        key_use: input.key_use,
        algorithm: input.algorithm,
        status: input.status,
        public_jwk: input.public_jwk,
        private_key_ref: input.private_key_ref,
        not_before: input.not_before,
        not_after: input.not_after ?? null,
        activated_at: input.activated_at ?? null,
      })
      .select(OIDC_SIGNING_KEY_COLUMNS)
      .single<OidcSigningKeyRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async retireActiveExcept(kid: string): Promise<OidcSigningKeyRow[]> {
    const supabase = requireSupabaseAdminClient();
    const retiredAt = new Date().toISOString();

    const { data, error } = await supabase
      .from("oidc_signing_keys")
      .update({
        status: "retiring",
        retired_at: retiredAt,
      })
      .eq("key_use", "sig")
      .eq("algorithm", "RS256")
      .eq("status", "active")
      .neq("kid", kid)
      .select(OIDC_SIGNING_KEY_COLUMNS)
      .returns<OidcSigningKeyRow[]>();

    if (error) {
      throw error;
    }

    return data || [];
  },

  async retireByKid(kid: string): Promise<OidcSigningKeyRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_signing_keys")
      .update({
        status: "retiring",
        retired_at: new Date().toISOString(),
      })
      .eq("kid", kid)
      .select(OIDC_SIGNING_KEY_COLUMNS)
      .maybeSingle<OidcSigningKeyRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async revokeByKid(kid: string): Promise<OidcSigningKeyRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_signing_keys")
      .update({
        status: "revoked",
        revoked_at: new Date().toISOString(),
      })
      .eq("kid", kid)
      .select(OIDC_SIGNING_KEY_COLUMNS)
      .maybeSingle<OidcSigningKeyRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },
};

export default oidcSigningKeyRepository;
