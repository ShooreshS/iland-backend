import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type { OidcSigningKeyRow } from "../types/db";

const OIDC_SIGNING_KEY_COLUMNS =
  "id,kid,key_use,algorithm,status,public_jwk,private_key_ref,not_before,not_after,activated_at,retired_at,revoked_at,created_at,updated_at";

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
};

export default oidcSigningKeyRepository;
