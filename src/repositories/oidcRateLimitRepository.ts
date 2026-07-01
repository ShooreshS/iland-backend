import { requireSupabaseAdminClient } from "../db/supabaseClient";

export type OidcRateLimitDecision = {
  allowed: boolean;
  requestCount: number;
  resetAt: string;
};

export const oidcRateLimitRepository = {
  async consume(input: {
    bucketKey: string;
    limit: number;
    windowSeconds: number;
  }): Promise<OidcRateLimitDecision> {
    const supabase = requireSupabaseAdminClient();

    // The database function performs the increment under row lock so rate
    // limiting remains consistent when Railway runs more than one backend
    // replica. The bucket key is already hashed by the caller; raw IPs and
    // bearer/QR secrets must never be stored in this table.
    const { data, error } = await supabase.rpc("consume_oidc_rate_limit", {
      p_bucket_key: input.bucketKey,
      p_limit: input.limit,
      p_window_seconds: input.windowSeconds,
      p_now: new Date().toISOString(),
    });

    if (error) {
      throw error;
    }

    const row = Array.isArray(data) ? data[0] : data;
    if (!row) {
      throw new Error("OIDC rate-limit function returned no decision.");
    }

    return {
      allowed: Boolean(row.allowed),
      requestCount: Number(row.request_count ?? row.requestCount ?? 0),
      resetAt: String(row.reset_at ?? row.resetAt),
    };
  },
};

export default oidcRateLimitRepository;
