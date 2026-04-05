import { env } from "../config/env";
import { getSupabaseAdminClient } from "../db/supabaseClient";

const startedAt = Date.now();

export const getHealthStatus = () => ({
  status: "ok" as const,
  version: "0.0.86",
  environment: env.nodeEnv,
  timestamp: new Date().toISOString(),
  uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000),
});

export const getSupabaseHealthStatus = async () => {
  const supabase = getSupabaseAdminClient();

  if (!supabase) {
    return {
      ok: false,
      status: "not_configured" as const,
      provider: "supabase" as const,
      check: "auth.admin.listUsers",
      message:
        "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are not configured.",
    };
  }

  const { error } = await supabase.auth.admin.listUsers({
    page: 1,
    perPage: 1,
  });

  if (error) {
    return {
      ok: false,
      status: "degraded" as const,
      provider: "supabase" as const,
      check: "auth.admin.listUsers",
      message: error.message,
    };
  }

  return {
    ok: true,
    status: "ok" as const,
    provider: "supabase" as const,
    check: "auth.admin.listUsers",
    message: "Supabase admin API reachable.",
  };
};
