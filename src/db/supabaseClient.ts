import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { env } from "../config/env";

let cachedClient: SupabaseClient | null = null;

if (env.supabase.enabled && env.supabase.url && env.supabase.serviceRoleKey) {
  cachedClient = createClient(env.supabase.url, env.supabase.serviceRoleKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
    global: {
      headers: {
        "X-Client-Info": "iland-backend/0.0.86-skeleton",
      },
    },
  });
}

export const getSupabaseAdminClient = (): SupabaseClient | null => cachedClient;

export const requireSupabaseAdminClient = (): SupabaseClient => {
  if (!cachedClient) {
    throw new Error("Supabase admin client is not configured.");
  }

  return cachedClient;
};
