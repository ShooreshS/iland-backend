import { json } from "../middleware/json";
import { getHealthStatus, getSupabaseHealthStatus } from "../services/healthService";
import type { RouteDefinition } from "../types/http";

const healthRoute: RouteDefinition = {
  method: "GET",
  path: "/health",
  handler: () => json(getHealthStatus()),
};

const dbHealthRoute: RouteDefinition = {
  method: "GET",
  path: "/health/db",
  handler: async () => {
    const result = await getSupabaseHealthStatus();
    return json(result, result.ok ? 200 : 503);
  },
};

export const healthRoutes: RouteDefinition[] = [healthRoute, dbHealthRoute];
