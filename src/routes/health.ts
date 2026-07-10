import { json } from "../middleware/json";
import {
  getHealthStatus,
  getSupabaseHealthStatus,
  getZkpHealthStatus,
} from "../services/healthService";
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

const zkpHealthRoute: RouteDefinition = {
  method: "GET",
  path: "/health/zkp",
  handler: () => {
    const result = getZkpHealthStatus();
    return json(result, result.ok ? 200 : 503);
  },
};

export const healthRoutes: RouteDefinition[] = [
  healthRoute,
  dbHealthRoute,
  zkpHealthRoute,
];
