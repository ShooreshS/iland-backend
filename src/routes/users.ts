import env from "../config/env";
import { json } from "../middleware/json";
import userBootstrapService from "../services/userBootstrapService";
import type { RouteDefinition } from "../types/http";

const bootstrapUserRoute: RouteDefinition = {
  method: "POST",
  path: "/users/bootstrap",
  handler: async () => {
    if (!env.supabase.enabled) {
      return json(
        {
          error: "database_not_configured",
          message: "Supabase is not configured.",
        },
        503,
      );
    }

    const result = await userBootstrapService.bootstrapProvisionalUser();
    console.info("[viewer/bootstrap] /users/bootstrap issued user", {
      viewerUserId: result.user.id,
    });
    return json(result, 201);
  },
};

export const userRoutes: RouteDefinition[] = [bootstrapUserRoute];

export default userRoutes;
