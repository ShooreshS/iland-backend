import env from "../config/env";
import { json } from "../middleware/json";
import userRepository from "../repositories/userRepository";
import type { ViewerContext } from "../types/auth";

type RequireViewerSuccess = {
  ok: true;
  viewer: ViewerContext;
};

type RequireViewerFailure = {
  ok: false;
  response: Response;
};

export type RequireViewerResult = RequireViewerSuccess | RequireViewerFailure;

const buildFailure = (
  status: number,
  error: string,
  message: string,
): RequireViewerFailure => ({
  ok: false,
  response: json({ error, message }, status),
});

// Temporary local/dev auth seam for 0.0.86 backend bootstrap.
// Replace this resolver with real request auth/session handling.
export const requireViewer = async (request: Request): Promise<RequireViewerResult> => {
  if (!env.auth.enableDevViewerAuth) {
    return buildFailure(
      503,
      "viewer_resolution_disabled",
      "Temporary dev viewer resolution is disabled. Configure real auth before using viewer-scoped endpoints.",
    );
  }

  if (!env.supabase.enabled) {
    return buildFailure(
      503,
      "database_not_configured",
      "Supabase is not configured.",
    );
  }

  const headerName = env.auth.devViewerIdHeader;
  const viewerId = request.headers.get(headerName)?.trim() || null;

  if (!viewerId) {
    return buildFailure(
      401,
      "viewer_not_resolved",
      `Missing required dev viewer header: ${headerName}`,
    );
  }

  const user = await userRepository.getById(viewerId);
  if (!user) {
    return buildFailure(
      401,
      "viewer_not_resolved",
      `No user found for viewer id from header ${headerName}.`,
    );
  }

  return {
    ok: true,
    viewer: {
      userId: user.id,
      user,
    },
  };
};

export default requireViewer;
