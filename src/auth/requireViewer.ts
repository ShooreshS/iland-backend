import env from "../config/env";
import { json } from "../middleware/json";
import userRepository from "../repositories/userRepository";
import type { ViewerContext } from "../types/auth";
import authPolicy from "./policy";

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
//
// Enforced policy intention:
// - production protected routes must eventually resolve the viewer from a
//   server-side session that originated from both a valid device auth
//   credential and a verified app attestation;
// - caller-supplied identity headers are a migration seam only, not a valid
//   long-term trust boundary.
export const requireViewer = async (request: Request): Promise<RequireViewerResult> => {
  const authorizationHeader = request.headers.get("authorization")?.trim() || null;
  if (authorizationHeader) {
    // Future path: bearer-token session validation belongs here. Until that is
    // implemented, reject explicitly instead of silently falling back to the
    // legacy bootstrap header. That makes the migration boundary visible and
    // avoids ambiguous mixed-auth behavior.
    return buildFailure(
      503,
      "session_auth_not_implemented",
      `Bearer-token viewer resolution is not implemented yet. Planned issuer: ${authPolicy.issuer}`,
    );
  }

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
  console.info("[viewer/auth] resolving viewer header", {
    headerName,
    viewerUserId: viewerId,
    method: request.method,
    path: new URL(request.url).pathname,
  });

  if (!viewerId) {
    return buildFailure(
      401,
      "viewer_not_resolved",
      `Missing required dev viewer header: ${headerName}`,
    );
  }

  const user = await userRepository.getById(viewerId);
  if (!user) {
    console.warn("[viewer/auth] viewer id not found", {
      viewerUserId: viewerId,
      method: request.method,
      path: new URL(request.url).pathname,
    });
    return buildFailure(
      401,
      "viewer_not_resolved",
      `No user found for viewer id from header ${headerName}.`,
    );
  }

  console.info("[viewer/auth] viewer resolved", {
    viewerUserId: user.id,
    method: request.method,
    path: new URL(request.url).pathname,
  });

  return {
    ok: true,
    viewer: {
      userId: user.id,
      user,
    },
  };
};

export default requireViewer;
