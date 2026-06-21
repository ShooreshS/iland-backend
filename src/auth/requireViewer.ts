import env from "../config/env";
import { hashOpaqueBearerToken } from "./tokens";
import { json } from "../middleware/json";
import authSessionRepository from "../repositories/authSessionRepository";
import userRepository from "../repositories/userRepository";
import type { ViewerContext } from "../types/auth";
import authPolicy from "./policy";
import type { AuthSessionRow } from "../types/db";

type RequireViewerSuccess = {
  ok: true;
  viewer: ViewerContext;
};

type RequireViewerFailure = {
  ok: false;
  response: Response;
};

export type RequireViewerResult = RequireViewerSuccess | RequireViewerFailure;

type RequireViewerDependencies = {
  authSessionRepositoryLike?: {
    getByAccessTokenHash(accessTokenHash: string): Promise<AuthSessionRow | null>;
    touchLastSeen(sessionId: string): Promise<void>;
    revokeById(sessionId: string, revocationReason: string): Promise<AuthSessionRow | null>;
  };
  userRepositoryLike?: {
    getById(userId: string): Promise<ViewerContext["user"] | null>;
  };
  nowFn?: () => number;
};

const buildFailure = (
  status: number,
  error: string,
  message: string,
): RequireViewerFailure => ({
  ok: false,
  response: json({ error, message }, status),
});

const buildRequireViewer = (
  dependencies: RequireViewerDependencies = {},
) => {
  const authSessionRepo = dependencies.authSessionRepositoryLike || authSessionRepository;
  const userRepo = dependencies.userRepositoryLike || userRepository;
  const now = dependencies.nowFn || (() => Date.now());

  // Temporary local/dev auth seam for 0.0.86 backend bootstrap.
  // Replace this resolver with real request auth/session handling.
  //
  // Enforced policy intention:
  // - production protected routes must eventually resolve the viewer from a
  //   server-side session that originated from both a valid device auth
  //   credential and a verified app attestation;
  // - caller-supplied identity headers are a migration seam only, not a valid
  //   long-term trust boundary.
  return async (request: Request): Promise<RequireViewerResult> => {
    const authorizationHeader = request.headers.get("authorization")?.trim() || null;
    if (authorizationHeader) {
      const tokenMatch = /^Bearer\s+(.+)$/i.exec(authorizationHeader);
      if (!tokenMatch?.[1]) {
        return buildFailure(
          401,
          "invalid_authorization_header",
          "Authorization header must use Bearer token format.",
        );
      }

      const session = await authSessionRepo.getByAccessTokenHash(
        hashOpaqueBearerToken(tokenMatch[1]),
      );
      if (!session || session.status !== "active") {
        return buildFailure(
          401,
          "viewer_not_resolved",
          `No active session found for bearer token under issuer ${authPolicy.issuer}.`,
        );
      }

      if (new Date(session.expires_at).getTime() <= now()) {
        // Enforced policy:
        // if an expired bearer token still reaches a protected route, revoke the
        // server-side session immediately so later inspection and cleanup see the
        // row as dead rather than leaving it "active but expired".
        await authSessionRepo.revokeById(session.id, "session_expired");
        return buildFailure(
          401,
          "session_expired",
          "Bearer session has expired.",
        );
      }

      const user = await userRepo.getById(session.user_id);
      if (!user) {
        return buildFailure(
          401,
          "viewer_not_resolved",
          "Session user could not be resolved.",
        );
      }

      if (user.account_status !== "active") {
        return buildFailure(
          403,
          "account_disabled",
          "The current account is disabled or banned.",
        );
      }

      if (user.auth_generation !== session.auth_generation) {
        // Enforced policy:
        // any auth-generation mismatch means recovery or a security action has
        // superseded this bearer session. Revoke it on first contact so the
        // stale row no longer appears active in session-management flows.
        await authSessionRepo.revokeById(session.id, "auth_generation_mismatch");
        return buildFailure(
          401,
          "session_stale",
          "Bearer session is no longer current for this user.",
        );
      }

      // Enforced policy:
      // protected production routes are expected to run on sessions that were
      // created from a verified attested app context. Session creation captures
      // that gate once so per-request viewer resolution can remain lightweight.
      await authSessionRepo.touchLastSeen(session.id);

      return {
        ok: true,
        viewer: {
          userId: user.id,
          user,
        },
      };
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

    const user = await userRepo.getById(viewerId);
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
};

export const createRequireViewer = buildRequireViewer;

export const requireViewer = buildRequireViewer();

export default requireViewer;
