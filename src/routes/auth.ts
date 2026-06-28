import { z } from "zod";
import { hashOpaqueBearerToken } from "../auth/tokens";
import defaultRequireViewer from "../auth/requireViewer";
import { json } from "../middleware/json";
import defaultAuthSessionRepository from "../repositories/authSessionRepository";
import defaultAuthService from "../services/authService";
import type { RouteDefinition } from "../types/http";

const challengeRequestSchema = z
  .object({
    platform: z.enum(["ios", "android"]),
    credentialIdHint: z.string().trim().min(1).nullable().optional(),
  })
  .strict();

const registrationCompleteSchema = z
  .object({
    challengeId: z.string().trim().min(1),
    challenge: z.string().trim().min(1),
    platform: z.enum(["ios", "android"]),
    credentialId: z.string().trim().min(1),
    publicKeyPem: z.string().trim().min(1),
    signature: z.string().trim().min(1),
    appAttestation: z.record(z.unknown()),
    nidnh: z.string().trim().min(1),
    normalizationVersion: z.number().int(),
    verificationMethod: z.enum(["passport_nfc"]).default("passport_nfc"),
  })
  .strict();

const loginCompleteSchema = z
  .object({
    challengeId: z.string().trim().min(1),
    challenge: z.string().trim().min(1),
    credentialId: z.string().trim().min(1),
    signature: z.string().trim().min(1),
    appAssertion: z.record(z.unknown()),
  })
  .strict();

const refreshSchema = z
  .object({
    refreshToken: z.string().trim().min(1),
  })
  .strict();

const parseJsonBody = async (request: Request) => {
  try {
    return await request.json();
  } catch {
    return null;
  }
};

const invalidJsonResponse = (message: string) =>
  json(
    {
      error: "invalid_request",
      message,
    },
    400,
    {
      "cache-control": "no-store",
    },
  );

const logAuthFlowFailure = (
  route: string,
  result: { success: false; errorCode?: string; message?: string },
) => {
  // Intention:
  // auth enrollment/login failures are expected during rollout, so log only the
  // stable diagnostic fields needed to identify policy/config mismatches without
  // dumping request payloads or sensitive material.
  console.warn("[auth]", {
    route,
    errorCode: result.errorCode || null,
    message: result.message || null,
  });
};

type AuthServiceLike = Pick<
  typeof defaultAuthService,
  | "issueChallenge"
  | "completeRegistration"
  | "completeLogin"
  | "refreshSession"
  | "logoutSession"
  | "listSessionsForUser"
  | "revokeSessionForUser"
>;

type RequireViewerFn = typeof defaultRequireViewer;

type AuthSessionRepositoryLike = Pick<
  typeof defaultAuthSessionRepository,
  "getByAccessTokenHash"
>;

export type AuthRouteDependencies = {
  authServiceLike?: AuthServiceLike;
  requireViewerFn?: RequireViewerFn;
  authSessionRepositoryLike?: AuthSessionRepositoryLike;
};

export const createAuthRoutes = (
  dependencies: AuthRouteDependencies = {},
): RouteDefinition[] => {
const authService = dependencies.authServiceLike ?? defaultAuthService;
const requireViewer = dependencies.requireViewerFn ?? defaultRequireViewer;
const authSessionRepository =
  dependencies.authSessionRepositoryLike ?? defaultAuthSessionRepository;

const registerChallengeRoute: RouteDefinition = {
  method: "POST",
  path: "/auth/register/challenge",
  handler: async ({ request }) => {
    const requestBody = await parseJsonBody(request);
    if (!requestBody) {
      return invalidJsonResponse("Request body must be valid JSON.");
    }

    const parsed = challengeRequestSchema.safeParse(requestBody);
    if (!parsed.success) {
      return invalidJsonResponse("Registration challenge request body is invalid.");
    }

    const result = await authService.issueChallenge({
      purpose: "register",
      platform: parsed.data.platform,
      credentialIdHint: parsed.data.credentialIdHint ?? null,
    });

    return json(result, 201, {
      "cache-control": "no-store",
    });
  },
};

const registerCompleteRoute: RouteDefinition = {
  method: "POST",
  path: "/auth/register/complete",
  handler: async ({ request }) => {
    const requestBody = await parseJsonBody(request);
    if (!requestBody) {
      return invalidJsonResponse("Request body must be valid JSON.");
    }

    const parsed = registrationCompleteSchema.safeParse(requestBody);
    if (!parsed.success) {
      return invalidJsonResponse("Registration completion request body is invalid.");
    }

    const result = await authService.completeRegistration(parsed.data);
    if (!result.success) {
      logAuthFlowFailure("/auth/register/complete", result);
    }

    return json(
      result,
      result.success
        ? 201
        : result.errorCode === "INVALID_CHALLENGE"
          ? 400
          : result.errorCode === "INVALID_PUBLIC_KEY"
            ? 400
            : result.errorCode === "INVALID_SIGNATURE_ENCODING"
              ? 400
              : result.errorCode === "INVALID_SIGNATURE"
                ? 401
                : result.errorCode === "ATTESTATION_INVALID"
                  ? 400
                  : result.errorCode === "CREDENTIAL_KEY_MISMATCH"
                    ? 409
          : result.errorCode === "ACCOUNT_DISABLED"
            ? 403
            : result.errorCode === "CREDENTIAL_ALREADY_BOUND"
              ? 409
              : 501,
      {
        "cache-control": "no-store",
      },
    );
  },
};

const loginChallengeRoute: RouteDefinition = {
  method: "POST",
  path: "/auth/login/challenge",
  handler: async ({ request }) => {
    const requestBody = await parseJsonBody(request);
    if (!requestBody) {
      return invalidJsonResponse("Request body must be valid JSON.");
    }

    const parsed = challengeRequestSchema.safeParse(requestBody);
    if (!parsed.success) {
      return invalidJsonResponse("Login challenge request body is invalid.");
    }

    const result = await authService.issueChallenge({
      purpose: "login",
      platform: parsed.data.platform,
      credentialIdHint: parsed.data.credentialIdHint ?? null,
    });

    return json(result, 201, {
      "cache-control": "no-store",
    });
  },
};

const loginCompleteRoute: RouteDefinition = {
  method: "POST",
  path: "/auth/login/complete",
  handler: async ({ request }) => {
    const requestBody = await parseJsonBody(request);
    if (!requestBody) {
      return invalidJsonResponse("Request body must be valid JSON.");
    }

    const parsed = loginCompleteSchema.safeParse(requestBody);
    if (!parsed.success) {
      return invalidJsonResponse("Login completion request body is invalid.");
    }

    const result = await authService.completeLogin(parsed.data);
    if (!result.success) {
      logAuthFlowFailure("/auth/login/complete", result);
    }

    return json(
      result,
      result.success
        ? 200
        : result.errorCode === "INVALID_CHALLENGE"
          ? 400
          : result.errorCode === "INVALID_SIGNATURE_ENCODING"
            ? 400
            : result.errorCode === "INVALID_SIGNATURE"
              ? 401
              : result.errorCode === "ATTESTATION_INVALID"
                ? 400
          : result.errorCode === "CREDENTIAL_NOT_FOUND"
            ? 404
            : result.errorCode === "USER_NOT_FOUND"
              ? 404
              : result.errorCode === "ACCOUNT_DISABLED"
                ? 403
                : result.errorCode === "ATTESTATION_REQUIRED"
                  ? 409
                  : result.errorCode === "SESSION_LIMIT_REACHED"
                    ? 409
                    : 501,
      {
        "cache-control": "no-store",
      },
    );
  },
};

const refreshRoute: RouteDefinition = {
  method: "POST",
  path: "/auth/refresh",
  handler: async ({ request }) => {
    const requestBody = await parseJsonBody(request);
    if (!requestBody) {
      return invalidJsonResponse("Request body must be valid JSON.");
    }

    const parsed = refreshSchema.safeParse(requestBody);
    if (!parsed.success) {
      return invalidJsonResponse("Refresh request body is invalid.");
    }

    const result = await authService.refreshSession(parsed.data);

    return json(
      result,
      result.success
        ? 200
        : result.errorCode === "REFRESH_TOKEN_NOT_FOUND"
          ? 404
          : result.errorCode === "REFRESH_TOKEN_NOT_ACTIVE"
            ? 409
            : result.errorCode === "REFRESH_TOKEN_EXPIRED"
              ? 401
              : result.errorCode === "ACCOUNT_DISABLED"
                ? 403
                : result.errorCode === "SESSION_SUPERSEDED"
                  ? 409
                  : result.errorCode === "SESSION_NOT_FOUND"
                    ? 404
                    : result.errorCode === "SESSION_NOT_ACTIVE"
                      ? 409
                      : result.errorCode === "USER_NOT_FOUND"
                        ? 404
                        : 501,
      {
        "cache-control": "no-store",
      },
    );
  },
};

const logoutRoute: RouteDefinition = {
  method: "POST",
  path: "/auth/logout",
  handler: async ({ request }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const authorizationHeader = request.headers.get("authorization")?.trim() || "";
    const tokenMatch = /^Bearer\s+(.+)$/i.exec(authorizationHeader);
    if (!tokenMatch?.[1]) {
      return json(
        {
          success: false,
          errorCode: "SESSION_CONTEXT_REQUIRED",
          message:
            "Logout requires an active bearer token.",
        },
        400,
        {
          "cache-control": "no-store",
        },
      );
    }

    const session = await authSessionRepository.getByAccessTokenHash(
      hashOpaqueBearerToken(tokenMatch[1]),
    );
    if (!session || session.user_id !== viewerResult.viewer.userId) {
      return json(
        {
          success: false,
          errorCode: "SESSION_CONTEXT_REQUIRED",
          message: "Logout session could not be resolved from the bearer token.",
        },
        400,
        {
          "cache-control": "no-store",
        },
      );
    }

    return json(
      await authService.logoutSession(viewerResult.viewer.userId, session.id),
      200,
      {
        "cache-control": "no-store",
      },
    );
  },
};

const listSessionsRoute: RouteDefinition = {
  method: "GET",
  path: "/auth/sessions",
  handler: async ({ request }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const result = await authService.listSessionsForUser(viewerResult.viewer.userId);

    return json(result, 200, {
      "cache-control": "no-store",
    });
  },
};

const revokeSessionRoute: RouteDefinition = {
  method: "POST",
  path: "/auth/sessions/:id/revoke",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const result = await authService.revokeSessionForUser(
      viewerResult.viewer.userId,
      params.id,
    );

    if (!result.success) {
      return json(result, 404, {
        "cache-control": "no-store",
      });
    }

    return json(result, 200, {
      "cache-control": "no-store",
    });
  },
};

return [
  registerChallengeRoute,
  registerCompleteRoute,
  loginChallengeRoute,
  loginCompleteRoute,
  refreshRoute,
  logoutRoute,
  listSessionsRoute,
  revokeSessionRoute,
];
};

export const authRoutes: RouteDefinition[] = createAuthRoutes();

export default authRoutes;
