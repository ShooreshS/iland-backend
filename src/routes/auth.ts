import { z } from "zod";
import requireViewer from "../auth/requireViewer";
import { json } from "../middleware/json";
import authService from "../services/authService";
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
    credentialId: z.string().trim().min(1),
    publicKeyPem: z.string().trim().min(1),
    signature: z.string().trim().min(1),
    appAttestation: z.record(z.unknown()),
    canonicalIdentityKey: z.string().trim().min(1),
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

    const result = await authService.completeRegistration();

    return json(result, result.success ? 201 : 501, {
      "cache-control": "no-store",
    });
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

    const result = await authService.completeLogin();

    return json(result, result.success ? 200 : 501, {
      "cache-control": "no-store",
    });
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

    const result = await authService.refreshSession();

    return json(result, result.success ? 200 : 501, {
      "cache-control": "no-store",
    });
  },
};

const logoutRoute: RouteDefinition = {
  method: "POST",
  path: "/auth/logout",
  handler: async () =>
    json(await authService.logoutSession(), 501, {
      "cache-control": "no-store",
    }),
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

export const authRoutes: RouteDefinition[] = [
  registerChallengeRoute,
  registerCompleteRoute,
  loginChallengeRoute,
  loginCompleteRoute,
  refreshRoute,
  logoutRoute,
  listSessionsRoute,
  revokeSessionRoute,
];

export default authRoutes;
