import { beforeEach, describe, expect, it } from "bun:test";

import { createAuthRoutes } from "./auth";
import type { RouteDefinition } from "../types/http";

const viewerUser = {
  id: "user-1",
  username: null,
  display_name: null,
  onboarding_status: "identity_pending",
  verification_level: "nid_verified",
  has_wallet: false,
  wallet_credential_id: null,
  selected_land_id: null,
  preferred_language: null,
  auth_generation: 1,
  account_status: "active",
  created_at: "2026-06-01T00:00:00.000Z",
  updated_at: "2026-06-01T00:00:00.000Z",
};

const state = {
  serviceCalls: [] as Array<{ method: string; input: unknown[] }>,
  refreshResult: {
    success: true,
    accessToken: "access-token",
    refreshToken: "refresh-token",
    accessTokenExpiresAt: "2999-01-01T00:00:00.000Z",
    refreshTokenExpiresAt: "2999-02-01T00:00:00.000Z",
  } as Record<string, unknown>,
  logoutResult: {
    success: true,
    session: {
      id: "session-1",
      status: "revoked",
    },
  } as Record<string, unknown>,
  listSessionsResult: {
    success: true,
    sessions: [
      {
        id: "session-1",
        status: "active",
        currentAccessTokenHash: undefined,
      },
    ],
    policy: {
      maxActiveSessionsPerUser: 3,
    },
  } as Record<string, unknown>,
  revokeResult: {
    success: true,
    session: {
      id: "session-2",
      status: "revoked",
    },
  } as Record<string, unknown>,
  deleteAccountResult: {
    success: true,
    deleted: {
      userFound: true,
      userAnonymized: true,
    },
  } as Record<string, unknown>,
};

const resetState = () => {
  state.serviceCalls = [];
  state.refreshResult = {
    success: true,
    accessToken: "access-token",
    refreshToken: "refresh-token",
    accessTokenExpiresAt: "2999-01-01T00:00:00.000Z",
    refreshTokenExpiresAt: "2999-02-01T00:00:00.000Z",
  };
  state.logoutResult = {
    success: true,
    session: {
      id: "session-1",
      status: "revoked",
    },
  };
  state.listSessionsResult = {
    success: true,
    sessions: [
      {
        id: "session-1",
        status: "active",
      },
    ],
    policy: {
      maxActiveSessionsPerUser: 3,
    },
  };
  state.revokeResult = {
    success: true,
    session: {
      id: "session-2",
      status: "revoked",
    },
  };
  state.deleteAccountResult = {
    success: true,
    deleted: {
      userFound: true,
      userAnonymized: true,
    },
  };
};

const requireViewer = async () => ({
  ok: true as const,
  viewer: {
    userId: viewerUser.id,
    user: viewerUser,
  },
});

const authSessionRepository = {
  getByAccessTokenHash: async () => ({
    id: "session-1",
    user_id: viewerUser.id,
  }),
};

const authService = {
  refreshSession: async (...input: unknown[]) => {
    state.serviceCalls.push({ method: "refreshSession", input });
    return state.refreshResult;
  },
  logoutSession: async (...input: unknown[]) => {
    state.serviceCalls.push({ method: "logoutSession", input });
    return state.logoutResult;
  },
  listSessionsForUser: async (...input: unknown[]) => {
    state.serviceCalls.push({ method: "listSessionsForUser", input });
    return state.listSessionsResult;
  },
  revokeSessionForUser: async (...input: unknown[]) => {
    state.serviceCalls.push({ method: "revokeSessionForUser", input });
    return state.revokeResult;
  },
  deleteAccount: async (...input: unknown[]) => {
    state.serviceCalls.push({ method: "deleteAccount", input });
    return state.deleteAccountResult;
  },
  issueChallenge: async () => ({ success: true as const }),
  completeRegistration: async (...input: unknown[]) => {
    state.serviceCalls.push({ method: "completeRegistration", input });
    return { success: true as const };
  },
  completeLogin: async () => ({ success: true as const }),
};

const authRoutes = createAuthRoutes({
  authServiceLike: authService as never,
  requireViewerFn: requireViewer as never,
  authSessionRepositoryLike: authSessionRepository as never,
});

const findRoute = (method: string, path: string): RouteDefinition => {
  const route = authRoutes.find(
    (candidate) => candidate.method === method && candidate.path === path,
  );
  if (!route) {
    throw new Error(`Route not found: ${method} ${path}`);
  }
  return route;
};

const invokeRoute = (
  route: RouteDefinition,
  input: {
    body?: unknown;
    authorization?: string;
    params?: Record<string, string>;
  } = {},
) => {
  const request = new Request(`http://127.0.0.1:3001${route.path}`, {
    method: route.method,
    headers: {
      ...(input.body !== undefined ? { "content-type": "application/json" } : null),
      ...(input.authorization ? { authorization: input.authorization } : null),
    },
    ...(input.body !== undefined ? { body: JSON.stringify(input.body) } : null),
  });

  return route.handler({
    request,
    url: new URL(request.url),
    params: input.params ?? {},
  });
};

const verificationEvidence = {
  liveness: {
    passed: true,
  },
  likeness: {
    passed: true,
    similarity: 0.91,
    threshold: 0.03,
  },
};

const buildRegistrationCompleteBody = (overrides: Record<string, unknown> = {}) => ({
  challengeId: "challenge-1",
  challenge: "challenge",
  platform: "ios",
  credentialId: "device-credential-1",
  publicKeyPem: "public-key",
  signature: "signature",
  appAttestation: {},
  nidnh: "a".repeat(128),
  normalizationVersion: 1,
  verificationMethod: "passport_nfc",
  verificationEvidence,
  ...overrides,
});

describe("auth lifecycle routes", () => {
  beforeEach(() => {
    resetState();
  });

  it("POST /auth/register/complete forwards verification evidence", async () => {
    const response = await invokeRoute(findRoute("POST", "/auth/register/complete"), {
      body: buildRegistrationCompleteBody(),
    });

    expect(response.status).toBe(201);
    expect(state.serviceCalls).toContainEqual({
      method: "completeRegistration",
      input: [buildRegistrationCompleteBody()],
    });
  });

  it("DELETE /auth/account forwards the confirmation phrase for the viewer", async () => {
    const route = findRoute("DELETE", "/auth/account");

    const response = await invokeRoute(route, {
      body: {
        confirmationPhrase: "I want to delete my account forever",
      },
    });

    expect(response.status).toBe(200);
    expect(state.serviceCalls).toContainEqual({
      method: "deleteAccount",
      input: [
        viewerUser.id,
        {
          confirmationPhrase: "I want to delete my account forever",
        },
      ],
    });
  });

  it("DELETE /auth/account rejects an invalid request body", async () => {
    const route = findRoute("DELETE", "/auth/account");

    const response = await invokeRoute(route, {
      body: {
        confirmationPhrase: 123,
      },
    });

    expect(response.status).toBe(400);
    expect(state.serviceCalls.some((call) => call.method === "deleteAccount")).toBe(false);
  });

  it("POST /auth/register/complete rejects missing verification evidence", async () => {
    const bodyWithoutEvidence: Record<string, unknown> = buildRegistrationCompleteBody();
    delete bodyWithoutEvidence.verificationEvidence;

    const response = await invokeRoute(findRoute("POST", "/auth/register/complete"), {
      body: bodyWithoutEvidence,
    });

    expect(response.status).toBe(400);
    expect(
      state.serviceCalls.some((call) => call.method === "completeRegistration"),
    ).toBe(false);
  });

  it("POST /auth/refresh forwards the refresh token and returns no-store", async () => {
    const response = await invokeRoute(findRoute("POST", "/auth/refresh"), {
      body: {
        refreshToken: "refresh-token",
      },
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(state.serviceCalls).toContainEqual({
      method: "refreshSession",
      input: [
        {
          refreshToken: "refresh-token",
        },
      ],
    });
  });

  it("POST /auth/logout revokes the bearer session resolved from authorization", async () => {
    const response = await invokeRoute(findRoute("POST", "/auth/logout"), {
      authorization: "Bearer access-token",
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      success: true,
      session: {
        id: "session-1",
        status: "revoked",
      },
    });
    expect(state.serviceCalls).toContainEqual({
      method: "logoutSession",
      input: [viewerUser.id, "session-1"],
    });
  });

  it("GET /auth/sessions returns sanitized session-management state", async () => {
    const response = await invokeRoute(findRoute("GET", "/auth/sessions"), {
      authorization: "Bearer access-token",
    });

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({
      success: true,
      policy: {
        maxActiveSessionsPerUser: 3,
      },
    });
    expect(JSON.stringify(body)).not.toContain("current_access_token_hash");
    expect(JSON.stringify(body)).not.toContain("currentAccessTokenHash");
    expect(state.serviceCalls).toContainEqual({
      method: "listSessionsForUser",
      input: [viewerUser.id],
    });
  });

  it("POST /auth/sessions/:id/revoke revokes an owned session", async () => {
    const response = await invokeRoute(
      findRoute("POST", "/auth/sessions/:id/revoke"),
      {
        authorization: "Bearer access-token",
        params: {
          id: "session-2",
        },
      },
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      success: true,
      session: {
        id: "session-2",
        status: "revoked",
      },
    });
    expect(state.serviceCalls).toContainEqual({
      method: "revokeSessionForUser",
      input: [viewerUser.id, "session-2"],
    });
  });

});
