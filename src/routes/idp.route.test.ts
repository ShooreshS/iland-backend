import { describe, expect, it } from "bun:test";

import { createIdpRoutes, type IdpRouteDependencies } from "./idp";
import type { RouteDefinition } from "../types/http";

const service = {
  getOpenIdConfiguration: () => ({
    issuer: "https://example.com/idp",
    authorization_endpoint: "https://example.com/idp/authorize",
    token_endpoint: "https://example.com/idp/token",
    userinfo_endpoint: "https://example.com/idp/userinfo",
    jwks_uri: "https://example.com/idp/jwks",
    revocation_endpoint: "https://example.com/idp/revoke",
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["pairwise"],
    id_token_signing_alg_values_supported: ["RS256"],
    token_endpoint_auth_methods_supported: [
      "client_secret_basic",
      "client_secret_post",
      "none",
    ],
    scopes_supported: ["openid", "profile", "offline_access"],
    claims_supported: [
      "sub",
      "iss",
      "aud",
      "exp",
      "iat",
      "auth_time",
      "nonce",
      "amr",
      "acr",
    ],
    code_challenge_methods_supported: ["S256"],
    claims_parameter_supported: false,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
    require_request_uri_registration: false,
    pkce_required: true,
  }),
  getJwks: async () => ({
    keys: [
      {
        kty: "RSA",
        kid: "kid-1",
        use: "sig",
        alg: "RS256",
        n: "modulus",
        e: "AQAB",
      },
    ],
  }),
};

const routes = createIdpRoutes({
  oidcDiscoveryServiceLike: service,
});

const findRoute = (method: string, path: string): RouteDefinition => {
  const route = routes.find(
    (candidate) => candidate.method === method && candidate.path === path,
  );
  if (!route) {
    throw new Error(`Route not found: ${method} ${path}`);
  }
  return route;
};

const invokeRoute = (route: RouteDefinition) => {
  const request = new Request(`http://127.0.0.1:3001${route.path}`, {
    method: route.method,
  });

  return route.handler({
    request,
    url: new URL(request.url),
    params: {},
  });
};

describe("idp public metadata routes", () => {
  it("serves path-based OpenID Provider metadata under /idp", async () => {
    const response = await invokeRoute(
      findRoute("GET", "/idp/.well-known/openid-configuration"),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("public, max-age=300");

    const body = (await response.json()) as Record<string, unknown>;
    expect(body.issuer).toBe("https://example.com/idp");
    expect(body.authorization_endpoint).toBe(
      "https://example.com/idp/authorize",
    );
    expect(body.jwks_uri).toBe("https://example.com/idp/jwks");
    expect(body.userinfo_endpoint).toBe("https://example.com/idp/userinfo");
    expect(body.revocation_endpoint).toBe("https://example.com/idp/revoke");
    expect(body.introspection_endpoint).toBeUndefined();
    expect(body.end_session_endpoint).toBeUndefined();
    expect(body.response_types_supported).toEqual(["code"]);
    expect(body.code_challenge_methods_supported).toEqual(["S256"]);
  });

  it("serves JWKS from active signing-key metadata", async () => {
    const response = await invokeRoute(findRoute("GET", "/idp/jwks"));

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("public, max-age=300");

    const body = (await response.json()) as {
      keys?: Array<Record<string, unknown>>;
    };
    expect(body.keys).toEqual([
      {
        kty: "RSA",
        kid: "kid-1",
        use: "sig",
        alg: "RS256",
        n: "modulus",
        e: "AQAB",
      },
    ]);
  });
});

describe("idp authorize QR approval routes", () => {
  const authorizationRequest = {
    client: {
      id: "client-db-id",
      client_id: "codeiland-web",
      client_name: "Code iLand",
    },
    redirectUri: "https://codeiland-back.example/auth/callback",
    responseType: "code",
    scopes: ["openid", "profile"],
    state: "state-1",
    nonce: "nonce-1",
    codeChallenge: "challenge",
    codeChallengeMethod: "S256",
  };

  const createRoutes = (
    overrides: Record<string, unknown> = {},
    requireViewerFn: IdpRouteDependencies["requireViewerFn"] = async () =>
      ({ ok: false }) as any,
  ) =>
    createIdpRoutes({
      oidcDiscoveryServiceLike: service,
      oidcProviderServiceLike: {
        validateAuthorizationRequest: async () => ({
          success: true,
          request: authorizationRequest,
        }),
        approveAuthorizationRequest: async () => ({
          redirectTo: "https://codeiland-back.example/auth/callback?code=direct",
        }),
        createAuthorizationQrTransaction: () => ({
          requestId: "request-1",
          pollSecret: "poll-secret-1",
          expiresAt: "2026-06-30T12:00:00.000Z",
          qrPayload: {
            type: "civicos.oidc.authorize",
            version: 1,
            requestId: "request-1",
            secret: "qr-secret-1",
            approveUrl: "https://example.com/idp/authorize/approve",
            audience: "codeiland-web",
            clientName: "Code iLand",
            scopes: ["openid", "profile"],
            expiresAt: "2026-06-30T12:00:00.000Z",
          },
        }),
        getAuthorizationQrTransactionStatus: () => ({
          status: "pending",
          expiresAt: "2026-06-30T12:00:00.000Z",
        }),
        previewAuthorizationQrTransaction: async () => ({
          success: true,
          body: {
            requestId: "request-1",
            client: {
              clientId: "codeiland-web",
              clientName: "Code iLand",
              sectorIdentifier: "codeiland.com",
            },
            scopes: ["openid", "profile"],
            claimOptions: [],
            expiresAt: "2026-06-30T12:00:00.000Z",
          },
        }),
        approveAuthorizationQrTransaction: async () => ({ success: true }),
        denyAuthorizationQrTransaction: () => ({ success: true }),
        exchangeAuthorizationCode: async () => ({
          success: false,
          status: 400,
          error: "invalid_request",
          error_description: "not used",
        }),
        ...overrides,
      } as any,
      requireViewerFn,
      authSessionRepositoryLike: {
        getByAccessTokenHash: async () => null,
      },
    });

  const findLocalRoute = (
    localRoutes: RouteDefinition[],
    method: string,
    path: string,
  ): RouteDefinition => {
    const route = localRoutes.find(
      (candidate) => candidate.method === method && candidate.path === path,
    );
    if (!route) {
      throw new Error(`Route not found: ${method} ${path}`);
    }
    return route;
  };

  it("renders a hosted QR approval page when the browser has no CivicOS bearer", async () => {
    const localRoutes = createRoutes();
    const request = new Request(
      "https://example.com/idp/authorize?client_id=codeiland-web",
    );

    const response = await findLocalRoute(
      localRoutes,
      "GET",
      "/idp/authorize",
    ).handler({
      request,
      url: new URL(request.url),
      params: {},
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    const html = await response.text();
    expect(html).toContain("Approve with CivicOS");
    expect(html).toContain("Code iLand");
    expect(html).toContain("/idp/authorize/status");
  });

  it("allows the CivicOS app to approve a pending authorize QR with a bearer session", async () => {
    let approvedInput: Record<string, unknown> | null = null;
    const localRoutes = createIdpRoutes({
      oidcDiscoveryServiceLike: service,
      oidcProviderServiceLike: {
        validateAuthorizationRequest: async () => ({
          success: true,
          request: authorizationRequest,
        }),
        approveAuthorizationRequest: async () => ({
          redirectTo: "https://codeiland-back.example/auth/callback?code=direct",
        }),
        createAuthorizationQrTransaction: () => ({
          requestId: "request-1",
          pollSecret: "poll-secret-1",
          expiresAt: "2026-06-30T12:00:00.000Z",
          qrPayload: {},
        }),
        getAuthorizationQrTransactionStatus: () => ({
          status: "pending",
          expiresAt: "2026-06-30T12:00:00.000Z",
        }),
        previewAuthorizationQrTransaction: async () => ({
          success: true,
          body: {
            requestId: "request-1",
            client: {
              clientId: "codeiland-web",
              clientName: "Code iLand",
              sectorIdentifier: "codeiland.com",
            },
            scopes: ["openid", "profile"],
            claimOptions: [
              {
                key: "nickname",
                label: "Public nickname",
                value: "public-name",
                defaultSelected: true,
              },
            ],
            expiresAt: "2026-06-30T12:00:00.000Z",
          },
        }),
        approveAuthorizationQrTransaction: async (input: Record<string, unknown>) => {
          approvedInput = input;
          return { success: true };
        },
        denyAuthorizationQrTransaction: () => ({ success: true }),
        exchangeAuthorizationCode: async () => ({
          success: false,
          status: 400,
          error: "invalid_request",
          error_description: "not used",
        }),
      } as any,
      requireViewerFn: async () =>
        ({
          ok: true,
          viewer: {
            userId: "user-1",
            user: {
              id: "user-1",
              auth_generation: 1,
              account_status: "active",
            },
          },
        }) as any,
      authSessionRepositoryLike: {
        getByAccessTokenHash: async () =>
          ({
            id: "session-1",
            user_id: "user-1",
          }) as any,
      },
    });
    const request = new Request("https://example.com/idp/authorize/approve", {
      method: "POST",
      headers: {
        authorization: "Bearer access-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        requestId: "request-1",
        secret: "secret-1",
        approvedClaims: {
          nickname: true,
          passport_verified: false,
        },
      }),
    });

    const response = await findLocalRoute(
      localRoutes,
      "POST",
      "/idp/authorize/approve",
    ).handler({
      request,
      url: new URL(request.url),
      params: {},
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });
    expect(approvedInput).toMatchObject({
      requestId: "request-1",
      secret: "secret-1",
      authSessionId: "session-1",
      approvedClaims: {
        nickname: true,
        passport_verified: false,
      },
    });
  });

  it("lets the CivicOS app preview a pending authorize QR before approval", async () => {
    const localRoutes = createRoutes({}, async () =>
      ({
        ok: true,
        viewer: {
          userId: "user-1",
          user: {
            id: "user-1",
            auth_generation: 1,
            account_status: "active",
          },
        },
      }) as any,
    );
    const request = new Request("https://example.com/idp/authorize/preview", {
      method: "POST",
      headers: {
        authorization: "Bearer access-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        requestId: "request-1",
        secret: "secret-1",
      }),
    });

    const response = await findLocalRoute(
      localRoutes,
      "POST",
      "/idp/authorize/preview",
    ).handler({
      request,
      url: new URL(request.url),
      params: {},
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      ok: true,
      requestId: "request-1",
      client: {
        clientId: "codeiland-web",
        clientName: "Code iLand",
        sectorIdentifier: "codeiland.com",
      },
      scopes: ["openid", "profile"],
    });
  });

  it("lets the CivicOS app deny a pending authorize QR", async () => {
    const seen: { denyInput: Record<string, unknown> | null } = {
      denyInput: null,
    };
    const localRoutes = createRoutes(
      {
        denyAuthorizationQrTransaction: (input: Record<string, unknown>) => {
          seen.denyInput = input;
          return { success: true };
        },
      },
      async () =>
        ({
          ok: true,
          viewer: {
            userId: "user-1",
            user: {
              id: "user-1",
              auth_generation: 1,
              account_status: "active",
            },
          },
        }) as any,
    );
    const request = new Request("https://example.com/idp/authorize/deny", {
      method: "POST",
      headers: {
        authorization: "Bearer access-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        requestId: "request-1",
        secret: "secret-1",
      }),
    });

    const response = await findLocalRoute(
      localRoutes,
      "POST",
      "/idp/authorize/deny",
    ).handler({
      request,
      url: new URL(request.url),
      params: {},
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });
    expect(seen.denyInput).toEqual({
      requestId: "request-1",
      secret: "secret-1",
    });
  });
});

describe("idp UserInfo and revocation routes", () => {
  const createRoutes = (overrides: Record<string, unknown> = {}) =>
    createIdpRoutes({
      oidcDiscoveryServiceLike: service,
      oidcProviderServiceLike: {
        validateAuthorizationRequest: async () => ({
          success: false,
          error: "invalid_request",
          message: "not used",
        }),
        approveAuthorizationRequest: async () => ({
          redirectTo: "https://example.com/callback?code=unused",
        }),
        createAuthorizationQrTransaction: () => ({
          requestId: "request-1",
          pollSecret: "poll-secret-1",
          expiresAt: "2026-06-30T12:00:00.000Z",
          qrPayload: {},
        }),
        getAuthorizationQrTransactionStatus: () => ({
          status: "pending",
          expiresAt: "2026-06-30T12:00:00.000Z",
        }),
        approveAuthorizationQrTransaction: async () => ({ success: true }),
        exchangeAuthorizationCode: async () => ({
          success: false,
          status: 400,
          error: "invalid_request",
          error_description: "not used",
        }),
        getUserInfo: async () => ({
          success: true,
          body: {
            sub: "pairwise-subject",
            passport_verified: true,
          },
        }),
        revokeToken: async () => ({ success: true }),
        ...overrides,
      } as any,
    });

  const findLocalRoute = (
    localRoutes: RouteDefinition[],
    method: string,
    path: string,
  ): RouteDefinition => {
    const route = localRoutes.find(
      (candidate) => candidate.method === method && candidate.path === path,
    );
    if (!route) {
      throw new Error(`Route not found: ${method} ${path}`);
    }
    return route;
  };

  it("serves UserInfo claims for a valid bearer access token", async () => {
    const seen: { accessToken?: string } = {};
    const localRoutes = createRoutes({
      getUserInfo: async (input: { accessToken: string }) => {
        seen.accessToken = input.accessToken;
        return {
          success: true,
          body: {
            sub: "pairwise-subject",
            nickname: "public-name",
            passport_verified: true,
          },
        };
      },
    });
    const request = new Request("https://example.com/idp/userinfo", {
      headers: {
        authorization: "Bearer access-token-1",
      },
    });

    const response = await findLocalRoute(
      localRoutes,
      "GET",
      "/idp/userinfo",
    ).handler({
      request,
      url: new URL(request.url),
      params: {},
    });

    expect(response.status).toBe(200);
    expect(seen.accessToken).toBe("access-token-1");
    expect(await response.json()).toEqual({
      sub: "pairwise-subject",
      nickname: "public-name",
      passport_verified: true,
    });
  });

  it("rejects UserInfo without a bearer access token", async () => {
    const localRoutes = createRoutes();
    const request = new Request("https://example.com/idp/userinfo");

    const response = await findLocalRoute(
      localRoutes,
      "GET",
      "/idp/userinfo",
    ).handler({
      request,
      url: new URL(request.url),
      params: {},
    });

    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain("invalid_token");
  });

  it("revokes a token through the revocation endpoint", async () => {
    const seen: {
      form?: URLSearchParams;
      authorizationHeader?: string | null;
    } = {};
    const localRoutes = createRoutes({
      revokeToken: async (input: {
        form: URLSearchParams;
        authorizationHeader: string | null;
      }) => {
        seen.form = input.form;
        seen.authorizationHeader = input.authorizationHeader;
        return { success: true };
      },
    });
    const request = new Request("https://example.com/idp/revoke", {
      method: "POST",
      headers: {
        authorization: "Basic abc123",
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        token: "token-to-revoke",
        token_type_hint: "refresh_token",
      }),
    });

    const response = await findLocalRoute(
      localRoutes,
      "POST",
      "/idp/revoke",
    ).handler({
      request,
      url: new URL(request.url),
      params: {},
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });
    expect(seen.form?.get("token")).toBe("token-to-revoke");
    expect(seen.form?.get("token_type_hint")).toBe("refresh_token");
    expect(seen.authorizationHeader).toBe("Basic abc123");
  });
});
