import { describe, expect, it } from "bun:test";

import { createIdpRoutes } from "./idp";
import type { RouteDefinition } from "../types/http";

const service = {
  getOpenIdConfiguration: () => ({
    issuer: "https://example.com/idp",
    authorization_endpoint: "https://example.com/idp/authorize",
    token_endpoint: "https://example.com/idp/token",
    userinfo_endpoint: "https://example.com/idp/userinfo",
    jwks_uri: "https://example.com/idp/jwks",
    revocation_endpoint: "https://example.com/idp/revoke",
    introspection_endpoint: "https://example.com/idp/introspect",
    end_session_endpoint: "https://example.com/idp/logout",
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
