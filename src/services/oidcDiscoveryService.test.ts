import { describe, expect, it } from "bun:test";

import { createOidcDiscoveryService } from "./oidcDiscoveryService";
import type { OidcSigningKeyRow } from "../types/db";

const signingKey = (
  overrides: Partial<OidcSigningKeyRow> = {},
): OidcSigningKeyRow => ({
  id: "key-row-1",
  kid: "kid-1",
  key_use: "sig",
  algorithm: "RS256",
  status: "active",
  public_jwk: {
    kty: "RSA",
    n: "modulus",
    e: "AQAB",
    d: "must-not-leak",
  },
  private_key_ref: "railway:OIDC_SIGNING_KEY_PRIVATE_PEM",
  not_before: "2026-01-01T00:00:00.000Z",
  not_after: null,
  activated_at: "2026-01-01T00:00:00.000Z",
  retired_at: null,
  revoked_at: null,
  created_at: "2026-01-01T00:00:00.000Z",
  updated_at: "2026-01-01T00:00:00.000Z",
  ...overrides,
});

describe("oidcDiscoveryService", () => {
  it("builds conservative OpenID Provider metadata from the configured issuer", () => {
    const service = createOidcDiscoveryService({
      issuer: "https://example.com/idp/",
    });

    const metadata = service.getOpenIdConfiguration();

    expect(metadata.issuer).toBe("https://example.com/idp");
    expect(metadata.authorization_endpoint).toBe(
      "https://example.com/idp/authorize",
    );
    expect(metadata.token_endpoint).toBe("https://example.com/idp/token");
    expect(metadata.userinfo_endpoint).toBe("https://example.com/idp/userinfo");
    expect(metadata.jwks_uri).toBe("https://example.com/idp/jwks");
    expect(metadata.revocation_endpoint).toBe("https://example.com/idp/revoke");
    expect(
      (metadata as Record<string, unknown>).introspection_endpoint,
    ).toBeUndefined();
    expect((metadata as Record<string, unknown>).end_session_endpoint).toBeUndefined();
    expect(metadata.response_types_supported).toEqual(["code"]);
    expect(metadata.grant_types_supported).toEqual([
      "authorization_code",
      "refresh_token",
    ]);
    expect(metadata.subject_types_supported).toEqual(["pairwise"]);
    expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
    expect(metadata.pkce_required).toBe(true);
  });

  it("returns only active public JWKS material", async () => {
    const service = createOidcDiscoveryService({
      issuer: "https://example.com/idp",
      now: () => new Date("2026-06-28T00:00:00.000Z"),
      oidcSigningKeyRepositoryLike: {
        listPublicSigningKeys: async () => [
          signingKey(),
          signingKey({
            id: "future",
            kid: "future",
            not_before: "2027-01-01T00:00:00.000Z",
          }),
          signingKey({
            id: "expired",
            kid: "expired",
            not_after: "2026-01-02T00:00:00.000Z",
          }),
          signingKey({
            id: "revoked",
            kid: "revoked",
            revoked_at: "2026-06-01T00:00:00.000Z",
          }),
          signingKey({
            id: "retired",
            kid: "retired",
            status: "retired",
          }),
        ],
      },
    });

    const jwks = await service.getJwks();

    expect(jwks.keys).toEqual([
      {
        kty: "RSA",
        n: "modulus",
        e: "AQAB",
        kid: "kid-1",
        use: "sig",
        alg: "RS256",
      },
    ]);
    expect(jwks.keys[0].d).toBeUndefined();
    expect(jwks.keys[0].private_key_ref).toBeUndefined();
  });
});
