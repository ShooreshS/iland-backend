import { describe, expect, it } from "bun:test";

import { createOidcSigningKeyService } from "./oidcSigningKeyService";
import type { OidcSigningKeyRow } from "../types/db";

const rowFromInsert = (input: {
  kid: string;
  public_jwk: Record<string, unknown>;
  private_key_ref: string;
  not_before: string;
}): OidcSigningKeyRow => ({
  id: "row-1",
  kid: input.kid,
  key_use: "sig",
  algorithm: "RS256",
  status: "active",
  public_jwk: input.public_jwk,
  private_key_ref: input.private_key_ref,
  not_before: input.not_before,
  not_after: null,
  activated_at: input.not_before,
  retired_at: null,
  revoked_at: null,
  created_at: input.not_before,
  updated_at: input.not_before,
});

describe("oidcSigningKeyService", () => {
  it("generates an RS256 key pair with public JWKS metadata and external private ref", () => {
    const service = createOidcSigningKeyService({
      now: () => new Date("2026-06-28T10:00:00.000Z"),
      randomBytesFn: () => Buffer.from("abcdef"),
    });

    const generated = service.generate();

    expect(generated.kid).toBe("rs256-20260628t100000z-YWJjZGVm");
    expect(generated.privateKeyRef).toBe(
      "OIDC_RS256_PRIVATE_KEY_RS256_20260628T100000Z_YWJJZGVM",
    );
    expect(generated.privateKeyPem).toContain("BEGIN PRIVATE KEY");
    expect(generated.publicJwk).toMatchObject({
      kty: "RSA",
      kid: generated.kid,
      use: "sig",
      alg: "RS256",
      e: "AQAB",
    });
    expect(generated.publicJwk.d).toBeUndefined();
    expect(typeof generated.publicJwk.n).toBe("string");
  });

  it("seeds a generated key and can retire existing active keys", async () => {
    const insertedRows: Array<Record<string, unknown>> = [];
    const retiredForKids: string[] = [];
    const service = createOidcSigningKeyService({
      now: () => new Date("2026-06-28T10:00:00.000Z"),
      randomBytesFn: () => Buffer.from("abcdef"),
      oidcSigningKeyRepositoryLike: {
        insert: async (input) => {
          insertedRows.push(input);
          return rowFromInsert(input);
        },
        retireActiveExcept: async (kid) => {
          retiredForKids.push(kid);
          return [
            rowFromInsert({
              kid: "old-key",
              public_jwk: { kid: "old-key" },
              private_key_ref: "OIDC_RS256_PRIVATE_KEY_OLD",
              not_before: "2026-01-01T00:00:00.000Z",
            }),
          ];
        },
        listAllSigningKeys: async () => [],
        retireByKid: async () => null,
        revokeByKid: async () => null,
      },
    });

    const result = await service.seed({ retireExistingActiveKeys: true });

    expect(insertedRows).toHaveLength(1);
    expect(insertedRows[0]).toMatchObject({
      kid: result.generated.kid,
      key_use: "sig",
      algorithm: "RS256",
      status: "active",
      private_key_ref: result.generated.privateKeyRef,
      activated_at: "2026-06-28T10:00:00.000Z",
    });
    expect(retiredForKids).toEqual([result.generated.kid]);
    expect(result.retiredExistingKeys[0].kid).toBe("old-key");
  });
});
