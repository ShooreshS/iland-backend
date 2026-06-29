import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "bun:test";

import { createOidcClientRegistrationService } from "./oidcClientRegistrationService";
import type {
  OidcClientRedirectUriRow,
  OidcClientRow,
  OidcClientSecretRow,
} from "../types/db";

let tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(
    tempDirs.map((dir) =>
      rm(dir, {
        recursive: true,
        force: true,
      }),
    ),
  );
  tempDirs = [];
});

const createTempDir = async () => {
  const dir = await mkdtemp(join(tmpdir(), "oidc-client-test-"));
  tempDirs.push(dir);
  return dir;
};

const clientRow = (overrides: Partial<OidcClientRow> = {}): OidcClientRow => ({
  id: "client-db-id",
  client_id: "codeiland-web",
  client_name: "Code iLand",
  client_type: "confidential",
  application_type: "web",
  status: "active",
  client_uri: null,
  logo_uri: null,
  tos_uri: null,
  policy_uri: null,
  sector_identifier: "codeiland.com",
  allowed_scopes: ["openid", "profile", "offline_access"],
  default_scopes: ["openid", "profile"],
  require_pkce: true,
  pkce_required_method: "S256",
  id_token_signed_response_alg: "RS256",
  access_token_ttl_seconds: 900,
  authorization_code_ttl_seconds: 300,
  refresh_token_ttl_days: 30,
  created_at: "2026-06-29T00:00:00.000Z",
  updated_at: "2026-06-29T00:00:00.000Z",
  ...overrides,
});

const secretRow = (overrides: Partial<OidcClientSecretRow> = {}):
  OidcClientSecretRow => ({
  id: "secret-id",
  client_id: "client-db-id",
  secret_hash: "hash",
  label: "label",
  status: "active",
  last_used_at: null,
  expires_at: null,
  revoked_at: null,
  revocation_reason: null,
  created_at: "2026-06-29T00:00:00.000Z",
  updated_at: "2026-06-29T00:00:00.000Z",
  ...overrides,
});

describe("oidcClientRegistrationService", () => {
  it("registers a client config and writes a one-time secret file", async () => {
    const tempDir = await createTempDir();
    const configPath = join(tempDir, "codeiland-web.json");
    const secretsPath = join(tempDir, "secrets", "codeiland-web.json");
    await writeFile(
      configPath,
      JSON.stringify({
        client_id: "codeiland-web",
        client_name: "Code iLand",
        client_type: "confidential",
        application_type: "web",
        sector_identifier: "codeiland.com",
        allowed_scopes: ["openid", "profile", "offline_access"],
        default_scopes: ["openid", "profile"],
        redirect_uri: "https://codeiland-back.example/auth/callback",
        post_logout_redirect_uri: "https://www.codeiland.com/",
      }),
    );

    const calls: Array<{ method: string; input: unknown }> = [];
    const service = createOidcClientRegistrationService({
      now: () => new Date("2026-06-29T00:00:00.000Z"),
      randomBytesFn: () => Buffer.alloc(32, 1),
      oidcClientRepositoryLike: {
        upsertClient: async (input) => {
          calls.push({ method: "upsertClient", input });
          return clientRow();
        },
        replaceRedirectUris: async (clientDbId, input) => {
          calls.push({ method: "replaceRedirectUris", input: { clientDbId, input } });
          return input.map((row, index): OidcClientRedirectUriRow => ({
            id: `redirect-${index}`,
            client_id: clientDbId,
            usage: row.usage,
            redirect_uri: row.redirect_uri,
            created_at: "2026-06-29T00:00:00.000Z",
          }));
        },
        listActiveSecrets: async () => [],
        insertSecret: async (input) => {
          calls.push({ method: "insertSecret", input });
          return secretRow({ secret_hash: input.secretHash });
        },
        revokeActiveSecrets: async () => [],
      },
    });

    const result = await service.register({
      configFilePath: configPath,
      secretsDirectoryPath: secretsPath,
    });

    expect(result.secretGenerated).toBe(true);
    expect(result.secretFilePath).toBe(secretsPath);
    expect(calls[0]).toMatchObject({
      method: "upsertClient",
      input: {
        client_id: "codeiland-web",
        client_type: "confidential",
        allowed_scopes: ["openid", "profile", "offline_access"],
        default_scopes: ["openid", "profile"],
        require_pkce: true,
      },
    });
    expect(calls[1]).toMatchObject({
      method: "replaceRedirectUris",
      input: {
        clientDbId: "client-db-id",
        input: [
          {
            usage: "redirect",
            redirect_uri: "https://codeiland-back.example/auth/callback",
          },
          {
            usage: "post_logout",
            redirect_uri: "https://www.codeiland.com/",
          },
        ],
      },
    });
    expect(calls[2].method).toBe("insertSecret");

    const secretFile = JSON.parse(await readFile(secretsPath, "utf8")) as {
      client_id: string;
      client_secret: string;
      set_in_codeiland_railway_as: string;
    };
    expect(secretFile.client_id).toBe("codeiland-web");
    expect(secretFile.client_secret).toMatch(/^ciland_/);
    expect(secretFile.set_in_codeiland_railway_as).toBe("OIDC_CLIENT_SECRET");
  });

  it("keeps an existing active secret unless rotation is requested", async () => {
    const tempDir = await createTempDir();
    const configPath = join(tempDir, "codeiland-web.json");
    await writeFile(
      configPath,
      JSON.stringify({
        client_id: "codeiland-web",
        client_name: "Code iLand",
        client_type: "confidential",
        application_type: "web",
        sector_identifier: "codeiland.com",
        allowed_scopes: ["openid", "profile", "offline_access"],
        default_scopes: ["openid", "profile"],
        redirect_uri: "https://codeiland-back.example/auth/callback",
      }),
    );

    let insertedSecret = false;
    const service = createOidcClientRegistrationService({
      oidcClientRepositoryLike: {
        upsertClient: async () => clientRow(),
        replaceRedirectUris: async () => [],
        listActiveSecrets: async () => [secretRow()],
        insertSecret: async () => {
          insertedSecret = true;
          return secretRow();
        },
        revokeActiveSecrets: async () => [],
      },
    });

    const result = await service.register({ configFilePath: configPath });

    expect(result.secretGenerated).toBe(false);
    expect(result.secretFilePath).toBeNull();
    expect(insertedSecret).toBe(false);
  });
});
