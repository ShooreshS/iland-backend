import { describe, expect, it } from "bun:test";

import { createRequireViewer } from "./requireViewer";
import { hashOpaqueBearerToken } from "./tokens";
import type { AuthSessionRow, UserRow } from "../types/db";

const activeUser: UserRow = {
  id: "user-1",
  username: null,
  display_name: null,
  onboarding_status: "complete",
  verification_level: "verified",
  has_wallet: true,
  wallet_credential_id: "wallet-1",
  selected_land_id: null,
  preferred_language: "en",
  auth_generation: 2,
  account_status: "active",
  created_at: "2026-06-01T00:00:00.000Z",
  updated_at: "2026-06-01T00:00:00.000Z",
};

const buildSession = (
  overrides: Partial<AuthSessionRow> = {},
): AuthSessionRow => ({
  id: "session-1",
  user_id: activeUser.id,
  auth_credential_id: "auth-credential-1",
  status: "active",
  auth_generation: activeUser.auth_generation,
  current_access_token_hash: "access-hash-1",
  attestation_verified_at: "2026-06-01T00:00:00.000Z",
  last_seen_at: "2026-06-01T00:00:00.000Z",
  expires_at: "2026-06-30T00:00:00.000Z",
  revoked_at: null,
  revocation_reason: null,
  created_at: "2026-06-01T00:00:00.000Z",
  updated_at: "2026-06-01T00:00:00.000Z",
  ...overrides,
});

describe("requireViewer", () => {
  it("revokes expired bearer sessions on first contact", async () => {
    const accessToken = "access-token-1";
    const revoked: Array<{ sessionId: string; reason: string }> = [];

    const requireViewer = createRequireViewer({
      nowFn: () => new Date("2026-06-21T12:00:00.000Z").getTime(),
      authSessionRepositoryLike: {
        getByAccessTokenHash: async (hash) => {
          if (hash !== hashOpaqueBearerToken(accessToken)) {
            return null;
          }

          return buildSession({
            expires_at: "2026-06-21T11:59:00.000Z",
          });
        },
        touchLastSeen: async () => {},
        revokeById: async (sessionId, reason) => {
          revoked.push({ sessionId, reason });
          return buildSession({
            id: sessionId,
            status: "revoked",
            revocation_reason: reason,
          });
        },
      },
      userRepositoryLike: {
        getById: async () => activeUser,
      },
    });

    const response = await requireViewer(
      new Request("http://127.0.0.1:3001/me/profile", {
        headers: {
          authorization: `Bearer ${accessToken}`,
        },
      }),
    );

    expect(response.ok).toBe(false);
    if (!response.ok) {
      expect(response.response.status).toBe(401);
      expect(await response.response.json()).toMatchObject({
        error: "session_expired",
      });
    }

    expect(revoked).toEqual([
      {
        sessionId: "session-1",
        reason: "session_expired",
      },
    ]);
  });

  it("revokes stale bearer sessions when auth_generation no longer matches", async () => {
    const accessToken = "access-token-2";
    const revoked: Array<{ sessionId: string; reason: string }> = [];

    const requireViewer = createRequireViewer({
      nowFn: () => new Date("2026-06-21T12:00:00.000Z").getTime(),
      authSessionRepositoryLike: {
        getByAccessTokenHash: async (hash) => {
          if (hash !== hashOpaqueBearerToken(accessToken)) {
            return null;
          }

          return buildSession({
            auth_generation: 1,
            expires_at: "2026-06-21T13:00:00.000Z",
          });
        },
        touchLastSeen: async () => {},
        revokeById: async (sessionId, reason) => {
          revoked.push({ sessionId, reason });
          return buildSession({
            id: sessionId,
            status: "revoked",
            revocation_reason: reason,
          });
        },
      },
      userRepositoryLike: {
        getById: async () => activeUser,
      },
    });

    const response = await requireViewer(
      new Request("http://127.0.0.1:3001/me/profile", {
        headers: {
          authorization: `Bearer ${accessToken}`,
        },
      }),
    );

    expect(response.ok).toBe(false);
    if (!response.ok) {
      expect(response.response.status).toBe(401);
      expect(await response.response.json()).toMatchObject({
        error: "session_stale",
      });
    }

    expect(revoked).toEqual([
      {
        sessionId: "session-1",
        reason: "auth_generation_mismatch",
      },
    ]);
  });

  it("touches last_seen for valid bearer sessions", async () => {
    const accessToken = "access-token-3";
    const touched: string[] = [];

    const requireViewer = createRequireViewer({
      nowFn: () => new Date("2026-06-21T12:00:00.000Z").getTime(),
      authSessionRepositoryLike: {
        getByAccessTokenHash: async (hash) => {
          if (hash !== hashOpaqueBearerToken(accessToken)) {
            return null;
          }

          return buildSession({
            expires_at: "2026-06-21T13:00:00.000Z",
          });
        },
        touchLastSeen: async (sessionId) => {
          touched.push(sessionId);
        },
        revokeById: async () => null,
      },
      userRepositoryLike: {
        getById: async () => activeUser,
      },
    });

    const result = await requireViewer(
      new Request("http://127.0.0.1:3001/me/profile", {
        headers: {
          authorization: `Bearer ${accessToken}`,
        },
      }),
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.viewer.userId).toBe(activeUser.id);
    }

    expect(touched).toEqual(["session-1"]);
  });
});
