import { describe, expect, it } from "bun:test";

import { createRequireViewer } from "./requireViewer";
import { hashOpaqueBearerToken } from "./tokens";
import type { AuthSessionRow, UserRow } from "../types/db";

const activeUser: UserRow = {
  id: "user-1",
  username: null,
  display_name: null,
  public_nickname: null,
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
  it("rejects protected requests without a bearer token", async () => {
    const requireViewer = createRequireViewer({
      authSessionRepositoryLike: {
        getByAccessTokenHash: async () => null,
        touchLastSeen: async () => {},
        revokeById: async () => null,
      },
      userRepositoryLike: {
        getById: async () => activeUser,
      },
    });

    const response = await requireViewer(
      new Request("http://127.0.0.1:3001/me/profile"),
    );

    expect(response.ok).toBe(false);
    if (!response.ok) {
      expect(response.response.status).toBe(401);
      expect(await response.response.json()).toMatchObject({
        error: "authorization_required",
      });
    }
  });

  it("revokes expired bearer sessions on first contact", async () => {
    const accessToken = "access-token-1";
    const revoked: Array<{ sessionId: string; reason: string }> = [];
    const revokedRefreshFamilies: Array<{
      sessionId: string;
      status: string;
      reason: string;
    }> = [];

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
      refreshTokenFamilyRepositoryLike: {
        revokeBySessionId: async (sessionId, input) => {
          revokedRefreshFamilies.push({
            sessionId,
            status: input.status,
            reason: input.revocationReason,
          });
          return null;
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
    expect(revokedRefreshFamilies).toEqual([
      {
        sessionId: "session-1",
        status: "expired",
        reason: "session_expired",
      },
    ]);
  });

  it("revokes stale bearer sessions when auth_generation no longer matches", async () => {
    const accessToken = "access-token-2";
    const revoked: Array<{ sessionId: string; reason: string }> = [];
    const revokedRefreshFamilies: Array<{
      sessionId: string;
      status: string;
      reason: string;
    }> = [];

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
      refreshTokenFamilyRepositoryLike: {
        revokeBySessionId: async (sessionId, input) => {
          revokedRefreshFamilies.push({
            sessionId,
            status: input.status,
            reason: input.revocationReason,
          });
          return null;
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
    expect(revokedRefreshFamilies).toEqual([
      {
        sessionId: "session-1",
        status: "revoked",
        reason: "auth_generation_mismatch",
      },
    ]);
  });

  it("revokes active sessions when the account is disabled", async () => {
    const accessToken = "access-token-disabled";
    const revoked: Array<{ sessionId: string; reason: string }> = [];
    const revokedRefreshFamilies: Array<{
      sessionId: string;
      status: string;
      reason: string;
    }> = [];

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
      refreshTokenFamilyRepositoryLike: {
        revokeBySessionId: async (sessionId, input) => {
          revokedRefreshFamilies.push({
            sessionId,
            status: input.status,
            reason: input.revocationReason,
          });
          return null;
        },
      },
      userRepositoryLike: {
        getById: async () => ({
          ...activeUser,
          account_status: "disabled",
        }),
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
      expect(response.response.status).toBe(403);
      expect(await response.response.json()).toMatchObject({
        error: "account_disabled",
      });
    }

    expect(revoked).toEqual([
      {
        sessionId: "session-1",
        reason: "account_disabled",
      },
    ]);
    expect(revokedRefreshFamilies).toEqual([
      {
        sessionId: "session-1",
        status: "revoked",
        reason: "account_disabled",
      },
    ]);
  });

  it("rejects revoked bearer sessions", async () => {
    const accessToken = "access-token-revoked";
    let touched = false;

    const requireViewer = createRequireViewer({
      nowFn: () => new Date("2026-06-21T12:00:00.000Z").getTime(),
      authSessionRepositoryLike: {
        getByAccessTokenHash: async (hash) => {
          if (hash !== hashOpaqueBearerToken(accessToken)) {
            return null;
          }

          return buildSession({
            status: "revoked",
            revoked_at: "2026-06-21T11:00:00.000Z",
            revocation_reason: "user_requested_session_revoke",
          });
        },
        touchLastSeen: async () => {
          touched = true;
        },
        revokeById: async () => null,
      },
      refreshTokenFamilyRepositoryLike: {
        revokeBySessionId: async () => null,
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
        error: "viewer_not_resolved",
      });
    }
    expect(touched).toBe(false);
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
