import { beforeEach, describe, expect, it, mock } from "bun:test";

import { hashOpaqueBearerToken } from "../auth/tokens";
import type {
  AuthCredentialRow,
  AuthSessionRow,
  RefreshTokenFamilyRow,
  UserRow,
} from "../types/db";

const nowIso = "2026-06-28T10:00:00.000Z";

const activeUser: UserRow = {
  id: "user-1",
  username: null,
  display_name: null,
  public_nickname: null,
  onboarding_status: "identity_pending",
  verification_level: "nid_verified",
  has_wallet: false,
  wallet_credential_id: null,
  selected_land_id: null,
  preferred_language: null,
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
  current_access_token_hash: "access-token-hash",
  attestation_verified_at: nowIso,
  last_seen_at: nowIso,
  expires_at: "2999-06-28T10:05:00.000Z",
  revoked_at: null,
  revocation_reason: null,
  created_at: "2026-06-28T09:55:00.000Z",
  updated_at: "2026-06-28T09:55:00.000Z",
  ...overrides,
});

const buildRefreshFamily = (
  overrides: Partial<RefreshTokenFamilyRow> = {},
): RefreshTokenFamilyRow => ({
  id: "refresh-family-1",
  session_id: "session-1",
  user_id: activeUser.id,
  status: "active",
  current_token_hash: hashOpaqueBearerToken("refresh-token-current"),
  previous_token_hash: null,
  rotation_counter: 0,
  last_rotated_at: nowIso,
  last_used_at: null,
  expires_at: "2026-07-28T10:00:00.000Z",
  revoked_at: null,
  revocation_reason: null,
  created_at: nowIso,
  updated_at: nowIso,
  ...overrides,
});

const buildCredential = (
  overrides: Partial<AuthCredentialRow> = {},
): AuthCredentialRow => ({
  id: "auth-credential-1",
  user_id: activeUser.id,
  platform: "ios",
  algorithm: "p256",
  credential_id: "device-credential-1",
  public_key_pem: "pem",
  status: "active",
  device_label: null,
  last_authenticated_at: null,
  superseded_by_auth_credential_id: null,
  revoked_at: null,
  revocation_reason: null,
  created_at: nowIso,
  updated_at: nowIso,
  ...overrides,
});

const state = {
  sessions: new Map<string, AuthSessionRow>(),
  refreshFamilies: new Map<string, RefreshTokenFamilyRow>(),
  users: new Map<string, UserRow>(),
  auditEvents: [] as Array<Record<string, unknown>>,
  consumedChallenges: [] as string[],
  revokedSessions: [] as Array<{ sessionId: string; reason: string }>,
  revokedRefreshFamilies: [] as Array<{
    familyId?: string;
    sessionId?: string;
    status: string;
    reason: string;
  }>,
  recoveryCounts: {
    credentials: 0,
    attestations: 0,
  },
  accountDeletionCalls: [] as string[],
};

const resetState = () => {
  state.sessions = new Map([["session-1", buildSession()]]);
  state.refreshFamilies = new Map([["refresh-family-1", buildRefreshFamily()]]);
  state.users = new Map([[activeUser.id, activeUser]]);
  state.auditEvents = [];
  state.consumedChallenges = [];
  state.revokedSessions = [];
  state.revokedRefreshFamilies = [];
  state.recoveryCounts = {
    credentials: 0,
    attestations: 0,
  };
  state.accountDeletionCalls = [];
};

mock.module("../repositories/authChallengeRepository", () => {
  const repository = {
    insert: async () => ({
      id: "challenge-1",
    }),
    getById: async (challengeId: string) => ({
      id: challengeId,
      purpose: "register",
      platform: "ios",
      challenge_hash: hashOpaqueBearerToken("challenge"),
      credential_id_hint: null,
      expires_at: "2999-06-28T10:00:00.000Z",
      consumed_at: null,
      metadata: {},
      created_at: nowIso,
    }),
    markConsumed: async (challengeId: string) => {
      state.consumedChallenges.push(challengeId);
      return null;
    },
  };

  return {
    authChallengeRepository: repository,
    default: repository,
  };
});

mock.module("../auth/credentialSignature", () => ({
  default: () => ({
    success: true,
    signatureEncoding: "base64-der",
  }),
}));

mock.module("../auth/appAttestation", () => ({
  default: {
    verifyRegistrationAttestation: async () => ({
      success: true,
      provider: "ios_app_attest",
      environment: "development",
      attestationKeyId: "app-attest-key-1",
      attestationPublicKeyPem: "app-attest-public-key-1",
      appIdentifier: "TEAM.com.shooresh.iland",
      packageName: null,
      signingCertDigest: null,
      transitionalCryptoBypassUsed: false,
    }),
    verifyLoginAssertion: async () => ({
      success: true,
      provider: "ios_app_attest",
      environment: "development",
      attestationKeyId: "app-attest-key-1",
      attestationPublicKeyPem: "app-attest-public-key-1",
      appIdentifier: "TEAM.com.shooresh.iland",
      packageName: null,
      signingCertDigest: null,
      lastAssertionNonceHash: "assertion-nonce-hash",
      lastCounter: 1,
      transitionalCryptoBypassUsed: false,
    }),
  },
}));

mock.module("./authAccountBindingService", () => ({
  default: {
    resolveOrCreateUserByVerifiedIdentity: async () => activeUser,
  },
}));

mock.module("../repositories/authSessionRepository", () => {
  const repository = {
    getById: async (sessionId: string) => state.sessions.get(sessionId) ?? null,
    listByUserId: async (userId: string) =>
      Array.from(state.sessions.values()).filter((session) => session.user_id === userId),
    revokeById: async (sessionId: string, reason: string) => {
      const session = state.sessions.get(sessionId);
      if (!session) {
        return null;
      }

      const revoked = {
        ...session,
        status: "revoked" as const,
        revoked_at: nowIso,
        revocation_reason: reason,
      };
      state.sessions.set(sessionId, revoked);
      state.revokedSessions.push({ sessionId, reason });
      return revoked;
    },
    revokeActiveByUserId: async (userId: string, reason: string) => {
      const revoked: AuthSessionRow[] = [];
      for (const session of state.sessions.values()) {
        if (session.user_id !== userId || session.status !== "active") {
          continue;
        }

        const row = await repository.revokeById(session.id, reason);
        if (row) {
          revoked.push(row);
        }
      }
      return revoked;
    },
    rotateAccessToken: async (
      sessionId: string,
      input: { currentAccessTokenHash: string; expiresAt: string },
    ) => {
      const session = state.sessions.get(sessionId);
      if (!session) {
        return null;
      }

      const rotated = {
        ...session,
        current_access_token_hash: input.currentAccessTokenHash,
        expires_at: input.expiresAt,
      };
      state.sessions.set(sessionId, rotated);
      return rotated;
    },
    insert: async () => buildSession(),
    getByAccessTokenHash: async () => null,
    touchLastSeen: async () => {},
    revokeActiveByAuthCredentialId: async () => [],
  };

  return {
    authSessionRepository: repository,
    default: repository,
  };
});

mock.module("../repositories/refreshTokenFamilyRepository", () => {
  const repository = {
    getByCurrentTokenHash: async (tokenHash: string) =>
      Array.from(state.refreshFamilies.values()).find(
        (family) => family.current_token_hash === tokenHash,
      ) ?? null,
    getByPreviousTokenHash: async (tokenHash: string) =>
      Array.from(state.refreshFamilies.values()).find(
        (family) => family.previous_token_hash === tokenHash,
      ) ?? null,
    getBySessionId: async (sessionId: string) =>
      Array.from(state.refreshFamilies.values()).find(
        (family) => family.session_id === sessionId,
      ) ?? null,
    revokeById: async (
      familyId: string,
      input: { status: "revoked" | "reused" | "expired"; revocationReason: string },
    ) => {
      const family = state.refreshFamilies.get(familyId);
      if (!family) {
        return null;
      }

      const revoked = {
        ...family,
        status: input.status,
        revoked_at: nowIso,
        revocation_reason: input.revocationReason,
      };
      state.refreshFamilies.set(familyId, revoked);
      state.revokedRefreshFamilies.push({
        familyId,
        status: input.status,
        reason: input.revocationReason,
      });
      return revoked;
    },
    revokeBySessionId: async (
      sessionId: string,
      input: { status: "revoked" | "reused" | "expired"; revocationReason: string },
    ) => {
      const family = Array.from(state.refreshFamilies.values()).find(
        (candidate) => candidate.session_id === sessionId,
      );
      if (!family) {
        return null;
      }

      const revoked = await repository.revokeById(family.id, input);
      state.revokedRefreshFamilies.push({
        sessionId,
        status: input.status,
        reason: input.revocationReason,
      });
      return revoked;
    },
    revokeActiveByUserId: async (
      userId: string,
      input: { status: "revoked" | "reused" | "expired"; revocationReason: string },
    ) => {
      const revoked: RefreshTokenFamilyRow[] = [];
      for (const family of state.refreshFamilies.values()) {
        if (family.user_id !== userId || family.status !== "active") {
          continue;
        }

        const row = await repository.revokeById(family.id, input);
        if (row) {
          revoked.push(row);
        }
      }
      return revoked;
    },
    rotateCurrentToken: async (
      familyId: string,
      input: {
        previousTokenHash: string;
        currentTokenHash: string;
        expiresAt: string;
        rotationCounter: number;
      },
    ) => {
      const family = state.refreshFamilies.get(familyId);
      if (!family) {
        return null;
      }

      const rotated = {
        ...family,
        previous_token_hash: input.previousTokenHash,
        current_token_hash: input.currentTokenHash,
        expires_at: input.expiresAt,
        rotation_counter: input.rotationCounter,
      };
      state.refreshFamilies.set(familyId, rotated);
      return rotated;
    },
    insert: async () => buildRefreshFamily(),
  };

  return {
    refreshTokenFamilyRepository: repository,
    default: repository,
  };
});

mock.module("../repositories/userRepository", () => {
  const repository = {
    getById: async (userId: string) => state.users.get(userId) ?? null,
    incrementAuthGeneration: async (userId: string) => {
      const user = state.users.get(userId);
      if (!user) {
        return null;
      }

      const updated = {
        ...user,
        auth_generation: user.auth_generation + 1,
      };
      state.users.set(userId, updated);
      return updated;
    },
  };

  return {
    userRepository: repository,
    default: repository,
  };
});

mock.module("../repositories/authCredentialRepository", () => {
  const repository = {
    revokeActiveByUserId: async () => {
      state.recoveryCounts.credentials += 2;
      return [buildCredential(), buildCredential({ id: "auth-credential-2" })];
    },
    getByCredentialId: async () => null,
    insert: async () => buildCredential(),
    touchLastAuthenticated: async () => buildCredential(),
    listByUserId: async () => [buildCredential()],
  };

  return {
    authCredentialRepository: repository,
    default: repository,
  };
});

mock.module("../repositories/appAttestationCredentialRepository", () => {
  const buildAttestation = () => ({
    id: "attestation-1",
    user_id: activeUser.id,
    auth_credential_id: "auth-credential-1",
    platform: "ios" as const,
    attestation_provider: "ios_app_attest" as const,
    environment: "development" as const,
    attestation_key_id: "app-attest-key-1",
    public_key_pem: "app-attest-public-key-1",
    app_identifier: "TEAM.com.shooresh.iland",
    package_name: null,
    signing_cert_digest: null,
    status: "verified" as const,
    last_counter: null,
    last_asserted_at: null,
    last_assertion_nonce_hash: null,
    revoked_at: null,
    revocation_reason: null,
    created_at: nowIso,
    updated_at: nowIso,
  });
  const repository = {
    revokeActiveByUserId: async () => {
      state.recoveryCounts.attestations += 1;
      return [
        {
          id: "attestation-1",
        },
      ];
    },
    getByAuthCredentialId: async () => null,
    updateByAuthCredentialId: async () => null,
    insert: async () => buildAttestation(),
    recordAssertion: async () => null,
  };

  return {
    appAttestationCredentialRepository: repository,
    default: repository,
  };
});

mock.module("../repositories/authAuditEventRepository", () => {
  const repository = {
    insert: async (event: Record<string, unknown>) => {
      state.auditEvents.push(event);
      return event;
    },
  };

  return {
    authAuditEventRepository: repository,
    default: repository,
  };
});

mock.module("../repositories/accountDeletionRepository", () => {
  const repository = {
    deleteAccountForUser: async (userId: string) => {
      state.accountDeletionCalls.push(userId);
      return {
        userFound: true,
        userAnonymized: true,
        votes: 2,
        discussionPosts: 1,
        discussionComments: 3,
        discussionPostLikes: 4,
        discussionPostBookmarks: 1,
        discussionPostReports: 1,
        discussionMediaUploads: 1,
        walletCredentials: 1,
        authCredentials: 1,
        oidcRecords: 0,
        authAuditEventsAnonymized: 2,
        oidcAuditEventsAnonymized: 0,
        adminReviewersDisabled: 0,
        pollOwnershipsCleared: 0,
        landFoundershipsCleared: 0,
        credentialRegistryEntriesRevoked: 1,
      };
    },
  };

  return {
    accountDeletionRepository: repository,
    default: repository,
  };
});

const { __testOnly, authService } = await import("./authService");

describe("authService first-party auth lifecycle hardening", () => {
  beforeEach(() => {
    resetState();
  });

  it("creates a first-party session during successful backend auth registration", async () => {
    const result = await authService.completeRegistration({
      challengeId: "challenge-1",
      challenge: "challenge",
      credentialId: "device-credential-1",
      publicKeyPem: "pem",
      signature: "signature",
      appAttestation: {},
      nidnh: "a".repeat(128),
      normalizationVersion: 1,
      verificationMethod: "passport_nfc",
      platform: "ios",
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      throw new Error(result.message);
    }
    expect(result).toMatchObject({
      accessTokenType: "Bearer",
      session: {
        id: "session-1",
        userId: activeUser.id,
        authGeneration: activeUser.auth_generation,
      },
    });
    expect(typeof result.accessToken).toBe("string");
    expect(typeof result.refreshToken).toBe("string");
    expect(state.consumedChallenges).toContain("challenge-1");
    expect(state.revokedSessions).toContainEqual({
      sessionId: "session-1",
      reason: "same_credential_session_superseded_before_login",
    });
    expect(state.auditEvents.some((event) => (
      event.event_type === "auth_registration_session_created"
    ))).toBe(true);
  });

  it("revokes the refresh family and session when a rotated refresh token is reused", async () => {
    const previousToken = "refresh-token-previous";
    state.refreshFamilies.set(
      "refresh-family-1",
      buildRefreshFamily({
        previous_token_hash: hashOpaqueBearerToken(previousToken),
      }),
    );

    const result = await authService.refreshSession({
      refreshToken: previousToken,
    });

    expect(result).toMatchObject({
      success: false,
      errorCode: "REFRESH_TOKEN_NOT_FOUND",
    });
    expect(state.revokedRefreshFamilies).toContainEqual({
      familyId: "refresh-family-1",
      status: "reused",
      reason: "refresh_token_reuse_detected",
    });
    expect(state.revokedSessions).toContainEqual({
      sessionId: "session-1",
      reason: "refresh_token_reuse_detected",
    });
  });

  it("revokes stale-generation refresh sessions and token families", async () => {
    state.sessions.set(
      "session-1",
      buildSession({
        auth_generation: 1,
      }),
    );

    const result = await authService.refreshSession({
      refreshToken: "refresh-token-current",
    });

    expect(result).toMatchObject({
      success: false,
      errorCode: "SESSION_SUPERSEDED",
    });
    expect(state.revokedSessions).toContainEqual({
      sessionId: "session-1",
      reason: "auth_generation_mismatch",
    });
    expect(state.revokedRefreshFamilies).toContainEqual({
      familyId: "refresh-family-1",
      status: "revoked",
      reason: "auth_generation_mismatch",
    });
  });

  it("revokes the refresh family when a user revokes a session", async () => {
    const result = await authService.revokeSessionForUser(
      activeUser.id,
      "session-1",
    );

    expect(result.success).toBe(true);
    expect(state.revokedSessions).toContainEqual({
      sessionId: "session-1",
      reason: "user_requested_session_revoke",
    });
    expect(state.revokedRefreshFamilies).toContainEqual({
      sessionId: "session-1",
      status: "revoked",
      reason: "user_requested_session_revoke",
    });
  });

  it("prunes expired and stale sessions before returning session-management state", async () => {
    state.sessions.set(
      "expired-session",
      buildSession({
        id: "expired-session",
        expires_at: "2026-06-01T00:00:00.000Z",
      }),
    );
    state.sessions.set(
      "stale-session",
      buildSession({
        id: "stale-session",
        auth_generation: 1,
      }),
    );

    const result = await authService.listSessionsForUser(activeUser.id);

    expect(result.success).toBe(true);
    expect(state.revokedSessions).toContainEqual({
      sessionId: "expired-session",
      reason: "session_expired_before_login",
    });
    expect(state.revokedSessions).toContainEqual({
      sessionId: "stale-session",
      reason: "auth_generation_mismatch_before_login",
    });
  });

  it("revokes same-credential sessions before issuing a replacement login", async () => {
    const sameCredentialSession = buildSession({
      id: "same-credential-session",
      auth_credential_id: "auth-credential-1",
    });
    state.sessions.set(sameCredentialSession.id, sameCredentialSession);
    state.refreshFamilies.set(
      "refresh-family-same-credential",
      buildRefreshFamily({
        id: "refresh-family-same-credential",
        session_id: sameCredentialSession.id,
      }),
    );

    const activeSessions = await __testOnly.pruneInactiveLoginSessions(
      activeUser.id,
      [sameCredentialSession],
      activeUser.auth_generation,
      "auth-credential-1",
    );

    expect(activeSessions).toEqual([]);
    expect(state.revokedSessions).toContainEqual({
      sessionId: "same-credential-session",
      reason: "same_credential_session_superseded_before_login",
    });
    expect(state.revokedRefreshFamilies).toContainEqual({
      sessionId: "same-credential-session",
      status: "revoked",
      reason: "same_credential_session_superseded_before_login",
    });
  });

  it("recovery revokes old auth lineages and increments auth_generation", async () => {
    const result = await authService.revokeAuthenticationForRecovery({
      userId: activeUser.id,
      reason: "test_recovery",
    });

    expect(result).toMatchObject({
      success: true,
      user: {
        id: activeUser.id,
        authGeneration: activeUser.auth_generation + 1,
      },
      revoked: {
        sessions: 1,
        refreshTokenFamilies: 1,
        authCredentials: 2,
        appAttestationCredentials: 1,
      },
    });
    expect(state.auditEvents).toContainEqual(
      expect.objectContaining({
        event_type: "auth_recovery_revoked_authentication_lineage",
      }),
    );
  });

  it("deletes an account only after the exact confirmation phrase", async () => {
    const rejected = await authService.deleteAccount(activeUser.id, {
      confirmationPhrase: "delete my account",
    });

    expect(rejected).toMatchObject({
      success: false,
      errorCode: "CONFIRMATION_PHRASE_MISMATCH",
    });
    expect(state.accountDeletionCalls).toEqual([]);

    const accepted = await authService.deleteAccount(activeUser.id, {
      confirmationPhrase: "I want to delete my account forever",
    });

    expect(accepted).toMatchObject({
      success: true,
      deleted: {
        userFound: true,
        userAnonymized: true,
        votes: 2,
        discussionPosts: 1,
        discussionComments: 3,
      },
    });
    expect(state.accountDeletionCalls).toEqual([activeUser.id]);
  });
});
