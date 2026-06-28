import appAttestationVerifier from "../auth/appAttestation";
import buildCanonicalAuthChallengePayload from "../auth/challengePayload";
import verifyCredentialSignature from "../auth/credentialSignature";
import authAccountBindingService from "./authAccountBindingService";
import authPolicy from "../auth/policy";
import {
  createOpaqueBearerToken,
  hashOpaqueBearerToken,
} from "../auth/tokens";
import appAttestationCredentialRepository from "../repositories/appAttestationCredentialRepository";
import authAuditEventRepository from "../repositories/authAuditEventRepository";
import authChallengeRepository from "../repositories/authChallengeRepository";
import authCredentialRepository from "../repositories/authCredentialRepository";
import authSessionRepository from "../repositories/authSessionRepository";
import refreshTokenFamilyRepository from "../repositories/refreshTokenFamilyRepository";
import userRepository from "../repositories/userRepository";
import type {
  AuthChallengePurpose,
  AuthCredentialPlatform,
  AuthSessionRow,
} from "../types/db";

const AUTH_CHALLENGE_TTL_MS = 5 * 60 * 1000;

type IssueAuthChallengeInput = {
  purpose: AuthChallengePurpose;
  platform: AuthCredentialPlatform;
  credentialIdHint?: string | null;
  metadata?: Record<string, unknown>;
};

type RegistrationCompletionInput = {
  challengeId: string;
  challenge: string;
  credentialId: string;
  publicKeyPem: string;
  signature: string;
  appAttestation: Record<string, unknown>;
  nidnh: string;
  normalizationVersion: number;
  verificationMethod: "passport_nfc";
  platform: AuthCredentialPlatform;
};

type LoginCompletionInput = {
  challengeId: string;
  challenge: string;
  credentialId: string;
  signature: string;
  appAssertion: Record<string, unknown>;
};

type RefreshSessionInput = {
  refreshToken: string;
};

type RecoveryRevocationInput = {
  userId: string;
  preserveAuthCredentialId?: string | null;
  reason?: string;
};

const createOpaqueChallenge = (): string => createOpaqueBearerToken().token;

const notImplementedErrorResponse = (operation: string) => ({
  success: false as const,
  errorCode: "NOT_IMPLEMENTED",
  message: `${operation} is not implemented yet. The auth foundation schema and route contract are in place, but full device-key verification or attestation verification is still pending.`,
});

const invalidChallengeResponse = (message: string) => ({
  success: false as const,
  errorCode: "INVALID_CHALLENGE",
  message,
});

const invalidSignatureResponse = (
  errorCode: "INVALID_PUBLIC_KEY" | "INVALID_SIGNATURE_ENCODING" | "INVALID_SIGNATURE",
  message: string,
) => ({
  success: false as const,
  errorCode,
  message,
});

const attestationRejectedResponse = (
  errorCode: "ATTESTATION_INVALID" | "NOT_IMPLEMENTED",
  message: string,
) => ({
  success: false as const,
  errorCode,
  message,
});

const disabledAccountResponse = {
  success: false as const,
  errorCode: "ACCOUNT_DISABLED",
  message:
    "This account is disabled or banned. Protected access, refresh, and recovery remain blocked until support/admin review re-enables the account.",
};

const verifyStoredChallenge = async (
  challengeId: string,
  rawChallenge: string,
  purpose: AuthChallengePurpose,
) => {
  const stored = await authChallengeRepository.getById(challengeId);
  if (!stored) {
    return invalidChallengeResponse("Auth challenge was not found.");
  }

  if (stored.purpose !== purpose) {
    return invalidChallengeResponse("Auth challenge purpose does not match the request.");
  }

  if (stored.consumed_at) {
    return invalidChallengeResponse("Auth challenge has already been consumed.");
  }

  if (new Date(stored.expires_at).getTime() <= Date.now()) {
    return invalidChallengeResponse("Auth challenge has expired.");
  }

  if (stored.challenge_hash !== hashOpaqueBearerToken(rawChallenge)) {
    return invalidChallengeResponse("Auth challenge value did not match.");
  }

  return {
    success: true as const,
    challenge: stored,
  };
};

const buildFirstPartySessionTokens = () => {
  const accessToken = createOpaqueBearerToken();
  const refreshToken = createOpaqueBearerToken();

  return {
    accessToken,
    refreshToken,
  };
};

const nowIsPast = (isoTimestamp: string) => new Date(isoTimestamp).getTime() <= Date.now();

const toPublicSession = (session: AuthSessionRow | null) => {
  if (!session) {
    return null;
  }

  return {
    id: session.id,
    userId: session.user_id,
    authCredentialId: session.auth_credential_id,
    status: session.status,
    authGeneration: session.auth_generation,
    attestationVerifiedAt: session.attestation_verified_at,
    lastSeenAt: session.last_seen_at,
    expiresAt: session.expires_at,
    revokedAt: session.revoked_at,
    revocationReason: session.revocation_reason,
    createdAt: session.created_at,
    updatedAt: session.updated_at,
  };
};

const revokeRefreshFamilyForSession = async (
  sessionId: string,
  reason: string,
  status: "revoked" | "reused" | "expired" = "revoked",
) =>
  refreshTokenFamilyRepository.revokeBySessionId(sessionId, {
    status,
    revocationReason: reason,
  });

const revokeSessionLineage = async (
  session: AuthSessionRow,
  reason: string,
  options: {
    refreshFamilyStatus?: "revoked" | "reused" | "expired";
    auditEventType?: string;
    auditMetadata?: Record<string, unknown>;
  } = {},
) => {
  // Enforced lifecycle policy:
  // a server session and its refresh-token family are one revocable lineage.
  // Leaving a refresh family active after revoking the access session creates
  // confusing UX and a possible stale retry path, so every session revocation
  // goes through this helper.
  const revokedSession =
    session.status === "active"
      ? await authSessionRepository.revokeById(session.id, reason)
      : session;
  await revokeRefreshFamilyForSession(
    session.id,
    reason,
    options.refreshFamilyStatus ?? "revoked",
  );

  await authAuditEventRepository.insert({
    user_id: session.user_id,
    session_id: session.id,
    event_type: options.auditEventType ?? `auth_session_revoked:${reason}`,
    metadata: {
      reason,
      ...(options.auditMetadata ?? {}),
    },
  });

  return revokedSession;
};

const pruneInactiveLoginSessions = async (
  userId: string,
  sessions: AuthSessionRow[],
  currentAuthGeneration: number,
  replacingAuthCredentialId: string,
): Promise<AuthSessionRow[]> => {
  const stillActive: AuthSessionRow[] = [];

  for (const session of sessions) {
    if (session.status !== "active") {
      continue;
    }

    let revocationReason: string | null = null;
    if (nowIsPast(session.expires_at)) {
      revocationReason = "session_expired_before_login";
    } else if (session.auth_generation !== currentAuthGeneration) {
      revocationReason = "auth_generation_mismatch_before_login";
    } else if (session.auth_credential_id === replacingAuthCredentialId) {
      revocationReason = "same_credential_session_superseded_before_login";
    }

    if (!revocationReason) {
      stillActive.push(session);
      continue;
    }

    await revokeSessionLineage(session, revocationReason, {
      auditMetadata: {
        prunedDuringLogin: true,
      },
    });
  }

  return stillActive;
};

export const authService = {
  async issueChallenge(input: IssueAuthChallengeInput) {
    const challenge = createOpaqueChallenge();
    const challengeHash = hashOpaqueBearerToken(challenge);
    const expiresAt = new Date(Date.now() + AUTH_CHALLENGE_TTL_MS).toISOString();

    const challengeRow = await authChallengeRepository.insert({
      purpose: input.purpose,
      platform: input.platform,
      challenge_hash: challengeHash,
      credential_id_hint: input.credentialIdHint ?? null,
      expires_at: expiresAt,
      metadata: input.metadata ?? {},
    });

    await authAuditEventRepository.insert({
      event_type: `auth_challenge_issued:${input.purpose}`,
      platform: input.platform,
      metadata: {
        challengeId: challengeRow.id,
        issuer: authPolicy.issuer,
        expiresAt,
      },
    });

    return {
      success: true as const,
      challengeId: challengeRow.id,
      challenge,
      signaturePayload: buildCanonicalAuthChallengePayload({
        challengeId: challengeRow.id,
        challenge,
        purpose: input.purpose,
        platform: input.platform,
      }),
      purpose: input.purpose,
      platform: input.platform,
      issuer: authPolicy.issuer,
      expiresAt,
    };
  },

  async completeRegistration(input: RegistrationCompletionInput) {
    const challengeResult = await verifyStoredChallenge(
      input.challengeId,
      input.challenge,
      "register",
    );
    if (!challengeResult.success) {
      return challengeResult;
    }

    const signatureResult = verifyCredentialSignature({
      publicKeyPem: input.publicKeyPem,
      challengeId: input.challengeId,
      challenge: input.challenge,
      purpose: "register",
      platform: input.platform,
      signature: input.signature,
    });
    if (!signatureResult.success) {
      return invalidSignatureResponse(
        signatureResult.errorCode,
        signatureResult.message,
      );
    }

    const user =
      await authAccountBindingService.resolveOrCreateUserByVerifiedIdentity({
        nidnh: input.nidnh,
        normalizationVersion: input.normalizationVersion,
        verificationMethod: input.verificationMethod,
      });

    if (user.account_status !== "active") {
      return disabledAccountResponse;
    }

    const existingCredential =
      await authCredentialRepository.getByCredentialId(input.credentialId);
    if (existingCredential && existingCredential.user_id !== user.id) {
      return {
        success: false as const,
        errorCode: "CREDENTIAL_ALREADY_BOUND",
        message:
          "The supplied authentication credential is already bound to a different user.",
      };
    }

    if (
      existingCredential &&
      existingCredential.public_key_pem.trim() !== input.publicKeyPem.trim()
    ) {
      return {
        success: false as const,
        errorCode: "CREDENTIAL_KEY_MISMATCH",
        message:
          "The supplied credential id is already enrolled with a different public key.",
      };
    }

    const appAttestationResult =
      await appAttestationVerifier.verifyRegistrationAttestation({
        platform: input.platform,
        appAttestation: input.appAttestation,
        challenge: input.challenge,
      });
    if (!appAttestationResult.success) {
      return attestationRejectedResponse(
        appAttestationResult.errorCode,
        appAttestationResult.message,
      );
    }

    const authCredential =
      existingCredential ||
      (await authCredentialRepository.insert({
        user_id: user.id,
        platform: input.platform,
        algorithm: "p256",
        credential_id: input.credentialId,
        public_key_pem: input.publicKeyPem,
      }));

    const existingAttestation =
      await appAttestationCredentialRepository.getByAuthCredentialId(
        authCredential.id,
      );

    const appAttestationCredential = existingAttestation
      ? (await appAttestationCredentialRepository.updateByAuthCredentialId(
          authCredential.id,
          {
            attestationProvider: appAttestationResult.provider,
            environment: appAttestationResult.environment,
            attestationKeyId: appAttestationResult.attestationKeyId,
            publicKeyPem: appAttestationResult.attestationPublicKeyPem,
            appIdentifier: appAttestationResult.appIdentifier,
            packageName: appAttestationResult.packageName,
            signingCertDigest: appAttestationResult.signingCertDigest,
            status: "verified",
          },
        )) || existingAttestation
      : await appAttestationCredentialRepository.insert({
          user_id: user.id,
          auth_credential_id: authCredential.id,
          platform: input.platform,
          attestation_provider: appAttestationResult.provider,
          environment: appAttestationResult.environment,
          attestation_key_id: appAttestationResult.attestationKeyId,
          public_key_pem: appAttestationResult.attestationPublicKeyPem,
          app_identifier: appAttestationResult.appIdentifier,
          package_name: appAttestationResult.packageName,
          signing_cert_digest: appAttestationResult.signingCertDigest,
          status: "verified",
        });

    await authChallengeRepository.markConsumed(input.challengeId);

    await authAuditEventRepository.insert({
      user_id: user.id,
      auth_credential_id: authCredential.id,
      event_type: "auth_registration_completed",
      platform: input.platform,
      metadata: {
        challengeId: input.challengeId,
        verifiedIdentityBound: true,
        signatureEncoding: signatureResult.signatureEncoding,
        signaturePayloadVersion: "iland-auth-v1",
        transitionalCryptoBypassUsed:
          appAttestationResult.transitionalCryptoBypassUsed,
        appAttestationCredentialId: appAttestationCredential.id,
      },
    });

    return {
      success: true as const,
      user: {
        id: user.id,
        authGeneration: user.auth_generation,
        accountStatus: user.account_status,
      },
      authCredential: {
        id: authCredential.id,
        credentialId: authCredential.credential_id,
        platform: authCredential.platform,
        status: authCredential.status,
      },
      appAttestationCredential: {
        id: appAttestationCredential.id,
        provider: appAttestationCredential.attestation_provider,
        status: appAttestationCredential.status,
      },
      transitionalCryptoBypassUsed:
        appAttestationResult.transitionalCryptoBypassUsed,
    };
  },

  async completeLogin(input: LoginCompletionInput) {
    const challengeResult = await verifyStoredChallenge(
      input.challengeId,
      input.challenge,
      "login",
    );
    if (!challengeResult.success) {
      return challengeResult;
    }

    const authCredential = await authCredentialRepository.getByCredentialId(
      input.credentialId,
    );
    if (!authCredential || authCredential.status !== "active") {
      return {
        success: false as const,
        errorCode: "CREDENTIAL_NOT_FOUND",
        message: "Authentication credential was not found or is not active.",
      };
    }

    const user = await userRepository.getById(authCredential.user_id);
    if (!user) {
      return {
        success: false as const,
        errorCode: "USER_NOT_FOUND",
        message: "Credential user could not be resolved.",
      };
    }

    if (user.account_status !== "active") {
      return disabledAccountResponse;
    }

    const appAttestationCredential =
      await appAttestationCredentialRepository.getByAuthCredentialId(
        authCredential.id,
      );

    if (!appAttestationCredential || appAttestationCredential.status !== "verified") {
      return {
        success: false as const,
        errorCode: "ATTESTATION_REQUIRED",
        message:
          "A verified app attestation credential is required before login can complete.",
      };
    }

    const signatureResult = verifyCredentialSignature({
      publicKeyPem: authCredential.public_key_pem,
      challengeId: input.challengeId,
      challenge: input.challenge,
      purpose: "login",
      platform: authCredential.platform,
      signature: input.signature,
    });
    if (!signatureResult.success) {
      return invalidSignatureResponse(
        signatureResult.errorCode,
        signatureResult.message,
      );
    }

    const loginAssertionResult = await appAttestationVerifier.verifyLoginAssertion({
      platform: authCredential.platform,
      appAssertion: input.appAssertion,
      challenge: input.challenge,
      storedCredential: appAttestationCredential,
    });
    if (!loginAssertionResult.success) {
      return attestationRejectedResponse(
        loginAssertionResult.errorCode,
        loginAssertionResult.message,
      );
    }

    const existingSessions = await authSessionRepository.listByUserId(user.id);
    const activeSessions = await pruneInactiveLoginSessions(
      user.id,
      existingSessions,
      user.auth_generation,
      authCredential.id,
    );
    const activeSessionCount = activeSessions.length;
    if (activeSessionCount >= authPolicy.maxActiveSessionsPerUser) {
      return {
        success: false as const,
        errorCode: "SESSION_LIMIT_REACHED",
        message:
          "Maximum active session limit reached. Revoke an existing session before logging in again.",
      };
    }

    const { accessToken, refreshToken } = buildFirstPartySessionTokens();
    const accessExpiresAt = new Date(
      Date.now() + authPolicy.accessTokenTtlSeconds * 1000,
    ).toISOString();
    const refreshExpiresAt = new Date(
      Date.now() + authPolicy.refreshTokenTtlDays * 24 * 60 * 60 * 1000,
    ).toISOString();

    const session = await authSessionRepository.insert({
      user_id: user.id,
      auth_credential_id: authCredential.id,
      auth_generation: user.auth_generation,
      current_access_token_hash: accessToken.tokenHash,
      attestation_verified_at: new Date().toISOString(),
      expires_at: accessExpiresAt,
    });

    await authCredentialRepository.touchLastAuthenticated(authCredential.id);
    await appAttestationCredentialRepository.recordAssertion(authCredential.id, {
      lastAssertionNonceHash: loginAssertionResult.lastAssertionNonceHash,
      lastCounter: loginAssertionResult.lastCounter,
    });

    await refreshTokenFamilyRepository.insert({
      session_id: session.id,
      user_id: user.id,
      current_token_hash: refreshToken.tokenHash,
      expires_at: refreshExpiresAt,
    });

    await authChallengeRepository.markConsumed(input.challengeId);
    await authAuditEventRepository.insert({
      user_id: user.id,
      auth_credential_id: authCredential.id,
      session_id: session.id,
      event_type: "auth_login_completed",
      platform: authCredential.platform,
      metadata: {
        challengeId: input.challengeId,
        signatureEncoding: signatureResult.signatureEncoding,
        signaturePayloadVersion: "iland-auth-v1",
        transitionalCryptoBypassUsed:
          loginAssertionResult.transitionalCryptoBypassUsed,
      },
    });

    return {
      success: true as const,
      accessToken: accessToken.token,
      accessTokenType: "Bearer",
      accessTokenExpiresAt: accessExpiresAt,
      refreshToken: refreshToken.token,
      refreshTokenExpiresAt: refreshExpiresAt,
      session: {
        id: session.id,
        userId: session.user_id,
        authGeneration: session.auth_generation,
      },
      transitionalCryptoBypassUsed:
        loginAssertionResult.transitionalCryptoBypassUsed,
    };
  },

  async refreshSession(input: RefreshSessionInput) {
    const refreshTokenHash = hashOpaqueBearerToken(input.refreshToken);
    const refreshFamily =
      await refreshTokenFamilyRepository.getByCurrentTokenHash(refreshTokenHash);
    if (!refreshFamily) {
      const reusedFamily =
        await refreshTokenFamilyRepository.getByPreviousTokenHash(refreshTokenHash);

      // Refresh-token replay on an already-rotated token is treated as a
      // security event for that session lineage. We revoke only that family and
      // session so unrelated healthy device sessions stay alive.
      if (reusedFamily) {
        await refreshTokenFamilyRepository.revokeById(reusedFamily.id, {
          status: "reused",
          revocationReason: "refresh_token_reuse_detected",
        });
        await authSessionRepository.revokeById(
          reusedFamily.session_id,
          "refresh_token_reuse_detected",
        );
        await authAuditEventRepository.insert({
          user_id: reusedFamily.user_id,
          session_id: reusedFamily.session_id,
          event_type: "auth_refresh_reuse_detected",
          metadata: {
            refreshTokenFamilyId: reusedFamily.id,
          },
        });
      }

      return {
        success: false as const,
        errorCode: "REFRESH_TOKEN_NOT_FOUND",
        message: "Refresh token was not found or is no longer active.",
      };
    }

    if (refreshFamily.status !== "active") {
      return {
        success: false as const,
        errorCode: "REFRESH_TOKEN_NOT_ACTIVE",
        message: "Refresh token family is no longer active.",
      };
    }

    if (nowIsPast(refreshFamily.expires_at)) {
      await refreshTokenFamilyRepository.revokeById(refreshFamily.id, {
        status: "expired",
        revocationReason: "refresh_token_expired",
      });
      await authSessionRepository.revokeById(
        refreshFamily.session_id,
        "refresh_token_expired",
      );

      return {
        success: false as const,
        errorCode: "REFRESH_TOKEN_EXPIRED",
        message: "Refresh token has expired.",
      };
    }

    const session = await authSessionRepository.getById(refreshFamily.session_id);
    if (!session || session.user_id !== refreshFamily.user_id) {
      return {
        success: false as const,
        errorCode: "SESSION_NOT_FOUND",
        message: "Refresh session could not be resolved.",
      };
    }

    if (session.status !== "active") {
      await refreshTokenFamilyRepository.revokeById(refreshFamily.id, {
        status: "revoked",
        revocationReason: "session_not_active",
      });
      return {
        success: false as const,
        errorCode: "SESSION_NOT_ACTIVE",
        message: "Refresh session is no longer active.",
      };
    }

    const user = await userRepository.getById(refreshFamily.user_id);
    if (!user) {
      return {
        success: false as const,
        errorCode: "USER_NOT_FOUND",
        message: "Refresh user could not be resolved.",
      };
    }

    if (user.account_status !== "active") {
      await revokeSessionLineage(session, "account_disabled", {
        auditEventType: "auth_session_revoked:account_disabled",
      });
      return disabledAccountResponse;
    }

    if (user.auth_generation !== session.auth_generation) {
      await authSessionRepository.revokeById(
        session.id,
        "auth_generation_mismatch",
      );
      await refreshTokenFamilyRepository.revokeById(refreshFamily.id, {
        status: "revoked",
        revocationReason: "auth_generation_mismatch",
      });

      return {
        success: false as const,
        errorCode: "SESSION_SUPERSEDED",
        message:
          "This session has been superseded by account recovery or a security action.",
      };
    }

    const { accessToken, refreshToken } = buildFirstPartySessionTokens();
    const accessExpiresAt = new Date(
      Date.now() + authPolicy.accessTokenTtlSeconds * 1000,
    ).toISOString();
    const refreshExpiresAt = new Date(
      Date.now() + authPolicy.refreshTokenTtlDays * 24 * 60 * 60 * 1000,
    ).toISOString();

    const rotatedSession = await authSessionRepository.rotateAccessToken(session.id, {
      currentAccessTokenHash: accessToken.tokenHash,
      expiresAt: accessExpiresAt,
    });
    const rotatedFamily = await refreshTokenFamilyRepository.rotateCurrentToken(
      refreshFamily.id,
      {
        previousTokenHash: refreshFamily.current_token_hash,
        currentTokenHash: refreshToken.tokenHash,
        expiresAt: refreshExpiresAt,
        rotationCounter: refreshFamily.rotation_counter + 1,
      },
    );

    await authAuditEventRepository.insert({
      user_id: user.id,
      session_id: session.id,
      event_type: "auth_refresh_completed",
      metadata: {
        refreshTokenFamilyId: refreshFamily.id,
        rotationCounter: refreshFamily.rotation_counter + 1,
      },
    });

    return {
      success: true as const,
      accessToken: accessToken.token,
      accessTokenType: "Bearer",
      accessTokenExpiresAt: accessExpiresAt,
      refreshToken: refreshToken.token,
      refreshTokenExpiresAt: refreshExpiresAt,
      session: {
        id: rotatedSession?.id ?? session.id,
        userId: user.id,
        authGeneration: session.auth_generation,
      },
      refresh: {
        familyId: rotatedFamily?.id ?? refreshFamily.id,
        rotationCounter: rotatedFamily?.rotation_counter ?? refreshFamily.rotation_counter + 1,
      },
    };
  },

  async logoutSession(userId: string, sessionId: string) {
    return this.revokeSessionForUser(userId, sessionId);
  },

  async listSessionsForUser(userId: string) {
    const user = await userRepository.getById(userId);
    if (!user) {
      return {
        success: false as const,
        errorCode: "USER_NOT_FOUND",
        message: "Session user could not be resolved.",
      };
    }

    const sessions = await authSessionRepository.listByUserId(userId);
    await pruneInactiveLoginSessions(
      userId,
      sessions,
      user.auth_generation,
      "__session_list_no_replacement__",
    );
    const refreshedSessions = await authSessionRepository.listByUserId(userId);

    return {
      success: true as const,
      sessions: refreshedSessions.map(toPublicSession),
      policy: {
        maxActiveSessionsPerUser: authPolicy.maxActiveSessionsPerUser,
      },
    };
  },

  async revokeSessionForUser(userId: string, sessionId: string) {
    const session = await authSessionRepository.getById(sessionId);
    if (!session || session.user_id !== userId) {
      return {
        success: false as const,
        errorCode: "SESSION_NOT_FOUND",
        message: "Session not found for the current user.",
      };
    }

    const revoked = await revokeSessionLineage(
      session,
      "user_requested_session_revoke",
      {
        auditEventType: "auth_session_revoked:user_request",
      },
    );

    return {
      success: true as const,
      session: toPublicSession(revoked),
    };
  },

  async revokeAuthenticationForRecovery(input: RecoveryRevocationInput) {
    const reason = input.reason ?? "identity_recovery_completed";
    const user = await userRepository.incrementAuthGeneration(input.userId);
    if (!user) {
      return {
        success: false as const,
        errorCode: "USER_NOT_FOUND",
        message: "Recovery user could not be resolved.",
      };
    }

    const sessions = await authSessionRepository.listByUserId(input.userId);
    const sessionsToRevoke = sessions.filter(
      (session) =>
        session.status === "active" &&
        session.auth_credential_id !== (input.preserveAuthCredentialId ?? null),
    );
    const revokedSessions: AuthSessionRow[] = [];
    let revokedRefreshFamilyCount = 0;
    for (const session of sessionsToRevoke) {
      const revokedSession = await revokeSessionLineage(session, reason, {
        auditEventType: "auth_session_revoked:identity_recovery",
      });
      if (revokedSession) {
        revokedSessions.push(revokedSession);
      }
      revokedRefreshFamilyCount += 1;
    }

    const [revokedCredentials, revokedAttestations] = await Promise.all([
      authCredentialRepository.revokeActiveByUserId(input.userId, {
        revocationReason: reason,
        excludeAuthCredentialId: input.preserveAuthCredentialId ?? null,
      }),
      appAttestationCredentialRepository.revokeActiveByUserId(input.userId, {
        revocationReason: reason,
        excludeAuthCredentialId: input.preserveAuthCredentialId ?? null,
      }),
    ]);

    await authAuditEventRepository.insert({
      user_id: input.userId,
      event_type: "auth_recovery_revoked_authentication_lineage",
      metadata: {
        reason,
        newAuthGeneration: user.auth_generation,
        preservedAuthCredentialId: input.preserveAuthCredentialId ?? null,
        revokedSessionCount: revokedSessions.length,
        revokedRefreshFamilyCount,
        revokedCredentialCount: revokedCredentials.length,
        revokedAttestationCredentialCount: revokedAttestations.length,
      },
    });

    return {
      success: true as const,
      user: {
        id: user.id,
        authGeneration: user.auth_generation,
      },
      revoked: {
        sessions: revokedSessions.length,
        refreshTokenFamilies: revokedRefreshFamilyCount,
        authCredentials: revokedCredentials.length,
        appAttestationCredentials: revokedAttestations.length,
      },
    };
  },
};

export const __testOnly = {
  pruneInactiveLoginSessions,
};

export default authService;
