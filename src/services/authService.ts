import { createHash, randomBytes } from "node:crypto";
import authPolicy from "../auth/policy";
import authAuditEventRepository from "../repositories/authAuditEventRepository";
import authChallengeRepository from "../repositories/authChallengeRepository";
import authSessionRepository from "../repositories/authSessionRepository";
import type { AuthChallengePurpose, AuthCredentialPlatform } from "../types/db";

const AUTH_CHALLENGE_TTL_MS = 5 * 60 * 1000;

type IssueAuthChallengeInput = {
  purpose: AuthChallengePurpose;
  platform: AuthCredentialPlatform;
  credentialIdHint?: string | null;
  metadata?: Record<string, unknown>;
};

const sha256Hex = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

const createOpaqueChallenge = (): string => randomBytes(32).toString("base64url");

const notImplementedErrorResponse = (operation: string) => ({
  success: false as const,
  errorCode: "NOT_IMPLEMENTED",
  message: `${operation} is not implemented yet. The auth foundation schema and route contract are in place, but device-key verification, attestation verification, and token issuance are still pending.`,
});

export const authService = {
  async issueChallenge(input: IssueAuthChallengeInput) {
    const challenge = createOpaqueChallenge();
    const challengeHash = sha256Hex(challenge);
    const expiresAt = new Date(Date.now() + AUTH_CHALLENGE_TTL_MS).toISOString();

    const challengeRow = await authChallengeRepository.insert({
      purpose: input.purpose,
      platform: input.platform,
      challenge_hash: challengeHash,
      credential_id_hint: input.credentialIdHint ?? null,
      expires_at: expiresAt,
      metadata: input.metadata ?? {},
    });

    // Intention:
    // - issue short-lived opaque challenges now so the mobile and backend
    //   integration can converge on a stable route contract;
    // - store only a hash server-side so later verification can reject replay
    //   without persisting the raw challenge secret at rest.
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
      purpose: input.purpose,
      platform: input.platform,
      issuer: authPolicy.issuer,
      expiresAt,
    };
  },

  async completeRegistration() {
    return notImplementedErrorResponse("Registration completion");
  },

  async completeLogin() {
    return notImplementedErrorResponse("Login completion");
  },

  async refreshSession() {
    return notImplementedErrorResponse("Session refresh");
  },

  async logoutSession() {
    return notImplementedErrorResponse("Session logout");
  },

  async listSessionsForUser(userId: string) {
    const sessions = await authSessionRepository.listByUserId(userId);
    return {
      success: true as const,
      sessions,
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

    const revoked = await authSessionRepository.revokeById(
      sessionId,
      "user_requested_session_revoke",
    );

    if (revoked) {
      await authAuditEventRepository.insert({
        user_id: userId,
        session_id: sessionId,
        event_type: "auth_session_revoked:user_request",
        metadata: {
          reason: "user_requested_session_revoke",
        },
      });
    }

    return {
      success: true as const,
      session: revoked,
    };
  },
};

export default authService;
