import {
  createHash,
  createSign,
  randomBytes,
} from "node:crypto";

import {
  createOpaqueBearerToken,
  hashOpaqueBearerToken,
} from "../auth/tokens";
import defaultIdentityProfileRepository from "../repositories/identityProfileRepository";
import defaultOidcProviderRepository, {
  type OidcAuthorizationRequestRow,
  type OidcAuthorizeQrTransactionRow,
  type OidcPairwiseSubjectRow,
} from "../repositories/oidcProviderRepository";
import defaultOidcSigningKeyRepository from "../repositories/oidcSigningKeyRepository";
import defaultUserRepository from "../repositories/userRepository";
import type {
  IdentityProfileRow,
  OidcClientRow,
  OidcSigningKeyRow,
  UserRow,
} from "../types/db";
import type { ViewerContext } from "../types/auth";
import authPolicy from "../auth/policy";
import {
  OIDC_SHAREABLE_CLAIMS,
  OIDC_USERINFO_PROFILE_CLAIMS,
} from "./oidcClaimContract";

const AUTHORIZATION_REQUEST_ID_BYTES = 18;
const AUTHORIZATION_CODE_BYTES = 32;
const PAIRWISE_SUBJECT_BYTES = 32;
const OIDC_REFRESH_TOKEN_BYTES = 32;
const OIDC_AUTHORIZE_QR_TYPE = "civicos.oidc.authorize";
const OIDC_AUTHORIZE_QR_VERSION = 1;
const OIDC_AUTHORIZE_QR_TRANSACTION_ID_BYTES = 18;
const OIDC_AUTHORIZE_QR_SECRET_BYTES = 32;
const OIDC_AUTHORIZE_QR_POLL_SECRET_BYTES = 32;
const OIDC_AUTHORIZE_QR_TTL_MS = 2 * 60 * 1000;
const OIDC_AUTHORIZE_QR_APPROVED_RESULT_TTL_MS = 60 * 1000;

type OidcProviderRepositoryLike = Pick<
  typeof defaultOidcProviderRepository,
  | "getClientByClientId"
  | "getClientById"
  | "getRedirectUri"
  | "getActiveSecretByHash"
  | "touchClientSecret"
  | "insertAuthorizationRequest"
  | "insertPendingAuthorizationRequest"
  | "getAuthorizationRequestById"
  | "insertAuthorizeQrTransaction"
  | "getAuthorizeQrTransactionByRequestId"
  | "expireAuthorizeQrTransaction"
  | "approveAuthorizeQrTransaction"
  | "denyAuthorizeQrTransaction"
  | "deliverAuthorizeQrCode"
  | "getPairwiseSubject"
  | "insertPairwiseSubject"
  | "getPairwiseSubjectById"
  | "upsertGrant"
  | "getGrantByUserAndClient"
  | "insertAuthorizationCode"
  | "getAuthorizationCodeByHash"
  | "consumeAuthorizationCode"
  | "expireAuthorizationCode"
  | "consumeAuthorizationRequest"
  | "insertRefreshTokenFamily"
  | "insertAccessToken"
  | "getAccessTokenByHash"
  | "touchAccessToken"
  | "expireAccessToken"
  | "revokeAccessTokenByHash"
  | "getRefreshTokenFamilyByTokenHash"
  | "revokeRefreshTokenFamilyById"
>;

type OidcSigningKeyRepositoryLike = Pick<
  typeof defaultOidcSigningKeyRepository,
  "listPublicSigningKeys"
>;

type UserRepositoryLike = Pick<typeof defaultUserRepository, "getById">;
type IdentityProfileRepositoryLike = Pick<
  typeof defaultIdentityProfileRepository,
  "getByUserId"
>;

export type OidcProviderServiceDependencies = {
  issuer?: string;
  now?: () => Date;
  randomBytesFn?: (size: number) => Buffer;
  oidcProviderRepositoryLike?: OidcProviderRepositoryLike;
  oidcSigningKeyRepositoryLike?: OidcSigningKeyRepositoryLike;
  userRepositoryLike?: UserRepositoryLike;
  identityProfileRepositoryLike?: IdentityProfileRepositoryLike;
};

type ValidatedAuthorizationRequest = {
  client: OidcClientRow;
  redirectUri: string;
  responseType: "code";
  scopes: string[];
  state: string | null;
  nonce: string | null;
  codeChallenge: string;
  codeChallengeMethod: "S256";
};

type AuthorizationValidationFailure = {
  success: false;
  error: "invalid_request" | "unauthorized_client" | "unsupported_response_type" | "invalid_scope";
  message: string;
  redirectUri?: string;
  state?: string | null;
};

type AuthorizationValidationSuccess = {
  success: true;
  request: ValidatedAuthorizationRequest;
};

export type AuthorizationValidationResult =
  | AuthorizationValidationSuccess
  | AuthorizationValidationFailure;

export type TokenExchangeSuccess = {
  success: true;
  body: {
    access_token: string;
    token_type: "Bearer";
    expires_in: number;
    scope: string;
    id_token: string;
    refresh_token?: string;
  };
  audit: {
    clientDbId: string;
    clientId: string;
    userId: string;
    authSessionId: string | null;
    authorizationRequestId: string;
    grantId: string;
    scopes: string[];
    issuedRefreshToken: boolean;
  };
};

export type TokenExchangeFailure = {
  success: false;
  status: number;
  error:
    | "invalid_request"
    | "invalid_client"
    | "invalid_grant"
    | "unsupported_grant_type"
    | "server_error";
  error_description: string;
};

export type TokenExchangeResult = TokenExchangeSuccess | TokenExchangeFailure;

export type UserInfoSuccess = {
  success: true;
  body: Record<string, unknown>;
};

export type UserInfoFailure = {
  success: false;
  status: number;
  error: "invalid_token" | "server_error";
  error_description: string;
};

export type UserInfoResult = UserInfoSuccess | UserInfoFailure;

export type TokenRevocationSuccess = {
  success: true;
};

export type TokenRevocationFailure = {
  success: false;
  status: number;
  error: "invalid_request" | "invalid_client";
  error_description: string;
};

export type TokenRevocationResult =
  | TokenRevocationSuccess
  | TokenRevocationFailure;

type AuthorizationQrTransactionStatus =
  | { status: "pending"; expiresAt: string }
  | { status: "approved"; redirectTo: string; expiresAt: string }
  | { status: "denied"; redirectTo: string; expiresAt: string }
  | { status: "expired" }
  | { status: "not_found" };

const toBase64Url = (value: Buffer | string): string =>
  Buffer.isBuffer(value)
    ? value.toString("base64url")
    : Buffer.from(value, "utf8").toString("base64url");

const sha256Hex = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

const sha256Base64Url = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("base64url");

const createRandomToken = (
  randomBytesForService: (size: number) => Buffer,
  byteLength: number,
): string => randomBytesForService(byteLength).toString("base64url");

const normalizeIssuer = (issuer: string): string =>
  issuer.length > 1 && issuer.endsWith("/") ? issuer.slice(0, -1) : issuer;

const splitScope = (scope: string | null): string[] =>
  (scope || "openid")
    .split(/\s+/u)
    .map((entry) => entry.trim())
    .filter(Boolean);

const parseOptional = (value: string | null): string | null =>
  value && value.trim().length > 0 ? value : null;

const buildFailure = (
  error: TokenExchangeFailure["error"],
  errorDescription: string,
  status = 400,
): TokenExchangeFailure => ({
  success: false,
  status,
  error,
  error_description: errorDescription,
});

const isUsableSigningKey = (row: OidcSigningKeyRow, now: Date): boolean => {
  if (row.status !== "active") {
    return false;
  }

  if (row.revoked_at) {
    return false;
  }

  const notBefore = Date.parse(row.not_before);
  if (Number.isFinite(notBefore) && now.getTime() < notBefore) {
    return false;
  }

  if (row.not_after) {
    const notAfter = Date.parse(row.not_after);
    if (Number.isFinite(notAfter) && now.getTime() >= notAfter) {
      return false;
    }
  }

  return true;
};

const loadPrivateKeyForSigningKey = (row: OidcSigningKeyRow): string | null => {
  const ref = row.private_key_ref?.trim();
  if (!ref) {
    return null;
  }

  const value = process.env[ref];
  return value?.trim().replace(/\\n/g, "\n") || null;
};

const signJwtRs256 = (
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  privateKeyPem: string,
): string => {
  const encodedHeader = toBase64Url(JSON.stringify(header));
  const encodedPayload = toBase64Url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = createSign("RSA-SHA256")
    .update(signingInput)
    .end()
    .sign(privateKeyPem)
    .toString("base64url");

  return `${signingInput}.${signature}`;
};

const extractBasicClientAuth = (
  authorizationHeader: string | null,
): { clientId: string; clientSecret: string } | null => {
  const match = /^Basic\s+(.+)$/iu.exec(authorizationHeader || "");
  if (!match?.[1]) {
    return null;
  }

  try {
    const decoded = Buffer.from(match[1], "base64").toString("utf8");
    const separatorIndex = decoded.indexOf(":");
    if (separatorIndex < 0) {
      return null;
    }

    return {
      clientId: decodeURIComponent(decoded.slice(0, separatorIndex)),
      clientSecret: decodeURIComponent(decoded.slice(separatorIndex + 1)),
    };
  } catch {
    return null;
  }
};

const filterUserInfoClaims = (
  scopes: string[],
  claims: Record<string, unknown>,
): Record<string, unknown> => {
  if (!scopes.includes("profile")) {
    return {};
  }

  const output: Record<string, unknown> = {};
  for (const key of OIDC_USERINFO_PROFILE_CLAIMS) {
    if (Object.prototype.hasOwnProperty.call(claims, key)) {
      output[key] = claims[key];
    }
  }
  return output;
};

const firstPartyClaimsForUser = (
  user: UserRow,
  profile: IdentityProfileRow | null,
): Record<string, unknown> => {
  const passportVerified = Boolean(profile?.passport_verified_at);
  const faceVerified = Boolean(profile?.face_verified_at);
  const profileCompleted =
    user.onboarding_status === "completed" || (passportVerified && faceVerified);
  const publicName = user.public_nickname || user.display_name || user.username || null;

  return {
    ...(publicName
      ? {
          nickname: publicName,
          preferred_username: publicName,
        }
      : {}),
    profile_completed: profileCompleted,
    passport_verified: passportVerified,
    face_verified: faceVerified,
  };
};

const selectApprovedClaims = (
  availableClaims: Record<string, unknown>,
  approvedClaims?: Record<string, unknown> | null,
): Record<string, unknown> => {
  if (!approvedClaims) {
    return availableClaims;
  }

  const selected: Record<string, unknown> = {};
  for (const claim of OIDC_SHAREABLE_CLAIMS) {
    if (
      approvedClaims[claim.key] === true &&
      availableClaims[claim.key] !== undefined &&
      availableClaims[claim.key] !== null
    ) {
      selected[claim.key] = availableClaims[claim.key];
    }
  }

  // Keep preferred_username aligned with nickname only when nickname is shared.
  if (selected.nickname && availableClaims.preferred_username) {
    selected.preferred_username = availableClaims.preferred_username;
  }

  return selected;
};

const appendAuthorizeError = (input: {
  redirectUri: string;
  error: string;
  errorDescription?: string;
  state?: string | null;
}): string => {
  const redirectUrl = new URL(input.redirectUri);
  redirectUrl.searchParams.set("error", input.error);
  if (input.errorDescription) {
    redirectUrl.searchParams.set("error_description", input.errorDescription);
  }
  if (input.state) {
    redirectUrl.searchParams.set("state", input.state);
  }
  return redirectUrl.toString();
};

export const createOidcProviderService = (
  dependencies: OidcProviderServiceDependencies = {},
) => {
  const issuer = normalizeIssuer(dependencies.issuer ?? authPolicy.issuer);
  const now = dependencies.now ?? (() => new Date());
  const randomBytesForService = dependencies.randomBytesFn ?? randomBytes;
  const oidcProviderRepository =
    dependencies.oidcProviderRepositoryLike ?? defaultOidcProviderRepository;
  const oidcSigningKeyRepository =
    dependencies.oidcSigningKeyRepositoryLike ?? defaultOidcSigningKeyRepository;
  const userRepository = dependencies.userRepositoryLike ?? defaultUserRepository;
  const identityProfileRepository =
    dependencies.identityProfileRepositoryLike ?? defaultIdentityProfileRepository;

  const getOrCreatePairwiseSubject = async (
    userId: string,
    client: OidcClientRow,
  ): Promise<OidcPairwiseSubjectRow> => {
    const existing = await oidcProviderRepository.getPairwiseSubject({
      userId,
      sectorIdentifier: client.sector_identifier,
    });
    if (existing) {
      return existing;
    }

    try {
      return await oidcProviderRepository.insertPairwiseSubject({
        userId,
        sectorIdentifier: client.sector_identifier,
        subjectIdentifier: createRandomToken(
          randomBytesForService,
          PAIRWISE_SUBJECT_BYTES,
        ),
        firstClientDbId: client.id,
      });
    } catch (error) {
      const afterRace = await oidcProviderRepository.getPairwiseSubject({
        userId,
        sectorIdentifier: client.sector_identifier,
      });
      if (afterRace) {
        return afterRace;
      }
      throw error;
    }
  };

  const getQrValidatedRequest = async (
    transaction: OidcAuthorizeQrTransactionRow,
  ): Promise<ValidatedAuthorizationRequest | null> => {
    const [authorizationRequest, client] = await Promise.all([
      oidcProviderRepository.getAuthorizationRequestById(
        transaction.authorization_request_id,
      ),
      oidcProviderRepository.getClientById(transaction.client_id),
    ]);

    if (!authorizationRequest || !client || client.status !== "active") {
      return null;
    }

    return {
      client,
      redirectUri: authorizationRequest.redirect_uri,
      responseType: authorizationRequest.response_type,
      scopes: authorizationRequest.scopes,
      state: authorizationRequest.state,
      nonce: authorizationRequest.nonce,
      codeChallenge: authorizationRequest.code_challenge,
      codeChallengeMethod: authorizationRequest.code_challenge_method,
    };
  };

  const isQrTransactionExpired = (
    transaction: OidcAuthorizeQrTransactionRow,
    effectiveNow: Date,
  ): boolean => {
    if (transaction.status === "pending") {
      return new Date(transaction.expires_at).getTime() <= effectiveNow.getTime();
    }

    if (
      (transaction.status === "approved" || transaction.status === "denied") &&
      transaction.result_expires_at
    ) {
      return (
        new Date(transaction.result_expires_at).getTime() <= effectiveNow.getTime()
      );
    }

    return false;
  };

  const classifyQrSecretFailure = async (input: {
    transaction: OidcAuthorizeQrTransactionRow | null;
    secretHash: string;
    effectiveNow: Date;
  }): Promise<{ success: false; status: number; error: string } | null> => {
    if (!input.transaction) {
      return {
        success: false,
        status: 404,
        error: "authorization_request_not_found",
      };
    }

    if (
      input.transaction.status === "expired" ||
      isQrTransactionExpired(input.transaction, input.effectiveNow)
    ) {
      await oidcProviderRepository.expireAuthorizeQrTransaction(
        input.transaction.request_id,
      );
      return {
        success: false,
        status: 410,
        error: "authorization_request_expired",
      };
    }

    if (input.transaction.status !== "pending") {
      return {
        success: false,
        status: 409,
        error: "authorization_request_already_used",
      };
    }

    if (input.transaction.secret_hash !== input.secretHash) {
      return {
        success: false,
        status: 403,
        error: "authorization_request_secret_invalid",
      };
    }

    return null;
  };

  const approveValidatedAuthorizationRequest = async (input: {
    request: ValidatedAuthorizationRequest;
    viewer: ViewerContext;
    authSessionId?: string | null;
    approvedClaims?: Record<string, unknown> | null;
  }): Promise<{ redirectTo: string }> => {
    const effectiveNow = now();
    const expiresAt = new Date(
      effectiveNow.getTime() +
        input.request.client.authorization_code_ttl_seconds * 1000,
    ).toISOString();
    const pairwiseSubject = await getOrCreatePairwiseSubject(
      input.viewer.userId,
      input.request.client,
    );
    const availableClaims = firstPartyClaimsForUser(
      input.viewer.user,
      await identityProfileRepository.getByUserId(input.viewer.userId),
    );
    const claims = selectApprovedClaims(availableClaims, input.approvedClaims);
    await oidcProviderRepository.upsertGrant({
      userId: input.viewer.userId,
      clientDbId: input.request.client.id,
      pairwiseSubjectId: pairwiseSubject.id,
      scopes: input.request.scopes,
      claims,
    });

    const authorizationRequest =
      await oidcProviderRepository.insertAuthorizationRequest({
        requestId: createRandomToken(
          randomBytesForService,
          AUTHORIZATION_REQUEST_ID_BYTES,
        ),
        clientDbId: input.request.client.id,
        userId: input.viewer.userId,
        authSessionId: input.authSessionId ?? null,
        redirectUri: input.request.redirectUri,
        scopes: input.request.scopes,
        state: input.request.state,
        nonce: input.request.nonce,
        codeChallenge: input.request.codeChallenge,
        codeChallengeMethod: input.request.codeChallengeMethod,
        expiresAt,
      });

    const authorizationCode = createRandomToken(
      randomBytesForService,
      AUTHORIZATION_CODE_BYTES,
    );
    await oidcProviderRepository.insertAuthorizationCode({
      codeHash: hashOpaqueBearerToken(authorizationCode),
      authorizationRequestId: authorizationRequest.id,
      clientDbId: input.request.client.id,
      userId: input.viewer.userId,
      authSessionId: input.authSessionId ?? null,
      pairwiseSubjectId: pairwiseSubject.id,
      redirectUri: input.request.redirectUri,
      scopes: input.request.scopes,
      nonce: input.request.nonce,
      codeChallenge: input.request.codeChallenge,
      codeChallengeMethod: input.request.codeChallengeMethod,
      authGeneration: input.viewer.user.auth_generation,
      expiresAt,
    });

    const redirectUrl = new URL(input.request.redirectUri);
    redirectUrl.searchParams.set("code", authorizationCode);
    if (input.request.state) {
      redirectUrl.searchParams.set("state", input.request.state);
    }

    return {
      redirectTo: redirectUrl.toString(),
    };
  };

  return {
    async validateAuthorizationRequest(
      params: URLSearchParams,
    ): Promise<AuthorizationValidationResult> {
      const clientId = params.get("client_id")?.trim() || "";
      const redirectUri = params.get("redirect_uri")?.trim() || "";
      const state = parseOptional(params.get("state"));

      if (!clientId) {
        return {
          success: false,
          error: "invalid_request",
          message: "Missing client_id.",
        };
      }

      const client = await oidcProviderRepository.getClientByClientId(clientId);
      if (!client || client.status !== "active") {
        return {
          success: false,
          error: "unauthorized_client",
          message: "OIDC client is not active or does not exist.",
        };
      }

      if (!redirectUri) {
        return {
          success: false,
          error: "invalid_request",
          message: "Missing redirect_uri.",
        };
      }

      const registeredRedirectUri = await oidcProviderRepository.getRedirectUri({
        clientDbId: client.id,
        usage: "redirect",
        redirectUri,
      });
      if (!registeredRedirectUri) {
        return {
          success: false,
          error: "invalid_request",
          message: "redirect_uri is not registered for this client.",
        };
      }

      const responseType = params.get("response_type");
      if (responseType !== "code") {
        return {
          success: false,
          error: "unsupported_response_type",
          message: "Only response_type=code is supported.",
          redirectUri,
          state,
        };
      }

      const scopes = splitScope(params.get("scope"));
      const unsupportedScopes = scopes.filter(
        (scope) => !client.allowed_scopes.includes(scope),
      );
      if (!scopes.includes("openid") || unsupportedScopes.length > 0) {
        return {
          success: false,
          error: "invalid_scope",
          message: "Requested scopes are not allowed for this client.",
          redirectUri,
          state,
        };
      }

      const codeChallenge = params.get("code_challenge")?.trim() || "";
      if (!codeChallenge) {
        return {
          success: false,
          error: "invalid_request",
          message: "Missing PKCE code_challenge.",
          redirectUri,
          state,
        };
      }

      const codeChallengeMethod = params.get("code_challenge_method");
      if (codeChallengeMethod !== "S256") {
        return {
          success: false,
          error: "invalid_request",
          message: "Only code_challenge_method=S256 is supported.",
          redirectUri,
          state,
        };
      }

      return {
        success: true,
        request: {
          client,
          redirectUri,
          responseType: "code",
          scopes,
          state,
          nonce: parseOptional(params.get("nonce")),
          codeChallenge,
          codeChallengeMethod,
        },
      };
    },

    async approveAuthorizationRequest(input: {
      request: ValidatedAuthorizationRequest;
      viewer: ViewerContext;
      authSessionId?: string | null;
      approvedClaims?: Record<string, unknown> | null;
    }): Promise<{ redirectTo: string }> {
      return approveValidatedAuthorizationRequest(input);
    },

    async createAuthorizationQrTransaction(request: ValidatedAuthorizationRequest): Promise<{
      requestId: string;
      pollSecret: string;
      expiresAt: string;
      qrPayload: Record<string, unknown>;
    }> {
      const effectiveNow = now();
      const requestId = createRandomToken(
        randomBytesForService,
        OIDC_AUTHORIZE_QR_TRANSACTION_ID_BYTES,
      );
      const secret = createRandomToken(
        randomBytesForService,
        OIDC_AUTHORIZE_QR_SECRET_BYTES,
      );
      const pollSecret = createRandomToken(
        randomBytesForService,
        OIDC_AUTHORIZE_QR_POLL_SECRET_BYTES,
      );
      const expiresAtMs = effectiveNow.getTime() + OIDC_AUTHORIZE_QR_TTL_MS;
      const expiresAt = new Date(expiresAtMs).toISOString();

      const authorizationRequest =
        await oidcProviderRepository.insertPendingAuthorizationRequest({
          requestId,
          clientDbId: request.client.id,
          redirectUri: request.redirectUri,
          scopes: request.scopes,
          state: request.state,
          nonce: request.nonce,
          codeChallenge: request.codeChallenge,
          codeChallengeMethod: request.codeChallengeMethod,
          expiresAt,
        });

      await oidcProviderRepository.insertAuthorizeQrTransaction({
        requestId,
        authorizationRequestId: authorizationRequest.id,
        clientDbId: request.client.id,
        secretHash: sha256Hex(secret),
        pollSecretHash: sha256Hex(pollSecret),
        expiresAt,
      });

      return {
        requestId,
        pollSecret,
        expiresAt,
        qrPayload: {
          type: OIDC_AUTHORIZE_QR_TYPE,
          version: OIDC_AUTHORIZE_QR_VERSION,
          requestId,
          secret,
          approveUrl: `${issuer}/authorize/approve`,
          audience: request.client.client_id,
          clientName: request.client.client_name,
          scopes: request.scopes,
          expiresAt,
        },
      };
    },

    async getAuthorizationQrTransactionStatus(input: {
      requestId: string;
      pollSecret: string;
    }): Promise<AuthorizationQrTransactionStatus> {
      const effectiveNow = now();
      const transaction =
        await oidcProviderRepository.getAuthorizeQrTransactionByRequestId(
          input.requestId,
        );
      if (!transaction || transaction.poll_secret_hash !== sha256Hex(input.pollSecret)) {
        return { status: "not_found" };
      }

      if (isQrTransactionExpired(transaction, effectiveNow)) {
        await oidcProviderRepository.expireAuthorizeQrTransaction(
          transaction.request_id,
        );
        return { status: "expired" };
      }

      if (transaction.status === "expired") {
        return { status: "expired" };
      }

      if (transaction.status === "approved") {
        if (transaction.code_delivered_at) {
          return { status: "not_found" };
        }

        const client = await oidcProviderRepository.getClientById(
          transaction.client_id,
        );
        if (!client || client.status !== "active") {
          return { status: "not_found" };
        }

        const authorizationCode = createRandomToken(
          randomBytesForService,
          AUTHORIZATION_CODE_BYTES,
        );
        const codeExpiresAt = new Date(
          effectiveNow.getTime() + client.authorization_code_ttl_seconds * 1000,
        ).toISOString();
        const delivery = await oidcProviderRepository.deliverAuthorizeQrCode({
          requestId: input.requestId,
          pollSecretHash: sha256Hex(input.pollSecret),
          codeHash: hashOpaqueBearerToken(authorizationCode),
          codeExpiresAt,
          now: effectiveNow.toISOString(),
        });

        if (!delivery) {
          return { status: "not_found" };
        }

        const redirectUrl = new URL(delivery.redirect_uri);
        redirectUrl.searchParams.set("code", authorizationCode);
        if (delivery.state) {
          redirectUrl.searchParams.set("state", delivery.state);
        }

        return {
          status: "approved",
          redirectTo: redirectUrl.toString(),
          expiresAt: codeExpiresAt,
        };
      }

      if (transaction.status === "denied") {
        const authorizationRequest =
          await oidcProviderRepository.getAuthorizationRequestById(
            transaction.authorization_request_id,
          );
        if (!authorizationRequest) {
          return { status: "not_found" };
        }

        return {
          status: "denied",
          redirectTo: appendAuthorizeError({
            redirectUri: authorizationRequest.redirect_uri,
            error: "access_denied",
            errorDescription: "The user denied the authorization request.",
            state: authorizationRequest.state,
          }),
          expiresAt: transaction.result_expires_at || transaction.expires_at,
        };
      }

      return {
        status: "pending",
        expiresAt: transaction.expires_at,
      };
    },

    async previewAuthorizationQrTransaction(input: {
      requestId: string;
      secret: string;
      viewer: ViewerContext;
    }): Promise<
      | {
          success: true;
          body: Record<string, unknown>;
        }
      | { success: false; status: number; error: string }
    > {
      const effectiveNow = now();
      const secretHash = sha256Hex(input.secret);
      const transaction =
        await oidcProviderRepository.getAuthorizeQrTransactionByRequestId(
          input.requestId,
        );
      const failure = await classifyQrSecretFailure({
        transaction,
        secretHash,
        effectiveNow,
      });
      if (failure) {
        return failure;
      }

      const request = transaction ? await getQrValidatedRequest(transaction) : null;
      if (!transaction || !request) {
        return {
          success: false,
          status: 404,
          error: "authorization_request_not_found",
        };
      }

      const availableClaims = firstPartyClaimsForUser(
        input.viewer.user,
        await identityProfileRepository.getByUserId(input.viewer.userId),
      );
      const claimOptions = OIDC_SHAREABLE_CLAIMS.map((claim) => ({
        key: claim.key,
        label: claim.label,
        description: claim.description,
        value: availableClaims[claim.key],
        defaultSelected: request.scopes.includes("profile"),
      }));

      return {
        success: true,
        body: {
          requestId: transaction.request_id,
          expiresAt: transaction.expires_at,
          client: {
            clientId: request.client.client_id,
            clientName: request.client.client_name,
            sectorIdentifier: request.client.sector_identifier,
            clientUri: request.client.client_uri,
            logoUri: request.client.logo_uri,
            tosUri: request.client.tos_uri,
            policyUri: request.client.policy_uri,
          },
          scopes: request.scopes,
          claimOptions,
        },
      };
    },

    async denyAuthorizationQrTransaction(input: {
      requestId: string;
      secret: string;
    }): Promise<{ success: true } | { success: false; status: number; error: string }> {
      const effectiveNow = now();
      const secretHash = sha256Hex(input.secret);
      const transaction =
        await oidcProviderRepository.getAuthorizeQrTransactionByRequestId(
          input.requestId,
        );
      const failure = await classifyQrSecretFailure({
        transaction,
        secretHash,
        effectiveNow,
      });
      if (failure) {
        return failure;
      }

      const resultExpiresAt = new Date(
        effectiveNow.getTime() + OIDC_AUTHORIZE_QR_APPROVED_RESULT_TTL_MS,
      ).toISOString();
      const denied = await oidcProviderRepository.denyAuthorizeQrTransaction({
        requestId: input.requestId,
        secretHash,
        resultExpiresAt,
        now: effectiveNow.toISOString(),
      });

      if (!denied) {
        const latest =
          await oidcProviderRepository.getAuthorizeQrTransactionByRequestId(
            input.requestId,
          );
        return (
          (await classifyQrSecretFailure({
            transaction: latest,
            secretHash,
            effectiveNow,
          })) || {
            success: false,
            status: 409,
            error: "authorization_request_already_used",
          }
        );
      }

      return { success: true };
    },

    async approveAuthorizationQrTransaction(input: {
      requestId: string;
      secret: string;
      viewer: ViewerContext;
      authSessionId?: string | null;
      approvedClaims?: Record<string, unknown> | null;
    }): Promise<{ success: true } | { success: false; status: number; error: string }> {
      const effectiveNow = now();
      const secretHash = sha256Hex(input.secret);
      const transaction =
        await oidcProviderRepository.getAuthorizeQrTransactionByRequestId(
          input.requestId,
        );
      const failure = await classifyQrSecretFailure({
        transaction,
        secretHash,
        effectiveNow,
      });
      if (failure) {
        return failure;
      }

      const request = transaction ? await getQrValidatedRequest(transaction) : null;
      if (!request) {
        return {
          success: false,
          status: 404,
          error: "authorization_request_not_found",
        };
      }

      const pairwiseSubject = await getOrCreatePairwiseSubject(
        input.viewer.userId,
        request.client,
      );
      const availableClaims = firstPartyClaimsForUser(
        input.viewer.user,
        await identityProfileRepository.getByUserId(input.viewer.userId),
      );
      const claims = selectApprovedClaims(
        availableClaims,
        input.approvedClaims ?? null,
      );
      const grant = await oidcProviderRepository.upsertGrant({
        userId: input.viewer.userId,
        clientDbId: request.client.id,
        pairwiseSubjectId: pairwiseSubject.id,
        scopes: request.scopes,
        claims,
      });
      const resultExpiresAt = new Date(
        effectiveNow.getTime() + OIDC_AUTHORIZE_QR_APPROVED_RESULT_TTL_MS,
      ).toISOString();
      const approved = await oidcProviderRepository.approveAuthorizeQrTransaction({
        requestId: input.requestId,
        secretHash,
        userId: input.viewer.userId,
        authSessionId: input.authSessionId ?? null,
        pairwiseSubjectId: pairwiseSubject.id,
        grantId: grant.id,
        approvedAuthGeneration: input.viewer.user.auth_generation,
        approvedClaims: claims,
        resultExpiresAt,
        now: effectiveNow.toISOString(),
      });

      if (!approved) {
        const latest =
          await oidcProviderRepository.getAuthorizeQrTransactionByRequestId(
            input.requestId,
          );
        return (
          (await classifyQrSecretFailure({
            transaction: latest,
            secretHash,
            effectiveNow,
          })) || {
            success: false,
            status: 409,
            error: "authorization_request_already_used",
          }
        );
      }

      return { success: true };
    },

    async exchangeAuthorizationCode(input: {
      form: URLSearchParams;
      authorizationHeader: string | null;
    }): Promise<TokenExchangeResult> {
      const grantType = input.form.get("grant_type");
      if (grantType !== "authorization_code") {
        return buildFailure(
          "unsupported_grant_type",
          "Only grant_type=authorization_code is supported.",
        );
      }

      const code = input.form.get("code")?.trim() || "";
      const redirectUri = input.form.get("redirect_uri")?.trim() || "";
      const codeVerifier = input.form.get("code_verifier")?.trim() || "";
      const clientIdFromBody = input.form.get("client_id")?.trim() || "";
      const clientSecretFromBody = input.form.get("client_secret") || "";
      const basicAuth = extractBasicClientAuth(input.authorizationHeader);
      const clientId = basicAuth?.clientId || clientIdFromBody;
      const clientSecret = basicAuth?.clientSecret || clientSecretFromBody;

      if (!code || !redirectUri || !codeVerifier || !clientId) {
        return buildFailure(
          "invalid_request",
          "code, redirect_uri, code_verifier, and client_id are required.",
        );
      }

      if (basicAuth && clientIdFromBody && basicAuth.clientId !== clientIdFromBody) {
        return buildFailure(
          "invalid_client",
          "Basic-auth client_id does not match request client_id.",
          401,
        );
      }

      const client = await oidcProviderRepository.getClientByClientId(clientId);
      if (!client || client.status !== "active") {
        return buildFailure("invalid_client", "Client was not found.", 401);
      }

      if (client.client_type === "confidential") {
        if (!clientSecret) {
          return buildFailure(
            "invalid_client",
            "Confidential client authentication is required.",
            401,
          );
        }

        const secretRow = await oidcProviderRepository.getActiveSecretByHash({
          clientDbId: client.id,
          secretHash: sha256Hex(clientSecret),
        });
        if (!secretRow) {
          return buildFailure("invalid_client", "Client secret is invalid.", 401);
        }
        await oidcProviderRepository.touchClientSecret(secretRow.id);
      }

      const authorizationCode =
        await oidcProviderRepository.getAuthorizationCodeByHash(
          hashOpaqueBearerToken(code),
        );
      if (!authorizationCode || authorizationCode.status !== "active") {
        return buildFailure(
          "invalid_grant",
          "Authorization code is not active or does not exist.",
        );
      }

      if (authorizationCode.client_id !== client.id) {
        return buildFailure(
          "invalid_grant",
          "Authorization code was not issued to this client.",
        );
      }

      if (authorizationCode.redirect_uri !== redirectUri) {
        return buildFailure(
          "invalid_grant",
          "redirect_uri does not match the authorization request.",
        );
      }

      if (new Date(authorizationCode.expires_at).getTime() <= now().getTime()) {
        await oidcProviderRepository.expireAuthorizationCode(authorizationCode.id);
        return buildFailure("invalid_grant", "Authorization code has expired.");
      }

      if (authorizationCode.code_challenge_method !== "S256") {
        return buildFailure("invalid_grant", "Unsupported PKCE method on code.");
      }

      if (sha256Base64Url(codeVerifier) !== authorizationCode.code_challenge) {
        return buildFailure("invalid_grant", "PKCE verification failed.");
      }

      const user = await userRepository.getById(authorizationCode.user_id);
      if (!user || user.account_status !== "active") {
        return buildFailure("invalid_grant", "Authorization user is not active.");
      }

      if (user.auth_generation !== authorizationCode.auth_generation) {
        return buildFailure(
          "invalid_grant",
          "Authorization code is stale for the current auth generation.",
        );
      }

      const pairwiseSubject = await oidcProviderRepository.getPairwiseSubjectById(
        authorizationCode.pairwise_subject_id,
      );
      if (!pairwiseSubject) {
        return buildFailure("server_error", "Pairwise subject was not found.", 500);
      }

      const signingKeys = await oidcSigningKeyRepository.listPublicSigningKeys();
      const signingKey = signingKeys.find((row) => isUsableSigningKey(row, now()));
      const privateKeyPem = signingKey ? loadPrivateKeyForSigningKey(signingKey) : null;
      if (!signingKey || !privateKeyPem) {
        return buildFailure(
          "server_error",
          "No active OIDC RS256 signing key is configured for token issuance.",
          500,
        );
      }

      const consumedCode = await oidcProviderRepository.consumeAuthorizationCode(
        authorizationCode.id,
      );
      if (!consumedCode) {
        return buildFailure(
          "invalid_grant",
          "Authorization code was already consumed.",
        );
      }
      await oidcProviderRepository.consumeAuthorizationRequest(
        authorizationCode.authorization_request_id,
      );

      const profile = await identityProfileRepository.getByUserId(user.id);
      const userClaims = firstPartyClaimsForUser(user, profile);
      const grant =
        (await oidcProviderRepository.getGrantByUserAndClient({
          userId: user.id,
          clientDbId: client.id,
        })) ||
        (await oidcProviderRepository.upsertGrant({
          userId: user.id,
          clientDbId: client.id,
          pairwiseSubjectId: pairwiseSubject.id,
          scopes: authorizationCode.scopes,
          claims: userClaims,
        }));
      const tokenClaims = grant.claims || userClaims;
      // Phase 2 security decision:
      // ID tokens are authentication/assurance artifacts only. Mutable public
      // profile and verification proof claims stay in the opaque access-token
      // snapshot and are released through UserInfo after RP/user consent. This
      // keeps the RP integration aligned with future proof/ZKP presentation
      // flows instead of training RPs to treat ID tokens as proof containers.
      const issuedAtSeconds = Math.floor(now().getTime() / 1000);
      const expiresAtSeconds = issuedAtSeconds + client.access_token_ttl_seconds;
      const accessToken = createOpaqueBearerToken();
      const idToken = signJwtRs256(
        {
          alg: "RS256",
          kid: signingKey.kid,
          typ: "JWT",
        },
        {
          iss: issuer,
          sub: pairwiseSubject.subject_identifier,
          aud: client.client_id,
          exp: expiresAtSeconds,
          iat: issuedAtSeconds,
          auth_time: Math.floor(
            new Date(authorizationCode.created_at).getTime() / 1000,
          ),
          ...(authorizationCode.nonce ? { nonce: authorizationCode.nonce } : {}),
          amr: ["civicos_app"],
          acr: profile?.face_verified_at
            ? "urn:civicos:verified:passport-face"
            : "urn:civicos:verified:app-session",
        },
        privateKeyPem,
      );

      const tokenResponse: TokenExchangeSuccess["body"] = {
        access_token: accessToken.token,
        token_type: "Bearer",
        expires_in: client.access_token_ttl_seconds,
        scope: authorizationCode.scopes.join(" "),
        id_token: idToken,
      };

      await oidcProviderRepository.insertAccessToken({
        tokenHash: accessToken.tokenHash,
        grantId: grant.id,
        authSessionId: authorizationCode.auth_session_id,
        clientDbId: client.id,
        userId: user.id,
        pairwiseSubjectId: pairwiseSubject.id,
        scopes: authorizationCode.scopes,
        claims: tokenClaims,
        authGeneration: user.auth_generation,
        expiresAt: new Date(expiresAtSeconds * 1000).toISOString(),
      });

      let issuedRefreshToken = false;
      if (authorizationCode.scopes.includes("offline_access")) {
        const refreshToken = createRandomToken(
          randomBytesForService,
          OIDC_REFRESH_TOKEN_BYTES,
        );

        await oidcProviderRepository.insertRefreshTokenFamily({
          grantId: grant.id,
          authSessionId: authorizationCode.auth_session_id,
          clientDbId: client.id,
          userId: user.id,
          currentTokenHash: hashOpaqueBearerToken(refreshToken),
          authGeneration: user.auth_generation,
          expiresAt: new Date(
            now().getTime() + client.refresh_token_ttl_days * 24 * 60 * 60 * 1000,
          ).toISOString(),
        });
        tokenResponse.refresh_token = refreshToken;
        issuedRefreshToken = true;
      }

      return {
        success: true,
        body: tokenResponse,
        audit: {
          clientDbId: client.id,
          clientId: client.client_id,
          userId: user.id,
          authSessionId: authorizationCode.auth_session_id,
          authorizationRequestId: authorizationCode.authorization_request_id,
          grantId: grant.id,
          scopes: authorizationCode.scopes,
          issuedRefreshToken,
        },
      };
    },

    async getUserInfo(input: {
      accessToken: string;
    }): Promise<UserInfoResult> {
      const accessToken = await oidcProviderRepository.getAccessTokenByHash(
        hashOpaqueBearerToken(input.accessToken),
      );

      if (!accessToken || accessToken.status !== "active") {
        return {
          success: false,
          status: 401,
          error: "invalid_token",
          error_description: "Access token is not active or does not exist.",
        };
      }

      if (new Date(accessToken.expires_at).getTime() <= now().getTime()) {
        await oidcProviderRepository.expireAccessToken(accessToken.id);
        return {
          success: false,
          status: 401,
          error: "invalid_token",
          error_description: "Access token has expired.",
        };
      }

      const user = await userRepository.getById(accessToken.user_id);
      if (!user || user.account_status !== "active") {
        return {
          success: false,
          status: 401,
          error: "invalid_token",
          error_description: "Access token user is not active.",
        };
      }

      if (user.auth_generation !== accessToken.auth_generation) {
        return {
          success: false,
          status: 401,
          error: "invalid_token",
          error_description: "Access token is stale for the current auth generation.",
        };
      }

      const pairwiseSubject = await oidcProviderRepository.getPairwiseSubjectById(
        accessToken.pairwise_subject_id,
      );
      if (!pairwiseSubject) {
        return {
          success: false,
          status: 500,
          error: "server_error",
          error_description: "Pairwise subject was not found.",
        };
      }

      await oidcProviderRepository.touchAccessToken(accessToken.id);

      // UserInfo is intentionally treated as a claims/proofs endpoint. It
      // returns the pairwise subject and consent-filtered claims only; it must
      // never return raw identity evidence or internal CivicOS identifiers.
      return {
        success: true,
        body: {
          sub: pairwiseSubject.subject_identifier,
          ...filterUserInfoClaims(accessToken.scopes, accessToken.claims),
        },
      };
    },

    async revokeToken(input: {
      form: URLSearchParams;
      authorizationHeader: string | null;
    }): Promise<TokenRevocationResult> {
      const token = input.form.get("token")?.trim() || "";
      const tokenTypeHint = input.form.get("token_type_hint")?.trim() || "";
      const clientIdFromBody = input.form.get("client_id")?.trim() || "";
      const clientSecretFromBody = input.form.get("client_secret") || "";
      const basicAuth = extractBasicClientAuth(input.authorizationHeader);
      const clientId = basicAuth?.clientId || clientIdFromBody;
      const clientSecret = basicAuth?.clientSecret || clientSecretFromBody;

      if (!token) {
        return {
          success: false,
          status: 400,
          error: "invalid_request",
          error_description: "token is required.",
        };
      }

      if (!clientId) {
        return {
          success: false,
          status: 401,
          error: "invalid_client",
          error_description: "Client authentication is required.",
        };
      }

      if (basicAuth && clientIdFromBody && basicAuth.clientId !== clientIdFromBody) {
        return {
          success: false,
          status: 401,
          error: "invalid_client",
          error_description: "Basic-auth client_id does not match request client_id.",
        };
      }

      const client = await oidcProviderRepository.getClientByClientId(clientId);
      if (!client || client.status !== "active") {
        return {
          success: false,
          status: 401,
          error: "invalid_client",
          error_description: "Client was not found.",
        };
      }

      if (client.client_type === "confidential") {
        if (!clientSecret) {
          return {
            success: false,
            status: 401,
            error: "invalid_client",
            error_description: "Confidential client authentication is required.",
          };
        }

        const secretRow = await oidcProviderRepository.getActiveSecretByHash({
          clientDbId: client.id,
          secretHash: sha256Hex(clientSecret),
        });
        if (!secretRow) {
          return {
            success: false,
            status: 401,
            error: "invalid_client",
            error_description: "Client secret is invalid.",
          };
        }
        await oidcProviderRepository.touchClientSecret(secretRow.id);
      }

      const tokenHash = hashOpaqueBearerToken(token);
      const revokeAccessToken = async () =>
        oidcProviderRepository.revokeAccessTokenByHash({
          tokenHash,
          clientDbId: client.id,
          revocationReason: "rp_token_revocation",
        });

      const revokeRefreshToken = async () => {
        const refreshFamily =
          await oidcProviderRepository.getRefreshTokenFamilyByTokenHash({
            tokenHash,
            clientDbId: client.id,
          });
        if (refreshFamily) {
          await oidcProviderRepository.revokeRefreshTokenFamilyById({
            familyId: refreshFamily.id,
            status: "revoked",
            revocationReason: "rp_token_revocation",
          });
        }
      };

      if (tokenTypeHint === "refresh_token") {
        await revokeRefreshToken();
        await revokeAccessToken();
      } else {
        await revokeAccessToken();
        await revokeRefreshToken();
      }

      // RFC 7009-compatible behavior: do not reveal whether the token existed.
      return { success: true };
    },
  };
};

export const oidcProviderService = createOidcProviderService();

export default oidcProviderService;
