import { createHash } from "node:crypto";

import { describe, expect, it } from "bun:test";

import { createOidcProviderService } from "./oidcProviderService";

const BASE_TIME_MS = Date.parse("2026-07-01T10:00:00.000Z");
const BASE_TIME_ISO = new Date(BASE_TIME_MS).toISOString();
const REDIRECT_URI = "https://codeiland-back.example/auth/callback";

const pkceChallengeFor = (verifier: string): string =>
  createHash("sha256").update(verifier, "utf8").digest("base64url");

const makeClient = (overrides: Record<string, unknown> = {}) =>
  ({
    id: "client-db-id",
    client_id: "codeiland-web",
    client_name: "Code iLand",
    client_type: "public",
    application_type: "web",
    status: "active",
    client_uri: "https://www.codeiland.com",
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
    authorization_code_ttl_seconds: 60,
    refresh_token_ttl_days: 30,
    created_at: BASE_TIME_ISO,
    updated_at: BASE_TIME_ISO,
    ...overrides,
  }) as any;

const makeAuthorizationRequest = (overrides: Record<string, unknown> = {}) =>
  ({
    client: makeClient(),
    redirectUri: REDIRECT_URI,
    responseType: "code",
    scopes: ["openid", "profile"],
    state: "state-1",
    nonce: "nonce-1",
    codeChallenge: pkceChallengeFor("verifier-1"),
    codeChallengeMethod: "S256",
    ...overrides,
  }) as any;

const makeViewer = () =>
  ({
    userId: "user-1",
    user: {
      id: "user-1",
      account_status: "active",
      auth_generation: 3,
      onboarding_status: "completed",
      public_nickname: "public-name",
      display_name: null,
      username: null,
    },
  }) as any;

const makeIdentityProfile = () =>
  ({
    user_id: "user-1",
    passport_verified_at: BASE_TIME_ISO,
    face_verified_at: BASE_TIME_ISO,
  }) as any;

const makePairwiseSubject = () =>
  ({
    id: "pairwise-1",
    user_id: "user-1",
    sector_identifier: "codeiland.com",
    subject_identifier: "pairwise-subject-1",
    first_client_id: "client-db-id",
    created_at: BASE_TIME_ISO,
    updated_at: BASE_TIME_ISO,
  }) as any;

const makeGrant = (input: any) =>
  ({
    id: "grant-1",
    user_id: input.userId,
    client_id: input.clientDbId,
    pairwise_subject_id: input.pairwiseSubjectId,
    status: "active",
    scopes: input.scopes,
    claims: input.claims,
    consented_at: BASE_TIME_ISO,
    expires_at: null,
    revoked_at: null,
    revocation_reason: null,
    created_at: BASE_TIME_ISO,
    updated_at: BASE_TIME_ISO,
  }) as any;

const makeAuthorizationCodeRow = (overrides: Record<string, unknown> = {}) =>
  ({
    id: "code-db-id",
    authorization_request_id: "authorization-request-db-id",
    client_id: "client-db-id",
    user_id: "user-1",
    auth_session_id: "auth-session-1",
    pairwise_subject_id: "pairwise-1",
    code_hash: "code-hash",
    status: "active",
    redirect_uri: REDIRECT_URI,
    scopes: ["openid", "profile"],
    nonce: "nonce-1",
    code_challenge: pkceChallengeFor("verifier-1"),
    code_challenge_method: "S256",
    auth_generation: 3,
    expires_at: new Date(BASE_TIME_MS + 60_000).toISOString(),
    consumed_at: null,
    revoked_at: null,
    revocation_reason: null,
    created_at: BASE_TIME_ISO,
    updated_at: BASE_TIME_ISO,
    ...overrides,
  }) as any;

const makeTokenForm = (overrides: Record<string, string> = {}) => {
  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code: "authorization-code-1",
    redirect_uri: REDIRECT_URI,
    code_verifier: "verifier-1",
    client_id: "codeiland-web",
    ...overrides,
  });
  return form;
};

const createQrTestService = () => {
  let nowMs = BASE_TIME_MS;
  let randomByte = 1;
  const pairwiseSubject = makePairwiseSubject();

  const oidcProviderRepositoryLike = {
    getPairwiseSubject: async () => null,
    insertPairwiseSubject: async () => pairwiseSubject,
    upsertGrant: async (input: any) => makeGrant(input),
    insertAuthorizationRequest: async (input: any) =>
      ({
        id: "authorization-request-db-id",
        request_id: input.requestId,
        client_id: input.clientDbId,
        user_id: input.userId,
        auth_session_id: input.authSessionId,
        status: "approved",
        response_type: "code",
        redirect_uri: input.redirectUri,
        scopes: input.scopes,
        state: input.state,
        nonce: input.nonce,
        code_challenge: input.codeChallenge,
        code_challenge_method: input.codeChallengeMethod,
        prompt: [],
        max_age_seconds: null,
        ui_locales: [],
        login_hint_hash: null,
        consent_required: false,
        approved_at: BASE_TIME_ISO,
        denied_at: null,
        consumed_at: null,
        expires_at: input.expiresAt,
        created_at: BASE_TIME_ISO,
        updated_at: BASE_TIME_ISO,
      }) as any,
    insertAuthorizationCode: async (input: any) =>
      ({
        id: "code-db-id",
        ...input,
        status: "active",
        consumed_at: null,
        revoked_at: null,
        revocation_reason: null,
        created_at: BASE_TIME_ISO,
        updated_at: BASE_TIME_ISO,
      }) as any,
  };

  const service = createOidcProviderService({
    issuer: "https://iland.example/idp",
    now: () => new Date(nowMs),
    randomBytesFn: (size) => Buffer.alloc(size, randomByte++),
    oidcProviderRepositoryLike: oidcProviderRepositoryLike as any,
    oidcSigningKeyRepositoryLike: { listPublicSigningKeys: async () => [] } as any,
    userRepositoryLike: { getById: async () => null } as any,
    identityProfileRepositoryLike: {
      getByUserId: async () => makeIdentityProfile(),
    } as any,
  });

  return {
    service,
    request: makeAuthorizationRequest(),
    viewer: makeViewer(),
    advance: (milliseconds: number) => {
      nowMs += milliseconds;
    },
  };
};

const createTokenTestService = (
  repositoryOverrides: Record<string, unknown> = {},
) => {
  let nowMs = BASE_TIME_MS;
  const state = {
    expiredAuthorizationCodeId: null as string | null,
  };
  const client = makeClient();

  const oidcProviderRepositoryLike = {
    getClientByClientId: async (clientId: string) =>
      clientId === client.client_id ? client : null,
    getActiveSecretByHash: async () => null,
    touchClientSecret: async () => null,
    getAuthorizationCodeByHash: async () => makeAuthorizationCodeRow(),
    expireAuthorizationCode: async (authorizationCodeId: string) => {
      state.expiredAuthorizationCodeId = authorizationCodeId;
      return makeAuthorizationCodeRow({
        id: authorizationCodeId,
        status: "expired",
      });
    },
    consumeAuthorizationCode: async () => makeAuthorizationCodeRow(),
    consumeAuthorizationRequest: async () => null,
    getPairwiseSubjectById: async () => makePairwiseSubject(),
    getGrantByUserAndClient: async () => null,
    upsertGrant: async (input: any) => makeGrant(input),
    insertRefreshTokenFamily: async () => null,
    insertAccessToken: async () => null,
    ...repositoryOverrides,
  };

  const service = createOidcProviderService({
    issuer: "https://iland.example/idp",
    now: () => new Date(nowMs),
    randomBytesFn: (size) => Buffer.alloc(size, 9),
    oidcProviderRepositoryLike: oidcProviderRepositoryLike as any,
    oidcSigningKeyRepositoryLike: { listPublicSigningKeys: async () => [] } as any,
    userRepositoryLike: { getById: async () => null } as any,
    identityProfileRepositoryLike: {
      getByUserId: async () => makeIdentityProfile(),
    } as any,
  });

  return {
    service,
    state,
    advance: (milliseconds: number) => {
      nowMs += milliseconds;
    },
  };
};

describe("oidcProviderService QR authorize transactions", () => {
  it("expires pending QR authorize transactions before approval", async () => {
    const { service, request, viewer, advance } = createQrTestService();
    const transaction = service.createAuthorizationQrTransaction(request);

    advance(2 * 60 * 1000 + 1);

    const preview = await service.previewAuthorizationQrTransaction({
      requestId: transaction.requestId,
      secret: String(transaction.qrPayload.secret),
      viewer,
    });

    expect(preview).toEqual({
      success: false,
      status: 410,
      error: "authorization_request_expired",
    });
    expect(
      service.getAuthorizationQrTransactionStatus({
        requestId: transaction.requestId,
        pollSecret: transaction.pollSecret,
      }),
    ).toEqual({ status: "not_found" });
  });

  it("rejects wrong QR secrets without consuming the transaction", async () => {
    const { service, request, viewer } = createQrTestService();
    const transaction = service.createAuthorizationQrTransaction(request);

    await expect(
      service.previewAuthorizationQrTransaction({
        requestId: transaction.requestId,
        secret: "wrong-secret",
        viewer,
      }),
    ).resolves.toEqual({
      success: false,
      status: 403,
      error: "authorization_request_secret_invalid",
    });
    await expect(
      service.approveAuthorizationQrTransaction({
        requestId: transaction.requestId,
        secret: "wrong-secret",
        viewer,
      }),
    ).resolves.toEqual({
      success: false,
      status: 403,
      error: "authorization_request_secret_invalid",
    });
    expect(
      service.getAuthorizationQrTransactionStatus({
        requestId: transaction.requestId,
        pollSecret: transaction.pollSecret,
      }).status,
    ).toBe("pending");
  });

  it("does not reveal status to callers with the wrong poll secret", () => {
    const { service, request } = createQrTestService();
    const transaction = service.createAuthorizationQrTransaction(request);

    expect(
      service.getAuthorizationQrTransactionStatus({
        requestId: transaction.requestId,
        pollSecret: "wrong-poll-secret",
      }),
    ).toEqual({ status: "not_found" });
    expect(
      service.getAuthorizationQrTransactionStatus({
        requestId: transaction.requestId,
        pollSecret: transaction.pollSecret,
      }).status,
    ).toBe("pending");
  });

  it("rejects approval replay after a QR authorize transaction is used", async () => {
    const { service, request, viewer } = createQrTestService();
    const transaction = service.createAuthorizationQrTransaction(request);
    const secret = String(transaction.qrPayload.secret);

    await expect(
      service.approveAuthorizationQrTransaction({
        requestId: transaction.requestId,
        secret,
        viewer,
        approvedClaims: {
          nickname: true,
          profile_completed: true,
          passport_verified: true,
          face_verified: true,
        },
      }),
    ).resolves.toEqual({ success: true });

    await expect(
      service.approveAuthorizationQrTransaction({
        requestId: transaction.requestId,
        secret,
        viewer,
      }),
    ).resolves.toEqual({
      success: false,
      status: 409,
      error: "authorization_request_already_used",
    });
    await expect(
      service.previewAuthorizationQrTransaction({
        requestId: transaction.requestId,
        secret,
        viewer,
      }),
    ).resolves.toEqual({
      success: false,
      status: 409,
      error: "authorization_request_already_used",
    });

    const status = service.getAuthorizationQrTransactionStatus({
      requestId: transaction.requestId,
      pollSecret: transaction.pollSecret,
    });
    expect(status.status).toBe("approved");
    if (status.status === "approved") {
      expect(status.redirectTo).toContain(`${REDIRECT_URI}?code=`);
      expect(status.redirectTo).toContain("state=state-1");
    }
  });
});

describe("oidcProviderService token exchange failures", () => {
  it("rejects unsupported token grant types", async () => {
    const { service } = createTokenTestService();
    const result = await service.exchangeAuthorizationCode({
      form: makeTokenForm({ grant_type: "refresh_token" }),
      authorizationHeader: null,
    });

    expect(result).toMatchObject({
      success: false,
      status: 400,
      error: "unsupported_grant_type",
    });
  });

  it("rejects token exchange requests with missing required parameters", async () => {
    const { service } = createTokenTestService();
    const result = await service.exchangeAuthorizationCode({
      form: new URLSearchParams({ grant_type: "authorization_code" }),
      authorizationHeader: null,
    });

    expect(result).toMatchObject({
      success: false,
      status: 400,
      error: "invalid_request",
    });
  });

  it("rejects token exchange for unknown clients", async () => {
    const { service } = createTokenTestService({
      getClientByClientId: async () => null,
    });
    const result = await service.exchangeAuthorizationCode({
      form: makeTokenForm(),
      authorizationHeader: null,
    });

    expect(result).toMatchObject({
      success: false,
      status: 401,
      error: "invalid_client",
      error_description: "Client was not found.",
    });
  });

  it("rejects authorization codes presented by the wrong client", async () => {
    const otherClient = makeClient({
      id: "other-client-db-id",
      client_id: "other-client",
    });
    const { service } = createTokenTestService({
      getClientByClientId: async (clientId: string) =>
        clientId === otherClient.client_id ? otherClient : null,
      getAuthorizationCodeByHash: async () =>
        makeAuthorizationCodeRow({ client_id: "client-db-id" }),
    });
    const result = await service.exchangeAuthorizationCode({
      form: makeTokenForm({ client_id: "other-client" }),
      authorizationHeader: null,
    });

    expect(result).toMatchObject({
      success: false,
      status: 400,
      error: "invalid_grant",
      error_description: "Authorization code was not issued to this client.",
    });
  });

  it("rejects authorization codes used with a different redirect URI", async () => {
    const { service } = createTokenTestService();
    const result = await service.exchangeAuthorizationCode({
      form: makeTokenForm({
        redirect_uri: "https://codeiland-back.example/other-callback",
      }),
      authorizationHeader: null,
    });

    expect(result).toMatchObject({
      success: false,
      status: 400,
      error: "invalid_grant",
      error_description: "redirect_uri does not match the authorization request.",
    });
  });

  it("expires and rejects stale authorization codes", async () => {
    const { service, state } = createTokenTestService({
      getAuthorizationCodeByHash: async () =>
        makeAuthorizationCodeRow({
          expires_at: new Date(BASE_TIME_MS - 1).toISOString(),
        }),
    });
    const result = await service.exchangeAuthorizationCode({
      form: makeTokenForm(),
      authorizationHeader: null,
    });

    expect(result).toMatchObject({
      success: false,
      status: 400,
      error: "invalid_grant",
      error_description: "Authorization code has expired.",
    });
    expect(state.expiredAuthorizationCodeId).toBe("code-db-id");
  });

  it("rejects token exchange when PKCE verification fails", async () => {
    const { service } = createTokenTestService({
      getAuthorizationCodeByHash: async () =>
        makeAuthorizationCodeRow({ code_challenge: "wrong-code-challenge" }),
    });
    const result = await service.exchangeAuthorizationCode({
      form: makeTokenForm(),
      authorizationHeader: null,
    });

    expect(result).toMatchObject({
      success: false,
      status: 400,
      error: "invalid_grant",
      error_description: "PKCE verification failed.",
    });
  });
});
