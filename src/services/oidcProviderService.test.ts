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

const makePairwiseSubject = (overrides: Record<string, unknown> = {}) =>
  ({
    id: "pairwise-1",
    user_id: "user-1",
    sector_identifier: "codeiland.com",
    subject_identifier: "pairwise-subject-1",
    first_client_id: "client-db-id",
    created_at: BASE_TIME_ISO,
    ...overrides,
  }) as any;

const makeGrant = (input: any, overrides: Record<string, unknown> = {}) =>
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
    ...overrides,
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

const makeAccessTokenRow = (overrides: Record<string, unknown> = {}) =>
  ({
    id: "access-token-db-id",
    token_hash: "access-token-hash",
    grant_id: "grant-1",
    auth_session_id: "auth-session-1",
    client_id: "client-db-id",
    user_id: "user-1",
    pairwise_subject_id: "pairwise-1",
    status: "active",
    scopes: ["openid", "profile"],
    claims: {
      nickname: "public-name",
      preferred_username: "public-name",
      profile_completed: true,
      passport_verified: true,
      face_verified: true,
      internal_user_id: "must-not-leak",
    },
    auth_generation: 3,
    last_used_at: null,
    expires_at: new Date(BASE_TIME_MS + 60_000).toISOString(),
    revoked_at: null,
    revocation_reason: null,
    created_at: BASE_TIME_ISO,
    updated_at: BASE_TIME_ISO,
    ...overrides,
  }) as any;

const makeTokenForm = (overrides: Record<string, string> = {}) =>
  new URLSearchParams({
    grant_type: "authorization_code",
    code: "authorization-code-1",
    redirect_uri: REDIRECT_URI,
    code_verifier: "verifier-1",
    client_id: "codeiland-web",
    ...overrides,
  });

const createSharedQrRepository = (client = makeClient()) => {
  const state = {
    clientsById: new Map<string, any>([[client.id, client]]),
    authorizationRequestsById: new Map<string, any>(),
    qrTransactionsByRequestId: new Map<string, any>(),
    pairwiseSubjects: new Map<string, any>(),
    grants: new Map<string, any>(),
    authorizationCodes: [] as any[],
  };

  const repository = {
    getClientById: async (clientDbId: string) =>
      state.clientsById.get(clientDbId) || null,

    insertPendingAuthorizationRequest: async (input: any) => {
      const row = {
        id: `authorization-request-${state.authorizationRequestsById.size + 1}`,
        request_id: input.requestId,
        client_id: input.clientDbId,
        user_id: null,
        auth_session_id: null,
        status: "pending",
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
        consent_required: true,
        approved_at: null,
        denied_at: null,
        consumed_at: null,
        expires_at: input.expiresAt,
        created_at: BASE_TIME_ISO,
        updated_at: BASE_TIME_ISO,
      };
      state.authorizationRequestsById.set(row.id, row);
      return row;
    },

    getAuthorizationRequestById: async (authorizationRequestId: string) =>
      state.authorizationRequestsById.get(authorizationRequestId) || null,

    insertAuthorizeQrTransaction: async (input: any) => {
      const row = {
        id: `qr-${state.qrTransactionsByRequestId.size + 1}`,
        request_id: input.requestId,
        authorization_request_id: input.authorizationRequestId,
        client_id: input.clientDbId,
        secret_hash: input.secretHash,
        poll_secret_hash: input.pollSecretHash,
        status: "pending",
        user_id: null,
        auth_session_id: null,
        pairwise_subject_id: null,
        grant_id: null,
        approved_auth_generation: null,
        approved_claims: {},
        approved_at: null,
        denied_at: null,
        code_delivered_at: null,
        expires_at: input.expiresAt,
        result_expires_at: null,
        created_at: BASE_TIME_ISO,
        updated_at: BASE_TIME_ISO,
      };
      state.qrTransactionsByRequestId.set(row.request_id, row);
      return row;
    },

    getAuthorizeQrTransactionByRequestId: async (requestId: string) =>
      state.qrTransactionsByRequestId.get(requestId) || null,

    expireAuthorizeQrTransaction: async (requestId: string) => {
      const row = state.qrTransactionsByRequestId.get(requestId);
      if (!row) {
        return null;
      }
      row.status = "expired";
      const authRequest = state.authorizationRequestsById.get(
        row.authorization_request_id,
      );
      if (authRequest && ["pending", "approved"].includes(authRequest.status)) {
        authRequest.status = "expired";
      }
      return row;
    },

    approveAuthorizeQrTransaction: async (input: any) => {
      const row = state.qrTransactionsByRequestId.get(input.requestId);
      if (
        !row ||
        row.status !== "pending" ||
        row.secret_hash !== input.secretHash ||
        Date.parse(row.expires_at) <= Date.parse(input.now)
      ) {
        return null;
      }
      row.status = "approved";
      row.user_id = input.userId;
      row.auth_session_id = input.authSessionId;
      row.pairwise_subject_id = input.pairwiseSubjectId;
      row.grant_id = input.grantId;
      row.approved_auth_generation = input.approvedAuthGeneration;
      row.approved_claims = input.approvedClaims;
      row.approved_at = input.now;
      row.result_expires_at = input.resultExpiresAt;

      const authRequest = state.authorizationRequestsById.get(
        row.authorization_request_id,
      );
      if (authRequest?.status === "pending") {
        authRequest.status = "approved";
        authRequest.user_id = input.userId;
        authRequest.auth_session_id = input.authSessionId;
        authRequest.approved_at = input.now;
        authRequest.expires_at = input.resultExpiresAt;
      }
      return row;
    },

    denyAuthorizeQrTransaction: async (input: any) => {
      const row = state.qrTransactionsByRequestId.get(input.requestId);
      if (
        !row ||
        row.status !== "pending" ||
        row.secret_hash !== input.secretHash ||
        Date.parse(row.expires_at) <= Date.parse(input.now)
      ) {
        return null;
      }
      row.status = "denied";
      row.denied_at = input.now;
      row.result_expires_at = input.resultExpiresAt;
      const authRequest = state.authorizationRequestsById.get(
        row.authorization_request_id,
      );
      if (authRequest?.status === "pending") {
        authRequest.status = "denied";
        authRequest.denied_at = input.now;
        authRequest.expires_at = input.resultExpiresAt;
      }
      return row;
    },

    deliverAuthorizeQrCode: async (input: any) => {
      const row = state.qrTransactionsByRequestId.get(input.requestId);
      if (
        !row ||
        row.status !== "approved" ||
        row.poll_secret_hash !== input.pollSecretHash ||
        row.code_delivered_at ||
        !row.result_expires_at ||
        Date.parse(row.result_expires_at) <= Date.parse(input.now)
      ) {
        return null;
      }

      const authRequest = state.authorizationRequestsById.get(
        row.authorization_request_id,
      );
      if (!authRequest || authRequest.status !== "approved") {
        return null;
      }

      row.code_delivered_at = input.now;
      state.authorizationCodes.push({
        code_hash: input.codeHash,
        authorization_request_id: authRequest.id,
        client_id: row.client_id,
        user_id: row.user_id,
        auth_session_id: row.auth_session_id,
        pairwise_subject_id: row.pairwise_subject_id,
        redirect_uri: authRequest.redirect_uri,
        scopes: authRequest.scopes,
        nonce: authRequest.nonce,
        code_challenge: authRequest.code_challenge,
        code_challenge_method: authRequest.code_challenge_method,
        auth_generation: row.approved_auth_generation,
        expires_at: input.codeExpiresAt,
      });

      return {
        authorization_request_id: authRequest.id,
        client_id: row.client_id,
        user_id: row.user_id,
        auth_session_id: row.auth_session_id,
        pairwise_subject_id: row.pairwise_subject_id,
        redirect_uri: authRequest.redirect_uri,
        scopes: authRequest.scopes,
        state: authRequest.state,
        nonce: authRequest.nonce,
        code_challenge: authRequest.code_challenge,
        code_challenge_method: authRequest.code_challenge_method,
        auth_generation: row.approved_auth_generation,
      };
    },

    getPairwiseSubject: async (input: any) =>
      state.pairwiseSubjects.get(`${input.userId}:${input.sectorIdentifier}`) ||
      null,

    insertPairwiseSubject: async (input: any) => {
      const row = makePairwiseSubject({
        id: `pairwise-${state.pairwiseSubjects.size + 1}`,
        user_id: input.userId,
        sector_identifier: input.sectorIdentifier,
        subject_identifier: input.subjectIdentifier,
        first_client_id: input.firstClientDbId,
      });
      state.pairwiseSubjects.set(`${input.userId}:${input.sectorIdentifier}`, row);
      return row;
    },

    upsertGrant: async (input: any) => {
      const key = `${input.userId}:${input.clientDbId}`;
      const existing = state.grants.get(key);
      const row = makeGrant(input, {
        id: existing?.id || `grant-${state.grants.size + 1}`,
      });
      state.grants.set(key, row);
      return row;
    },
  };

  return { repository, state };
};

const createQrTestService = (
  shared = createSharedQrRepository(),
  nowRef = { nowMs: BASE_TIME_MS },
) => {
  let randomByte = 1;
  const service = createOidcProviderService({
    issuer: "https://iland.example/idp",
    now: () => new Date(nowRef.nowMs),
    randomBytesFn: (size) => Buffer.alloc(size, randomByte++),
    oidcProviderRepositoryLike: shared.repository as any,
    oidcSigningKeyRepositoryLike: { listPublicSigningKeys: async () => [] } as any,
    userRepositoryLike: { getById: async () => null } as any,
    identityProfileRepositoryLike: {
      getByUserId: async () => makeIdentityProfile(),
    } as any,
  });

  return {
    service,
    shared,
    request: makeAuthorizationRequest(),
    viewer: makeViewer(),
    advance: (milliseconds: number) => {
      nowRef.nowMs += milliseconds;
    },
    nowRef,
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

const createUserInfoTestService = (
  accessTokenOverrides: Record<string, unknown> = {},
) => {
  const accessToken = makeAccessTokenRow(accessTokenOverrides);
  let touchedAccessTokenId: string | null = null;

  const service = createOidcProviderService({
    issuer: "https://iland.example/idp",
    now: () => new Date(BASE_TIME_MS),
    randomBytesFn: (size) => Buffer.alloc(size, 9),
    oidcProviderRepositoryLike: {
      getAccessTokenByHash: async () => accessToken,
      expireAccessToken: async () => null,
      getPairwiseSubjectById: async () =>
        makePairwiseSubject({
          id: accessToken.pairwise_subject_id,
        }),
      touchAccessToken: async (accessTokenId: string) => {
        touchedAccessTokenId = accessTokenId;
      },
    } as any,
    oidcSigningKeyRepositoryLike: { listPublicSigningKeys: async () => [] } as any,
    userRepositoryLike: {
      getById: async () => makeViewer().user,
    } as any,
    identityProfileRepositoryLike: {
      getByUserId: async () => makeIdentityProfile(),
    } as any,
  });

  return {
    service,
    get touchedAccessTokenId() {
      return touchedAccessTokenId;
    },
  };
};

describe("oidcProviderService QR authorize transactions", () => {
  it("persists QR authorize transactions across service instances", async () => {
    const shared = createSharedQrRepository();
    const nowRef = { nowMs: BASE_TIME_MS };
    const first = createQrTestService(shared, nowRef);
    const second = createQrTestService(shared, nowRef);

    const transaction = await first.service.createAuthorizationQrTransaction(
      first.request,
    );
    const secret = String(transaction.qrPayload.secret);

    await expect(
      second.service.previewAuthorizationQrTransaction({
        requestId: transaction.requestId,
        secret,
        viewer: second.viewer,
      }),
    ).resolves.toMatchObject({
      success: true,
      body: {
        requestId: transaction.requestId,
        client: {
          clientId: "codeiland-web",
        },
      },
    });
    await expect(
      second.service.approveAuthorizationQrTransaction({
        requestId: transaction.requestId,
        secret,
        viewer: second.viewer,
        authSessionId: "auth-session-1",
        approvedClaims: {
          nickname: true,
          profile_completed: true,
          passport_verified: true,
          face_verified: true,
        },
      }),
    ).resolves.toEqual({ success: true });

    const status = await first.service.getAuthorizationQrTransactionStatus({
      requestId: transaction.requestId,
      pollSecret: transaction.pollSecret,
    });
    expect(status.status).toBe("approved");
    if (status.status === "approved") {
      expect(status.redirectTo).toContain(`${REDIRECT_URI}?code=`);
      expect(status.redirectTo).toContain("state=state-1");
    }
    expect(shared.state.authorizationCodes).toHaveLength(1);
  });

  it("expires pending QR authorize transactions before approval", async () => {
    const { service, request, viewer, advance } = createQrTestService();
    const transaction = await service.createAuthorizationQrTransaction(request);

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
    await expect(
      service.getAuthorizationQrTransactionStatus({
        requestId: transaction.requestId,
        pollSecret: transaction.pollSecret,
      }),
    ).resolves.toEqual({ status: "expired" });
  });

  it("rejects wrong QR secrets without consuming the transaction", async () => {
    const { service, request, viewer } = createQrTestService();
    const transaction = await service.createAuthorizationQrTransaction(request);

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
    await expect(
      service.getAuthorizationQrTransactionStatus({
        requestId: transaction.requestId,
        pollSecret: transaction.pollSecret,
      }),
    ).resolves.toMatchObject({ status: "pending" });
  });

  it("does not reveal status to callers with the wrong poll secret", async () => {
    const { service, request } = createQrTestService();
    const transaction = await service.createAuthorizationQrTransaction(request);

    await expect(
      service.getAuthorizationQrTransactionStatus({
        requestId: transaction.requestId,
        pollSecret: "wrong-poll-secret",
      }),
    ).resolves.toEqual({ status: "not_found" });
    await expect(
      service.getAuthorizationQrTransactionStatus({
        requestId: transaction.requestId,
        pollSecret: transaction.pollSecret,
      }),
    ).resolves.toMatchObject({ status: "pending" });
  });

  it("rejects approval replay after a QR authorize transaction is used", async () => {
    const { service, request, viewer } = createQrTestService();
    const transaction = await service.createAuthorizationQrTransaction(request);
    const secret = String(transaction.qrPayload.secret);

    await expect(
      service.approveAuthorizationQrTransaction({
        requestId: transaction.requestId,
        secret,
        viewer,
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
  });

  it("delivers the browser authorization code only once", async () => {
    const { service, request, viewer } = createQrTestService();
    const transaction = await service.createAuthorizationQrTransaction(request);
    const secret = String(transaction.qrPayload.secret);

    await service.approveAuthorizationQrTransaction({
      requestId: transaction.requestId,
      secret,
      viewer,
    });

    await expect(
      service.getAuthorizationQrTransactionStatus({
        requestId: transaction.requestId,
        pollSecret: transaction.pollSecret,
      }),
    ).resolves.toMatchObject({ status: "approved" });
    await expect(
      service.getAuthorizationQrTransactionStatus({
        requestId: transaction.requestId,
        pollSecret: transaction.pollSecret,
      }),
    ).resolves.toEqual({ status: "not_found" });
  });

  it("returns a denied redirect for denied QR authorize transactions", async () => {
    const { service, request } = createQrTestService();
    const transaction = await service.createAuthorizationQrTransaction(request);

    await expect(
      service.denyAuthorizationQrTransaction({
        requestId: transaction.requestId,
        secret: String(transaction.qrPayload.secret),
      }),
    ).resolves.toEqual({ success: true });

    const status = await service.getAuthorizationQrTransactionStatus({
      requestId: transaction.requestId,
      pollSecret: transaction.pollSecret,
    });
    expect(status.status).toBe("denied");
    if (status.status === "denied") {
      expect(status.redirectTo).toContain("error=access_denied");
      expect(status.redirectTo).toContain("state=state-1");
    }
  });
});

describe("oidcProviderService UserInfo claim contract", () => {
  it("returns only consent-filtered profile claims for the profile scope", async () => {
    const context = createUserInfoTestService();

    const result = await context.service.getUserInfo({
      accessToken: "access-token-1",
    });

    expect(result).toEqual({
      success: true,
      body: {
        sub: "pairwise-subject-1",
        nickname: "public-name",
        preferred_username: "public-name",
        profile_completed: true,
        passport_verified: true,
        face_verified: true,
      },
    });
    expect(context.touchedAccessTokenId).toBe("access-token-db-id");
  });

  it("returns only sub when the access token lacks the profile scope", async () => {
    const context = createUserInfoTestService({
      scopes: ["openid"],
    });

    const result = await context.service.getUserInfo({
      accessToken: "access-token-1",
    });

    expect(result).toEqual({
      success: true,
      body: {
        sub: "pairwise-subject-1",
      },
    });
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
