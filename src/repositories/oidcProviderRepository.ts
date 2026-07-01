import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  OidcClientRedirectUriRow,
  OidcClientRow,
  OidcClientSecretRow,
} from "../types/db";

const OIDC_CLIENT_COLUMNS =
  "id,client_id,client_name,client_type,application_type,status,client_uri,logo_uri,tos_uri,policy_uri,sector_identifier,allowed_scopes,default_scopes,require_pkce,pkce_required_method,id_token_signed_response_alg,access_token_ttl_seconds,authorization_code_ttl_seconds,refresh_token_ttl_days,created_at,updated_at";

const OIDC_CLIENT_SECRET_COLUMNS =
  "id,client_id,secret_hash,label,status,last_used_at,expires_at,revoked_at,revocation_reason,created_at,updated_at";

const OIDC_CLIENT_REDIRECT_URI_COLUMNS =
  "id,client_id,usage,redirect_uri,created_at";

const OIDC_AUTHORIZATION_REQUEST_COLUMNS =
  "id,request_id,client_id,user_id,auth_session_id,status,response_type,redirect_uri,scopes,state,nonce,code_challenge,code_challenge_method,prompt,max_age_seconds,ui_locales,login_hint_hash,consent_required,approved_at,denied_at,consumed_at,expires_at,created_at,updated_at";

const OIDC_AUTHORIZATION_CODE_COLUMNS =
  "id,code_hash,authorization_request_id,client_id,user_id,auth_session_id,pairwise_subject_id,status,redirect_uri,scopes,nonce,code_challenge,code_challenge_method,auth_generation,expires_at,consumed_at,revoked_at,revocation_reason,created_at,updated_at";

const OIDC_PAIRWISE_SUBJECT_COLUMNS =
  "id,user_id,sector_identifier,subject_identifier,first_client_id,created_at";

const OIDC_GRANT_COLUMNS =
  "id,user_id,client_id,pairwise_subject_id,status,scopes,claims,consented_at,expires_at,revoked_at,revocation_reason,created_at,updated_at";

const OIDC_REFRESH_TOKEN_FAMILY_COLUMNS =
  "id,grant_id,auth_session_id,client_id,user_id,status,current_token_hash,previous_token_hash,rotation_counter,auth_generation,last_rotated_at,last_used_at,expires_at,revoked_at,revocation_reason,created_at,updated_at";

const OIDC_ACCESS_TOKEN_COLUMNS =
  "id,token_hash,grant_id,auth_session_id,client_id,user_id,pairwise_subject_id,status,scopes,claims,auth_generation,last_used_at,expires_at,revoked_at,revocation_reason,created_at,updated_at";

const OIDC_AUTHORIZE_QR_TRANSACTION_COLUMNS =
  "id,request_id,authorization_request_id,client_id,secret_hash,poll_secret_hash,status,user_id,auth_session_id,pairwise_subject_id,grant_id,approved_auth_generation,approved_claims,approved_at,denied_at,code_delivered_at,expires_at,result_expires_at,created_at,updated_at";

export type OidcAuthorizationRequestRow = {
  id: string;
  request_id: string;
  client_id: string;
  user_id: string | null;
  auth_session_id: string | null;
  status:
    | "pending"
    | "approved"
    | "denied"
    | "expired"
    | "consumed"
    | "cancelled";
  response_type: "code";
  redirect_uri: string;
  scopes: string[];
  state: string | null;
  nonce: string | null;
  code_challenge: string;
  code_challenge_method: "S256";
  prompt: string[];
  max_age_seconds: number | null;
  ui_locales: string[];
  login_hint_hash: string | null;
  consent_required: boolean;
  approved_at: string | null;
  denied_at: string | null;
  consumed_at: string | null;
  expires_at: string;
  created_at: string;
  updated_at: string;
};

export type OidcAuthorizationCodeRow = {
  id: string;
  code_hash: string;
  authorization_request_id: string;
  client_id: string;
  user_id: string;
  auth_session_id: string | null;
  pairwise_subject_id: string;
  status: "active" | "consumed" | "expired" | "revoked";
  redirect_uri: string;
  scopes: string[];
  nonce: string | null;
  code_challenge: string;
  code_challenge_method: "S256";
  auth_generation: number;
  expires_at: string;
  consumed_at: string | null;
  revoked_at: string | null;
  revocation_reason: string | null;
  created_at: string;
  updated_at: string;
};

export type OidcPairwiseSubjectRow = {
  id: string;
  user_id: string;
  sector_identifier: string;
  subject_identifier: string;
  first_client_id: string | null;
  created_at: string;
};

export type OidcGrantRow = {
  id: string;
  user_id: string;
  client_id: string;
  pairwise_subject_id: string;
  status: "active" | "revoked" | "expired";
  scopes: string[];
  claims: Record<string, unknown>;
  consented_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  revocation_reason: string | null;
  created_at: string;
  updated_at: string;
};

export type OidcRefreshTokenFamilyRow = {
  id: string;
  grant_id: string;
  auth_session_id: string | null;
  client_id: string;
  user_id: string;
  status: "active" | "revoked" | "reused" | "expired";
  current_token_hash: string;
  previous_token_hash: string | null;
  rotation_counter: number;
  auth_generation: number;
  last_rotated_at: string;
  last_used_at: string | null;
  expires_at: string;
  revoked_at: string | null;
  revocation_reason: string | null;
  created_at: string;
  updated_at: string;
};

export type OidcAccessTokenRow = {
  id: string;
  token_hash: string;
  grant_id: string | null;
  auth_session_id: string | null;
  client_id: string;
  user_id: string;
  pairwise_subject_id: string;
  status: "active" | "revoked" | "expired";
  scopes: string[];
  claims: Record<string, unknown>;
  auth_generation: number;
  last_used_at: string | null;
  expires_at: string;
  revoked_at: string | null;
  revocation_reason: string | null;
  created_at: string;
  updated_at: string;
};

export type OidcAuthorizeQrTransactionRow = {
  id: string;
  request_id: string;
  authorization_request_id: string;
  client_id: string;
  secret_hash: string;
  poll_secret_hash: string;
  status: "pending" | "approved" | "denied" | "expired";
  user_id: string | null;
  auth_session_id: string | null;
  pairwise_subject_id: string | null;
  grant_id: string | null;
  approved_auth_generation: number | null;
  approved_claims: Record<string, unknown>;
  approved_at: string | null;
  denied_at: string | null;
  code_delivered_at: string | null;
  expires_at: string;
  result_expires_at: string | null;
  created_at: string;
  updated_at: string;
};

export type OidcAuthorizeQrCodeDeliveryRow = {
  authorization_request_id: string;
  client_id: string;
  user_id: string;
  auth_session_id: string | null;
  pairwise_subject_id: string;
  redirect_uri: string;
  scopes: string[];
  state: string | null;
  nonce: string | null;
  code_challenge: string;
  code_challenge_method: "S256";
  auth_generation: number;
};

export const oidcProviderRepository = {
  async getClientByClientId(clientId: string): Promise<OidcClientRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_clients")
      .select(OIDC_CLIENT_COLUMNS)
      .eq("client_id", clientId)
      .maybeSingle<OidcClientRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getClientById(clientDbId: string): Promise<OidcClientRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_clients")
      .select(OIDC_CLIENT_COLUMNS)
      .eq("id", clientDbId)
      .maybeSingle<OidcClientRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getRedirectUri(input: {
    clientDbId: string;
    usage: "redirect" | "post_logout";
    redirectUri: string;
  }): Promise<OidcClientRedirectUriRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_client_redirect_uris")
      .select(OIDC_CLIENT_REDIRECT_URI_COLUMNS)
      .eq("client_id", input.clientDbId)
      .eq("usage", input.usage)
      .eq("redirect_uri", input.redirectUri)
      .maybeSingle<OidcClientRedirectUriRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getActiveSecretByHash(input: {
    clientDbId: string;
    secretHash: string;
  }): Promise<OidcClientSecretRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_client_secrets")
      .select(OIDC_CLIENT_SECRET_COLUMNS)
      .eq("client_id", input.clientDbId)
      .eq("secret_hash", input.secretHash)
      .eq("status", "active")
      .maybeSingle<OidcClientSecretRow>();

    if (error) {
      throw error;
    }

    if (data?.expires_at && Date.parse(data.expires_at) <= Date.now()) {
      return null;
    }

    return data || null;
  },

  async touchClientSecret(secretId: string): Promise<void> {
    const supabase = requireSupabaseAdminClient();

    const { error } = await supabase
      .from("oidc_client_secrets")
      .update({
        last_used_at: new Date().toISOString(),
      })
      .eq("id", secretId);

    if (error) {
      throw error;
    }
  },

  async insertAuthorizationRequest(input: {
    requestId: string;
    clientDbId: string;
    userId: string;
    authSessionId: string | null;
    redirectUri: string;
    scopes: string[];
    state: string | null;
    nonce: string | null;
    codeChallenge: string;
    codeChallengeMethod: "S256";
    expiresAt: string;
  }): Promise<OidcAuthorizationRequestRow> {
    const now = new Date().toISOString();
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_authorization_requests")
      .insert({
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
        ui_locales: [],
        consent_required: false,
        approved_at: now,
        expires_at: input.expiresAt,
      })
      .select(OIDC_AUTHORIZATION_REQUEST_COLUMNS)
      .single<OidcAuthorizationRequestRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async insertPendingAuthorizationRequest(input: {
    requestId: string;
    clientDbId: string;
    redirectUri: string;
    scopes: string[];
    state: string | null;
    nonce: string | null;
    codeChallenge: string;
    codeChallengeMethod: "S256";
    expiresAt: string;
  }): Promise<OidcAuthorizationRequestRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_authorization_requests")
      .insert({
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
        ui_locales: [],
        consent_required: true,
        expires_at: input.expiresAt,
      })
      .select(OIDC_AUTHORIZATION_REQUEST_COLUMNS)
      .single<OidcAuthorizationRequestRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async getAuthorizationRequestById(
    authorizationRequestId: string,
  ): Promise<OidcAuthorizationRequestRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_authorization_requests")
      .select(OIDC_AUTHORIZATION_REQUEST_COLUMNS)
      .eq("id", authorizationRequestId)
      .maybeSingle<OidcAuthorizationRequestRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insertAuthorizeQrTransaction(input: {
    requestId: string;
    authorizationRequestId: string;
    clientDbId: string;
    secretHash: string;
    pollSecretHash: string;
    expiresAt: string;
  }): Promise<OidcAuthorizeQrTransactionRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_authorize_qr_transactions")
      .insert({
        request_id: input.requestId,
        authorization_request_id: input.authorizationRequestId,
        client_id: input.clientDbId,
        secret_hash: input.secretHash,
        poll_secret_hash: input.pollSecretHash,
        status: "pending",
        expires_at: input.expiresAt,
      })
      .select(OIDC_AUTHORIZE_QR_TRANSACTION_COLUMNS)
      .single<OidcAuthorizeQrTransactionRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async getAuthorizeQrTransactionByRequestId(
    requestId: string,
  ): Promise<OidcAuthorizeQrTransactionRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_authorize_qr_transactions")
      .select(OIDC_AUTHORIZE_QR_TRANSACTION_COLUMNS)
      .eq("request_id", requestId)
      .maybeSingle<OidcAuthorizeQrTransactionRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async expireAuthorizeQrTransaction(
    requestId: string,
  ): Promise<OidcAuthorizeQrTransactionRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_authorize_qr_transactions")
      .update({
        status: "expired",
      })
      .eq("request_id", requestId)
      .in("status", ["pending", "approved"])
      .select(OIDC_AUTHORIZE_QR_TRANSACTION_COLUMNS)
      .maybeSingle<OidcAuthorizeQrTransactionRow>();

    if (error) {
      throw error;
    }

    if (data?.authorization_request_id) {
      const { error: requestError } = await supabase
        .from("oidc_authorization_requests")
        .update({
          status: "expired",
        })
        .eq("id", data.authorization_request_id)
        .in("status", ["pending", "approved"]);

      if (requestError) {
        throw requestError;
      }
    }

    return data || null;
  },

  async approveAuthorizeQrTransaction(input: {
    requestId: string;
    secretHash: string;
    userId: string;
    authSessionId: string | null;
    pairwiseSubjectId: string;
    grantId: string;
    approvedAuthGeneration: number;
    approvedClaims: Record<string, unknown>;
    resultExpiresAt: string;
    now: string;
  }): Promise<OidcAuthorizeQrTransactionRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase.rpc(
      "approve_oidc_authorize_qr_transaction",
      {
        p_request_id: input.requestId,
        p_secret_hash: input.secretHash,
        p_user_id: input.userId,
        p_auth_session_id: input.authSessionId,
        p_pairwise_subject_id: input.pairwiseSubjectId,
        p_grant_id: input.grantId,
        p_approved_auth_generation: input.approvedAuthGeneration,
        p_approved_claims: input.approvedClaims,
        p_result_expires_at: input.resultExpiresAt,
        p_now: input.now,
      },
    );

    if (error) {
      throw error;
    }

    return (data as OidcAuthorizeQrTransactionRow | null) || null;
  },

  async denyAuthorizeQrTransaction(input: {
    requestId: string;
    secretHash: string;
    resultExpiresAt: string;
    now: string;
  }): Promise<OidcAuthorizeQrTransactionRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase.rpc(
      "deny_oidc_authorize_qr_transaction",
      {
        p_request_id: input.requestId,
        p_secret_hash: input.secretHash,
        p_result_expires_at: input.resultExpiresAt,
        p_now: input.now,
      },
    );

    if (error) {
      throw error;
    }

    return (data as OidcAuthorizeQrTransactionRow | null) || null;
  },

  async deliverAuthorizeQrCode(input: {
    requestId: string;
    pollSecretHash: string;
    codeHash: string;
    codeExpiresAt: string;
    now: string;
  }): Promise<OidcAuthorizeQrCodeDeliveryRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase.rpc("deliver_oidc_authorize_qr_code", {
      p_request_id: input.requestId,
      p_poll_secret_hash: input.pollSecretHash,
      p_code_hash: input.codeHash,
      p_code_expires_at: input.codeExpiresAt,
      p_now: input.now,
    });

    if (error) {
      throw error;
    }

    const rows = data as OidcAuthorizeQrCodeDeliveryRow[] | null;
    return rows?.[0] || null;
  },

  async getPairwiseSubject(input: {
    userId: string;
    sectorIdentifier: string;
  }): Promise<OidcPairwiseSubjectRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_pairwise_subjects")
      .select(OIDC_PAIRWISE_SUBJECT_COLUMNS)
      .eq("user_id", input.userId)
      .eq("sector_identifier", input.sectorIdentifier)
      .maybeSingle<OidcPairwiseSubjectRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insertPairwiseSubject(input: {
    userId: string;
    sectorIdentifier: string;
    subjectIdentifier: string;
    firstClientDbId: string;
  }): Promise<OidcPairwiseSubjectRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_pairwise_subjects")
      .insert({
        user_id: input.userId,
        sector_identifier: input.sectorIdentifier,
        subject_identifier: input.subjectIdentifier,
        first_client_id: input.firstClientDbId,
      })
      .select(OIDC_PAIRWISE_SUBJECT_COLUMNS)
      .single<OidcPairwiseSubjectRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async getPairwiseSubjectById(
    pairwiseSubjectId: string,
  ): Promise<OidcPairwiseSubjectRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_pairwise_subjects")
      .select(OIDC_PAIRWISE_SUBJECT_COLUMNS)
      .eq("id", pairwiseSubjectId)
      .maybeSingle<OidcPairwiseSubjectRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async upsertGrant(input: {
    userId: string;
    clientDbId: string;
    pairwiseSubjectId: string;
    scopes: string[];
    claims: Record<string, unknown>;
  }): Promise<OidcGrantRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_grants")
      .upsert(
        {
          user_id: input.userId,
          client_id: input.clientDbId,
          pairwise_subject_id: input.pairwiseSubjectId,
          status: "active",
          scopes: input.scopes,
          claims: input.claims,
          consented_at: new Date().toISOString(),
          expires_at: null,
          revoked_at: null,
          revocation_reason: null,
        },
        {
          onConflict: "user_id,client_id",
        },
      )
      .select(OIDC_GRANT_COLUMNS)
      .single<OidcGrantRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async getGrantByUserAndClient(input: {
    userId: string;
    clientDbId: string;
  }): Promise<OidcGrantRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_grants")
      .select(OIDC_GRANT_COLUMNS)
      .eq("user_id", input.userId)
      .eq("client_id", input.clientDbId)
      .maybeSingle<OidcGrantRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getGrantById(grantId: string): Promise<OidcGrantRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_grants")
      .select(OIDC_GRANT_COLUMNS)
      .eq("id", grantId)
      .maybeSingle<OidcGrantRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insertAuthorizationCode(input: {
    codeHash: string;
    authorizationRequestId: string;
    clientDbId: string;
    userId: string;
    authSessionId: string | null;
    pairwiseSubjectId: string;
    redirectUri: string;
    scopes: string[];
    nonce: string | null;
    codeChallenge: string;
    codeChallengeMethod: "S256";
    authGeneration: number;
    expiresAt: string;
  }): Promise<OidcAuthorizationCodeRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_authorization_codes")
      .insert({
        code_hash: input.codeHash,
        authorization_request_id: input.authorizationRequestId,
        client_id: input.clientDbId,
        user_id: input.userId,
        auth_session_id: input.authSessionId,
        pairwise_subject_id: input.pairwiseSubjectId,
        status: "active",
        redirect_uri: input.redirectUri,
        scopes: input.scopes,
        nonce: input.nonce,
        code_challenge: input.codeChallenge,
        code_challenge_method: input.codeChallengeMethod,
        auth_generation: input.authGeneration,
        expires_at: input.expiresAt,
      })
      .select(OIDC_AUTHORIZATION_CODE_COLUMNS)
      .single<OidcAuthorizationCodeRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async getAuthorizationCodeByHash(
    codeHash: string,
  ): Promise<OidcAuthorizationCodeRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_authorization_codes")
      .select(OIDC_AUTHORIZATION_CODE_COLUMNS)
      .eq("code_hash", codeHash)
      .maybeSingle<OidcAuthorizationCodeRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async consumeAuthorizationCode(
    codeId: string,
  ): Promise<OidcAuthorizationCodeRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_authorization_codes")
      .update({
        status: "consumed",
        consumed_at: new Date().toISOString(),
      })
      .eq("id", codeId)
      .eq("status", "active")
      .select(OIDC_AUTHORIZATION_CODE_COLUMNS)
      .maybeSingle<OidcAuthorizationCodeRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async expireAuthorizationCode(
    codeId: string,
  ): Promise<OidcAuthorizationCodeRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_authorization_codes")
      .update({
        status: "expired",
        revoked_at: new Date().toISOString(),
        revocation_reason: "authorization_code_expired",
      })
      .eq("id", codeId)
      .eq("status", "active")
      .select(OIDC_AUTHORIZATION_CODE_COLUMNS)
      .maybeSingle<OidcAuthorizationCodeRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async consumeAuthorizationRequest(requestId: string): Promise<void> {
    const supabase = requireSupabaseAdminClient();

    const { error } = await supabase
      .from("oidc_authorization_requests")
      .update({
        status: "consumed",
        consumed_at: new Date().toISOString(),
      })
      .eq("id", requestId);

    if (error) {
      throw error;
    }
  },

  async insertRefreshTokenFamily(input: {
    grantId: string;
    authSessionId: string | null;
    clientDbId: string;
    userId: string;
    currentTokenHash: string;
    authGeneration: number;
    expiresAt: string;
  }): Promise<OidcRefreshTokenFamilyRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_refresh_token_families")
      .insert({
        grant_id: input.grantId,
        auth_session_id: input.authSessionId,
        client_id: input.clientDbId,
        user_id: input.userId,
        status: "active",
        current_token_hash: input.currentTokenHash,
        previous_token_hash: null,
        rotation_counter: 0,
        auth_generation: input.authGeneration,
        expires_at: input.expiresAt,
      })
      .select(OIDC_REFRESH_TOKEN_FAMILY_COLUMNS)
      .single<OidcRefreshTokenFamilyRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async insertAccessToken(input: {
    tokenHash: string;
    grantId: string | null;
    authSessionId: string | null;
    clientDbId: string;
    userId: string;
    pairwiseSubjectId: string;
    scopes: string[];
    claims: Record<string, unknown>;
    authGeneration: number;
    expiresAt: string;
  }): Promise<OidcAccessTokenRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_access_tokens")
      .insert({
        token_hash: input.tokenHash,
        grant_id: input.grantId,
        auth_session_id: input.authSessionId,
        client_id: input.clientDbId,
        user_id: input.userId,
        pairwise_subject_id: input.pairwiseSubjectId,
        status: "active",
        scopes: input.scopes,
        claims: input.claims,
        auth_generation: input.authGeneration,
        expires_at: input.expiresAt,
      })
      .select(OIDC_ACCESS_TOKEN_COLUMNS)
      .single<OidcAccessTokenRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async getAccessTokenByHash(
    tokenHash: string,
  ): Promise<OidcAccessTokenRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_access_tokens")
      .select(OIDC_ACCESS_TOKEN_COLUMNS)
      .eq("token_hash", tokenHash)
      .maybeSingle<OidcAccessTokenRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async touchAccessToken(accessTokenId: string): Promise<void> {
    const supabase = requireSupabaseAdminClient();

    const { error } = await supabase
      .from("oidc_access_tokens")
      .update({
        last_used_at: new Date().toISOString(),
      })
      .eq("id", accessTokenId);

    if (error) {
      throw error;
    }
  },

  async expireAccessToken(
    accessTokenId: string,
  ): Promise<OidcAccessTokenRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_access_tokens")
      .update({
        status: "expired",
        revoked_at: new Date().toISOString(),
        revocation_reason: "access_token_expired",
      })
      .eq("id", accessTokenId)
      .eq("status", "active")
      .select(OIDC_ACCESS_TOKEN_COLUMNS)
      .maybeSingle<OidcAccessTokenRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async revokeAccessTokenByHash(input: {
    tokenHash: string;
    clientDbId: string;
    revocationReason: string;
  }): Promise<OidcAccessTokenRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_access_tokens")
      .update({
        status: "revoked",
        revoked_at: new Date().toISOString(),
        revocation_reason: input.revocationReason,
      })
      .eq("token_hash", input.tokenHash)
      .eq("client_id", input.clientDbId)
      .eq("status", "active")
      .select(OIDC_ACCESS_TOKEN_COLUMNS)
      .maybeSingle<OidcAccessTokenRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getRefreshTokenFamilyByTokenHash(input: {
    tokenHash: string;
    clientDbId: string;
  }): Promise<OidcRefreshTokenFamilyRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_refresh_token_families")
      .select(OIDC_REFRESH_TOKEN_FAMILY_COLUMNS)
      .eq("client_id", input.clientDbId)
      .or(
        `current_token_hash.eq.${input.tokenHash},previous_token_hash.eq.${input.tokenHash}`,
      )
      .maybeSingle<OidcRefreshTokenFamilyRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async revokeRefreshTokenFamilyById(input: {
    familyId: string;
    status: "revoked" | "reused" | "expired";
    revocationReason: string;
  }): Promise<OidcRefreshTokenFamilyRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_refresh_token_families")
      .update({
        status: input.status,
        revoked_at: new Date().toISOString(),
        revocation_reason: input.revocationReason,
      })
      .eq("id", input.familyId)
      .eq("status", "active")
      .select(OIDC_REFRESH_TOKEN_FAMILY_COLUMNS)
      .maybeSingle<OidcRefreshTokenFamilyRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async rotateRefreshTokenFamily(input: {
    familyId: string;
    previousTokenHash: string;
    currentTokenHash: string;
    rotationCounter: number;
  }): Promise<OidcRefreshTokenFamilyRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("oidc_refresh_token_families")
      .update({
        previous_token_hash: input.previousTokenHash,
        current_token_hash: input.currentTokenHash,
        rotation_counter: input.rotationCounter,
        last_rotated_at: new Date().toISOString(),
        last_used_at: new Date().toISOString(),
      })
      .eq("id", input.familyId)
      .eq("status", "active")
      .eq("current_token_hash", input.previousTokenHash)
      .select(OIDC_REFRESH_TOKEN_FAMILY_COLUMNS)
      .maybeSingle<OidcRefreshTokenFamilyRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },
};

export default oidcProviderRepository;
