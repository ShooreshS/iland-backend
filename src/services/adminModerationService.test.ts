import { describe, expect, it } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { hashOpaqueBearerToken } from "../auth/tokens";
import type {
  AdminReviewerRow,
  DiscussionPostRow,
  ModerationReviewActionRow,
  PollOptionRow,
  PollRow,
  UserRow,
  VerifiedIdentityRow,
} from "../types/db";

const { privateKey: googleOAuthPrivateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

process.env.AUTH_IOS_TEAM_ID = "DJWBN8658Q";
process.env.AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS = "true";
process.env.AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_CLIENT_EMAIL =
  "play-integrity-test@example.iam.gserviceaccount.com";
process.env.AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY = googleOAuthPrivateKey
  .export({ format: "pem", type: "pkcs8" })
  .toString();
process.env.AUTH_ANDROID_ALLOWED_SIGNING_CERT_DIGESTS =
  "23e31a67fd079259091c31ab079846a30d07f18e66ae675863b18a0a77e66763";
process.env.SOLANA_AUDIT_TRANSACTIONS_ENABLED = "false";

const { createAdminModerationService } = await import("./adminModerationService");

const FIXED_TIME = "2026-07-17T12:00:00.000Z";

const user: UserRow = {
  id: "user-1",
  username: null,
  display_name: null,
  public_nickname: "reviewer",
  onboarding_status: "completed",
  verification_level: "verified",
  has_wallet: true,
  wallet_credential_id: null,
  selected_land_id: null,
  preferred_language: "en",
  auth_generation: 1,
  account_status: "active",
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
};

const verifiedIdentity: VerifiedIdentityRow = {
  id: "verified-identity-1",
  user_id: "user-1",
  canonical_identity_key: "canonical-key",
  normalization_version: 1,
  verification_method: "passport_nfc",
  verified_at: FIXED_TIME,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
};

const reviewer: AdminReviewerRow = {
  id: "reviewer-1",
  verified_identity_id: "verified-identity-1",
  role: "reviewer",
  status: "active",
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
};

const createPollRow = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "poll-1",
  slug: "poll-1",
  created_by_user_id: "creator-1",
  title: "A flagged poll",
  description: "Needs review",
  status: "active",
  moderation_status: "review_required",
  moderation_model: "omni-moderation-latest",
  moderation_flagged: true,
  moderation_categories: { harassment: true },
  moderation_category_scores: { harassment: 0.8 },
  moderation_applied_input_types: { harassment: ["text"] },
  moderation_raw: null,
  moderated_at: FIXED_TIME,
  moderation_error: null,
  moderation_policy_version: "gate1-v2",
  gate2_status: null,
  gate2_model: null,
  gate2_result: null,
  human_review_status: null,
  human_review_decision: null,
  human_reviewed_at: null,
  jurisdiction_type: "global",
  jurisdiction_country_code: null,
  jurisdiction_area_ids: [],
  jurisdiction_land_ids: [],
  requires_verified_identity: true,
  allowed_document_country_codes: [],
  allowed_home_area_ids: [],
  allowed_land_ids: [],
  minimum_age: null,
  starts_at: null,
  ends_at: null,
  poll_policy_json: null,
  poll_policy_hash: null,
  credential_schema_json: null,
  credential_schema_hash: null,
  vote_privacy_mode: "zk_secret_ballot_v1",
  result_publication_mode: "auto_on_close",
  option_set_hash: null,
  poll_encryption_key_id: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createPostRow = (
  overrides: Partial<DiscussionPostRow> = {},
): DiscussionPostRow => ({
  id: "post-1",
  author_user_id: "creator-1",
  author_public_nickname: "creator",
  post_type: "discussion",
  caption: "A flagged discussion",
  image_url: null,
  image_storage_bucket: "discussion-media",
  image_storage_path: "discussions/ab/upload-1.jpg",
  image_mime_type: "image/jpeg",
  image_size_bytes: 1234,
  image_alt_text: "Uploaded image",
  moderation_status: "review_required",
  moderation_model: "omni-moderation-latest",
  moderation_flagged: true,
  moderation_categories: { violence: true },
  moderation_category_scores: { violence: 0.8 },
  moderation_applied_input_types: { violence: ["image"] },
  moderation_raw: null,
  moderated_at: FIXED_TIME,
  moderation_error: null,
  moderation_policy_version: "gate1-v2",
  gate2_status: null,
  gate2_model: null,
  gate2_result: null,
  human_review_status: null,
  human_review_decision: null,
  human_reviewed_at: null,
  like_count: 0,
  comment_count: 0,
  feed_score: 0,
  deliberation_id: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const option: PollOptionRow = {
  id: "option-1",
  poll_id: "poll-1",
  label: "Yes",
  description: null,
  color: null,
  display_order: 0,
  is_active: true,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
};

const createReviewActionRow = (
  overrides: Partial<ModerationReviewActionRow> = {},
): ModerationReviewActionRow => ({
  id: "review-action-1",
  content_type: "poll",
  content_id: "poll-1",
  reviewer_verified_identity_id: "verified-identity-1",
  reviewer_user_id: "user-1",
  action: "approve",
  previous_status: "review_required",
  new_status: "published",
  internal_note: null,
  user_message: null,
  created_at: FIXED_TIME,
  ...overrides,
});

const createBaseService = (overrides: Record<string, unknown> = {}) =>
  createAdminModerationService({
    adminOidcClientId: "admin-dashboard-web",
    now: () => new Date(FIXED_TIME),
    oidcProviderRepositoryLike: {
      getAccessTokenByHash: async (hash: string) =>
        hash === hashOpaqueBearerToken("oidc-access-token")
          ? {
              id: "access-token-1",
              token_hash: hash,
              grant_id: null,
              auth_session_id: null,
              client_id: "client-db-id",
              user_id: "user-1",
              pairwise_subject_id: "subject-1",
              status: "active",
              scopes: ["openid", "profile"],
              claims: {},
              auth_generation: 1,
              last_used_at: null,
              expires_at: "2999-01-01T00:00:00.000Z",
              revoked_at: null,
              revocation_reason: null,
              created_at: FIXED_TIME,
              updated_at: FIXED_TIME,
            }
          : null,
      expireAccessToken: async () => null,
      touchAccessToken: async () => undefined,
      getClientById: async () => ({
        id: "client-db-id",
        client_id: "admin-dashboard-web",
        client_name: "Admin dashboard",
        client_type: "confidential",
        application_type: "web",
        status: "active",
        client_uri: "https://admin.codeiland.com/",
        logo_uri: null,
        tos_uri: null,
        policy_uri: null,
        sector_identifier: "admin.codeiland.com",
        allowed_scopes: ["openid", "profile"],
        default_scopes: ["openid", "profile"],
        require_pkce: true,
        pkce_required_method: "S256",
        id_token_signed_response_alg: "RS256",
        access_token_ttl_seconds: 900,
        authorization_code_ttl_seconds: 300,
        refresh_token_ttl_days: 30,
        created_at: FIXED_TIME,
        updated_at: FIXED_TIME,
      }),
      ...(overrides.oidcProviderRepositoryLike as Record<string, unknown>),
    } as any,
    userRepositoryLike: {
      getById: async () => user,
      ...(overrides.userRepositoryLike as Record<string, unknown>),
    } as any,
    verifiedIdentityRepositoryLike: {
      getByUserId: async () => verifiedIdentity,
      ...(overrides.verifiedIdentityRepositoryLike as Record<string, unknown>),
    } as any,
    pollRepositoryLike: {
      getOptionsByPollId: async () => [option],
    },
    mediaServiceLike: {
      createDisplayImageUrl: async (bucket: string | null, path: string | null) =>
        bucket && path ? `https://storage.example.test/${bucket}/${path}?signed=1` : null,
      ...(overrides.mediaServiceLike as Record<string, unknown>),
    } as any,
    repositoryLike: {
      getActiveReviewerByVerifiedIdentityId: async () => reviewer,
      listReviewRequiredPolls: async () => [createPollRow()],
      listReviewRequiredPosts: async () => [],
      listOpenReportedPosts: async () => [],
      listReviewRequiredComments: async () => [],
      getPollById: async () => createPollRow(),
      getPostById: async () => null,
      getOpenReportSummaryForPost: async () => null,
      listOpenReportsForPost: async () => [],
      getCommentById: async () => null,
      updatePollReviewStatus: async (input: any) =>
        createPollRow({
          moderation_status: input.status,
          human_review_status: "reviewed",
          human_review_decision: input.decision,
          human_reviewed_at: input.reviewedAt,
        }),
      updatePostReviewStatus: async () => null,
      updateReportedPostReviewStatus: async () => null,
      updateCommentReviewStatus: async () => null,
      markOpenPostReportsReviewed: async () => undefined,
      insertReviewAction: async (input: any) =>
        createReviewActionRow({
          content_type: input.contentType,
          content_id: input.contentId,
          reviewer_verified_identity_id: input.reviewerVerifiedIdentityId,
          reviewer_user_id: input.reviewerUserId,
          action: input.action,
          previous_status: input.previousStatus,
          new_status: input.newStatus,
          internal_note: input.internalNote,
          user_message: input.userMessage,
        }),
      ...(overrides.repositoryLike as Record<string, unknown>),
    } as any,
  });

describe("adminModerationService", () => {
  it("resolves an active admin from an admin-dashboard OIDC access token", async () => {
    const service = createBaseService();

    const result = await service.requireAdmin("Bearer oidc-access-token");

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.admin.verifiedIdentity.id).toBe("verified-identity-1");
      expect(result.admin.reviewer.role).toBe("reviewer");
    }
  });

  it("rejects OIDC tokens issued to non-admin clients", async () => {
    const service = createBaseService({
      oidcProviderRepositoryLike: {
        getClientById: async () => ({
          id: "client-db-id",
          client_id: "other-client",
          client_name: "Other",
          client_type: "confidential",
          application_type: "web",
          status: "active",
          client_uri: null,
          logo_uri: null,
          tos_uri: null,
          policy_uri: null,
          sector_identifier: "other.example",
          allowed_scopes: ["openid"],
          default_scopes: ["openid"],
          require_pkce: true,
          pkce_required_method: "S256",
          id_token_signed_response_alg: "RS256",
          access_token_ttl_seconds: 900,
          authorization_code_ttl_seconds: 300,
          refresh_token_ttl_days: 30,
          created_at: FIXED_TIME,
          updated_at: FIXED_TIME,
        }),
      },
    });

    const result = await service.requireAdmin("Bearer oidc-access-token");

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(403);
      expect(result.error).toBe("admin_client_required");
    }
  });

  it("lists review-required polls in the admin queue", async () => {
    const service = createBaseService();

    const items = await service.listQueue("poll", 10);

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      contentType: "poll",
      contentId: "poll-1",
      moderationStatus: "review_required",
    });
  });

  it("lists open reported published posts in the admin queue", async () => {
    const service = createBaseService({
      repositoryLike: {
        listReviewRequiredPosts: async () => [],
        listOpenReportedPosts: async () => [
          {
            post: createPostRow({
              moderation_status: "published",
              moderation_flagged: false,
              moderation_categories: {},
              moderation_category_scores: {},
            }),
            reportCount: 2,
            firstReportedAt: "2026-07-17T12:05:00.000Z",
            latestReportedAt: "2026-07-17T12:08:00.000Z",
          },
        ],
      },
    });

    const items = await service.listQueue("post", 10);

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      contentType: "post",
      contentId: "post-1",
      reviewSource: "user_report",
      reportStatus: "open",
      reportCount: 2,
      moderationStatus: "published",
    });
  });

  it("includes a signed preview URL for stored discussion post images", async () => {
    const service = createBaseService({
      repositoryLike: {
        getPostById: async () =>
          createPostRow({
            moderation_status: "published",
          }),
        getOpenReportSummaryForPost: async () => ({
          reportCount: 1,
          firstReportedAt: "2026-07-17T12:05:00.000Z",
          latestReportedAt: "2026-07-17T12:05:00.000Z",
        }),
        listOpenReportsForPost: async () => [
          {
            id: "report-1",
            post_id: "post-1",
            reporter_user_id: "reporter-1",
            category: "misinformation",
            comment: "This claim needs a source.",
            status: "open",
            created_at: "2026-07-17T12:05:00.000Z",
            updated_at: "2026-07-17T12:05:00.000Z",
          },
        ],
      },
    });

    const detail = await service.getReviewDetail("post", "post-1");

    expect(detail).toMatchObject({
      contentType: "post",
      imagePreviewUrl:
        "https://storage.example.test/discussion-media/discussions/ab/upload-1.jpg?signed=1",
      reports: [
        {
          category: "misinformation",
          comment: "This claim needs a source.",
          reporterUserId: "reporter-1",
        },
      ],
    });
  });

  it("approves a review-required poll and writes an audit action", async () => {
    const service = createBaseService();
    const auth = await service.requireAdmin("Bearer oidc-access-token");
    if (!auth.ok) {
      throw new Error("Expected admin auth success.");
    }

    const result = await service.applyDecision({
      admin: auth.admin,
      contentType: "poll",
      contentId: "poll-1",
      action: "approve",
      internalNote: "Acceptable civic content.",
    });

    expect(result).toMatchObject({
      success: true,
      status: "published",
    });
    if (result.success) {
      expect(result.reviewAction).toMatchObject({
        content_type: "poll",
        action: "approve",
        previous_status: "review_required",
        new_status: "published",
        internal_note: "Acceptable civic content.",
      });
    }
  });

  it("approves a reported published post without hiding it and closes reports", async () => {
    let closedReports = false;
    const service = createBaseService({
      repositoryLike: {
        getPostById: async () =>
          createPostRow({
            moderation_status: "published",
            moderation_flagged: false,
          }),
        getOpenReportSummaryForPost: async () => ({
          reportCount: 1,
          firstReportedAt: "2026-07-17T12:05:00.000Z",
          latestReportedAt: "2026-07-17T12:05:00.000Z",
        }),
        updateReportedPostReviewStatus: async (input: any) =>
          createPostRow({
            moderation_status: input.status,
            human_review_status: "reviewed",
            human_review_decision: input.decision,
            human_reviewed_at: input.reviewedAt,
          }),
        markOpenPostReportsReviewed: async () => {
          closedReports = true;
        },
        insertReviewAction: async (input: any) =>
          createReviewActionRow({
            content_type: input.contentType,
            content_id: input.contentId,
            reviewer_verified_identity_id: input.reviewerVerifiedIdentityId,
            reviewer_user_id: input.reviewerUserId,
            action: input.action,
            previous_status: input.previousStatus,
            new_status: input.newStatus,
          }),
      },
    });
    const auth = await service.requireAdmin("Bearer oidc-access-token");
    if (!auth.ok) {
      throw new Error("Expected admin auth success.");
    }

    const result = await service.applyDecision({
      admin: auth.admin,
      contentType: "post",
      contentId: "post-1",
      action: "approve",
    });

    expect(result).toMatchObject({
      success: true,
      status: "published",
    });
    expect(closedReports).toBe(true);
    if (result.success) {
      expect(result.reviewAction).toMatchObject({
        content_type: "discussion_post",
        previous_status: "published",
        new_status: "published",
      });
    }
  });
});
