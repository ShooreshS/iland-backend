import { describe, expect, it } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import type {
  DiscussionPostRow,
  ModerationReviewActionRow,
  PollRow,
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

const { createViewerContentService } = await import("./viewerContentService");

const FIXED_TIME = "2026-07-17T12:00:00.000Z";

const createPostRow = (
  overrides: Partial<DiscussionPostRow> = {},
): DiscussionPostRow => ({
  id: "post-1",
  author_user_id: "user-1",
  author_public_nickname: "clear-voter",
  post_type: "discussion",
  caption: "A discussion that needs edits",
  image_url: null,
  image_storage_bucket: "discussion-media",
  image_storage_path: "discussions/ab/upload-1.jpg",
  image_mime_type: "image/jpeg",
  image_size_bytes: 1234,
  image_alt_text: "Uploaded image",
  moderation_status: "needs_edit",
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
  human_review_status: "reviewed",
  human_review_decision: "request_edit",
  human_reviewed_at: FIXED_TIME,
  like_count: 4,
  comment_count: 2,
  feed_score: 6,
  deliberation_id: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createReviewActionRow = (
  overrides: Partial<ModerationReviewActionRow> = {},
): ModerationReviewActionRow => ({
  id: "review-action-1",
  content_type: "discussion_post",
  content_id: "post-1",
  reviewer_verified_identity_id: "verified-identity-1",
  reviewer_user_id: "reviewer-1",
  action: "request_edit",
  previous_status: "review_required",
  new_status: "needs_edit",
  internal_note: "Internal note",
  user_message: "Please remove the sale language before publishing.",
  created_at: FIXED_TIME,
  ...overrides,
});

const createPollRow = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "poll-1",
  slug: "poll-1",
  created_by_user_id: "user-1",
  title: "A poll",
  description: null,
  status: "active",
  moderation_status: "published",
  moderation_model: null,
  moderation_flagged: false,
  moderation_categories: null,
  moderation_category_scores: null,
  moderation_applied_input_types: null,
  moderation_raw: null,
  moderated_at: null,
  moderation_error: null,
  moderation_policy_version: null,
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

describe("viewerContentService", () => {
  it("returns owner discussion posts with the latest human-facing review note", async () => {
    const service = createViewerContentService({
      discussionRepositoryLike: {
        listPostsByAuthorUserId: async (userId: string, limit: number) => {
          expect(userId).toBe("user-1");
          expect(limit).toBe(5);
          return [createPostRow()];
        },
        listReviewActionsForDiscussionPosts: async (postIds: string[]) => {
          expect(postIds).toEqual(["post-1"]);
          return [
            createReviewActionRow({
              id: "review-action-1",
              user_message: "Older note",
              created_at: "2026-07-17T11:00:00.000Z",
            }),
            createReviewActionRow({
              id: "review-action-2",
              user_message: "Please remove the sale language before publishing.",
              created_at: "2026-07-17T12:00:00.000Z",
            }),
          ];
        },
        getPostEngagementTotalsByAuthorUserId: async () => ({
          postCount: 0,
          likeCount: 0,
          commentCount: 0,
        }),
      },
      mediaServiceLike: {
        createDisplayImageUrl: async (bucket: string | null, path: string | null) =>
          bucket && path
            ? `https://storage.example.test/${bucket}/${path}?signed=1`
            : null,
      },
    } as any);

    const result = await service.listDiscussionPosts("user-1", 5);

    expect(result.posts).toHaveLength(1);
    expect(result.posts[0]).toMatchObject({
      id: "post-1",
      moderationStatus: "needs_edit",
      humanReviewStatus: "reviewed",
      humanReviewDecision: "request_edit",
      imageUrl:
        "https://storage.example.test/discussion-media/discussions/ab/upload-1.jpg?signed=1",
      latestReviewUserMessage:
        "Please remove the sale language before publishing.",
      latestReviewAction: {
        action: "request_edit",
        newStatus: "needs_edit",
      },
    });
  });

  it("aggregates post reactions and votes cast on viewer-created polls", async () => {
    const seenLegacyPollIds: string[][] = [];
    const seenZkPollIds: string[][] = [];
    const service = createViewerContentService({
      discussionRepositoryLike: {
        listPostsByAuthorUserId: async () => [],
        listReviewActionsForDiscussionPosts: async () => [],
        getPostEngagementTotalsByAuthorUserId: async (userId: string) => {
          expect(userId).toBe("user-1");
          return {
            postCount: 2,
            likeCount: 7,
            commentCount: 3,
          };
        },
      },
      pollRepositoryLike: {
        listByCreatedByUserId: async (userId: string) => {
          expect(userId).toBe("user-1");
          return [
            createPollRow({ id: "poll-1" }),
            createPollRow({ id: "poll-2", slug: "poll-2" }),
          ];
        },
      },
      voteRepositoryLike: {
        countValidByPollIds: async (pollIds: string[]) => {
          seenLegacyPollIds.push(pollIds);
          return 5;
        },
      },
      pollZkVoteRepositoryLike: {
        countAcceptedByPollIds: async (pollIds: string[]) => {
          seenZkPollIds.push(pollIds);
          return 4;
        },
      },
    } as any);

    const result = await service.getActivityOverview("user-1");

    expect(seenLegacyPollIds).toEqual([["poll-1", "poll-2"]]);
    expect(seenZkPollIds).toEqual([["poll-1", "poll-2"]]);
    expect(result).toEqual({
      createdPostCount: 2,
      postLikesReceived: 7,
      postCommentsReceived: 3,
      postReactionsReceived: 10,
      createdPollCount: 2,
      pollVotesReceived: 9,
    });
  });
});
