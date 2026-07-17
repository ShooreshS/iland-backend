import { describe, expect, it } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import type {
  DiscussionCommentRow,
  DiscussionPostRow,
  UserRow,
  VerifiedIdentityRow,
} from "../types/db";
import type { ModeratePostResult } from "./contentModerationService";

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

const { createDiscussionService } = await import("./discussionService");

const FIXED_TIME = "2026-07-17T12:00:00.000Z";

const createUser = (overrides: Partial<UserRow> = {}): UserRow => ({
  id: "user-1",
  username: "user1",
  display_name: null,
  public_nickname: "clear-voter",
  onboarding_status: "completed",
  verification_level: "nid_verified",
  has_wallet: true,
  wallet_credential_id: null,
  selected_land_id: null,
  preferred_language: null,
  auth_generation: 1,
  account_status: "active",
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

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

const createModerationResult = (
  overrides: Partial<ModeratePostResult> = {},
): ModeratePostResult => ({
  decision: "allow",
  moderationStatus: "published",
  model: "omni-moderation-latest",
  flagged: false,
  categories: {},
  categoryScores: {},
  appliedInputTypes: {},
  raw: null,
  error: null,
  policyVersion: "gate1-v1",
  moderatedAt: FIXED_TIME,
  ...overrides,
});

const createPostRow = (
  overrides: Partial<DiscussionPostRow> = {},
): DiscussionPostRow => ({
  id: "post-1",
  author_user_id: "user-1",
  author_public_nickname: "clear-voter",
  post_type: "discussion",
  caption: "A clean discussion",
  image_url: null,
  image_mime_type: null,
  image_size_bytes: null,
  image_alt_text: null,
  moderation_status: "published",
  moderation_model: "omni-moderation-latest",
  moderation_flagged: false,
  moderation_categories: {},
  moderation_category_scores: {},
  moderation_applied_input_types: {},
  moderation_raw: null,
  moderated_at: FIXED_TIME,
  moderation_error: null,
  moderation_policy_version: "gate1-v1",
  gate2_status: null,
  gate2_model: null,
  gate2_result: null,
  human_review_status: null,
  human_review_decision: null,
  human_reviewed_at: null,
  like_count: 0,
  comment_count: 0,
  feed_score: 1,
  deliberation_id: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createCommentRow = (
  overrides: Partial<DiscussionCommentRow> = {},
): DiscussionCommentRow => ({
  id: "comment-1",
  post_id: "post-1",
  author_user_id: "user-1",
  author_public_nickname: "clear-voter",
  body: "A clean comment",
  moderation_status: "published",
  moderation_model: "omni-moderation-latest",
  moderation_flagged: false,
  moderation_categories: {},
  moderation_category_scores: {},
  moderation_applied_input_types: {},
  moderation_raw: null,
  moderated_at: FIXED_TIME,
  moderation_error: null,
  moderation_policy_version: "gate1-v1",
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createRepo = () => {
  const posts: DiscussionPostRow[] = [];
  const comments: DiscussionCommentRow[] = [];

  return {
    posts,
    comments,
    repo: {
      listPublishedPosts: async () =>
        posts.filter((post) => post.moderation_status === "published"),
      getPostById: async (postId: string) =>
        posts.find((post) => post.id === postId) || null,
      insertPost: async (input: any) => {
        const row = createPostRow({
          id: input.id,
          author_user_id: input.author_user_id,
          author_public_nickname: input.author_public_nickname,
          post_type: input.post_type,
          caption: input.caption,
          image_url: input.image_url,
          image_mime_type: input.image_mime_type,
          image_size_bytes: input.image_size_bytes,
          image_alt_text: input.image_alt_text,
          moderation_status: input.moderation_status,
          moderation_model: input.moderation_model,
          moderation_flagged: input.moderation_flagged,
          moderation_categories: input.moderation_categories,
          moderation_category_scores: input.moderation_category_scores,
          moderation_applied_input_types: input.moderation_applied_input_types,
          moderation_error: input.moderation_error,
          moderation_policy_version: input.moderation_policy_version,
        });
        posts.push(row);
        return row;
      },
      getLikedPostIds: async () => new Set<string>(),
      getLike: async () => null,
      insertLike: async () => undefined,
      deleteLike: async () => undefined,
      listPublishedComments: async (postId: string) =>
        comments.filter(
          (comment) =>
            comment.post_id === postId &&
            comment.moderation_status === "published",
        ),
      insertComment: async (input: any) => {
        const row = createCommentRow({
          id: input.id,
          post_id: input.post_id,
          author_user_id: input.author_user_id,
          author_public_nickname: input.author_public_nickname,
          body: input.body,
          moderation_status: input.moderation_status,
          moderation_model: input.moderation_model,
          moderation_flagged: input.moderation_flagged,
          moderation_error: input.moderation_error,
          moderation_policy_version: input.moderation_policy_version,
        });
        comments.push(row);
        return row;
      },
    },
  };
};

describe("discussionService", () => {
  it("rejects publishing when the viewer has no linked verified identity", async () => {
    const { repo } = createRepo();
    const service = createDiscussionService({
      discussionRepositoryLike: repo as any,
      userRepositoryLike: { getById: async () => createUser() },
      verifiedIdentityRepositoryLike: { getByUserId: async () => null },
      moderationServiceLike: {
        moderatePost: async () => createModerationResult(),
      },
    });

    const result = await service.createPost(
      { postType: "discussion", caption: "Hello" },
      "user-1",
    );

    expect(result).toMatchObject({
      success: false,
      errorCode: "VERIFIED_IDENTITY_REQUIRED",
    });
  });

  it("moderates and stores a published image discussion", async () => {
    const { repo, posts } = createRepo();
    const moderatedInputs: any[] = [];
    const service = createDiscussionService({
      discussionRepositoryLike: repo as any,
      userRepositoryLike: { getById: async () => createUser() },
      verifiedIdentityRepositoryLike: { getByUserId: async () => verifiedIdentity },
      imageResolver: async (image) => image,
      moderationServiceLike: {
        moderatePost: async (input) => {
          moderatedInputs.push(input);
          return createModerationResult();
        },
      },
    });

    const result = await service.createPost(
      {
        postType: "proposal",
        caption: "Add night buses",
        image: {
          imageUrl: "https://example.test/bus.jpg",
          mimeType: "image/jpeg",
          sizeBytes: 10_000,
          altText: "A night bus",
        },
      },
      "user-1",
    );

    expect(result.success).toBe(true);
    expect(result.post?.moderationStatus).toBe("published");
    expect(result.post?.postType).toBe("proposal");
    expect(posts[0].image_url).toBe("https://example.test/bus.jpg");
    expect(moderatedInputs[0]).toMatchObject({
      body: "Add night buses",
      imageUrl: "https://example.test/bus.jpg",
      imageAltText: "A night bus",
    });
  });

  it("stores moderated comments individually and hides held comments from public lists", async () => {
    const { repo, posts } = createRepo();
    posts.push(createPostRow());
    const service = createDiscussionService({
      discussionRepositoryLike: repo as any,
      userRepositoryLike: { getById: async () => createUser() },
      verifiedIdentityRepositoryLike: { getByUserId: async () => verifiedIdentity },
      moderationServiceLike: {
        moderatePost: async () =>
          createModerationResult({
            decision: "blocked",
            moderationStatus: "blocked",
            flagged: true,
            categories: { harassment: true },
          }),
      },
    });

    const result = await service.createComment(
      "post-1",
      { body: "A comment requiring moderation" },
      "user-1",
    );
    const list = await service.listComments("post-1");

    expect(result.success).toBe(true);
    expect(result.comment?.moderationStatus).toBe("blocked");
    expect(result.message).toContain("could not be published");
    expect(list.comments).toEqual([]);
  });
});
