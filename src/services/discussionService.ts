import { randomUUID } from "node:crypto";
import discussionRepository from "../repositories/discussionRepository";
import userRepository from "../repositories/userRepository";
import verifiedIdentityRepository from "../repositories/verifiedIdentityRepository";
import {
  contentModerationService,
  type ModeratePostResult,
} from "./contentModerationService";
import { validateModerationGate0 } from "./contentModerationGate0Service";
import {
  discussionMediaService,
  type DiscussionImageResolutionResult,
} from "./discussionMediaService";
import type {
  CreateDiscussionCommentRequestDto,
  CreateDiscussionCommentResultDto,
  CreateDiscussionPostRequestDto,
  CreateDiscussionPostResultDto,
  DeleteDiscussionPostResultDto,
  DiscussionCommentDto,
  DiscussionCommentListDto,
  DiscussionImageInputDto,
  DiscussionLikeResultDto,
  DiscussionMutationErrorCode,
  DiscussionPostDto,
  DiscussionPostListDto,
  DiscussionPostType,
} from "../types/contracts";
import type {
  DiscussionCommentRow,
  DiscussionPostRow,
  UserRow,
  VerifiedIdentityRow,
} from "../types/db";

const DISCUSSION_POST_TYPES = new Set<DiscussionPostType>([
  "discussion",
  "question",
  "proposal",
  "announcement",
]);

const DEFAULT_POST_LIMIT = 50;
const MAX_POST_LIMIT = 100;
const DEFAULT_COMMENT_LIMIT = 100;
const MAX_COMMENT_LIMIT = 200;
const EDITABLE_POST_MODERATION_STATUSES = new Set([
  "review_required",
  "needs_edit",
  "moderation_error",
]);
const DELETABLE_POST_MODERATION_STATUSES = [
  "draft",
  "moderation_pending",
  "review_required",
  "needs_edit",
  "blocked",
  "moderation_error",
  "appeal_pending",
  "appeal_approved",
  "appeal_rejected",
];
const DELETABLE_POST_MODERATION_STATUS_SET = new Set(
  DELETABLE_POST_MODERATION_STATUSES,
);

const MODERATION_USER_MESSAGES: Record<
  ModeratePostResult["decision"],
  string | null
> = {
  allow: null,
  review_required:
    "Your discussion needs additional review before it can be published.",
  blocked:
    "This discussion could not be published because it appears to violate CivicOS safety rules.",
  moderation_error:
    "We could not complete moderation. The discussion has not been published.",
};

const COMMENT_MODERATION_USER_MESSAGES: Record<
  ModeratePostResult["decision"],
  string | null
> = {
  allow: null,
  review_required:
    "Your comment needs additional review before it can be published.",
  blocked:
    "This comment could not be published because it appears to violate CivicOS safety rules.",
  moderation_error:
    "We could not complete moderation. The comment has not been published.",
};

type ImageResolver = (
  input: DiscussionImageInputDto | null,
  viewerUserId: string,
) => Promise<DiscussionImageResolutionResult>;

type ResolvedPostImageForModeration = NonNullable<
  Extract<DiscussionImageResolutionResult, { ok: true }>["image"]
>;

type DiscussionServiceDependencies = {
  discussionRepositoryLike?: typeof discussionRepository;
  userRepositoryLike?: Pick<typeof userRepository, "getById">;
  verifiedIdentityRepositoryLike?: Pick<typeof verifiedIdentityRepository, "getByUserId">;
  moderationServiceLike?: Pick<typeof contentModerationService, "moderatePost">;
  mediaServiceLike?: Pick<
    typeof discussionMediaService,
    | "resolveUploadedImageForModeration"
    | "createDisplayImageUrl"
    | "attachUploadToPost"
  >;
  imageResolver?: ImageResolver;
};

const normalizeText = (value: unknown): string | null => {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
};

const normalizePostType = (value: unknown): DiscussionPostType =>
  DISCUSSION_POST_TYPES.has(value as DiscussionPostType)
    ? (value as DiscussionPostType)
    : "discussion";

const normalizeLimit = (
  value: number | null | undefined,
  fallback: number,
  max: number,
): number => {
  if (!Number.isFinite(value)) {
    return fallback;
  }

  return Math.min(max, Math.max(1, Math.trunc(value as number)));
};

const getAuthorNickname = (user: UserRow): string | null =>
  user.public_nickname || user.display_name || user.username || null;

const createFailure = <T extends { success: boolean }>(
  errorCode: DiscussionMutationErrorCode,
  message: string,
): T =>
  ({
    success: false,
    errorCode,
    message,
  }) as unknown as T;

const hasUploadedImageReference = (input: DiscussionImageInputDto | null): boolean =>
  Boolean(
    normalizeText(input?.uploadId) ||
      normalizeText(input?.storageBucket) ||
      normalizeText(input?.storagePath),
  );

const resolveImageMetadataFromUrl = async (
  input: DiscussionImageInputDto | null,
): Promise<DiscussionImageResolutionResult> => {
  const imageUrl = normalizeText(input?.imageUrl);
  if (!imageUrl) {
    return { ok: true, image: null };
  }

  let mimeType = normalizeText(input?.mimeType)?.toLowerCase() || null;
  let sizeBytes =
    Number.isInteger(input?.sizeBytes) && Number(input?.sizeBytes) > 0
      ? Number(input?.sizeBytes)
      : null;

  if (!mimeType || !sizeBytes) {
    try {
      const response = await fetch(imageUrl, { method: "HEAD" });
      mimeType =
        mimeType ||
        normalizeText(response.headers.get("content-type"))?.split(";")[0]?.toLowerCase() ||
        null;
      const contentLength = Number(response.headers.get("content-length"));
      sizeBytes =
        sizeBytes || (Number.isInteger(contentLength) && contentLength > 0
          ? contentLength
          : null);
    } catch {
      // Gate 0 will return a user-safe metadata error when HEAD cannot resolve it.
    }
  }

  return {
    ok: true,
    image: {
      moderationImageUrl: imageUrl,
      storedImageUrl: imageUrl,
      storageBucket: null,
      storagePath: null,
      uploadId: null,
      mimeType: mimeType || "",
      sizeBytes: sizeBytes || 0,
      altText: normalizeText(input?.altText),
    },
  };
};

const createExistingImageForModeration = async (
  row: DiscussionPostRow,
  createDisplayImageUrl: (
    storageBucket: string | null,
    storagePath: string | null,
  ) => Promise<string | null>,
  altTextOverride?: string | null,
): Promise<DiscussionImageResolutionResult> => {
  if (!row.image_url && !row.image_storage_path) {
    return { ok: true, image: null };
  }

  const moderationImageUrl =
    row.image_url ||
    (await createDisplayImageUrl(
      row.image_storage_bucket,
      row.image_storage_path,
    ));

  if (!moderationImageUrl) {
    return {
      ok: false,
      errorCode: "MODERATION_FAILED",
      message: "We could not prepare the current image for moderation.",
    };
  }

  return {
    ok: true,
    image: {
      moderationImageUrl,
      storedImageUrl: row.image_url,
      storageBucket: row.image_storage_bucket,
      storagePath: row.image_storage_path,
      uploadId: null,
      mimeType: row.image_mime_type || "",
      sizeBytes: row.image_size_bytes || 0,
      altText:
        altTextOverride !== undefined
          ? normalizeText(altTextOverride)
          : row.image_alt_text,
    },
  };
};

const mapPost = (
  row: DiscussionPostRow,
  viewerLikedPostIds = new Set<string>(),
  displayImageUrl: string | null = row.image_url,
): DiscussionPostDto => ({
  id: row.id,
  authorUserId: row.author_user_id,
  authorNickname: row.author_public_nickname,
  postType: row.post_type,
  caption: row.caption,
  imageUrl: displayImageUrl,
  imageStorageBucket: row.image_storage_bucket,
  imageStoragePath: row.image_storage_path,
  imageMimeType: row.image_mime_type,
  imageSizeBytes: row.image_size_bytes,
  imageAltText: row.image_alt_text,
  moderationStatus: row.moderation_status,
  moderationModel: row.moderation_model,
  moderationFlagged: row.moderation_flagged,
  moderatedAt: row.moderated_at,
  moderationPolicyVersion: row.moderation_policy_version,
  likeCount: row.like_count,
  commentCount: row.comment_count,
  feedScore: row.feed_score,
  viewerHasLiked: viewerLikedPostIds.has(row.id),
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

const mapComment = (row: DiscussionCommentRow): DiscussionCommentDto => ({
  id: row.id,
  postId: row.post_id,
  authorUserId: row.author_user_id,
  authorNickname: row.author_public_nickname,
  body: row.body,
  moderationStatus: row.moderation_status,
  moderationModel: row.moderation_model,
  moderationFlagged: row.moderation_flagged,
  moderatedAt: row.moderated_at,
  moderationPolicyVersion: row.moderation_policy_version,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

const applyModeration = (moderation: ModeratePostResult) => ({
  moderation_status: moderation.moderationStatus,
  moderation_model: moderation.model,
  moderation_flagged: moderation.flagged,
  moderation_categories: moderation.categories,
  moderation_category_scores: moderation.categoryScores,
  moderation_applied_input_types: moderation.appliedInputTypes,
  moderation_raw: moderation.raw,
  moderated_at: moderation.moderatedAt,
  moderation_error: moderation.error,
  moderation_policy_version: moderation.policyVersion,
});

export const createDiscussionService = (
  dependencies: DiscussionServiceDependencies = {},
) => {
  const repo = dependencies.discussionRepositoryLike || discussionRepository;
  const userRepo = dependencies.userRepositoryLike || userRepository;
  const verifiedIdentityRepo =
    dependencies.verifiedIdentityRepositoryLike || verifiedIdentityRepository;
  const moderationService =
    dependencies.moderationServiceLike || contentModerationService;
  const mediaService = dependencies.mediaServiceLike || discussionMediaService;
  const imageResolver =
    dependencies.imageResolver ||
    (async (input: DiscussionImageInputDto | null, viewerUserId: string) => {
      if (!input) {
        return { ok: true, image: null };
      }

      if (hasUploadedImageReference(input)) {
        return mediaService.resolveUploadedImageForModeration(
          input,
          viewerUserId,
        );
      }

      return resolveImageMetadataFromUrl(input);
    });

  const resolveDisplayImageUrl = async (
    row: DiscussionPostRow,
  ): Promise<string | null> => {
    if (row.image_url) {
      return row.image_url;
    }

    return mediaService.createDisplayImageUrl(
      row.image_storage_bucket,
      row.image_storage_path,
    );
  };

  const requireVerifiedCreator = async (
    viewerUserId: string,
  ): Promise<
    | { ok: true; user: UserRow; verifiedIdentity: VerifiedIdentityRow }
    | { ok: false; errorCode: DiscussionMutationErrorCode; message: string }
  > => {
    const [user, verifiedIdentity] = await Promise.all([
      userRepo.getById(viewerUserId),
      verifiedIdentityRepo.getByUserId(viewerUserId),
    ]);

    if (!user) {
      return {
        ok: false,
        errorCode: "USER_NOT_FOUND",
        message: "The current user could not be resolved.",
      };
    }

    if (!verifiedIdentity) {
      return {
        ok: false,
        errorCode: "VERIFIED_IDENTITY_REQUIRED",
        message: "A verified identity is required for discussion publishing.",
      };
    }

    return { ok: true, user, verifiedIdentity };
  };

  const moderatePostInput = async (params: {
    postId: string;
    input: CreateDiscussionPostRequestDto;
    viewerUserId: string;
    existingPost?: DiscussionPostRow | null;
  }): Promise<
    | {
        ok: true;
        caption: string | null;
        image: ResolvedPostImageForModeration | null;
        moderation: ModeratePostResult;
      }
    | {
        ok: false;
        errorCode: DiscussionMutationErrorCode;
        message: string;
      }
  > => {
    const { postId, input, viewerUserId, existingPost } = params;
    const caption = normalizeText(input.caption);
    const imageResult =
      existingPost && input.image === undefined
        ? await createExistingImageForModeration(
            existingPost,
            mediaService.createDisplayImageUrl,
            input.imageAltText,
          )
        : await imageResolver(input.image ?? null, viewerUserId);

    if (!imageResult.ok) {
      return {
        ok: false,
        errorCode: imageResult.errorCode,
        message: imageResult.message,
      };
    }

    const image = imageResult.image;
    const gate0 = validateModerationGate0({
      body: caption,
      image: image
        ? {
            imageUrl: image.moderationImageUrl,
            mimeType: image.mimeType,
            sizeBytes: image.sizeBytes,
            altText: image.altText,
          }
        : null,
    });

    if (!gate0.ok) {
      return {
        ok: false,
        errorCode: "VALIDATION_FAILED",
        message: gate0.message,
      };
    }

    const moderation = await moderationService.moderatePost({
      postId,
      body: caption,
      imageUrl: image?.moderationImageUrl,
      imageAltText: image?.altText,
    });

    return {
      ok: true,
      caption,
      image,
      moderation,
    };
  };

  return {
    async listPosts(
      viewerUserId: string | null,
      limit?: number | null,
    ): Promise<DiscussionPostListDto> {
      const rows = await repo.listPublishedPosts(
        normalizeLimit(limit, DEFAULT_POST_LIMIT, MAX_POST_LIMIT),
      );
      const likedPostIds = viewerUserId
        ? await repo.getLikedPostIds(
            viewerUserId,
            rows.map((row) => row.id),
          )
        : new Set<string>();

      const posts = await Promise.all(
        rows.map(async (row) =>
          mapPost(row, likedPostIds, await resolveDisplayImageUrl(row)),
        ),
      );

      return { posts };
    },

    async createPost(
      input: CreateDiscussionPostRequestDto,
      viewerUserId: string,
    ): Promise<CreateDiscussionPostResultDto> {
      const creator = await requireVerifiedCreator(viewerUserId);
      if (!creator.ok) {
        return createFailure<CreateDiscussionPostResultDto>(
          creator.errorCode,
          creator.message,
        );
      }

      const postId = randomUUID();
      const moderationResult = await moderatePostInput({
        postId,
        input,
        viewerUserId: creator.user.id,
      });
      if (!moderationResult.ok) {
        return createFailure<CreateDiscussionPostResultDto>(
          moderationResult.errorCode,
          moderationResult.message,
        );
      }

      const { caption, image, moderation } = moderationResult;
      const stored = await repo.insertPost({
        id: postId,
        author_user_id: creator.user.id,
        author_public_nickname: getAuthorNickname(creator.user),
        post_type: normalizePostType(input.postType),
        caption,
        image_url: image?.storedImageUrl ?? null,
        image_storage_bucket: image?.storageBucket ?? null,
        image_storage_path: image?.storagePath ?? null,
        image_mime_type: image?.mimeType ?? null,
        image_size_bytes: image?.sizeBytes ?? null,
        image_alt_text: image?.altText ?? null,
        ...applyModeration(moderation),
      });
      await mediaService.attachUploadToPost(
        image?.uploadId ?? null,
        creator.user.id,
        stored.id,
      );
      const displayImageUrl = await resolveDisplayImageUrl(stored);

      return {
        success: true,
        post: mapPost(stored, new Set(), displayImageUrl),
        ...(MODERATION_USER_MESSAGES[moderation.decision]
          ? { message: MODERATION_USER_MESSAGES[moderation.decision] as string }
          : null),
      };
    },

    async updatePost(
      postId: string,
      input: CreateDiscussionPostRequestDto,
      viewerUserId: string,
    ): Promise<CreateDiscussionPostResultDto> {
      const creator = await requireVerifiedCreator(viewerUserId);
      if (!creator.ok) {
        return createFailure<CreateDiscussionPostResultDto>(
          creator.errorCode,
          creator.message,
        );
      }

      const existingPost = await repo.getPostById(postId);
      if (!existingPost || existingPost.author_user_id !== creator.user.id) {
        return createFailure<CreateDiscussionPostResultDto>(
          "POST_NOT_FOUND",
          "The discussion post could not be found.",
        );
      }

      if (!EDITABLE_POST_MODERATION_STATUSES.has(existingPost.moderation_status)) {
        return createFailure<CreateDiscussionPostResultDto>(
          "POST_NOT_EDITABLE",
          "Only unpublished posts waiting for review or edits can be changed here.",
        );
      }

      const moderationResult = await moderatePostInput({
        postId: existingPost.id,
        input,
        viewerUserId: creator.user.id,
        existingPost,
      });
      if (!moderationResult.ok) {
        return createFailure<CreateDiscussionPostResultDto>(
          moderationResult.errorCode,
          moderationResult.message,
        );
      }

      const { caption, image, moderation } = moderationResult;
      const stored = await repo.updatePostById(existingPost.id, {
        id: existingPost.id,
        author_user_id: creator.user.id,
        author_public_nickname: getAuthorNickname(creator.user),
        post_type: normalizePostType(input.postType),
        caption,
        image_url: image?.storedImageUrl ?? null,
        image_storage_bucket: image?.storageBucket ?? null,
        image_storage_path: image?.storagePath ?? null,
        image_mime_type: image?.mimeType ?? null,
        image_size_bytes: image?.sizeBytes ?? null,
        image_alt_text: image?.altText ?? null,
        human_review_status: null,
        human_review_decision: null,
        human_reviewed_at: null,
        gate2_status: null,
        gate2_model: null,
        gate2_result: null,
        ...applyModeration(moderation),
      });

      if (!stored) {
        return createFailure<CreateDiscussionPostResultDto>(
          "POST_NOT_FOUND",
          "The discussion post could not be found.",
        );
      }

      await mediaService.attachUploadToPost(
        image?.uploadId ?? null,
        creator.user.id,
        stored.id,
      );
      const displayImageUrl = await resolveDisplayImageUrl(stored);

      return {
        success: true,
        post: mapPost(stored, new Set(), displayImageUrl),
        ...(MODERATION_USER_MESSAGES[moderation.decision]
          ? { message: MODERATION_USER_MESSAGES[moderation.decision] as string }
          : null),
      };
    },

    async deletePost(
      postId: string,
      viewerUserId: string,
    ): Promise<DeleteDiscussionPostResultDto> {
      const creator = await requireVerifiedCreator(viewerUserId);
      if (!creator.ok) {
        return createFailure<DeleteDiscussionPostResultDto>(
          creator.errorCode,
          creator.message,
        );
      }

      const existingPost = await repo.getPostById(postId);
      if (!existingPost || existingPost.author_user_id !== creator.user.id) {
        return createFailure<DeleteDiscussionPostResultDto>(
          "POST_NOT_FOUND",
          "The discussion post could not be found.",
        );
      }

      if (
        !DELETABLE_POST_MODERATION_STATUS_SET.has(existingPost.moderation_status)
      ) {
        return createFailure<DeleteDiscussionPostResultDto>(
          "POST_NOT_EDITABLE",
          "Only unpublished discussion posts can be deleted here.",
        );
      }

      const deleted = await repo.deletePostById(
        existingPost.id,
        creator.user.id,
        DELETABLE_POST_MODERATION_STATUSES,
      );
      if (!deleted) {
        return createFailure<DeleteDiscussionPostResultDto>(
          "POST_NOT_EDITABLE",
          "This discussion post is no longer unpublished.",
        );
      }

      return {
        success: true,
        postId: existingPost.id,
      };
    },

    async listComments(
      postId: string,
      limit?: number | null,
    ): Promise<DiscussionCommentListDto> {
      const post = await repo.getPostById(postId);
      if (!post || post.moderation_status !== "published") {
        return { comments: [] };
      }

      const comments = await repo.listPublishedComments(
        postId,
        normalizeLimit(limit, DEFAULT_COMMENT_LIMIT, MAX_COMMENT_LIMIT),
      );

      return { comments: comments.map(mapComment) };
    },

    async createComment(
      postId: string,
      input: CreateDiscussionCommentRequestDto,
      viewerUserId: string,
    ): Promise<CreateDiscussionCommentResultDto> {
      const creator = await requireVerifiedCreator(viewerUserId);
      if (!creator.ok) {
        return createFailure<CreateDiscussionCommentResultDto>(
          creator.errorCode,
          creator.message,
        );
      }

      const post = await repo.getPostById(postId);
      if (!post || post.moderation_status !== "published") {
        return createFailure<CreateDiscussionCommentResultDto>(
          "POST_NOT_FOUND",
          "The discussion post could not be found.",
        );
      }

      const body = normalizeText(input.body);
      const gate0 = validateModerationGate0({ body });
      if (!gate0.ok) {
        return createFailure<CreateDiscussionCommentResultDto>(
          "VALIDATION_FAILED",
          gate0.message,
        );
      }

      const commentId = randomUUID();
      const moderation = await moderationService.moderatePost({
        postId: commentId,
        body,
      });
      const stored = await repo.insertComment({
        id: commentId,
        post_id: post.id,
        author_user_id: creator.user.id,
        author_public_nickname: getAuthorNickname(creator.user),
        body: body as string,
        ...applyModeration(moderation),
      });

      return {
        success: true,
        comment: mapComment(stored),
        ...(COMMENT_MODERATION_USER_MESSAGES[moderation.decision]
          ? { message: COMMENT_MODERATION_USER_MESSAGES[moderation.decision] as string }
          : null),
      };
    },

    async likePost(
      postId: string,
      viewerUserId: string,
    ): Promise<DiscussionLikeResultDto> {
      const creator = await requireVerifiedCreator(viewerUserId);
      if (!creator.ok) {
        return createFailure<DiscussionLikeResultDto>(
          creator.errorCode,
          creator.message,
        );
      }

      const post = await repo.getPostById(postId);
      if (!post || post.moderation_status !== "published") {
        return createFailure<DiscussionLikeResultDto>(
          "POST_NOT_FOUND",
          "The discussion post could not be found.",
        );
      }

      if (!(await repo.getLike(postId, viewerUserId))) {
        await repo.insertLike(postId, viewerUserId);
      }
      const updated = await repo.getPostById(postId);

      return {
        success: true,
        postId,
        liked: true,
        likeCount: updated?.like_count ?? post.like_count,
      };
    },

    async unlikePost(
      postId: string,
      viewerUserId: string,
    ): Promise<DiscussionLikeResultDto> {
      const creator = await requireVerifiedCreator(viewerUserId);
      if (!creator.ok) {
        return createFailure<DiscussionLikeResultDto>(
          creator.errorCode,
          creator.message,
        );
      }

      const post = await repo.getPostById(postId);
      if (!post || post.moderation_status !== "published") {
        return createFailure<DiscussionLikeResultDto>(
          "POST_NOT_FOUND",
          "The discussion post could not be found.",
        );
      }

      await repo.deleteLike(postId, viewerUserId);
      const updated = await repo.getPostById(postId);

      return {
        success: true,
        postId,
        liked: false,
        likeCount: updated?.like_count ?? Math.max(post.like_count - 1, 0),
      };
    },
  };
};

export const discussionService = createDiscussionService();

export default discussionService;
