import { z } from "zod";
import requireViewer, { optionalViewer } from "../auth/requireViewer";
import { json } from "../middleware/json";
import discussionService from "../services/discussionService";
import type {
  CreateDiscussionCommentRequestDto,
  CreateDiscussionPostReportRequestDto,
  CreateDiscussionPostRequestDto,
  DiscussionMutationErrorCode,
} from "../types/contracts";
import type { RouteDefinition } from "../types/http";

const discussionPostTypeSchema = z.enum([
  "discussion",
  "question",
  "proposal",
  "announcement",
]);

const discussionImageSchema = z
  .object({
    imageUrl: z.string().trim().min(1).nullable().optional(),
    storageBucket: z.string().trim().min(1).nullable().optional(),
    storagePath: z.string().trim().min(1).nullable().optional(),
    uploadId: z.string().trim().min(1).nullable().optional(),
    mimeType: z.string().trim().min(1).nullable().optional(),
    sizeBytes: z.number().int().positive().nullable().optional(),
    altText: z.string().trim().nullable().optional(),
  })
  .strict()
  .refine(
    (image) =>
      Boolean(image.imageUrl) ||
      Boolean(image.storageBucket && image.storagePath && image.uploadId),
    {
      message: "Image URL or completed upload reference is required.",
    },
  );

const createDiscussionPostSchema = z
  .object({
    postType: discussionPostTypeSchema.default("discussion"),
    caption: z.string().nullable().optional(),
    image: discussionImageSchema.nullable().optional(),
    imageAltText: z.string().trim().nullable().optional(),
  })
  .strict();

const createDiscussionCommentSchema = z
  .object({
    body: z.string(),
  })
  .strict();

const discussionReportCategorySchema = z.enum([
  "spam",
  "harassment",
  "hate_or_abuse",
  "misinformation",
  "illegal_or_unsafe",
  "other",
]);

const createDiscussionPostReportSchema = z
  .object({
    category: discussionReportCategorySchema,
    comment: z.string().trim().max(1000).nullable().optional(),
  })
  .strict();

const mutationErrorStatusMap: Record<DiscussionMutationErrorCode, number> = {
  USER_NOT_FOUND: 401,
  VERIFIED_IDENTITY_REQUIRED: 403,
  POST_NOT_FOUND: 404,
  POST_NOT_EDITABLE: 409,
  USER_BLOCK_NOT_ALLOWED: 409,
  VALIDATION_FAILED: 400,
  MODERATION_FAILED: 502,
};

const parseJsonBody = async (request: Request): Promise<
  | { ok: true; body: unknown }
  | { ok: false; response: Response }
> => {
  try {
    return { ok: true, body: await request.json() };
  } catch {
    return {
      ok: false,
      response: json(
        {
          error: "invalid_request",
          message: "Request body must be valid JSON.",
        },
        400,
      ),
    };
  }
};

const parseLimit = (url: URL): number | null => {
  const raw = url.searchParams.get("limit");
  if (!raw) {
    return null;
  }

  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : null;
};

const getDiscussionsRoute: RouteDefinition = {
  method: "GET",
  path: "/discussions",
  handler: async ({ request, url }) => {
    const viewerResult = await optionalViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    return json(
      await discussionService.listPosts(
        viewerResult.viewer?.userId ?? null,
        parseLimit(url),
      ),
    );
  },
};

const createDiscussionRoute: RouteDefinition = {
  method: "POST",
  path: "/discussions",
  handler: async ({ request }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const bodyResult = await parseJsonBody(request);
    if (!bodyResult.ok) {
      return bodyResult.response;
    }

    const parsed = createDiscussionPostSchema.safeParse(bodyResult.body);
    if (!parsed.success) {
      return json(
        {
          success: false,
          errorCode: "VALIDATION_FAILED",
          message: "Discussion post request body is invalid.",
        },
        400,
      );
    }

    const result = await discussionService.createPost(
      parsed.data as CreateDiscussionPostRequestDto,
      viewerResult.viewer.userId,
    );

    return json(
      result,
      result.success
        ? 201
        : mutationErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400,
    );
  },
};

const getDiscussionRoute: RouteDefinition = {
  method: "GET",
  path: "/discussions/:id",
  handler: async ({ request, params }) => {
    const viewerResult = await optionalViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const postId = params.id?.trim() || "";
    if (!postId) {
      return json(
        {
          success: false,
          errorCode: "POST_NOT_FOUND",
          message: "The discussion post could not be found.",
        },
        404,
      );
    }

    const result = await discussionService.getPost(
      postId,
      viewerResult.viewer?.userId ?? null,
    );
    if (!result) {
      return json(
        {
          success: false,
          errorCode: "POST_NOT_FOUND",
          message: "The discussion post could not be found.",
        },
        404,
      );
    }

    return json(result);
  },
};

const updateDiscussionRoute: RouteDefinition = {
  method: "PATCH",
  path: "/discussions/:id",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const postId = params.id?.trim() || "";
    if (!postId) {
      return json(
        {
          success: false,
          errorCode: "POST_NOT_FOUND",
          message: "The discussion post could not be found.",
        },
        404,
      );
    }

    const bodyResult = await parseJsonBody(request);
    if (!bodyResult.ok) {
      return bodyResult.response;
    }

    const parsed = createDiscussionPostSchema.safeParse(bodyResult.body);
    if (!parsed.success) {
      return json(
        {
          success: false,
          errorCode: "VALIDATION_FAILED",
          message: "Discussion post request body is invalid.",
        },
        400,
      );
    }

    const result = await discussionService.updatePost(
      postId,
      parsed.data as CreateDiscussionPostRequestDto,
      viewerResult.viewer.userId,
    );

    return json(
      result,
      result.success
        ? 200
        : mutationErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400,
    );
  },
};

const deleteDiscussionRoute: RouteDefinition = {
  method: "DELETE",
  path: "/discussions/:id",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const postId = params.id?.trim() || "";
    if (!postId) {
      return json(
        {
          success: false,
          errorCode: "POST_NOT_FOUND",
          message: "The discussion post could not be found.",
        },
        404,
      );
    }

    const result = await discussionService.deletePost(
      postId,
      viewerResult.viewer.userId,
    );

    return json(
      result,
      result.success
        ? 200
        : mutationErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400,
    );
  },
};

const getDiscussionCommentsRoute: RouteDefinition = {
  method: "GET",
  path: "/discussions/:id/comments",
  handler: async ({ request, params, url }) => {
    const viewerResult = await optionalViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const postId = params.id?.trim() || "";
    if (!postId) {
      return json({ comments: [] });
    }

    return json(
      await discussionService.listComments(
        postId,
        viewerResult.viewer?.userId ?? null,
        parseLimit(url),
      ),
    );
  },
};

const createDiscussionCommentRoute: RouteDefinition = {
  method: "POST",
  path: "/discussions/:id/comments",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const postId = params.id?.trim() || "";
    if (!postId) {
      return json(
        {
          success: false,
          errorCode: "POST_NOT_FOUND",
          message: "The discussion post could not be found.",
        },
        404,
      );
    }

    const bodyResult = await parseJsonBody(request);
    if (!bodyResult.ok) {
      return bodyResult.response;
    }

    const parsed = createDiscussionCommentSchema.safeParse(bodyResult.body);
    if (!parsed.success) {
      return json(
        {
          success: false,
          errorCode: "VALIDATION_FAILED",
          message: "Discussion comment request body is invalid.",
        },
        400,
      );
    }

    const result = await discussionService.createComment(
      postId,
      parsed.data as CreateDiscussionCommentRequestDto,
      viewerResult.viewer.userId,
    );

    return json(
      result,
      result.success
        ? 201
        : mutationErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400,
    );
  },
};

const likeDiscussionRoute: RouteDefinition = {
  method: "POST",
  path: "/discussions/:id/like",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const result = await discussionService.likePost(
      params.id?.trim() || "",
      viewerResult.viewer.userId,
    );
    return json(
      result,
      result.success
        ? 200
        : mutationErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400,
    );
  },
};

const unlikeDiscussionRoute: RouteDefinition = {
  method: "DELETE",
  path: "/discussions/:id/like",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const result = await discussionService.unlikePost(
      params.id?.trim() || "",
      viewerResult.viewer.userId,
    );
    return json(
      result,
      result.success
        ? 200
        : mutationErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400,
    );
  },
};

const bookmarkDiscussionRoute: RouteDefinition = {
  method: "POST",
  path: "/discussions/:id/bookmark",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const result = await discussionService.setPostBookmarked(
      params.id?.trim() || "",
      viewerResult.viewer.userId,
      true,
    );
    return json(
      result,
      result.success
        ? 200
        : mutationErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400,
    );
  },
};

const unbookmarkDiscussionRoute: RouteDefinition = {
  method: "DELETE",
  path: "/discussions/:id/bookmark",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const result = await discussionService.setPostBookmarked(
      params.id?.trim() || "",
      viewerResult.viewer.userId,
      false,
    );
    return json(
      result,
      result.success
        ? 200
        : mutationErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400,
    );
  },
};

const blockDiscussionAuthorRoute: RouteDefinition = {
  method: "POST",
  path: "/discussions/:id/block",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const result = await discussionService.blockPostAuthor(
      params.id?.trim() || "",
      viewerResult.viewer.userId,
    );
    return json(
      result,
      result.success
        ? 200
        : mutationErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400,
    );
  },
};

const unblockDiscussionAuthorRoute: RouteDefinition = {
  method: "DELETE",
  path: "/discussions/:id/block",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const result = await discussionService.unblockPostAuthor(
      params.id?.trim() || "",
      viewerResult.viewer.userId,
    );
    return json(
      result,
      result.success
        ? 200
        : mutationErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400,
    );
  },
};

const reportDiscussionRoute: RouteDefinition = {
  method: "POST",
  path: "/discussions/:id/report",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const bodyResult = await parseJsonBody(request);
    if (!bodyResult.ok) {
      return bodyResult.response;
    }

    const parsed = createDiscussionPostReportSchema.safeParse(bodyResult.body);
    if (!parsed.success) {
      return json(
        {
          success: false,
          errorCode: "VALIDATION_FAILED",
          message: "Discussion report request body is invalid.",
        },
        400,
      );
    }

    const result = await discussionService.reportPost(
      params.id?.trim() || "",
      parsed.data as CreateDiscussionPostReportRequestDto,
      viewerResult.viewer.userId,
    );
    return json(
      result,
      result.success
        ? 201
        : mutationErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400,
    );
  },
};

export const discussionRoutes: RouteDefinition[] = [
  getDiscussionsRoute,
  createDiscussionRoute,
  getDiscussionRoute,
  updateDiscussionRoute,
  deleteDiscussionRoute,
  getDiscussionCommentsRoute,
  createDiscussionCommentRoute,
  likeDiscussionRoute,
  unlikeDiscussionRoute,
  bookmarkDiscussionRoute,
  unbookmarkDiscussionRoute,
  blockDiscussionAuthorRoute,
  unblockDiscussionAuthorRoute,
  reportDiscussionRoute,
];
