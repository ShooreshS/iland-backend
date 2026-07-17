import { z } from "zod";
import requireViewer from "../auth/requireViewer";
import { json } from "../middleware/json";
import discussionMediaService from "../services/discussionMediaService";
import type {
  CreateDiscussionImageUploadRequestDto,
  DiscussionImageUploadErrorCode,
} from "../types/contracts";
import type { RouteDefinition } from "../types/http";

const createDiscussionImageUploadSchema = z
  .object({
    fileName: z.string().trim().nullable().optional(),
    mimeType: z.string().trim().min(1),
    sizeBytes: z.number().int().positive(),
  })
  .strict();

const mediaErrorStatusMap: Record<DiscussionImageUploadErrorCode, number> = {
  USER_NOT_FOUND: 401,
  VERIFIED_IDENTITY_REQUIRED: 403,
  VALIDATION_FAILED: 400,
  STORAGE_NOT_CONFIGURED: 503,
  STORAGE_FAILED: 502,
  UPLOAD_NOT_FOUND: 404,
  UPLOAD_NOT_READY: 409,
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
          success: false,
          errorCode: "VALIDATION_FAILED",
          message: "Request body must be valid JSON.",
        },
        400,
      ),
    };
  }
};

const createDiscussionImageUploadRoute: RouteDefinition = {
  method: "POST",
  path: "/discussions/images/uploads",
  handler: async ({ request }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const bodyResult = await parseJsonBody(request);
    if (!bodyResult.ok) {
      return bodyResult.response;
    }

    const parsed = createDiscussionImageUploadSchema.safeParse(bodyResult.body);
    if (!parsed.success) {
      return json(
        {
          success: false,
          errorCode: "VALIDATION_FAILED",
          message: "Image upload request body is invalid.",
        },
        400,
      );
    }

    const result = await discussionMediaService.createImageUpload(
      parsed.data as CreateDiscussionImageUploadRequestDto,
      viewerResult.viewer.userId,
    );

    return json(
      result,
      result.success
        ? 201
        : mediaErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400,
    );
  },
};

const completeDiscussionImageUploadRoute: RouteDefinition = {
  method: "POST",
  path: "/discussions/images/uploads/:id/complete",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const uploadId = params.id?.trim() || "";
    if (!uploadId) {
      return json(
        {
          success: false,
          errorCode: "UPLOAD_NOT_FOUND",
          message: "The image upload could not be found.",
        },
        404,
      );
    }

    const result = await discussionMediaService.completeImageUpload(
      uploadId,
      viewerResult.viewer.userId,
    );

    return json(
      result,
      result.success
        ? 200
        : mediaErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400,
    );
  },
};

export const discussionMediaRoutes: RouteDefinition[] = [
  createDiscussionImageUploadRoute,
  completeDiscussionImageUploadRoute,
];
