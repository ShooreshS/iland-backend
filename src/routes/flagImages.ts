import { z } from "zod";
import requireViewer from "../auth/requireViewer";
import { json } from "../middleware/json";
import flagImageService from "../services/flagImageService";
import type { FlagImageErrorCode } from "../types/contracts";
import type { RouteDefinition } from "../types/http";

const createFlagImageUploadSchema = z
  .object({
    name: z.string().trim().min(1).max(80),
    fileName: z.string().trim().nullable().optional(),
    mimeType: z.enum(["image/jpeg", "image/png", "image/webp"]),
    sizeBytes: z.number().int().positive().max(5 * 1024 * 1024),
    width: z.number().int().min(20).max(512),
    height: z.number().int().min(20).max(512),
  })
  .superRefine((value, context) => {
    const ratio = value.width / value.height;
    if (ratio > 10 || ratio < 0.1) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Flag image aspect ratio must be between 10:1 and 1:10.",
      });
    }
  });

const errorStatusMap: Record<FlagImageErrorCode, number> = {
  USER_NOT_FOUND: 401,
  FLAG_IMAGE_NOT_FOUND: 404,
  FLAG_IMAGE_IN_USE: 409,
  NOT_FLAG_IMAGE_CREATOR: 403,
  VALIDATION_FAILED: 400,
  STORAGE_FAILED: 502,
  UPLOAD_NOT_READY: 409,
};

const createFlagImageUploadRoute: RouteDefinition = {
  method: "POST",
  path: "/flag-images/uploads",
  handler: async ({ request }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) return viewerResult.response;

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return json(
        { success: false, errorCode: "VALIDATION_FAILED", message: "Request body must be valid JSON." },
        400,
      );
    }

    const parsed = createFlagImageUploadSchema.safeParse(body);
    if (!parsed.success) {
      return json(
        { success: false, errorCode: "VALIDATION_FAILED", message: "Flag image upload request is invalid." },
        400,
      );
    }

    const result = await flagImageService.createUpload(
      parsed.data,
      viewerResult.viewer.userId,
    );
    return json(
      result,
      result.success ? 201 : errorStatusMap[result.errorCode || "VALIDATION_FAILED"],
    );
  },
};

const completeFlagImageUploadRoute: RouteDefinition = {
  method: "POST",
  path: "/flag-images/uploads/:id/complete",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) return viewerResult.response;

    const id = params.id?.trim() || "";
    if (!z.string().uuid().safeParse(id).success) {
      return json(
        { success: false, errorCode: "FLAG_IMAGE_NOT_FOUND", message: "The flag image upload could not be found." },
        404,
      );
    }

    const result = await flagImageService.completeUpload(
      id,
      viewerResult.viewer.userId,
    );
    return json(
      result,
      result.success ? 200 : errorStatusMap[result.errorCode || "VALIDATION_FAILED"],
    );
  },
};

const deleteFlagImageRoute: RouteDefinition = {
  method: "DELETE",
  path: "/flag-images/:id",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) return viewerResult.response;

    const id = params.id?.trim() || "";
    if (!z.string().uuid().safeParse(id).success) {
      return json(
        { success: false, errorCode: "FLAG_IMAGE_NOT_FOUND", message: "The flag image could not be found." },
        404,
      );
    }

    const result = await flagImageService.deleteImage(
      id,
      viewerResult.viewer.userId,
    );
    return json(
      result,
      result.success ? 200 : errorStatusMap[result.errorCode || "VALIDATION_FAILED"],
    );
  },
};

export const flagImageRoutes: RouteDefinition[] = [
  createFlagImageUploadRoute,
  completeFlagImageUploadRoute,
  deleteFlagImageRoute,
];

export default flagImageRoutes;
