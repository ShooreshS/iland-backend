import { z } from "zod";
import { json } from "../middleware/json";
import adminModerationService from "../services/adminModerationService";
import type {
  AdminContentType,
  AdminContext,
} from "../services/adminModerationService";
import type { RouteDefinition } from "../types/http";

const contentTypeSchema = z.enum(["poll", "post", "comment"]);
const queueTypeSchema = z.enum(["all", "poll", "post", "comment"]).default("all");
const decisionSchema = z
  .object({
    action: z.enum(["approve", "reject", "request_edit"]),
    internalNote: z.string().trim().max(4000).nullable().optional(),
    userMessage: z.string().trim().max(1000).nullable().optional(),
  })
  .strict();

const parseLimit = (url: URL): number | null => {
  const raw = url.searchParams.get("limit");
  if (!raw) {
    return null;
  }

  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : null;
};

const parseJsonBody = async (
  request: Request,
): Promise<{ ok: true; body: unknown } | { ok: false; response: Response }> => {
  try {
    return { ok: true, body: await request.json() };
  } catch {
    return {
      ok: false,
      response: json(
        {
          success: false,
          errorCode: "INVALID_INPUT",
          message: "Request body must be valid JSON.",
        },
        400,
      ),
    };
  }
};

const requireAdmin = async (
  request: Request,
): Promise<{ ok: true; admin: AdminContext } | { ok: false; response: Response }> => {
  const authResult = await adminModerationService.requireAdmin(
    request.headers.get("authorization"),
  );
  if (!authResult.ok) {
    return {
      ok: false,
      response: json(
        {
          success: false,
          errorCode: authResult.error,
          message: authResult.message,
        },
        authResult.status,
      ),
    };
  }

  return { ok: true, admin: authResult.admin };
};

const adminMeRoute: RouteDefinition = {
  method: "GET",
  path: "/admin/me",
  handler: async ({ request }) => {
    const adminResult = await requireAdmin(request);
    if (!adminResult.ok) {
      return adminResult.response;
    }

    return json({
      success: true,
      admin: {
        userId: adminResult.admin.user.id,
        publicNickname: adminResult.admin.user.public_nickname,
        verifiedIdentityId: adminResult.admin.verifiedIdentity.id,
        role: adminResult.admin.reviewer.role,
      },
    });
  },
};

const reviewQueueRoute: RouteDefinition = {
  method: "GET",
  path: "/admin/moderation/queue",
  handler: async ({ request, url }) => {
    const adminResult = await requireAdmin(request);
    if (!adminResult.ok) {
      return adminResult.response;
    }

    const parsedType = queueTypeSchema.safeParse(
      url.searchParams.get("type") || "all",
    );
    if (!parsedType.success) {
      return json(
        {
          success: false,
          errorCode: "INVALID_INPUT",
          message: "Queue type must be all, poll, post, or comment.",
        },
        400,
      );
    }

    return json({
      success: true,
      items: await adminModerationService.listQueue(
        parsedType.data,
        parseLimit(url),
      ),
    });
  },
};

const reviewDetailRoute: RouteDefinition = {
  method: "GET",
  path: "/admin/moderation/:contentType/:id",
  handler: async ({ request, params }) => {
    const adminResult = await requireAdmin(request);
    if (!adminResult.ok) {
      return adminResult.response;
    }

    const parsedType = contentTypeSchema.safeParse(params.contentType);
    if (!parsedType.success) {
      return json(
        {
          success: false,
          errorCode: "INVALID_INPUT",
          message: "Content type must be poll, post, or comment.",
        },
        400,
      );
    }

    const detail = await adminModerationService.getReviewDetail(
      parsedType.data,
      params.id,
    );
    if (!detail) {
      return json(
        {
          success: false,
          errorCode: "CONTENT_NOT_FOUND",
          message: "The requested review item could not be found.",
        },
        404,
      );
    }

    return json({ success: true, detail });
  },
};

const reviewDecisionRoute: RouteDefinition = {
  method: "POST",
  path: "/admin/moderation/:contentType/:id/decision",
  handler: async ({ request, params }) => {
    const adminResult = await requireAdmin(request);
    if (!adminResult.ok) {
      return adminResult.response;
    }

    const parsedType = contentTypeSchema.safeParse(params.contentType);
    if (!parsedType.success) {
      return json(
        {
          success: false,
          errorCode: "INVALID_INPUT",
          message: "Content type must be poll, post, or comment.",
        },
        400,
      );
    }

    const bodyResult = await parseJsonBody(request);
    if (!bodyResult.ok) {
      return bodyResult.response;
    }

    const parsedBody = decisionSchema.safeParse(bodyResult.body);
    if (!parsedBody.success) {
      return json(
        {
          success: false,
          errorCode: "INVALID_INPUT",
          message: "Review decision request body is invalid.",
        },
        400,
      );
    }

    const result = await adminModerationService.applyDecision({
      admin: adminResult.admin,
      contentType: parsedType.data as AdminContentType,
      contentId: params.id,
      action: parsedBody.data.action,
      internalNote: parsedBody.data.internalNote,
      userMessage: parsedBody.data.userMessage,
    });

    if (!result.success) {
      const status =
        result.errorCode === "CONTENT_NOT_FOUND"
          ? 404
          : result.errorCode === "FORBIDDEN"
            ? 403
            : result.errorCode === "NOT_REVIEWABLE"
              ? 409
              : 400;
      return json(result, status);
    }

    return json(result);
  },
};

export const adminModerationRoutes: RouteDefinition[] = [
  adminMeRoute,
  reviewQueueRoute,
  reviewDetailRoute,
  reviewDecisionRoute,
];

export default adminModerationRoutes;
