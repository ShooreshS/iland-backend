import { z } from "zod";

import { json } from "../middleware/json";
import adminModerationService from "../services/adminModerationService";
import humanVerificationService from "../services/humanVerificationService";
import type { HumanVerificationMediaKind } from "../types/db";
import type { RouteDefinition } from "../types/http";

const platformSchema = z.enum(["ios", "android"]);
const challengeSchema = z
  .object({
    platform: platformSchema,
    credentialIdHint: z.string().trim().min(1).nullable().optional(),
  })
  .strict();
const mediaSchema = z
  .object({
    kind: z.enum(["document_portrait", "live_face"]),
    mimeType: z.literal("image/jpeg"),
    sizeBytes: z.number().int().positive().max(10 * 1024 * 1024),
    width: z.number().int().min(113).max(8192),
    height: z.number().int().min(113).max(8192),
    sha256: z.string().regex(/^[0-9a-f]{64}$/u),
  })
  .strict();
const createSchema = z
  .object({
    challengeId: z.string().uuid(),
    challenge: z.string().trim().min(1),
    platform: platformSchema,
    credentialId: z.string().trim().min(1).max(200),
    publicKeyPem: z.string().trim().min(1).max(4000),
    signature: z.string().trim().min(1).max(2000),
    appAttestation: z.record(z.unknown()),
    documentType: z.string().trim().min(1).max(80),
    comparison: z
      .object({
        similarity: z.number().finite().min(-1).max(1),
        threshold: z.number().finite().min(0).max(1),
        model: z.string().trim().min(1).max(100).nullable().optional(),
      })
      .strict(),
    livenessPassed: z.literal(true),
    gazePassed: z.boolean().nullable().optional(),
    media: z.array(mediaSchema).length(2),
  })
  .strict();
const pushSchema = z
  .object({
    platform: platformSchema,
    provider: z.enum(["apns", "fcm"]),
    providerEnvironment: z.enum(["sandbox", "production"]),
    token: z.string().trim().min(1).max(8192),
    locale: z.string().trim().min(2).max(35).nullable().optional(),
  })
  .strict();
const decisionSchema = z
  .object({
    action: z.enum(["approve", "reject"]),
    internalNote: z.string().trim().max(4000).nullable().optional(),
    userMessage: z.string().trim().max(1000).nullable().optional(),
  })
  .strict();

const parseJson = async (request: Request) => {
  try {
    return { ok: true as const, value: await request.json() };
  } catch {
    return { ok: false as const };
  }
};

const reviewToken = (request: Request): string | null =>
  /^Bearer\s+(.+)$/iu.exec(request.headers.get("authorization")?.trim() || "")?.[1]?.trim() ||
  null;

const invalid = (message: string) =>
  json({ success: false, errorCode: "INVALID_INPUT", message }, 400, {
    "cache-control": "no-store",
  });

const statusForError = (errorCode?: string) => {
  switch (errorCode) {
    case "NOT_FOUND":
      return 404;
    case "FORBIDDEN":
      return 403;
    case "INVALID_CHALLENGE":
    case "INVALID_PUBLIC_KEY":
    case "INVALID_SIGNATURE_ENCODING":
    case "INVALID_MEDIA":
    case "NOT_ELIGIBLE":
    case "USER_MESSAGE_REQUIRED":
      return 400;
    case "INVALID_SIGNATURE":
      return 401;
    case "ATTESTATION_INVALID":
      return 400;
    case "ACTIVE_REQUEST_EXISTS":
    case "NOT_UPLOADABLE":
    case "NOT_CANCELLABLE":
    case "NOT_REVIEWABLE":
    case "CONFLICT":
      return 409;
    case "STORAGE_FAILED":
    case "PUSH_NOT_CONFIGURED":
      return 503;
    case "MEDIA_NOT_READY":
    case "MEDIA_MISMATCH":
      return 409;
    default:
      return 400;
  }
};

const challengeRoute: RouteDefinition = {
  method: "POST",
  path: "/verification-reviews/challenge",
  handler: async ({ request }) => {
    const body = await parseJson(request);
    const parsed = body.ok ? challengeSchema.safeParse(body.value) : null;
    if (!parsed?.success) return invalid("Challenge request body is invalid.");
    return json(await humanVerificationService.issueChallenge(parsed.data), 201, {
      "cache-control": "no-store",
    });
  },
};

const createRoute: RouteDefinition = {
  method: "POST",
  path: "/verification-reviews",
  handler: async ({ request }) => {
    const body = await parseJson(request);
    const parsed = body.ok ? createSchema.safeParse(body.value) : null;
    if (!parsed?.success) return invalid("Human-verification request body is invalid.");
    const result = await humanVerificationService.createRequest(parsed.data);
    return json(result, result.success ? 201 : statusForError(result.errorCode), {
      "cache-control": "no-store",
    });
  },
};

const completeRoute: RouteDefinition = {
  method: "POST",
  path: "/verification-reviews/:id/complete",
  handler: async ({ request, params }) => {
    const token = reviewToken(request);
    if (!token) return json({ success: false, errorCode: "NOT_FOUND" }, 404);
    const result = await humanVerificationService.completeRequest(params.id, token);
    return json(result, result.success ? 200 : statusForError(result.errorCode), {
      "cache-control": "no-store",
    });
  },
};

const refreshUploadsRoute: RouteDefinition = {
  method: "POST",
  path: "/verification-reviews/:id/uploads",
  handler: async ({ request, params }) => {
    const token = reviewToken(request);
    if (!token) return json({ success: false, errorCode: "NOT_FOUND" }, 404);
    const result = await humanVerificationService.refreshUploadUrls(params.id, token);
    return json(result, result.success ? 200 : statusForError(result.errorCode), {
      "cache-control": "no-store",
    });
  },
};

const statusRoute: RouteDefinition = {
  method: "GET",
  path: "/verification-reviews/:id",
  handler: async ({ request, params }) => {
    const token = reviewToken(request);
    if (!token) return json({ success: false, errorCode: "NOT_FOUND" }, 404);
    const result = await humanVerificationService.getRequest(params.id, token);
    return json(result, result.success ? 200 : 404, {
      "cache-control": "no-store",
    });
  },
};

const cancelRoute: RouteDefinition = {
  method: "DELETE",
  path: "/verification-reviews/:id",
  handler: async ({ request, params }) => {
    const token = reviewToken(request);
    if (!token) return json({ success: false, errorCode: "NOT_FOUND" }, 404);
    const result = await humanVerificationService.cancelRequest(params.id, token);
    return json(result, result.success ? 200 : statusForError(result.errorCode), {
      "cache-control": "no-store",
    });
  },
};

const pushRoute: RouteDefinition = {
  method: "PUT",
  path: "/verification-reviews/:id/push-installation",
  handler: async ({ request, params }) => {
    const token = reviewToken(request);
    if (!token) return json({ success: false, errorCode: "NOT_FOUND" }, 404);
    const body = await parseJson(request);
    const parsed = body.ok ? pushSchema.safeParse(body.value) : null;
    if (!parsed?.success) return invalid("Push installation body is invalid.");
    const result = await humanVerificationService.registerPushInstallation(
      params.id,
      token,
      parsed.data,
    );
    return json(result, result.success ? 200 : statusForError(result.errorCode), {
      "cache-control": "no-store",
    });
  },
};

const requireAdmin = async (request: Request) => {
  const result = await adminModerationService.requireAdmin(
    request.headers.get("authorization"),
  );
  return result.ok
    ? result
    : {
        ...result,
        response: json(
          { success: false, errorCode: result.error, message: result.message },
          result.status,
          { "cache-control": "no-store" },
        ),
      };
};

const adminQueueRoute: RouteDefinition = {
  method: "GET",
  path: "/admin/user-verifications",
  handler: async ({ request, url }) => {
    const admin = await requireAdmin(request);
    if (!admin.ok) return admin.response;
    const limit = Number(url.searchParams.get("limit") || 50);
    return json({
      success: true,
      items: await humanVerificationService.listAdminQueue(limit),
    }, 200, { "cache-control": "no-store" });
  },
};

const adminDetailRoute: RouteDefinition = {
  method: "GET",
  path: "/admin/user-verifications/:id",
  handler: async ({ request, params }) => {
    const admin = await requireAdmin(request);
    if (!admin.ok) return admin.response;
    const detail = await humanVerificationService.getAdminDetail(params.id);
    return detail
      ? json({ success: true, detail }, 200, { "cache-control": "no-store" })
      : json({ success: false, errorCode: "NOT_FOUND" }, 404);
  },
};

const adminMediaRoute: RouteDefinition = {
  method: "GET",
  path: "/admin/user-verifications/:id/media/:kind",
  handler: async ({ request, params }) => {
    const admin = await requireAdmin(request);
    if (!admin.ok) return admin.response;
    if (params.kind !== "document_portrait" && params.kind !== "live_face") {
      return invalid("Media kind is invalid.");
    }
    const media = await humanVerificationService.getAdminMedia(
      params.id,
      params.kind as HumanVerificationMediaKind,
    );
    return media
      ? new Response(media.bytes, {
          status: 200,
          headers: {
            "content-type": media.mimeType,
            "cache-control": "no-store, private",
            "content-disposition": "inline",
            "x-content-type-options": "nosniff",
          },
        })
      : json({ success: false, errorCode: "NOT_FOUND" }, 404);
  },
};

const adminDecisionRoute: RouteDefinition = {
  method: "POST",
  path: "/admin/user-verifications/:id/decision",
  handler: async ({ request, params }) => {
    const admin = await requireAdmin(request);
    if (!admin.ok) return admin.response;
    const body = await parseJson(request);
    const parsed = body.ok ? decisionSchema.safeParse(body.value) : null;
    if (!parsed?.success) return invalid("Decision body is invalid.");
    const result = await humanVerificationService.applyAdminDecision({
      admin: admin.admin,
      requestId: params.id,
      ...parsed.data,
    });
    return json(result, result.success ? 200 : statusForError(result.errorCode), {
      "cache-control": "no-store",
    });
  },
};

export const humanVerificationRoutes: RouteDefinition[] = [
  challengeRoute,
  createRoute,
  completeRoute,
  refreshUploadsRoute,
  statusRoute,
  cancelRoute,
  pushRoute,
  adminQueueRoute,
  adminDetailRoute,
  adminMediaRoute,
  adminDecisionRoute,
];

export default humanVerificationRoutes;
