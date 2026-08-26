import { z } from "zod";
import { hashOpaqueBearerToken } from "../auth/tokens";
import defaultRequireViewer from "../auth/requireViewer";
import env from "../config/env";
import { json } from "../middleware/json";
import authSessionRepository from "../repositories/authSessionRepository";
import notificationRepository from "../repositories/notificationRepository";
import notificationService, {
  decodeNotificationCursor,
} from "../services/notificationService";
import { encryptPushToken, hashPushToken } from "../services/pushTokenCrypto";
import type { RouteDefinition } from "../types/http";

const notificationUpdateSchema = z
  .object({
    read: z.boolean().optional(),
    archived: z.boolean().optional(),
  })
  .refine((value) => value.read !== undefined || value.archived !== undefined);

const preferenceUpdateSchema = z
  .object({
    pushEnabled: z.boolean().optional(),
    commentsAndRepliesPush: z.boolean().optional(),
    likesPush: z.boolean().optional(),
    preferredLocale: z.string().trim().min(2).max(16).nullable().optional(),
  })
  .refine((value) => Object.keys(value).length > 0);

const installationSchema = z
  .object({
    platform: z.enum(["ios", "android"]),
    provider: z.enum(["apns", "fcm"]),
    providerEnvironment: z.enum(["sandbox", "production"]),
    token: z.string().trim().min(8).max(8192),
    permissionStatus: z.enum(["granted", "denied", "undetermined"]),
    locale: z.string().trim().min(2).max(16).nullable().optional(),
    appVersion: z.string().trim().max(40).nullable().optional(),
    buildNumber: z.string().trim().max(40).nullable().optional(),
  })
  .superRefine((value, context) => {
    if (
      (value.platform === "ios" && value.provider !== "apns") ||
      (value.platform === "android" && value.provider !== "fcm")
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "The push provider does not match the device platform.",
      });
    }
    if (value.provider === "fcm" && value.providerEnvironment !== "production") {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "FCM installations must use the production provider environment.",
      });
    }
  });

const parseJson = async (request: Request): Promise<unknown | null> => {
  try {
    return await request.json();
  } catch {
    return null;
  }
};

const currentSessionId = async (
  request: Request,
  expectedUserId: string,
): Promise<string | null> => {
  const authorizationHeader = request.headers.get("authorization")?.trim() || "";
  const token = /^Bearer\s+(.+)$/iu.exec(authorizationHeader)?.[1];
  if (!token) return null;
  const session = await authSessionRepository.getByAccessTokenHash(
    hashOpaqueBearerToken(token),
  );
  return session?.user_id === expectedUserId && session.status === "active"
    ? session.id
    : null;
};

type Dependencies = {
  requireViewerFn?: typeof defaultRequireViewer;
  service?: typeof notificationService;
};

export const createNotificationRoutes = (
  dependencies: Dependencies = {},
): RouteDefinition[] => {
  const requireViewer = dependencies.requireViewerFn ?? defaultRequireViewer;
  const service = dependencies.service ?? notificationService;

  return [
    {
      method: "GET",
      path: "/me/notifications",
      handler: async ({ request, url }) => {
        const viewerResult = await requireViewer(request);
        if (!viewerResult.ok) return viewerResult.response;

        const rawCursor = url.searchParams.get("cursor");
        const cursor = decodeNotificationCursor(rawCursor);
        if (rawCursor && !cursor) {
          return json({ error: "invalid_cursor", message: "Notification cursor is invalid." }, 400);
        }
        const limitValue = Number(url.searchParams.get("limit") || "30");
        const limit = Number.isFinite(limitValue)
          ? Math.max(1, Math.min(50, Math.trunc(limitValue)))
          : 30;
        const unreadOnly = url.searchParams.get("unreadOnly") === "true";
        return json(
          await service.list({
            userId: viewerResult.viewer.userId,
            limit,
            unreadOnly,
            cursor,
          }),
          200,
          { "cache-control": "no-store" },
        );
      },
    },
    {
      method: "GET",
      path: "/me/notifications/unread-count",
      handler: async ({ request }) => {
        const viewerResult = await requireViewer(request);
        if (!viewerResult.ok) return viewerResult.response;
        return json(
          await service.countUnread(viewerResult.viewer.userId),
          200,
          { "cache-control": "no-store" },
        );
      },
    },
    {
      method: "PATCH",
      path: "/me/notifications/:id",
      handler: async ({ request, params }) => {
        const viewerResult = await requireViewer(request);
        if (!viewerResult.ok) return viewerResult.response;
        if (!z.string().uuid().safeParse(params.id).success) {
          return json({ error: "not_found", message: "Notification not found." }, 404);
        }
        const parsed = notificationUpdateSchema.safeParse(await parseJson(request));
        if (!parsed.success) {
          return json({ error: "invalid_request", message: "Notification update is invalid." }, 400);
        }
        const notification = await service.update(
          viewerResult.viewer.userId,
          params.id,
          parsed.data,
        );
        return notification
          ? json({ notification }, 200, { "cache-control": "no-store" })
          : json({ error: "not_found", message: "Notification not found." }, 404);
      },
    },
    {
      method: "POST",
      path: "/me/notifications/read-all",
      handler: async ({ request }) => {
        const viewerResult = await requireViewer(request);
        if (!viewerResult.ok) return viewerResult.response;
        return json(
          await service.markAllRead(viewerResult.viewer.userId),
          200,
          { "cache-control": "no-store" },
        );
      },
    },
    {
      method: "GET",
      path: "/me/notification-preferences",
      handler: async ({ request }) => {
        const viewerResult = await requireViewer(request);
        if (!viewerResult.ok) return viewerResult.response;
        return json(
          { preferences: await service.getPreferences(viewerResult.viewer.userId) },
          200,
          { "cache-control": "no-store" },
        );
      },
    },
    {
      method: "PATCH",
      path: "/me/notification-preferences",
      handler: async ({ request }) => {
        const viewerResult = await requireViewer(request);
        if (!viewerResult.ok) return viewerResult.response;
        const parsed = preferenceUpdateSchema.safeParse(await parseJson(request));
        if (!parsed.success) {
          return json({ error: "invalid_request", message: "Notification preferences are invalid." }, 400);
        }
        return json(
          {
            preferences: await service.updatePreferences(
              viewerResult.viewer.userId,
              parsed.data,
            ),
          },
          200,
          { "cache-control": "no-store" },
        );
      },
    },
    {
      method: "PUT",
      path: "/me/push-installations/current",
      handler: async ({ request }) => {
        const viewerResult = await requireViewer(request);
        if (!viewerResult.ok) return viewerResult.response;
        if (!env.notifications.tokenEncryptionKey) {
          return json(
            {
              error: "push_registration_unavailable",
              message: "Push registration is not configured on this server.",
            },
            503,
          );
        }
        const parsed = installationSchema.safeParse(await parseJson(request));
        if (!parsed.success) {
          return json({ error: "invalid_request", message: "Push installation is invalid." }, 400);
        }
        const sessionId = await currentSessionId(
          request,
          viewerResult.viewer.userId,
        );
        if (!sessionId) {
          return json({ error: "session_context_required", message: "Current session was not found." }, 401);
        }
        await notificationRepository.upsertInstallation({
          userId: viewerResult.viewer.userId,
          authSessionId: sessionId,
          platform: parsed.data.platform,
          provider: parsed.data.provider,
          providerEnvironment: parsed.data.providerEnvironment,
          tokenCiphertext: encryptPushToken(
            parsed.data.token,
            env.notifications.tokenEncryptionKey,
          ),
          tokenHash: hashPushToken(parsed.data.token),
          permissionStatus: parsed.data.permissionStatus,
          locale: parsed.data.locale,
          appVersion: parsed.data.appVersion,
          buildNumber: parsed.data.buildNumber,
        });
        return json({ success: true }, 200, { "cache-control": "no-store" });
      },
    },
    {
      method: "DELETE",
      path: "/me/push-installations/current",
      handler: async ({ request }) => {
        const viewerResult = await requireViewer(request);
        if (!viewerResult.ok) return viewerResult.response;
        const sessionId = await currentSessionId(
          request,
          viewerResult.viewer.userId,
        );
        if (sessionId) await notificationRepository.revokeInstallation(sessionId);
        return json({ success: true }, 200, { "cache-control": "no-store" });
      },
    },
  ];
};

export const notificationRoutes = createNotificationRoutes();
export default notificationRoutes;
