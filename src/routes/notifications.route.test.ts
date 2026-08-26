import { describe, expect, it } from "bun:test";

process.env.ILAND_ENV_VALIDATION_SCOPE = "supabase-admin-script";
process.env.SOLANA_AUDIT_TRANSACTIONS_ENABLED = "false";

const viewerUserId = "00000000-0000-4000-8000-000000000001";

const buildDependencies = async () => {
  const { createNotificationRoutes } = await import("./notifications");
  const calls: Array<{ method: string; input: unknown }> = [];
  const service = {
    async list(input: unknown) {
      calls.push({ method: "list", input });
      return { notifications: [], nextCursor: null };
    },
    async countUnread(userId: string) {
      calls.push({ method: "countUnread", input: userId });
      return { unreadCount: 3 };
    },
    async update() {
      return null;
    },
    async markAllRead() {
      return { updatedCount: 0 };
    },
    async getPreferences() {
      return {
        pushEnabled: false,
        commentsAndRepliesPush: true,
        likesPush: true,
        preferredLocale: null,
      };
    },
    async updatePreferences() {
      return {
        pushEnabled: false,
        commentsAndRepliesPush: true,
        likesPush: true,
        preferredLocale: null,
      };
    },
  };
  return {
    calls,
    routes: createNotificationRoutes({
      requireViewerFn: (async () => ({
        ok: true,
        viewer: { userId: viewerUserId, user: { id: viewerUserId } },
      })) as never,
      service: service as never,
    }),
  };
};

describe("notification routes", () => {
  it("returns the authenticated viewer unread count without caching", async () => {
    const { routes, calls } = await buildDependencies();
    const route = routes.find(
      (candidate) => candidate.path === "/me/notifications/unread-count",
    );
    const request = new Request("https://backend.test/me/notifications/unread-count");
    const response = await route?.handler({
      request,
      url: new URL(request.url),
      params: {},
    });

    expect(response?.status).toBe(200);
    expect(response?.headers.get("cache-control")).toBe("no-store");
    expect(await response?.json()).toEqual({ unreadCount: 3 });
    expect(calls).toEqual([{ method: "countUnread", input: viewerUserId }]);
  });

  it("rejects a malformed cursor before querying the repository", async () => {
    const { routes, calls } = await buildDependencies();
    const route = routes.find(
      (candidate) => candidate.path === "/me/notifications",
    );
    const request = new Request(
      "https://backend.test/me/notifications?cursor=not-a-cursor",
    );
    const response = await route?.handler({
      request,
      url: new URL(request.url),
      params: {},
    });

    expect(response?.status).toBe(400);
    expect(calls).toHaveLength(0);
  });
});
