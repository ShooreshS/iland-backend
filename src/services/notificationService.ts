import notificationRepository, {
  type NotificationPreferenceRow,
  type NotificationRow,
} from "../repositories/notificationRepository";

export type NotificationCursor = {
  lastEventAt: string;
  id: string;
};

const encodeCursor = (cursor: NotificationCursor): string =>
  Buffer.from(JSON.stringify(cursor), "utf8").toString("base64url");

export const decodeNotificationCursor = (
  value: string | null | undefined,
): NotificationCursor | null => {
  if (!value) return null;
  try {
    const decoded = JSON.parse(
      Buffer.from(value, "base64url").toString("utf8"),
    ) as Partial<NotificationCursor>;
    if (
      typeof decoded.id !== "string" ||
      !/^[0-9a-f-]{36}$/iu.test(decoded.id) ||
      typeof decoded.lastEventAt !== "string" ||
      !Number.isFinite(new Date(decoded.lastEventAt).getTime())
    ) {
      return null;
    }
    return { id: decoded.id, lastEventAt: decoded.lastEventAt };
  } catch {
    return null;
  }
};

const toNotificationDto = (row: NotificationRow) => ({
  id: row.id,
  eventType: row.event_type,
  actorUserId: row.actor_user_id,
  actorPublicNickname:
    typeof row.payload?.actorPublicNickname === "string"
      ? row.payload.actorPublicNickname
      : null,
  subjectType: row.subject_type,
  subjectId: row.subject_id,
  parentPostId: row.parent_post_id,
  targetUrl: row.target_url,
  aggregationCount: row.aggregation_count,
  firstEventAt: row.first_event_at,
  lastEventAt: row.last_event_at,
  readAt: row.read_at,
  archivedAt: row.archived_at,
});

const toPreferenceDto = (row: NotificationPreferenceRow) => ({
  pushEnabled: row.push_enabled,
  commentsAndRepliesPush: row.comments_and_replies_push,
  likesPush: row.likes_push,
  preferredLocale: row.preferred_locale,
});

export const notificationService = {
  async list(input: {
    userId: string;
    limit: number;
    unreadOnly: boolean;
    cursor: NotificationCursor | null;
  }) {
    const rows = await notificationRepository.list(input);
    const hasMore = rows.length > input.limit;
    const page = rows.slice(0, input.limit);
    const last = page.at(-1);
    return {
      notifications: page.map(toNotificationDto),
      nextCursor:
        hasMore && last
          ? encodeCursor({ lastEventAt: last.last_event_at, id: last.id })
          : null,
    };
  },

  async countUnread(userId: string) {
    return { unreadCount: await notificationRepository.countUnread(userId) };
  },

  async update(
    userId: string,
    notificationId: string,
    input: { read?: boolean; archived?: boolean },
  ) {
    const row = await notificationRepository.update(userId, notificationId, input);
    return row ? toNotificationDto(row) : null;
  },

  async markAllRead(userId: string) {
    return { updatedCount: await notificationRepository.markAllRead(userId) };
  },

  async getPreferences(userId: string) {
    return toPreferenceDto(
      await notificationRepository.getOrCreatePreferences(userId),
    );
  },

  async updatePreferences(
    userId: string,
    input: {
      pushEnabled?: boolean;
      commentsAndRepliesPush?: boolean;
      likesPush?: boolean;
      preferredLocale?: string | null;
    },
  ) {
    return toPreferenceDto(
      await notificationRepository.updatePreferences(userId, input),
    );
  },
};

export default notificationService;
