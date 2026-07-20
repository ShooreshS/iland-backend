import { hashOpaqueBearerToken } from "../auth/tokens";
import adminModerationRepository from "../repositories/adminModerationRepository";
import oidcProviderRepository, {
  type OidcAccessTokenRow,
} from "../repositories/oidcProviderRepository";
import pollRepository from "../repositories/pollRepository";
import userRepository from "../repositories/userRepository";
import verifiedIdentityRepository from "../repositories/verifiedIdentityRepository";
import discussionMediaService from "./discussionMediaService";
import type {
  AdminReviewerRow,
  DiscussionCommentRow,
  DiscussionPostReportRow,
  DiscussionPostRow,
  ModerationReviewAction,
  ModerationReviewActionRow,
  ModerationReviewContentType,
  PollOptionRow,
  PollRow,
  UserRow,
  VerifiedIdentityRow,
} from "../types/db";
import type { PollModerationStatus } from "../types/contracts";

export type AdminContentType = "poll" | "post" | "comment";

export type AdminContext = {
  user: UserRow;
  verifiedIdentity: VerifiedIdentityRow;
  reviewer: AdminReviewerRow;
  oidcAccessToken: OidcAccessTokenRow;
};

export type AdminAuthResult =
  | { ok: true; admin: AdminContext }
  | { ok: false; status: number; error: string; message: string };

export type ReviewQueueItem = {
  contentType: AdminContentType;
  contentId: string;
  reviewSource: "moderation" | "user_report";
  reportStatus: "open" | null;
  reportCount: number | null;
  firstReportedAt: string | null;
  latestReportedAt: string | null;
  authorUserId: string | null;
  authorNickname: string | null;
  title: string | null;
  body: string | null;
  imageUrl: string | null;
  moderationStatus: PollModerationStatus;
  moderationModel: string | null;
  moderationFlagged: boolean | null;
  moderationCategories: unknown;
  moderationCategoryScores: unknown;
  moderatedAt: string | null;
  createdAt: string;
};

export type ReviewPostReport = {
  id: string;
  postId: string;
  reporterUserId: string;
  category: string;
  comment: string | null;
  status: string;
  createdAt: string;
};

export type ReviewDetail =
  | {
      contentType: "poll";
      item: ReviewQueueItem;
      poll: PollRow;
      options: PollOptionRow[];
    }
  | {
      contentType: "post";
      item: ReviewQueueItem;
      post: DiscussionPostRow;
      imagePreviewUrl: string | null;
      reports: ReviewPostReport[];
    }
  | {
      contentType: "comment";
      item: ReviewQueueItem;
      comment: DiscussionCommentRow;
    };

export type ReviewDecisionResult =
  | {
      success: true;
      contentType: AdminContentType;
      contentId: string;
      status: PollModerationStatus;
      reviewAction: ModerationReviewActionRow;
    }
  | {
      success: false;
      errorCode:
        | "INVALID_INPUT"
        | "CONTENT_NOT_FOUND"
        | "NOT_REVIEWABLE"
        | "FORBIDDEN";
      message: string;
    };

type RepositoryLike = typeof adminModerationRepository;
type OidcProviderRepositoryLike = Pick<
  typeof oidcProviderRepository,
  "getAccessTokenByHash" | "expireAccessToken" | "touchAccessToken" | "getClientById"
>;

type AdminModerationServiceDependencies = {
  repositoryLike?: RepositoryLike;
  oidcProviderRepositoryLike?: OidcProviderRepositoryLike;
  userRepositoryLike?: Pick<typeof userRepository, "getById">;
  verifiedIdentityRepositoryLike?: Pick<typeof verifiedIdentityRepository, "getByUserId">;
  pollRepositoryLike?: Pick<typeof pollRepository, "getOptionsByPollId">;
  mediaServiceLike?: Pick<typeof discussionMediaService, "createDisplayImageUrl">;
  adminOidcClientId?: string;
  now?: () => Date;
};

const DEFAULT_ADMIN_OIDC_CLIENT_ID = "admin-dashboard-web";
const MAX_QUEUE_LIMIT = 100;

const contentTypeToReviewType = (
  contentType: AdminContentType,
): ModerationReviewContentType => {
  switch (contentType) {
    case "poll":
      return "poll";
    case "post":
      return "discussion_post";
    case "comment":
      return "discussion_comment";
  }
};

const statusForAction = (
  action: ModerationReviewAction,
): PollModerationStatus => {
  switch (action) {
    case "approve":
      return "published";
    case "reject":
      return "blocked";
    case "request_edit":
      return "needs_edit";
  }
};

const parseBearerToken = (authorizationHeader: string | null): string | null => {
  const tokenMatch = /^Bearer\s+(.+)$/i.exec(authorizationHeader?.trim() || "");
  return tokenMatch?.[1]?.trim() || null;
};

const normalizeLimit = (limit: number | null | undefined): number =>
  Math.min(Math.max(Number.isFinite(Number(limit)) ? Number(limit) : 50, 1), MAX_QUEUE_LIMIT);

const excerpt = (value: string | null | undefined): string | null => {
  const normalized = typeof value === "string" ? value.trim() : "";
  if (!normalized) {
    return null;
  }
  return normalized.length > 220 ? `${normalized.slice(0, 217)}...` : normalized;
};

const mapPollQueueItem = (row: PollRow): ReviewQueueItem => ({
  contentType: "poll",
  contentId: row.id,
  reviewSource: "moderation",
  reportStatus: null,
  reportCount: null,
  firstReportedAt: null,
  latestReportedAt: null,
  authorUserId: row.created_by_user_id,
  authorNickname: null,
  title: row.title,
  body: excerpt(row.description),
  imageUrl: null,
  moderationStatus: row.moderation_status ?? "review_required",
  moderationModel: row.moderation_model ?? null,
  moderationFlagged: row.moderation_flagged ?? null,
  moderationCategories: row.moderation_categories ?? null,
  moderationCategoryScores: row.moderation_category_scores ?? null,
  moderatedAt: row.moderated_at ?? null,
  createdAt: row.created_at,
});

const mapPostQueueItem = (
  row: DiscussionPostRow,
  reportSummary?: {
    reportCount: number;
    firstReportedAt: string;
    latestReportedAt: string;
  } | null,
): ReviewQueueItem => ({
  contentType: "post",
  contentId: row.id,
  reviewSource: reportSummary ? "user_report" : "moderation",
  reportStatus: reportSummary ? "open" : null,
  reportCount: reportSummary?.reportCount ?? null,
  firstReportedAt: reportSummary?.firstReportedAt ?? null,
  latestReportedAt: reportSummary?.latestReportedAt ?? null,
  authorUserId: row.author_user_id,
  authorNickname: row.author_public_nickname,
  title: row.post_type,
  body: excerpt(row.caption),
  imageUrl: row.image_url,
  moderationStatus: row.moderation_status,
  moderationModel: row.moderation_model,
  moderationFlagged: row.moderation_flagged,
  moderationCategories: row.moderation_categories,
  moderationCategoryScores: row.moderation_category_scores,
  moderatedAt: row.moderated_at,
  createdAt: row.created_at,
});

const mapCommentQueueItem = (row: DiscussionCommentRow): ReviewQueueItem => ({
  contentType: "comment",
  contentId: row.id,
  reviewSource: "moderation",
  reportStatus: null,
  reportCount: null,
  firstReportedAt: null,
  latestReportedAt: null,
  authorUserId: row.author_user_id,
  authorNickname: row.author_public_nickname,
  title: `Comment on ${row.post_id}`,
  body: excerpt(row.body),
  imageUrl: null,
  moderationStatus: row.moderation_status,
  moderationModel: row.moderation_model,
  moderationFlagged: row.moderation_flagged,
  moderationCategories: row.moderation_categories,
  moderationCategoryScores: row.moderation_category_scores,
  moderatedAt: row.moderated_at,
  createdAt: row.created_at,
});

const mapPostReport = (row: DiscussionPostReportRow): ReviewPostReport => ({
  id: row.id,
  postId: row.post_id,
  reporterUserId: row.reporter_user_id,
  category: row.category,
  comment: row.comment,
  status: row.status,
  createdAt: row.created_at,
});

const createAuthFailure = (
  status: number,
  error: string,
  message: string,
): AdminAuthResult => ({
  ok: false,
  status,
  error,
  message,
});

export const createAdminModerationService = (
  dependencies: AdminModerationServiceDependencies = {},
) => {
  const repo = dependencies.repositoryLike || adminModerationRepository;
  const oidcRepo = dependencies.oidcProviderRepositoryLike || oidcProviderRepository;
  const userRepo = dependencies.userRepositoryLike || userRepository;
  const verifiedIdentityRepo =
    dependencies.verifiedIdentityRepositoryLike || verifiedIdentityRepository;
  const pollRepo = dependencies.pollRepositoryLike || pollRepository;
  const mediaService = dependencies.mediaServiceLike || discussionMediaService;
  const now = dependencies.now || (() => new Date());
  const adminOidcClientId =
    dependencies.adminOidcClientId ||
    process.env.ADMIN_DASHBOARD_OIDC_CLIENT_ID ||
    DEFAULT_ADMIN_OIDC_CLIENT_ID;

  const requireAdmin = async (
    authorizationHeader: string | null,
  ): Promise<AdminAuthResult> => {
    const token = parseBearerToken(authorizationHeader);
    if (!token) {
      return createAuthFailure(
        401,
        "authorization_required",
        "Admin routes require a CivicOS OIDC bearer token.",
      );
    }

    const accessToken = await oidcRepo.getAccessTokenByHash(
      hashOpaqueBearerToken(token),
    );
    if (!accessToken || accessToken.status !== "active") {
      return createAuthFailure(
        401,
        "viewer_not_resolved",
        "No active CivicOS OIDC access token was found.",
      );
    }

    if (new Date(accessToken.expires_at).getTime() <= now().getTime()) {
      await oidcRepo.expireAccessToken(accessToken.id);
      return createAuthFailure(401, "session_expired", "OIDC access token expired.");
    }

    const client = await oidcRepo.getClientById(accessToken.client_id);
    if (!client || client.client_id !== adminOidcClientId) {
      return createAuthFailure(
        403,
        "admin_client_required",
        "This token was not issued to the admin dashboard client.",
      );
    }

    const user = await userRepo.getById(accessToken.user_id);
    if (!user || user.account_status !== "active") {
      return createAuthFailure(403, "account_disabled", "Admin user is not active.");
    }

    if (user.auth_generation !== accessToken.auth_generation) {
      return createAuthFailure(401, "session_stale", "OIDC access token is stale.");
    }

    const verifiedIdentity = await verifiedIdentityRepo.getByUserId(user.id);
    if (!verifiedIdentity) {
      return createAuthFailure(
        403,
        "verified_identity_required",
        "Admin access requires a verified identity.",
      );
    }

    const reviewer = await repo.getActiveReviewerByVerifiedIdentityId(
      verifiedIdentity.id,
    );
    if (!reviewer) {
      return createAuthFailure(
        403,
        "admin_not_allowed",
        "This verified identity is not on the admin reviewer allowlist.",
      );
    }

    await oidcRepo.touchAccessToken(accessToken.id);
    return {
      ok: true,
      admin: {
        user,
        verifiedIdentity,
        reviewer,
        oidcAccessToken: accessToken,
      },
    };
  };

  const listQueue = async (
    contentType: AdminContentType | "all" = "all",
    limit?: number | null,
  ): Promise<ReviewQueueItem[]> => {
    const normalizedLimit = normalizeLimit(limit);
    const tasks: Array<Promise<ReviewQueueItem[]>> = [];

    if (contentType === "all" || contentType === "poll") {
      tasks.push(
        repo.listReviewRequiredPolls(normalizedLimit).then((rows) =>
          rows.map(mapPollQueueItem),
        ),
      );
    }
    if (contentType === "all" || contentType === "post") {
      tasks.push(
        repo.listReviewRequiredPosts(normalizedLimit).then((rows) =>
          rows.map((row) => mapPostQueueItem(row)),
        ),
      );
      tasks.push(
        repo.listOpenReportedPosts(normalizedLimit).then((rows) =>
          rows.map((row) =>
            mapPostQueueItem(row.post, {
              reportCount: row.reportCount,
              firstReportedAt: row.firstReportedAt,
              latestReportedAt: row.latestReportedAt,
            }),
          ),
        ),
      );
    }
    if (contentType === "all" || contentType === "comment") {
      tasks.push(
        repo.listReviewRequiredComments(normalizedLimit).then((rows) =>
          rows.map(mapCommentQueueItem),
        ),
      );
    }

    const itemsByKey = new Map<string, ReviewQueueItem>();
    for (const item of (await Promise.all(tasks)).flat()) {
      const key = `${item.contentType}:${item.contentId}`;
      const current = itemsByKey.get(key);
      if (!current || current.reviewSource === "user_report") {
        itemsByKey.set(key, item);
      }
    }

    return Array.from(itemsByKey.values())
      .sort((left, right) => {
        const leftTime = new Date(
          left.firstReportedAt || left.moderatedAt || left.createdAt,
        ).getTime();
        const rightTime = new Date(
          right.firstReportedAt || right.moderatedAt || right.createdAt,
        ).getTime();
        return leftTime - rightTime || left.contentId.localeCompare(right.contentId);
      })
      .slice(0, normalizedLimit);
  };

  const getReviewDetail = async (
    contentType: AdminContentType,
    contentId: string,
  ): Promise<ReviewDetail | null> => {
    if (contentType === "poll") {
      const poll = await repo.getPollById(contentId);
      if (!poll) {
        return null;
      }
      return {
        contentType,
        item: mapPollQueueItem(poll),
        poll,
        options: await pollRepo.getOptionsByPollId(poll.id),
      };
    }

    if (contentType === "post") {
      const post = await repo.getPostById(contentId);
      const reportSummary =
        post?.moderation_status === "published"
          ? await repo.getOpenReportSummaryForPost(contentId)
          : null;
      const reports = reportSummary
        ? await repo.listOpenReportsForPost(contentId)
        : [];
      return post
        ? {
            contentType,
            item: mapPostQueueItem(post, reportSummary),
            post,
            imagePreviewUrl:
              post.image_url ||
              (await mediaService.createDisplayImageUrl(
                post.image_storage_bucket,
                post.image_storage_path,
              )),
            reports: reports.map(mapPostReport),
          }
        : null;
    }

    const comment = await repo.getCommentById(contentId);
    return comment
      ? {
          contentType,
          item: mapCommentQueueItem(comment),
          comment,
        }
      : null;
  };

  const applyDecision = async (input: {
    admin: AdminContext;
    contentType: AdminContentType;
    contentId: string;
    action: ModerationReviewAction;
    internalNote?: string | null;
    userMessage?: string | null;
  }): Promise<ReviewDecisionResult> => {
    if (input.admin.reviewer.role === "viewer") {
      return {
        success: false,
        errorCode: "FORBIDDEN",
        message: "Viewer admins cannot make moderation decisions.",
      };
    }

    const current = await getReviewDetail(input.contentType, input.contentId);
    if (!current) {
      return {
        success: false,
        errorCode: "CONTENT_NOT_FOUND",
        message: "The requested review item could not be found.",
      };
    }

    const isReportedPublishedPost =
      input.contentType === "post" &&
      current.item.reviewSource === "user_report" &&
      current.item.reportStatus === "open" &&
      current.item.moderationStatus === "published";

    if (
      current.item.moderationStatus !== "review_required" &&
      !isReportedPublishedPost
    ) {
      return {
        success: false,
        errorCode: "NOT_REVIEWABLE",
        message: "This item is no longer waiting for review.",
      };
    }

    const nextStatus = statusForAction(input.action);
    const reviewedAt = now().toISOString();
    const updated =
      input.contentType === "poll"
        ? await repo.updatePollReviewStatus({
            contentId: input.contentId,
            status: nextStatus,
            decision: input.action,
            reviewedAt,
          })
        : input.contentType === "post"
          ? isReportedPublishedPost
            ? await repo.updateReportedPostReviewStatus({
                contentId: input.contentId,
                status: nextStatus,
                decision: input.action,
                reviewedAt,
              })
            : await repo.updatePostReviewStatus({
                contentId: input.contentId,
                status: nextStatus,
                decision: input.action,
                reviewedAt,
              })
          : await repo.updateCommentReviewStatus({
              contentId: input.contentId,
              status: nextStatus,
              decision: input.action,
              reviewedAt,
            });

    if (!updated) {
      return {
        success: false,
        errorCode: "NOT_REVIEWABLE",
        message: "This item was already reviewed.",
      };
    }

    const reviewAction = await repo.insertReviewAction({
      contentType: contentTypeToReviewType(input.contentType),
      contentId: input.contentId,
      reviewerVerifiedIdentityId: input.admin.verifiedIdentity.id,
      reviewerUserId: input.admin.user.id,
      action: input.action,
      previousStatus: current.item.moderationStatus,
      newStatus: nextStatus,
      internalNote: input.internalNote,
      userMessage: input.userMessage,
    });

    if (isReportedPublishedPost) {
      await repo.markOpenPostReportsReviewed(input.contentId, reviewedAt);
    }

    return {
      success: true,
      contentType: input.contentType,
      contentId: input.contentId,
      status: nextStatus,
      reviewAction,
    };
  };

  return {
    requireAdmin,
    listQueue,
    getReviewDetail,
    applyDecision,
  };
};

export const adminModerationService = createAdminModerationService();

export default adminModerationService;
