import discussionRepository from "../repositories/discussionRepository";
import pollRepository from "../repositories/pollRepository";
import pollZkVoteRepository from "../repositories/pollZkVoteRepository";
import voteRepository from "../repositories/voteRepository";
import { discussionMediaService } from "./discussionMediaService";
import type {
  DiscussionPostDto,
  ModerationReviewActionDto,
  ViewerActivityOverviewDto,
  ViewerDiscussionPostDto,
  ViewerDiscussionPostListDto,
} from "../types/contracts";
import type {
  DiscussionPostRow,
  ModerationReviewActionRow,
} from "../types/db";

const MAX_POST_LIMIT = 100;

type ViewerContentDiscussionRepository = Pick<
  typeof discussionRepository,
  | "listPostsByAuthorUserId"
  | "listReviewActionsForDiscussionPosts"
  | "getPostEngagementTotalsByAuthorUserId"
>;

type ViewerContentPollRepository = Pick<
  typeof pollRepository,
  "listByCreatedByUserId"
>;

type ViewerContentVoteRepository = Pick<
  typeof voteRepository,
  "countValidByPollIds"
>;

type ViewerContentPollZkVoteRepository = Pick<
  typeof pollZkVoteRepository,
  "countAcceptedByPollIds"
>;

type ViewerContentMediaService = Pick<
  typeof discussionMediaService,
  "createDisplayImageUrl"
>;

type ViewerContentServiceDependencies = {
  discussionRepositoryLike?: ViewerContentDiscussionRepository;
  pollRepositoryLike?: ViewerContentPollRepository;
  voteRepositoryLike?: ViewerContentVoteRepository;
  pollZkVoteRepositoryLike?: ViewerContentPollZkVoteRepository;
  mediaServiceLike?: ViewerContentMediaService;
};

const normalizeLimit = (value: number | null | undefined): number | null => {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return null;
  }

  return Math.min(MAX_POST_LIMIT, Math.max(1, Math.trunc(value as number)));
};

const mapPost = (
  row: DiscussionPostRow,
  displayImageUrl: string | null,
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
  viewerHasLiked: false,
  viewerHasBookmarked: false,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

const mapReviewAction = (
  row: ModerationReviewActionRow,
): ModerationReviewActionDto => ({
  action: row.action,
  previousStatus: row.previous_status,
  newStatus: row.new_status,
  userMessage: row.user_message,
  createdAt: row.created_at,
});

const isActionNewer = (
  candidate: ModerationReviewActionRow,
  existing: ModerationReviewActionRow,
): boolean => {
  const candidateTime = Date.parse(candidate.created_at);
  const existingTime = Date.parse(existing.created_at);

  if (Number.isFinite(candidateTime) && Number.isFinite(existingTime)) {
    if (candidateTime !== existingTime) {
      return candidateTime > existingTime;
    }
  }

  return candidate.id > existing.id;
};

const buildLatestReviewActionsByContentId = (
  actions: ModerationReviewActionRow[],
): Map<string, ModerationReviewActionRow> => {
  const actionsByContentId = new Map<string, ModerationReviewActionRow>();

  for (const action of actions) {
    const existing = actionsByContentId.get(action.content_id);
    if (!existing || isActionNewer(action, existing)) {
      actionsByContentId.set(action.content_id, action);
    }
  }

  return actionsByContentId;
};

export const createViewerContentService = (
  dependencies: ViewerContentServiceDependencies = {},
) => {
  const discussionRepo =
    dependencies.discussionRepositoryLike || discussionRepository;
  const pollRepo = dependencies.pollRepositoryLike || pollRepository;
  const legacyVoteRepo = dependencies.voteRepositoryLike || voteRepository;
  const zkVoteRepo =
    dependencies.pollZkVoteRepositoryLike || pollZkVoteRepository;
  const mediaService = dependencies.mediaServiceLike || discussionMediaService;

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

  return {
    async listDiscussionPosts(
      viewerUserId: string,
      limit?: number | null,
    ): Promise<ViewerDiscussionPostListDto> {
      const rows = await discussionRepo.listPostsByAuthorUserId(
        viewerUserId,
        normalizeLimit(limit),
      );
      const reviewActions =
        await discussionRepo.listReviewActionsForDiscussionPosts(
          rows.map((row) => row.id),
        );
      const latestActionsByPostId =
        buildLatestReviewActionsByContentId(reviewActions);

      const posts = await Promise.all(
        rows.map(async (row): Promise<ViewerDiscussionPostDto> => {
          const latestReviewAction =
            row.human_review_status || row.human_review_decision
              ? latestActionsByPostId.get(row.id) || null
              : null;

          return {
            ...mapPost(row, await resolveDisplayImageUrl(row)),
            humanReviewStatus: row.human_review_status,
            humanReviewDecision: row.human_review_decision,
            humanReviewedAt: row.human_reviewed_at,
            latestReviewAction: latestReviewAction
              ? mapReviewAction(latestReviewAction)
              : null,
            latestReviewUserMessage:
              latestReviewAction?.user_message?.trim() || null,
          };
        }),
      );

      return { posts };
    },

    async getActivityOverview(
      viewerUserId: string,
    ): Promise<ViewerActivityOverviewDto> {
      const [postTotals, polls] = await Promise.all([
        discussionRepo.getPostEngagementTotalsByAuthorUserId(viewerUserId),
        pollRepo.listByCreatedByUserId(viewerUserId),
      ]);
      const pollIds = polls.map((poll) => poll.id);
      const [legacyVoteCount, zkVoteCount] = await Promise.all([
        legacyVoteRepo.countValidByPollIds(pollIds),
        zkVoteRepo.countAcceptedByPollIds(pollIds),
      ]);
      const postLikesReceived = Math.max(0, postTotals.likeCount);
      const postCommentsReceived = Math.max(0, postTotals.commentCount);

      return {
        createdPostCount: Math.max(0, postTotals.postCount),
        postLikesReceived,
        postCommentsReceived,
        postReactionsReceived: postLikesReceived + postCommentsReceived,
        createdPollCount: Math.max(0, polls.length),
        pollVotesReceived: Math.max(0, legacyVoteCount + zkVoteCount),
      };
    },
  };
};

export const viewerContentService = createViewerContentService();

export default viewerContentService;
