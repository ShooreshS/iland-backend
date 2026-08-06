import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  DiscussionCommentLikeRow,
  DiscussionCommentRow,
  DiscussionPostBookmarkRow,
  DiscussionPostLikeRow,
  DiscussionPostReportRow,
  DiscussionPostRow,
  DiscussionUserBlockRow,
  ModerationReviewActionRow,
  NewDiscussionCommentRow,
  NewDiscussionPostReportRow,
  NewDiscussionPostRow,
  NewDiscussionUserBlockRow,
} from "../types/db";

const POST_COLUMNS =
  "id,author_user_id,author_public_nickname,post_type,caption,image_url,image_storage_bucket,image_storage_path,image_mime_type,image_size_bytes,image_alt_text,moderation_status,moderation_model,moderation_flagged,moderation_categories,moderation_category_scores,moderation_applied_input_types,moderation_raw,moderated_at,moderation_error,moderation_policy_version,gate2_status,gate2_model,gate2_result,human_review_status,human_review_decision,human_reviewed_at,like_count,comment_count,feed_score,deliberation_id,created_at,updated_at";

const COMMENT_COLUMNS =
  "id,post_id,thread_root_comment_id,reply_to_comment_id,author_user_id,author_public_nickname,body,moderation_status,moderation_model,moderation_flagged,moderation_categories,moderation_category_scores,moderation_applied_input_types,moderation_raw,moderated_at,moderation_error,moderation_policy_version,human_review_status,human_review_decision,human_reviewed_at,like_count,direct_reply_count,thread_reply_count,feed_score,created_at,updated_at";
const REVIEW_ACTION_COLUMNS =
  "id,content_type,content_id,reviewer_verified_identity_id,reviewer_user_id,action,previous_status,new_status,internal_note,user_message,created_at";
const REPORT_COLUMNS =
  "id,post_id,comment_id,reporter_user_id,category,comment,status,created_at,updated_at";
const BLOCK_COLUMNS =
  "blocker_user_id,blocked_user_id,source_post_id,created_at";

const buildPostPayload = (input: NewDiscussionPostRow) => ({
  ...(input.id ? { id: input.id } : null),
  author_user_id: input.author_user_id,
  author_public_nickname: input.author_public_nickname ?? null,
  post_type: input.post_type,
  caption: input.caption ?? null,
  image_url: input.image_url ?? null,
  image_storage_bucket: input.image_storage_bucket ?? null,
  image_storage_path: input.image_storage_path ?? null,
  image_mime_type: input.image_mime_type ?? null,
  image_size_bytes: input.image_size_bytes ?? null,
  image_alt_text: input.image_alt_text ?? null,
  moderation_status: input.moderation_status,
  moderation_model: input.moderation_model ?? null,
  moderation_flagged: input.moderation_flagged ?? null,
  moderation_categories: input.moderation_categories ?? null,
  moderation_category_scores: input.moderation_category_scores ?? null,
  moderation_applied_input_types: input.moderation_applied_input_types ?? null,
  moderation_raw: input.moderation_raw ?? null,
  moderated_at: input.moderated_at ?? null,
  moderation_error: input.moderation_error ?? null,
  moderation_policy_version: input.moderation_policy_version ?? null,
  gate2_status: input.gate2_status ?? null,
  gate2_model: input.gate2_model ?? null,
  gate2_result: input.gate2_result ?? null,
  human_review_status: input.human_review_status ?? null,
  human_review_decision: input.human_review_decision ?? null,
  human_reviewed_at: input.human_reviewed_at ?? null,
  deliberation_id: input.deliberation_id ?? null,
});

const buildCommentPayload = (input: NewDiscussionCommentRow) => ({
  ...(input.id ? { id: input.id } : null),
  post_id: input.post_id,
  thread_root_comment_id: input.thread_root_comment_id ?? null,
  reply_to_comment_id: input.reply_to_comment_id ?? null,
  author_user_id: input.author_user_id,
  author_public_nickname: input.author_public_nickname ?? null,
  body: input.body,
  moderation_status: input.moderation_status,
  moderation_model: input.moderation_model ?? null,
  moderation_flagged: input.moderation_flagged ?? null,
  moderation_categories: input.moderation_categories ?? null,
  moderation_category_scores: input.moderation_category_scores ?? null,
  moderation_applied_input_types: input.moderation_applied_input_types ?? null,
  moderation_raw: input.moderation_raw ?? null,
  moderated_at: input.moderated_at ?? null,
  moderation_error: input.moderation_error ?? null,
  moderation_policy_version: input.moderation_policy_version ?? null,
  human_review_status: input.human_review_status ?? null,
  human_review_decision: input.human_review_decision ?? null,
  human_reviewed_at: input.human_reviewed_at ?? null,
});

export const discussionRepository = {
  async listPublishedPosts(limit: number): Promise<DiscussionPostRow[]> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_posts")
      .select(POST_COLUMNS)
      .eq("moderation_status", "published")
      .order("feed_score", { ascending: false })
      .order("created_at", { ascending: false })
      .order("id", { ascending: false })
      .limit(limit);

    if (error) {
      throw error;
    }

    return data || [];
  },

  async listPostsByAuthorUserId(
    userId: string,
    limit?: number | null,
  ): Promise<DiscussionPostRow[]> {
    const supabase = requireSupabaseAdminClient();
    let query = supabase
      .from("discussion_posts")
      .select(POST_COLUMNS)
      .eq("author_user_id", userId)
      .order("created_at", { ascending: false })
      .order("id", { ascending: false });

    if (Number.isFinite(limit)) {
      query = query.limit(Math.max(1, Math.trunc(limit as number)));
    }

    const { data, error } = await query;

    if (error) {
      throw error;
    }

    return data || [];
  },

  async listPostsByIds(postIds: string[]): Promise<DiscussionPostRow[]> {
    if (postIds.length === 0) {
      return [];
    }

    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_posts")
      .select(POST_COLUMNS)
      .in("id", postIds);

    if (error) {
      throw error;
    }

    return data || [];
  },

  async listCommentsByIds(commentIds: string[]): Promise<DiscussionCommentRow[]> {
    if (commentIds.length === 0) {
      return [];
    }

    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_comments")
      .select(COMMENT_COLUMNS)
      .in("id", commentIds);

    if (error) {
      throw error;
    }

    return data || [];
  },

  async getPostEngagementTotalsByAuthorUserId(userId: string): Promise<{
    postCount: number;
    likeCount: number;
    commentCount: number;
  }> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_posts")
      .select("id,like_count,comment_count")
      .eq("author_user_id", userId);

    if (error) {
      throw error;
    }

    return (data || []).reduce(
      (totals, row) => ({
        postCount: totals.postCount + 1,
        likeCount: totals.likeCount + Math.max(0, Number(row.like_count) || 0),
        commentCount:
          totals.commentCount + Math.max(0, Number(row.comment_count) || 0),
      }),
      { postCount: 0, likeCount: 0, commentCount: 0 },
    );
  },

  async listReviewActionsForDiscussionPosts(
    postIds: string[],
  ): Promise<ModerationReviewActionRow[]> {
    if (postIds.length === 0) {
      return [];
    }

    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("moderation_review_actions")
      .select(REVIEW_ACTION_COLUMNS)
      .eq("content_type", "discussion_post")
      .in("content_id", postIds)
      .order("created_at", { ascending: false })
      .order("id", { ascending: false });

    if (error) {
      throw error;
    }

    return data || [];
  },

  async getPostById(postId: string): Promise<DiscussionPostRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_posts")
      .select(POST_COLUMNS)
      .eq("id", postId)
      .maybeSingle<DiscussionPostRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getCommentById(commentId: string): Promise<DiscussionCommentRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_comments")
      .select(COMMENT_COLUMNS)
      .eq("id", commentId)
      .maybeSingle<DiscussionCommentRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insertPost(input: NewDiscussionPostRow): Promise<DiscussionPostRow> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_posts")
      .insert(buildPostPayload(input))
      .select(POST_COLUMNS)
      .single<DiscussionPostRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async updatePostById(
    postId: string,
    input: NewDiscussionPostRow,
  ): Promise<DiscussionPostRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { id: _id, ...payload } = buildPostPayload(input);
    const { data, error } = await supabase
      .from("discussion_posts")
      .update({
        ...payload,
        updated_at: new Date().toISOString(),
      })
      .eq("id", postId)
      .select(POST_COLUMNS)
      .maybeSingle<DiscussionPostRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async deletePostById(
    postId: string,
    authorUserId: string,
    moderationStatuses: string[],
  ): Promise<boolean> {
    if (moderationStatuses.length === 0) {
      return false;
    }

    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_posts")
      .delete()
      .eq("id", postId)
      .eq("author_user_id", authorUserId)
      .in("moderation_status", moderationStatuses)
      .select("id")
      .maybeSingle<{ id: string }>();

    if (error) {
      throw error;
    }

    return Boolean(data?.id);
  },

  async getLikedPostIds(
    userId: string,
    postIds: string[],
  ): Promise<Set<string>> {
    if (postIds.length === 0) {
      return new Set();
    }

    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_post_likes")
      .select("post_id")
      .eq("user_id", userId)
      .in("post_id", postIds);

    if (error) {
      throw error;
    }

    return new Set((data || []).map((row) => row.post_id as string));
  },

  async getBookmarkedPostIds(
    userId: string,
    postIds: string[],
  ): Promise<Set<string>> {
    if (postIds.length === 0) {
      return new Set();
    }

    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_post_bookmarks")
      .select("post_id")
      .eq("user_id", userId)
      .in("post_id", postIds);

    if (error) {
      throw error;
    }

    return new Set((data || []).map((row) => row.post_id as string));
  },

  async getLike(
    postId: string,
    userId: string,
  ): Promise<DiscussionPostLikeRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_post_likes")
      .select("post_id,user_id,created_at")
      .eq("post_id", postId)
      .eq("user_id", userId)
      .maybeSingle<DiscussionPostLikeRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insertLike(postId: string, userId: string): Promise<void> {
    const supabase = requireSupabaseAdminClient();
    const { error } = await supabase
      .from("discussion_post_likes")
      .insert({ post_id: postId, user_id: userId });

    if (error && error.code !== "23505") {
      throw error;
    }
  },

  async deleteLike(postId: string, userId: string): Promise<void> {
    const supabase = requireSupabaseAdminClient();
    const { error } = await supabase
      .from("discussion_post_likes")
      .delete()
      .eq("post_id", postId)
      .eq("user_id", userId);

    if (error) {
      throw error;
    }
  },

  async getLikedCommentIds(
    userId: string,
    commentIds: string[],
  ): Promise<Set<string>> {
    if (commentIds.length === 0) {
      return new Set();
    }

    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_comment_likes")
      .select("comment_id")
      .eq("user_id", userId)
      .in("comment_id", commentIds);

    if (error) {
      throw error;
    }

    return new Set((data || []).map((row) => row.comment_id as string));
  },

  async getCommentLike(
    commentId: string,
    userId: string,
  ): Promise<DiscussionCommentLikeRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_comment_likes")
      .select("comment_id,user_id,created_at")
      .eq("comment_id", commentId)
      .eq("user_id", userId)
      .maybeSingle<DiscussionCommentLikeRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insertCommentLike(commentId: string, userId: string): Promise<void> {
    const supabase = requireSupabaseAdminClient();
    const { error } = await supabase
      .from("discussion_comment_likes")
      .insert({ comment_id: commentId, user_id: userId });

    if (error && error.code !== "23505") {
      throw error;
    }
  },

  async deleteCommentLike(commentId: string, userId: string): Promise<void> {
    const supabase = requireSupabaseAdminClient();
    const { error } = await supabase
      .from("discussion_comment_likes")
      .delete()
      .eq("comment_id", commentId)
      .eq("user_id", userId);

    if (error) {
      throw error;
    }
  },

  async getBookmark(
    postId: string,
    userId: string,
  ): Promise<DiscussionPostBookmarkRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_post_bookmarks")
      .select("post_id,user_id,created_at")
      .eq("post_id", postId)
      .eq("user_id", userId)
      .maybeSingle<DiscussionPostBookmarkRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insertBookmark(postId: string, userId: string): Promise<void> {
    const supabase = requireSupabaseAdminClient();
    const { error } = await supabase
      .from("discussion_post_bookmarks")
      .insert({ post_id: postId, user_id: userId });

    if (error && error.code !== "23505") {
      throw error;
    }
  },

  async deleteBookmark(postId: string, userId: string): Promise<void> {
    const supabase = requireSupabaseAdminClient();
    const { error } = await supabase
      .from("discussion_post_bookmarks")
      .delete()
      .eq("post_id", postId)
      .eq("user_id", userId);

    if (error) {
      throw error;
    }
  },

  async getBlockedUserIds(blockerUserId: string): Promise<Set<string>> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_user_blocks")
      .select("blocked_user_id")
      .eq("blocker_user_id", blockerUserId);

    if (error) {
      throw error;
    }

    return new Set((data || []).map((row) => row.blocked_user_id as string));
  },

  async listUserBlocksByBlockerUserId(
    blockerUserId: string,
    limit?: number | null,
  ): Promise<DiscussionUserBlockRow[]> {
    const supabase = requireSupabaseAdminClient();
    let query = supabase
      .from("discussion_user_blocks")
      .select(BLOCK_COLUMNS)
      .eq("blocker_user_id", blockerUserId)
      .order("created_at", { ascending: false })
      .order("blocked_user_id", { ascending: true });

    if (Number.isFinite(limit)) {
      query = query.limit(Math.max(1, Math.trunc(limit as number)));
    }

    const { data, error } = await query;

    if (error) {
      throw error;
    }

    return data || [];
  },

  async getUserBlock(
    blockerUserId: string,
    blockedUserId: string,
  ): Promise<DiscussionUserBlockRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_user_blocks")
      .select(BLOCK_COLUMNS)
      .eq("blocker_user_id", blockerUserId)
      .eq("blocked_user_id", blockedUserId)
      .maybeSingle<DiscussionUserBlockRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insertUserBlock(
    input: NewDiscussionUserBlockRow,
  ): Promise<DiscussionUserBlockRow> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_user_blocks")
      .insert({
        blocker_user_id: input.blocker_user_id,
        blocked_user_id: input.blocked_user_id,
        source_post_id: input.source_post_id ?? null,
      })
      .select(BLOCK_COLUMNS)
      .single<DiscussionUserBlockRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async deleteUserBlock(
    blockerUserId: string,
    blockedUserId: string,
  ): Promise<void> {
    const supabase = requireSupabaseAdminClient();
    const { error } = await supabase
      .from("discussion_user_blocks")
      .delete()
      .eq("blocker_user_id", blockerUserId)
      .eq("blocked_user_id", blockedUserId);

    if (error) {
      throw error;
    }
  },

  async getReport(
    postId: string,
    reporterUserId: string,
    commentId: string | null = null,
  ): Promise<DiscussionPostReportRow | null> {
    const supabase = requireSupabaseAdminClient();
    let query = supabase
      .from("discussion_post_reports")
      .select(REPORT_COLUMNS)
      .eq("post_id", postId)
      .eq("reporter_user_id", reporterUserId);
    query = commentId ? query.eq("comment_id", commentId) : query.is("comment_id", null);
    const { data, error } = await query.maybeSingle<DiscussionPostReportRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insertReport(
    input: NewDiscussionPostReportRow,
  ): Promise<DiscussionPostReportRow> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_post_reports")
      .insert({
        ...(input.id ? { id: input.id } : null),
        post_id: input.post_id,
        comment_id: input.comment_id ?? null,
        reporter_user_id: input.reporter_user_id,
        category: input.category,
        comment: input.comment ?? null,
        status: input.status ?? "open",
      })
      .select(REPORT_COLUMNS)
      .single<DiscussionPostReportRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async listReportsByReporterUserId(
    reporterUserId: string,
    limit?: number | null,
  ): Promise<DiscussionPostReportRow[]> {
    const supabase = requireSupabaseAdminClient();
    let query = supabase
      .from("discussion_post_reports")
      .select(REPORT_COLUMNS)
      .eq("reporter_user_id", reporterUserId)
      .order("created_at", { ascending: false })
      .order("id", { ascending: false });

    if (Number.isFinite(limit)) {
      query = query.limit(Math.max(1, Math.trunc(limit as number)));
    }

    const { data, error } = await query;

    if (error) {
      throw error;
    }

    return data || [];
  },

  async listPublishedRootComments(
    postId: string,
    limit: number,
    cursor?: {
      feedScore: number;
      createdAt: string;
      id: string;
    } | null,
  ): Promise<DiscussionCommentRow[]> {
    const supabase = requireSupabaseAdminClient();
    let query = supabase
      .from("discussion_comments")
      .select(COMMENT_COLUMNS)
      .eq("post_id", postId)
      .eq("moderation_status", "published")
      .is("thread_root_comment_id", null)
      .order("feed_score", { ascending: false })
      .order("created_at", { ascending: false })
      .order("id", { ascending: false })
      .limit(limit);

    if (cursor) {
      query = query.or(
        [
          `feed_score.lt.${cursor.feedScore}`,
          `and(feed_score.eq.${cursor.feedScore},created_at.lt.${cursor.createdAt})`,
          `and(feed_score.eq.${cursor.feedScore},created_at.eq.${cursor.createdAt},id.lt.${cursor.id})`,
        ].join(","),
      );
    }

    const { data, error } = await query;

    if (error) {
      throw error;
    }

    return data || [];
  },

  async listPublishedReplyPreview(
    threadRootCommentIds: string[],
    perRootLimit: number,
  ): Promise<DiscussionCommentRow[]> {
    if (threadRootCommentIds.length === 0) {
      return [];
    }

    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .rpc("list_discussion_comment_reply_preview", {
        p_thread_root_comment_ids: threadRootCommentIds,
        p_per_root_limit: perRootLimit,
      });

    if (error) {
      throw error;
    }

    return (data || []) as unknown as DiscussionCommentRow[];
  },

  async listPublishedReplies(
    threadRootCommentId: string,
    limit: number,
    cursor?: { createdAt: string; id: string } | null,
  ): Promise<DiscussionCommentRow[]> {
    const supabase = requireSupabaseAdminClient();
    let query = supabase
      .from("discussion_comments")
      .select(COMMENT_COLUMNS)
      .eq("thread_root_comment_id", threadRootCommentId)
      .eq("moderation_status", "published")
      .order("created_at", { ascending: true })
      .order("id", { ascending: true })
      .limit(limit);

    if (cursor) {
      query = query.or(
        [
          `created_at.gt.${cursor.createdAt}`,
          `and(created_at.eq.${cursor.createdAt},id.gt.${cursor.id})`,
        ].join(","),
      );
    }

    const { data, error } = await query;
    if (error) {
      throw error;
    }

    return data || [];
  },

  async listPublishedOrphanReplies(
    postId: string,
    limit: number,
  ): Promise<DiscussionCommentRow[]> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .rpc("list_discussion_comment_orphans", {
        p_post_id: postId,
        p_limit: limit,
      });

    if (error) {
      throw error;
    }

    return (data || []) as unknown as DiscussionCommentRow[];
  },

  async insertComment(
    input: NewDiscussionCommentRow,
  ): Promise<DiscussionCommentRow> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_comments")
      .insert(buildCommentPayload(input))
      .select(COMMENT_COLUMNS)
      .single<DiscussionCommentRow>();

    if (error) {
      throw error;
    }

    return data;
  },
};

export default discussionRepository;
