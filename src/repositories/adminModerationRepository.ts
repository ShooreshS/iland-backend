import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  AdminReviewerRow,
  DiscussionCommentRow,
  DiscussionPostOpenReportQueueRow,
  DiscussionPostRow,
  ModerationReviewAction,
  ModerationReviewActionRow,
  ModerationReviewContentType,
  PollRow,
} from "../types/db";
import type { PollModerationStatus } from "../types/contracts";

const ADMIN_REVIEWER_COLUMNS =
  "id,verified_identity_id,role,status,created_at,updated_at";

const REVIEW_ACTION_COLUMNS =
  "id,content_type,content_id,reviewer_verified_identity_id,reviewer_user_id,action,previous_status,new_status,internal_note,user_message,created_at";

const POLL_COLUMNS =
  "id,slug,created_by_user_id,title,description,status,moderation_status,moderation_model,moderation_flagged,moderation_categories,moderation_category_scores,moderation_applied_input_types,moderation_raw,moderated_at,moderation_error,moderation_policy_version,gate2_status,gate2_model,gate2_result,human_review_status,human_review_decision,human_reviewed_at,jurisdiction_type,jurisdiction_country_code,jurisdiction_area_ids,jurisdiction_land_ids,requires_verified_identity,allowed_document_country_codes,allowed_home_area_ids,allowed_land_ids,minimum_age,starts_at,ends_at,poll_policy_json,poll_policy_hash,credential_schema_json,credential_schema_hash,vote_privacy_mode,result_publication_mode,option_set_hash,poll_encryption_key_id,created_at,updated_at";

const POST_COLUMNS =
  "id,author_user_id,author_public_nickname,post_type,caption,image_url,image_storage_bucket,image_storage_path,image_mime_type,image_size_bytes,image_alt_text,moderation_status,moderation_model,moderation_flagged,moderation_categories,moderation_category_scores,moderation_applied_input_types,moderation_raw,moderated_at,moderation_error,moderation_policy_version,gate2_status,gate2_model,gate2_result,human_review_status,human_review_decision,human_reviewed_at,like_count,comment_count,feed_score,deliberation_id,created_at,updated_at";

const COMMENT_COLUMNS =
  "id,post_id,author_user_id,author_public_nickname,body,moderation_status,moderation_model,moderation_flagged,moderation_categories,moderation_category_scores,moderation_applied_input_types,moderation_raw,moderated_at,moderation_error,moderation_policy_version,human_review_status,human_review_decision,human_reviewed_at,created_at,updated_at";
const REPORT_QUEUE_COLUMNS =
  "post_id,report_count,first_reported_at,latest_reported_at";

const buildReviewUpdate = (
  status: PollModerationStatus,
  decision: ModerationReviewAction,
  reviewedAt: string,
) => ({
  moderation_status: status,
  human_review_status: "reviewed",
  human_review_decision: decision,
  human_reviewed_at: reviewedAt,
  updated_at: reviewedAt,
});

export const adminModerationRepository = {
  async getActiveReviewerByVerifiedIdentityId(
    verifiedIdentityId: string,
  ): Promise<AdminReviewerRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("admin_reviewers")
      .select(ADMIN_REVIEWER_COLUMNS)
      .eq("verified_identity_id", verifiedIdentityId)
      .eq("status", "active")
      .maybeSingle<AdminReviewerRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async listReviewRequiredPolls(limit: number): Promise<PollRow[]> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("polls")
      .select(POLL_COLUMNS)
      .eq("moderation_status", "review_required")
      .order("moderated_at", { ascending: true, nullsFirst: false })
      .order("created_at", { ascending: true })
      .limit(limit)
      .returns<PollRow[]>();

    if (error) {
      throw error;
    }

    return data || [];
  },

  async listReviewRequiredPosts(limit: number): Promise<DiscussionPostRow[]> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_posts")
      .select(POST_COLUMNS)
      .eq("moderation_status", "review_required")
      .order("moderated_at", { ascending: true, nullsFirst: false })
      .order("created_at", { ascending: true })
      .limit(limit)
      .returns<DiscussionPostRow[]>();

    if (error) {
      throw error;
    }

    return data || [];
  },

  async listOpenReportedPosts(limit: number): Promise<
    Array<{
      post: DiscussionPostRow;
      reportCount: number;
      firstReportedAt: string;
      latestReportedAt: string;
    }>
  > {
    const supabase = requireSupabaseAdminClient();
    const { data: reports, error: reportError } = await supabase
      .from("discussion_post_open_report_queue")
      .select(REPORT_QUEUE_COLUMNS)
      .order("first_reported_at", { ascending: true })
      .order("post_id", { ascending: true })
      .limit(limit)
      .returns<DiscussionPostOpenReportQueueRow[]>();

    if (reportError) {
      throw reportError;
    }

    const reportRows = reports || [];
    const postIds = reportRows.map((row) => row.post_id);
    if (postIds.length === 0) {
      return [];
    }

    const { data: posts, error: postError } = await supabase
      .from("discussion_posts")
      .select(POST_COLUMNS)
      .in("id", postIds)
      .eq("moderation_status", "published")
      .returns<DiscussionPostRow[]>();

    if (postError) {
      throw postError;
    }

    const postsById = new Map((posts || []).map((post) => [post.id, post]));
    return reportRows
      .map((row) => {
        const post = postsById.get(row.post_id);
        return post
          ? {
              post,
              reportCount: row.report_count,
              firstReportedAt: row.first_reported_at,
              latestReportedAt: row.latest_reported_at,
            }
          : null;
      })
      .filter(Boolean) as Array<{
        post: DiscussionPostRow;
        reportCount: number;
        firstReportedAt: string;
        latestReportedAt: string;
      }>;
  },

  async getOpenReportSummaryForPost(contentId: string): Promise<{
    reportCount: number;
    firstReportedAt: string;
    latestReportedAt: string;
  } | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_post_open_report_queue")
      .select(REPORT_QUEUE_COLUMNS)
      .eq("post_id", contentId)
      .maybeSingle<DiscussionPostOpenReportQueueRow>();

    if (error) {
      throw error;
    }

    return data
      ? {
          reportCount: data.report_count,
          firstReportedAt: data.first_reported_at,
          latestReportedAt: data.latest_reported_at,
        }
      : null;
  },

  async listReviewRequiredComments(limit: number): Promise<DiscussionCommentRow[]> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_comments")
      .select(COMMENT_COLUMNS)
      .eq("moderation_status", "review_required")
      .order("moderated_at", { ascending: true, nullsFirst: false })
      .order("created_at", { ascending: true })
      .limit(limit)
      .returns<DiscussionCommentRow[]>();

    if (error) {
      throw error;
    }

    return data || [];
  },

  async getPollById(contentId: string): Promise<PollRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("polls")
      .select(POLL_COLUMNS)
      .eq("id", contentId)
      .maybeSingle<PollRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getPostById(contentId: string): Promise<DiscussionPostRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_posts")
      .select(POST_COLUMNS)
      .eq("id", contentId)
      .maybeSingle<DiscussionPostRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getCommentById(contentId: string): Promise<DiscussionCommentRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_comments")
      .select(COMMENT_COLUMNS)
      .eq("id", contentId)
      .maybeSingle<DiscussionCommentRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async updatePollReviewStatus(input: {
    contentId: string;
    status: PollModerationStatus;
    decision: ModerationReviewAction;
    reviewedAt: string;
  }): Promise<PollRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("polls")
      .update(buildReviewUpdate(input.status, input.decision, input.reviewedAt))
      .eq("id", input.contentId)
      .eq("moderation_status", "review_required")
      .select(POLL_COLUMNS)
      .maybeSingle<PollRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async updatePostReviewStatus(input: {
    contentId: string;
    status: PollModerationStatus;
    decision: ModerationReviewAction;
    reviewedAt: string;
  }): Promise<DiscussionPostRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_posts")
      .update(buildReviewUpdate(input.status, input.decision, input.reviewedAt))
      .eq("id", input.contentId)
      .eq("moderation_status", "review_required")
      .select(POST_COLUMNS)
      .maybeSingle<DiscussionPostRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async updateReportedPostReviewStatus(input: {
    contentId: string;
    status: PollModerationStatus;
    decision: ModerationReviewAction;
    reviewedAt: string;
  }): Promise<DiscussionPostRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_posts")
      .update(buildReviewUpdate(input.status, input.decision, input.reviewedAt))
      .eq("id", input.contentId)
      .eq("moderation_status", "published")
      .select(POST_COLUMNS)
      .maybeSingle<DiscussionPostRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async markOpenPostReportsReviewed(
    contentId: string,
    reviewedAt: string,
  ): Promise<void> {
    const supabase = requireSupabaseAdminClient();
    const { error } = await supabase
      .from("discussion_post_reports")
      .update({
        status: "reviewed",
        updated_at: reviewedAt,
      })
      .eq("post_id", contentId)
      .eq("status", "open");

    if (error) {
      throw error;
    }
  },

  async updateCommentReviewStatus(input: {
    contentId: string;
    status: PollModerationStatus;
    decision: ModerationReviewAction;
    reviewedAt: string;
  }): Promise<DiscussionCommentRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_comments")
      .update(buildReviewUpdate(input.status, input.decision, input.reviewedAt))
      .eq("id", input.contentId)
      .eq("moderation_status", "review_required")
      .select(COMMENT_COLUMNS)
      .maybeSingle<DiscussionCommentRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insertReviewAction(input: {
    contentType: ModerationReviewContentType;
    contentId: string;
    reviewerVerifiedIdentityId: string;
    reviewerUserId: string;
    action: ModerationReviewAction;
    previousStatus: string;
    newStatus: string;
    internalNote?: string | null;
    userMessage?: string | null;
  }): Promise<ModerationReviewActionRow> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("moderation_review_actions")
      .insert({
        content_type: input.contentType,
        content_id: input.contentId,
        reviewer_verified_identity_id: input.reviewerVerifiedIdentityId,
        reviewer_user_id: input.reviewerUserId,
        action: input.action,
        previous_status: input.previousStatus,
        new_status: input.newStatus,
        internal_note: input.internalNote ?? null,
        user_message: input.userMessage ?? null,
      })
      .select(REVIEW_ACTION_COLUMNS)
      .single<ModerationReviewActionRow>();

    if (error) {
      throw error;
    }

    return data;
  },
};

export default adminModerationRepository;
