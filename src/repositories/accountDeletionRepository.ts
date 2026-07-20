import { requireSupabaseAdminClient } from "../db/supabaseClient";

export type AccountDeletionSummary = {
  userFound: boolean;
  userAnonymized: boolean;
  votes: number;
  discussionPosts: number;
  discussionComments: number;
  discussionPostLikes: number;
  discussionPostBookmarks: number;
  discussionPostReports: number;
  discussionMediaUploads: number;
  walletCredentials: number;
  authCredentials: number;
  oidcRecords: number;
  authAuditEventsAnonymized: number;
  oidcAuditEventsAnonymized: number;
  adminReviewersDisabled: number;
  pollOwnershipsCleared: number;
  landFoundershipsCleared: number;
  credentialRegistryEntriesRevoked: number;
};

const asRecord = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};

const asBoolean = (value: unknown): boolean => value === true;

const asCount = (value: unknown): number => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.max(0, Math.trunc(value));
  }

  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? Math.max(0, Math.trunc(parsed)) : 0;
  }

  return 0;
};

const normalizeSummary = (value: unknown): AccountDeletionSummary => {
  const record = asRecord(value);

  return {
    userFound: asBoolean(record.userFound),
    userAnonymized: asBoolean(record.userAnonymized),
    votes: asCount(record.votes),
    discussionPosts: asCount(record.discussionPosts),
    discussionComments: asCount(record.discussionComments),
    discussionPostLikes: asCount(record.discussionPostLikes),
    discussionPostBookmarks: asCount(record.discussionPostBookmarks),
    discussionPostReports: asCount(record.discussionPostReports),
    discussionMediaUploads: asCount(record.discussionMediaUploads),
    walletCredentials: asCount(record.walletCredentials),
    authCredentials: asCount(record.authCredentials),
    oidcRecords: asCount(record.oidcRecords),
    authAuditEventsAnonymized: asCount(record.authAuditEventsAnonymized),
    oidcAuditEventsAnonymized: asCount(record.oidcAuditEventsAnonymized),
    adminReviewersDisabled: asCount(record.adminReviewersDisabled),
    pollOwnershipsCleared: asCount(record.pollOwnershipsCleared),
    landFoundershipsCleared: asCount(record.landFoundershipsCleared),
    credentialRegistryEntriesRevoked: asCount(
      record.credentialRegistryEntriesRevoked,
    ),
  };
};

export const accountDeletionRepository = {
  async deleteAccountForUser(userId: string): Promise<AccountDeletionSummary> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase.rpc("delete_account_for_user", {
      target_user_id: userId,
    });

    if (error) {
      throw error;
    }

    return normalizeSummary(data);
  },
};

export default accountDeletionRepository;
