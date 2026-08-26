import { requireSupabaseAdminClient } from "../db/supabaseClient";

export type NotificationEventType =
  | "discussion.post_commented"
  | "discussion.comment_replied"
  | "discussion.post_liked"
  | "discussion.comment_liked";

export type NotificationRow = {
  id: string;
  recipient_user_id: string;
  event_type: NotificationEventType;
  actor_user_id: string | null;
  subject_type: "discussion_post" | "discussion_comment";
  subject_id: string;
  parent_post_id: string;
  target_url: string;
  payload_version: number;
  payload: Record<string, unknown>;
  aggregation_count: number;
  first_event_at: string;
  last_event_at: string;
  read_at: string | null;
  archived_at: string | null;
  created_at: string;
  updated_at: string;
};

export type NotificationPreferenceRow = {
  user_id: string;
  push_enabled: boolean;
  comments_and_replies_push: boolean;
  likes_push: boolean;
  preferred_locale: string | null;
  created_at: string;
  updated_at: string;
};

export type ClaimedPushDelivery = {
  delivery_id: string;
  notification_id: string;
  installation_id: string;
  attempt_count: number;
  event_type: NotificationEventType;
  aggregation_count: number;
  target_url: string;
  payload: Record<string, unknown>;
  provider: "apns" | "fcm";
  provider_environment: "sandbox" | "production";
  token_ciphertext: string;
  locale: string | null;
};

const NOTIFICATION_COLUMNS =
  "id,recipient_user_id,event_type,actor_user_id,subject_type,subject_id,parent_post_id,target_url,payload_version,payload,aggregation_count,first_event_at,last_event_at,read_at,archived_at,created_at,updated_at";

const PREFERENCE_COLUMNS =
  "user_id,push_enabled,comments_and_replies_push,likes_push,preferred_locale,created_at,updated_at";

export const notificationRepository = {
  async list(input: {
    userId: string;
    limit: number;
    unreadOnly: boolean;
    cursor?: { lastEventAt: string; id: string } | null;
  }): Promise<NotificationRow[]> {
    const supabase = requireSupabaseAdminClient();
    let query = supabase
      .from("notifications")
      .select(NOTIFICATION_COLUMNS)
      .eq("recipient_user_id", input.userId)
      .is("archived_at", null)
      .order("last_event_at", { ascending: false })
      .order("id", { ascending: false })
      .limit(input.limit + 1);

    if (input.unreadOnly) {
      query = query.is("read_at", null);
    }
    if (input.cursor) {
      query = query.or(
        `last_event_at.lt.${input.cursor.lastEventAt},and(last_event_at.eq.${input.cursor.lastEventAt},id.lt.${input.cursor.id})`,
      );
    }

    const { data, error } = await query.returns<NotificationRow[]>();
    if (error) throw error;
    return data || [];
  },

  async countUnread(userId: string): Promise<number> {
    const supabase = requireSupabaseAdminClient();
    const { count, error } = await supabase
      .from("notifications")
      .select("id", { count: "exact", head: true })
      .eq("recipient_user_id", userId)
      .is("read_at", null)
      .is("archived_at", null);
    if (error) throw error;
    return count || 0;
  },

  async update(
    userId: string,
    notificationId: string,
    input: { read?: boolean; archived?: boolean },
  ): Promise<NotificationRow | null> {
    const supabase = requireSupabaseAdminClient();
    const now = new Date().toISOString();
    const updates: Record<string, string | null> = {};
    if (input.read !== undefined) updates.read_at = input.read ? now : null;
    if (input.archived !== undefined) {
      updates.archived_at = input.archived ? now : null;
    }
    const { data, error } = await supabase
      .from("notifications")
      .update(updates)
      .eq("id", notificationId)
      .eq("recipient_user_id", userId)
      .select(NOTIFICATION_COLUMNS)
      .maybeSingle<NotificationRow>();
    if (error) throw error;
    return data || null;
  },

  async markAllRead(userId: string): Promise<number> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("notifications")
      .update({ read_at: new Date().toISOString() })
      .eq("recipient_user_id", userId)
      .is("read_at", null)
      .is("archived_at", null)
      .select("id");
    if (error) throw error;
    return data?.length || 0;
  },

  async getOrCreatePreferences(userId: string): Promise<NotificationPreferenceRow> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("notification_preferences")
      .upsert({ user_id: userId }, { onConflict: "user_id" })
      .select(PREFERENCE_COLUMNS)
      .single<NotificationPreferenceRow>();
    if (error) throw error;
    return data;
  },

  async updatePreferences(
    userId: string,
    input: {
      pushEnabled?: boolean;
      commentsAndRepliesPush?: boolean;
      likesPush?: boolean;
      preferredLocale?: string | null;
    },
  ): Promise<NotificationPreferenceRow> {
    const supabase = requireSupabaseAdminClient();
    const values: Record<string, unknown> = { user_id: userId };
    if (input.pushEnabled !== undefined) values.push_enabled = input.pushEnabled;
    if (input.commentsAndRepliesPush !== undefined) {
      values.comments_and_replies_push = input.commentsAndRepliesPush;
    }
    if (input.likesPush !== undefined) values.likes_push = input.likesPush;
    if (input.preferredLocale !== undefined) {
      values.preferred_locale = input.preferredLocale;
    }
    const { data, error } = await supabase
      .from("notification_preferences")
      .upsert(values, { onConflict: "user_id" })
      .select(PREFERENCE_COLUMNS)
      .single<NotificationPreferenceRow>();
    if (error) throw error;
    return data;
  },

  async upsertInstallation(input: {
    userId: string;
    authSessionId: string;
    platform: "ios" | "android";
    provider: "apns" | "fcm";
    providerEnvironment: "sandbox" | "production";
    tokenCiphertext: string;
    tokenHash: string;
    permissionStatus: "granted" | "denied" | "undetermined";
    locale?: string | null;
    appVersion?: string | null;
    buildNumber?: string | null;
  }): Promise<void> {
    const supabase = requireSupabaseAdminClient();
    const { error } = await supabase.rpc("register_push_installation", {
      p_user_id: input.userId,
      p_auth_session_id: input.authSessionId,
      p_platform: input.platform,
      p_provider: input.provider,
      p_provider_environment: input.providerEnvironment,
      p_token_ciphertext: input.tokenCiphertext,
      p_token_hash: input.tokenHash,
      p_permission_status: input.permissionStatus,
      p_locale: input.locale ?? null,
      p_app_version: input.appVersion ?? null,
      p_build_number: input.buildNumber ?? null,
    });
    if (error) throw error;
  },

  async revokeInstallation(authSessionId: string, provider?: "apns" | "fcm"): Promise<void> {
    const supabase = requireSupabaseAdminClient();
    let query = supabase
      .from("push_installations")
      .update({ status: "revoked" })
      .eq("auth_session_id", authSessionId);
    if (provider) query = query.eq("provider", provider);
    const { error } = await query;
    if (error) throw error;
  },

  async claimDeliveries(input: {
    workerId: string;
    batchSize: number;
    lockTimeoutSeconds: number;
  }): Promise<ClaimedPushDelivery[]> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase.rpc("claim_notification_push_deliveries", {
      worker_id: input.workerId,
      batch_size: input.batchSize,
      lock_timeout_seconds: input.lockTimeoutSeconds,
    });
    if (error) throw error;
    return (data || []) as ClaimedPushDelivery[];
  },

  async completeDelivery(input: {
    deliveryId: string;
    status: "sent" | "retry" | "invalid_token" | "dead";
    providerMessageId?: string | null;
    errorCode?: string | null;
    errorMessage?: string | null;
    availableAt?: string | null;
  }): Promise<void> {
    const supabase = requireSupabaseAdminClient();
    const { error } = await supabase
      .from("push_deliveries")
      .update({
        status: input.status,
        provider_message_id: input.providerMessageId ?? null,
        last_error_code: input.errorCode ?? null,
        last_error_message: input.errorMessage?.slice(0, 500) ?? null,
        available_at: input.availableAt ?? new Date().toISOString(),
        sent_at: input.status === "sent" ? new Date().toISOString() : null,
        leased_at: null,
        leased_by: null,
      })
      .eq("id", input.deliveryId);
    if (error) throw error;
  },

  async markInstallationInvalid(installationId: string): Promise<void> {
    const supabase = requireSupabaseAdminClient();
    const { error } = await supabase
      .from("push_installations")
      .update({ status: "invalid", invalidated_at: new Date().toISOString() })
      .eq("id", installationId);
    if (error) throw error;
  },

  async markInstallationSuccessful(installationId: string): Promise<void> {
    const supabase = requireSupabaseAdminClient();
    const { error } = await supabase
      .from("push_installations")
      .update({ last_success_at: new Date().toISOString() })
      .eq("id", installationId);
    if (error) throw error;
  },
};

export default notificationRepository;
