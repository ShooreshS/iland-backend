import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  HumanVerificationMediaKind,
  HumanVerificationMediaRow,
  HumanVerificationPushInstallationRow,
  HumanVerificationRequestRow,
  HumanVerificationReviewActionRow,
  HumanVerificationStatus,
} from "../types/db";

const REQUEST_COLUMNS =
  "id,access_token_hash,device_credential_id,device_public_key_pem,platform,status,document_type,similarity,comparison_threshold,comparison_model,liveness_passed,gaze_passed,app_attestation,reviewer_verified_identity_id,reviewer_user_id,user_message,internal_note,submitted_at,decided_at,consumed_at,consumed_by_user_id,expires_at,created_at,updated_at";
const MEDIA_COLUMNS =
  "id,request_id,kind,storage_bucket,storage_path,mime_type,size_bytes,width,height,sha256,upload_status,completed_at,deleted_at,created_at,updated_at";
const ACTION_COLUMNS =
  "id,request_id,reviewer_verified_identity_id,reviewer_user_id,action,previous_status,new_status,internal_note,user_message,created_at";
const PUSH_COLUMNS =
  "request_id,platform,provider,provider_environment,token_ciphertext,token_hash,locale,status,last_delivery_error,last_registered_at,last_delivery_at,created_at,updated_at";

export const humanVerificationRepository = {
  async insertRequest(input: {
    id: string;
    accessTokenHash: string;
    deviceCredentialId: string;
    devicePublicKeyPem: string;
    platform: "ios" | "android";
    documentType: string;
    similarity: number;
    comparisonThreshold: number;
    comparisonModel?: string | null;
    livenessPassed: boolean;
    gazePassed?: boolean | null;
    appAttestation: Record<string, unknown>;
    expiresAt: string;
  }): Promise<HumanVerificationRequestRow> {
    const { data, error } = await requireSupabaseAdminClient()
      .from("human_verification_requests")
      .insert({
        id: input.id,
        access_token_hash: input.accessTokenHash,
        device_credential_id: input.deviceCredentialId,
        device_public_key_pem: input.devicePublicKeyPem,
        platform: input.platform,
        status: "uploading",
        document_type: input.documentType,
        similarity: input.similarity,
        comparison_threshold: input.comparisonThreshold,
        comparison_model: input.comparisonModel ?? null,
        liveness_passed: input.livenessPassed,
        gaze_passed: input.gazePassed ?? null,
        app_attestation: input.appAttestation,
        expires_at: input.expiresAt,
      })
      .select(REQUEST_COLUMNS)
      .single<HumanVerificationRequestRow>();
    if (error) throw error;
    return data;
  },

  async insertMedia(input: {
    requestId: string;
    kind: HumanVerificationMediaKind;
    storageBucket: string;
    storagePath: string;
    mimeType: "image/jpeg";
    sizeBytes: number;
    width: number;
    height: number;
    sha256: string;
  }): Promise<HumanVerificationMediaRow> {
    const { data, error } = await requireSupabaseAdminClient()
      .from("human_verification_media")
      .insert({
        request_id: input.requestId,
        kind: input.kind,
        storage_bucket: input.storageBucket,
        storage_path: input.storagePath,
        mime_type: input.mimeType,
        size_bytes: input.sizeBytes,
        width: input.width,
        height: input.height,
        sha256: input.sha256,
        upload_status: "signed",
      })
      .select(MEDIA_COLUMNS)
      .single<HumanVerificationMediaRow>();
    if (error) throw error;
    return data;
  },

  async getRequestById(id: string): Promise<HumanVerificationRequestRow | null> {
    const { data, error } = await requireSupabaseAdminClient()
      .from("human_verification_requests")
      .select(REQUEST_COLUMNS)
      .eq("id", id)
      .maybeSingle<HumanVerificationRequestRow>();
    if (error) throw error;
    return data || null;
  },

  async findActiveByCredentialId(
    credentialId: string,
  ): Promise<HumanVerificationRequestRow | null> {
    const { data, error } = await requireSupabaseAdminClient()
      .from("human_verification_requests")
      .select(REQUEST_COLUMNS)
      .eq("device_credential_id", credentialId)
      .in("status", ["uploading", "pending", "approved"])
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle<HumanVerificationRequestRow>();
    if (error) throw error;
    return data || null;
  },

  async listMedia(requestId: string): Promise<HumanVerificationMediaRow[]> {
    const { data, error } = await requireSupabaseAdminClient()
      .from("human_verification_media")
      .select(MEDIA_COLUMNS)
      .eq("request_id", requestId)
      .order("kind", { ascending: true })
      .returns<HumanVerificationMediaRow[]>();
    if (error) throw error;
    return data || [];
  },

  async markMediaUploaded(id: string): Promise<HumanVerificationMediaRow> {
    const { data, error } = await requireSupabaseAdminClient()
      .from("human_verification_media")
      .update({
        upload_status: "uploaded",
        completed_at: new Date().toISOString(),
      })
      .eq("id", id)
      .select(MEDIA_COLUMNS)
      .single<HumanVerificationMediaRow>();
    if (error) throw error;
    return data;
  },

  async markMediaDeleted(id: string): Promise<void> {
    const { error } = await requireSupabaseAdminClient()
      .from("human_verification_media")
      .update({
        upload_status: "deleted",
        deleted_at: new Date().toISOString(),
      })
      .eq("id", id);
    if (error) throw error;
  },

  async transitionRequest(
    id: string,
    expectedStatus: HumanVerificationStatus,
    nextStatus: HumanVerificationStatus,
    values: Record<string, unknown> = {},
  ): Promise<HumanVerificationRequestRow | null> {
    const { data, error } = await requireSupabaseAdminClient()
      .from("human_verification_requests")
      .update({ status: nextStatus, ...values })
      .eq("id", id)
      .eq("status", expectedStatus)
      .select(REQUEST_COLUMNS)
      .maybeSingle<HumanVerificationRequestRow>();
    if (error) throw error;
    return data || null;
  },

  async listPending(limit: number): Promise<HumanVerificationRequestRow[]> {
    const { data, error } = await requireSupabaseAdminClient()
      .from("human_verification_requests")
      .select(REQUEST_COLUMNS)
      .eq("status", "pending")
      .order("submitted_at", { ascending: true })
      .order("id", { ascending: true })
      .limit(limit)
      .returns<HumanVerificationRequestRow[]>();
    if (error) throw error;
    return data || [];
  },

  async listOverdueActive(
    expiredBefore: string,
    limit = 100,
  ): Promise<HumanVerificationRequestRow[]> {
    const { data, error } = await requireSupabaseAdminClient()
      .from("human_verification_requests")
      .select(REQUEST_COLUMNS)
      .in("status", ["uploading", "pending", "approved"])
      .lt("expires_at", expiredBefore)
      .limit(limit)
      .returns<HumanVerificationRequestRow[]>();
    if (error) throw error;
    return data || [];
  },

  async listMediaCleanupCandidates(
    updatedBefore: string,
    limit = 100,
  ): Promise<HumanVerificationRequestRow[]> {
    const { data, error } = await requireSupabaseAdminClient()
      .from("human_verification_requests")
      .select(REQUEST_COLUMNS)
      .in("status", ["consumed", "rejected", "expired", "cancelled"])
      .lt("updated_at", updatedBefore)
      .order("updated_at", { ascending: true })
      .limit(limit)
      .returns<HumanVerificationRequestRow[]>();
    if (error) throw error;
    return data || [];
  },

  async insertReviewAction(input: {
    requestId: string;
    reviewerVerifiedIdentityId: string;
    reviewerUserId: string;
    action: "approve" | "reject";
    previousStatus: HumanVerificationStatus;
    newStatus: HumanVerificationStatus;
    internalNote?: string | null;
    userMessage?: string | null;
  }): Promise<HumanVerificationReviewActionRow> {
    const { data, error } = await requireSupabaseAdminClient()
      .from("human_verification_review_actions")
      .insert({
        request_id: input.requestId,
        reviewer_verified_identity_id: input.reviewerVerifiedIdentityId,
        reviewer_user_id: input.reviewerUserId,
        action: input.action,
        previous_status: input.previousStatus,
        new_status: input.newStatus,
        internal_note: input.internalNote ?? null,
        user_message: input.userMessage ?? null,
      })
      .select(ACTION_COLUMNS)
      .single<HumanVerificationReviewActionRow>();
    if (error) throw error;
    return data;
  },

  async listReviewActions(
    requestId: string,
  ): Promise<HumanVerificationReviewActionRow[]> {
    const { data, error } = await requireSupabaseAdminClient()
      .from("human_verification_review_actions")
      .select(ACTION_COLUMNS)
      .eq("request_id", requestId)
      .order("created_at", { ascending: false })
      .returns<HumanVerificationReviewActionRow[]>();
    if (error) throw error;
    return data || [];
  },

  async upsertPushInstallation(input: {
    requestId: string;
    platform: "ios" | "android";
    provider: "apns" | "fcm";
    providerEnvironment: "sandbox" | "production";
    tokenCiphertext: string;
    tokenHash: string;
    locale?: string | null;
  }): Promise<HumanVerificationPushInstallationRow> {
    const { data, error } = await requireSupabaseAdminClient()
      .from("human_verification_push_installations")
      .upsert(
        {
          request_id: input.requestId,
          platform: input.platform,
          provider: input.provider,
          provider_environment: input.providerEnvironment,
          token_ciphertext: input.tokenCiphertext,
          token_hash: input.tokenHash,
          locale: input.locale ?? null,
          status: "active",
          last_delivery_error: null,
          last_registered_at: new Date().toISOString(),
        },
        { onConflict: "request_id" },
      )
      .select(PUSH_COLUMNS)
      .single<HumanVerificationPushInstallationRow>();
    if (error) throw error;
    return data;
  },

  async getPushInstallation(
    requestId: string,
  ): Promise<HumanVerificationPushInstallationRow | null> {
    const { data, error } = await requireSupabaseAdminClient()
      .from("human_verification_push_installations")
      .select(PUSH_COLUMNS)
      .eq("request_id", requestId)
      .maybeSingle<HumanVerificationPushInstallationRow>();
    if (error) throw error;
    return data || null;
  },

  async recordPushDelivery(
    requestId: string,
    input: { status: "sent" | "invalid" | "failed"; error?: string | null },
  ): Promise<void> {
    const { error } = await requireSupabaseAdminClient()
      .from("human_verification_push_installations")
      .update({
        status: input.status,
        last_delivery_error: input.error?.slice(0, 500) ?? null,
        last_delivery_at: new Date().toISOString(),
      })
      .eq("request_id", requestId);
    if (error) throw error;
  },

  async associateConsumedUser(requestId: string, userId: string): Promise<void> {
    const { error } = await requireSupabaseAdminClient()
      .from("human_verification_requests")
      .update({ consumed_by_user_id: userId })
      .eq("id", requestId)
      .eq("status", "consumed");
    if (error) throw error;
  },
};

export default humanVerificationRepository;
