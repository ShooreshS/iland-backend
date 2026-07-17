import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  DiscussionMediaUploadRow,
  NewDiscussionMediaUploadRow,
} from "../types/db";

const UPLOAD_COLUMNS =
  "id,uploader_user_id,storage_bucket,storage_path,original_file_name,mime_type,size_bytes,upload_status,attached_post_id,signed_at,completed_at,attached_at,created_at,updated_at";

const buildUploadPayload = (input: NewDiscussionMediaUploadRow) => ({
  ...(input.id ? { id: input.id } : null),
  uploader_user_id: input.uploader_user_id,
  storage_bucket: input.storage_bucket,
  storage_path: input.storage_path,
  original_file_name: input.original_file_name ?? null,
  mime_type: input.mime_type,
  size_bytes: input.size_bytes,
  upload_status: input.upload_status ?? "signed",
});

export const discussionMediaRepository = {
  async insertUpload(
    input: NewDiscussionMediaUploadRow,
  ): Promise<DiscussionMediaUploadRow> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_media_uploads")
      .insert(buildUploadPayload(input))
      .select(UPLOAD_COLUMNS)
      .single<DiscussionMediaUploadRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async getUploadById(
    uploadId: string,
  ): Promise<DiscussionMediaUploadRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_media_uploads")
      .select(UPLOAD_COLUMNS)
      .eq("id", uploadId)
      .maybeSingle<DiscussionMediaUploadRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async markUploadCompleted(
    uploadId: string,
  ): Promise<DiscussionMediaUploadRow> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_media_uploads")
      .update({
        upload_status: "uploaded",
        completed_at: new Date().toISOString(),
      })
      .eq("id", uploadId)
      .select(UPLOAD_COLUMNS)
      .single<DiscussionMediaUploadRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async attachUploadToPost(
    uploadId: string,
    postId: string,
  ): Promise<DiscussionMediaUploadRow> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("discussion_media_uploads")
      .update({
        upload_status: "attached",
        attached_post_id: postId,
        attached_at: new Date().toISOString(),
      })
      .eq("id", uploadId)
      .select(UPLOAD_COLUMNS)
      .single<DiscussionMediaUploadRow>();

    if (error) {
      throw error;
    }

    return data;
  },
};

export default discussionMediaRepository;
