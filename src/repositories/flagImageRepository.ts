import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type { FlagImageRow, NewFlagImageRow } from "../types/db";

const FLAG_IMAGE_COLUMNS =
  "id,name,creator_user_id,storage_bucket,storage_path,original_file_name,mime_type,size_bytes,width,height,upload_status,completed_at,created_at,updated_at";

export const flagImageRepository = {
  async insert(input: NewFlagImageRow): Promise<FlagImageRow> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("flag_images")
      .insert({
        ...(input.id ? { id: input.id } : null),
        name: input.name,
        creator_user_id: input.creator_user_id,
        storage_bucket: input.storage_bucket,
        storage_path: input.storage_path,
        original_file_name: input.original_file_name ?? null,
        mime_type: input.mime_type,
        size_bytes: input.size_bytes,
        width: input.width,
        height: input.height,
        upload_status: input.upload_status ?? "signed",
      })
      .select(FLAG_IMAGE_COLUMNS)
      .single<FlagImageRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async getById(flagImageId: string): Promise<FlagImageRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("flag_images")
      .select(FLAG_IMAGE_COLUMNS)
      .eq("id", flagImageId)
      .maybeSingle<FlagImageRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async listActive(): Promise<FlagImageRow[]> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("flag_images")
      .select(FLAG_IMAGE_COLUMNS)
      .eq("upload_status", "active")
      .order("created_at", { ascending: false })
      .limit(100);

    if (error) {
      throw error;
    }

    return (data || []) as FlagImageRow[];
  },

  async markActive(flagImageId: string): Promise<FlagImageRow> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("flag_images")
      .update({
        upload_status: "active",
        completed_at: new Date().toISOString(),
      })
      .eq("id", flagImageId)
      .select(FLAG_IMAGE_COLUMNS)
      .single<FlagImageRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async countSelections(flagImageId: string): Promise<number> {
    const supabase = requireSupabaseAdminClient();
    const { count, error } = await supabase
      .from("users")
      .select("id", { count: "exact", head: true })
      .eq("selected_flag_image_id", flagImageId);

    if (error) {
      throw error;
    }

    return count || 0;
  },

  async deleteById(flagImageId: string): Promise<boolean> {
    const supabase = requireSupabaseAdminClient();
    const { error, count } = await supabase
      .from("flag_images")
      .delete({ count: "exact" })
      .eq("id", flagImageId);

    if (error) {
      throw error;
    }

    return (count || 0) > 0;
  },
};

export default flagImageRepository;
