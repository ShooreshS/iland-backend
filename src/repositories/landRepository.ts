import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type { LandRow, NewLandRow } from "../types/db";

const LAND_COLUMNS =
  "id,name,slug,type,flag_type,flag_asset,flag_emoji,founder_user_id,description,is_active,created_at,updated_at";

export const landRepository = {
  async listAll(): Promise<LandRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("lands")
      .select(LAND_COLUMNS)
      .order("name", { ascending: true })
      .order("created_at", { ascending: true });

    if (error) {
      throw error;
    }

    return (data || []) as LandRow[];
  },

  async listActive(): Promise<LandRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("lands")
      .select(LAND_COLUMNS)
      .eq("is_active", true)
      .order("name", { ascending: true })
      .order("created_at", { ascending: true });

    if (error) {
      throw error;
    }

    return (data || []) as LandRow[];
  },

  async getById(landId: string): Promise<LandRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("lands")
      .select(LAND_COLUMNS)
      .eq("id", landId)
      .maybeSingle<LandRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getBySlug(slug: string): Promise<LandRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("lands")
      .select(LAND_COLUMNS)
      .eq("slug", slug)
      .maybeSingle<LandRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insert(input: NewLandRow): Promise<LandRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("lands")
      .insert({
        ...(input.id ? { id: input.id } : null),
        name: input.name,
        slug: input.slug,
        type: input.type || "user_defined",
        flag_type: input.flag_type || "user_defined",
        flag_asset: input.flag_asset || null,
        flag_emoji: input.flag_emoji || null,
        founder_user_id: input.founder_user_id || null,
        description: input.description || null,
        is_active: input.is_active !== false,
      })
      .select(LAND_COLUMNS)
      .single<LandRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async updateById(
    landId: string,
    input: Partial<Pick<NewLandRow, "name" | "slug" | "flag_type" | "flag_asset" | "flag_emoji" | "description" | "is_active">>,
  ): Promise<LandRow | null> {
    const supabase = requireSupabaseAdminClient();

    const payload: Record<string, unknown> = {};

    if (input.name !== undefined) {
      payload.name = input.name;
    }
    if (input.slug !== undefined) {
      payload.slug = input.slug;
    }
    if (input.flag_type !== undefined) {
      payload.flag_type = input.flag_type;
    }
    if (input.flag_asset !== undefined) {
      payload.flag_asset = input.flag_asset;
    }
    if (input.flag_emoji !== undefined) {
      payload.flag_emoji = input.flag_emoji;
    }
    if (input.description !== undefined) {
      payload.description = input.description;
    }
    if (input.is_active !== undefined) {
      payload.is_active = input.is_active;
    }

    if (Object.keys(payload).length === 0) {
      return this.getById(landId);
    }

    const { data, error } = await supabase
      .from("lands")
      .update(payload)
      .eq("id", landId)
      .select(LAND_COLUMNS)
      .maybeSingle<LandRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },
};

export default landRepository;
