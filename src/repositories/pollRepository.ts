import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  NewPollOptionRow,
  NewPollRow,
  PollOptionRow,
  PollRow,
} from "../types/db";

const POLL_COLUMNS =
  "id,slug,created_by_user_id,title,description,status,jurisdiction_type,jurisdiction_country_code,jurisdiction_area_ids,jurisdiction_land_ids,requires_verified_identity,allowed_document_country_codes,allowed_home_area_ids,allowed_land_ids,minimum_age,starts_at,ends_at,created_at,updated_at";

const POLL_OPTION_COLUMNS =
  "id,poll_id,label,description,color,display_order,is_active,created_at,updated_at";

export const pollRepository = {
  async listAll(): Promise<PollRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("polls")
      .select(POLL_COLUMNS)
      .order("created_at", { ascending: false });

    if (error) {
      throw error;
    }

    return (data || []) as PollRow[];
  },

  async getById(pollId: string): Promise<PollRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("polls")
      .select(POLL_COLUMNS)
      .eq("id", pollId)
      .maybeSingle<PollRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getOptionsByPollId(pollId: string): Promise<PollOptionRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_options")
      .select(POLL_OPTION_COLUMNS)
      .eq("poll_id", pollId)
      .order("display_order", { ascending: true })
      .order("created_at", { ascending: true });

    if (error) {
      throw error;
    }

    return (data || []) as PollOptionRow[];
  },

  async getOptionsByPollIds(pollIds: string[]): Promise<PollOptionRow[]> {
    if (pollIds.length === 0) {
      return [];
    }

    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("poll_options")
      .select(POLL_OPTION_COLUMNS)
      .in("poll_id", pollIds);

    if (error) {
      throw error;
    }

    return (data || []) as PollOptionRow[];
  },

  async getOptionById(optionId: string): Promise<PollOptionRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_options")
      .select(POLL_OPTION_COLUMNS)
      .eq("id", optionId)
      .maybeSingle<PollOptionRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getOptionByIdForPoll(pollId: string, optionId: string): Promise<PollOptionRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_options")
      .select(POLL_OPTION_COLUMNS)
      .eq("poll_id", pollId)
      .eq("id", optionId)
      .maybeSingle<PollOptionRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insert(input: NewPollRow): Promise<PollRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("polls")
      .insert({
        slug: input.slug,
        created_by_user_id: input.created_by_user_id,
        title: input.title,
        description: input.description,
        status: input.status,
        jurisdiction_type: input.jurisdiction_type,
        jurisdiction_country_code: input.jurisdiction_country_code,
        jurisdiction_area_ids: input.jurisdiction_area_ids,
        jurisdiction_land_ids: input.jurisdiction_land_ids,
        requires_verified_identity: input.requires_verified_identity,
        allowed_document_country_codes: input.allowed_document_country_codes,
        allowed_home_area_ids: input.allowed_home_area_ids,
        allowed_land_ids: input.allowed_land_ids,
        minimum_age: input.minimum_age,
        starts_at: input.starts_at,
        ends_at: input.ends_at,
      })
      .select(POLL_COLUMNS)
      .single<PollRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async updateById(pollId: string, input: NewPollRow): Promise<PollRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("polls")
      .update({
        slug: input.slug,
        title: input.title,
        description: input.description,
        status: input.status,
        jurisdiction_type: input.jurisdiction_type,
        jurisdiction_country_code: input.jurisdiction_country_code,
        jurisdiction_area_ids: input.jurisdiction_area_ids,
        jurisdiction_land_ids: input.jurisdiction_land_ids,
        requires_verified_identity: input.requires_verified_identity,
        allowed_document_country_codes: input.allowed_document_country_codes,
        allowed_home_area_ids: input.allowed_home_area_ids,
        allowed_land_ids: input.allowed_land_ids,
        minimum_age: input.minimum_age,
        starts_at: input.starts_at,
        ends_at: input.ends_at,
      })
      .eq("id", pollId)
      .select(POLL_COLUMNS)
      .maybeSingle<PollRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insertOptions(options: NewPollOptionRow[]): Promise<PollOptionRow[]> {
    if (options.length === 0) {
      return [];
    }

    const supabase = requireSupabaseAdminClient();
    const payload = options.map((option) => ({
      ...(option.id ? { id: option.id } : null),
      poll_id: option.poll_id,
      label: option.label,
      description: option.description,
      color: option.color,
      display_order: option.display_order,
      is_active: option.is_active,
      ...(option.created_at ? { created_at: option.created_at } : null),
    }));

    const { error } = await supabase.from("poll_options").insert(payload);
    if (error) {
      throw error;
    }

    const pollId = options[0].poll_id;
    return this.getOptionsByPollId(pollId);
  },

  async replaceOptions(pollId: string, options: NewPollOptionRow[]): Promise<PollOptionRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { error: deleteError } = await supabase
      .from("poll_options")
      .delete()
      .eq("poll_id", pollId);

    if (deleteError) {
      throw deleteError;
    }

    if (options.length === 0) {
      return [];
    }

    return this.insertOptions(options);
  },
};

export default pollRepository;
