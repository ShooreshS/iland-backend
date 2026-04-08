import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type { NewVoteRow, VoteRow } from "../types/db";

const VOTE_COLUMNS =
  "id,poll_id,option_id,user_id,verified_identity_id,vote_latitude_l0,vote_longitude_l0,vote_location_snapshot_at,vote_location_snapshot_version,submitted_at,is_valid,invalid_reason,created_at,updated_at";

export const voteRepository = {
  async getByUserIdAndPollId(userId: string, pollId: string): Promise<VoteRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .select(VOTE_COLUMNS)
      .eq("user_id", userId)
      .eq("poll_id", pollId)
      .maybeSingle<VoteRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getByVerifiedIdentityIdAndPollId(
    verifiedIdentityId: string,
    pollId: string,
  ): Promise<VoteRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .select(VOTE_COLUMNS)
      .eq("verified_identity_id", verifiedIdentityId)
      .eq("poll_id", pollId)
      .maybeSingle<VoteRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getValidByPollId(pollId: string): Promise<VoteRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .select(VOTE_COLUMNS)
      .eq("poll_id", pollId)
      .eq("is_valid", true);

    if (error) {
      throw error;
    }

    return (data || []) as VoteRow[];
  },

  async getValidByPollIdPage(
    pollId: string,
    fromInclusive: number,
    toInclusive: number,
  ): Promise<VoteRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .select(VOTE_COLUMNS)
      .eq("poll_id", pollId)
      .eq("is_valid", true)
      .order("created_at", { ascending: true })
      .order("id", { ascending: true })
      .range(fromInclusive, toInclusive);

    if (error) {
      throw error;
    }

    return (data || []) as VoteRow[];
  },

  async getByPollId(pollId: string): Promise<VoteRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .select(VOTE_COLUMNS)
      .eq("poll_id", pollId);

    if (error) {
      throw error;
    }

    return (data || []) as VoteRow[];
  },

  async countByPollId(pollId: string): Promise<number> {
    const supabase = requireSupabaseAdminClient();

    const { count, error } = await supabase
      .from("votes")
      .select("id", { head: true, count: "exact" })
      .eq("poll_id", pollId);

    if (error) {
      throw error;
    }

    return count || 0;
  },

  async countValidByPollId(pollId: string): Promise<number> {
    const supabase = requireSupabaseAdminClient();

    const { count, error } = await supabase
      .from("votes")
      .select("id", { head: true, count: "exact" })
      .eq("poll_id", pollId)
      .eq("is_valid", true);

    if (error) {
      throw error;
    }

    return count || 0;
  },

  async getValidByPollIds(pollIds: string[]): Promise<VoteRow[]> {
    if (pollIds.length === 0) {
      return [];
    }

    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .select(VOTE_COLUMNS)
      .in("poll_id", pollIds)
      .eq("is_valid", true);

    if (error) {
      throw error;
    }

    return (data || []) as VoteRow[];
  },

  async getViewerVotesByPollIds(userId: string, pollIds: string[]): Promise<VoteRow[]> {
    if (pollIds.length === 0) {
      return [];
    }

    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .select(VOTE_COLUMNS)
      .eq("user_id", userId)
      .in("poll_id", pollIds);

    if (error) {
      throw error;
    }

    return (data || []) as VoteRow[];
  },

  async insert(input: NewVoteRow): Promise<VoteRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .insert({
        poll_id: input.poll_id,
        option_id: input.option_id,
        user_id: input.user_id,
        verified_identity_id: input.verified_identity_id ?? null,
        vote_latitude_l0: input.vote_latitude_l0 ?? null,
        vote_longitude_l0: input.vote_longitude_l0 ?? null,
        vote_location_snapshot_at: input.vote_location_snapshot_at ?? null,
        vote_location_snapshot_version: input.vote_location_snapshot_version ?? 1,
        submitted_at: input.submitted_at,
        is_valid: input.is_valid ?? true,
        invalid_reason: input.invalid_reason ?? null,
      })
      .select(VOTE_COLUMNS)
      .single<VoteRow>();

    if (error) {
      throw error;
    }

    return data;
  },
};

export default voteRepository;
