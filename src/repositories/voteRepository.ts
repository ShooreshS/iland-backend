import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type { NewVoteRow, VoteRow } from "../types/db";

const BASE_VOTE_COLUMNS =
  "id,poll_id,option_id,user_id,verified_identity_id,submitted_at,is_valid,invalid_reason,created_at,updated_at";
const SNAPSHOT_VOTE_COLUMNS =
  "vote_latitude_l0,vote_longitude_l0,vote_location_snapshot_at,vote_location_snapshot_version";
const VOTE_COLUMNS_WITH_SNAPSHOT = `${BASE_VOTE_COLUMNS},${SNAPSHOT_VOTE_COLUMNS}`;
const MAP_CACHE_REBUILD_VOTE_COLUMNS =
  "id,option_id,submitted_at,vote_latitude_l0,vote_longitude_l0";
const SNAPSHOT_VOTE_COLUMN_NAMES = [
  "vote_latitude_l0",
  "vote_longitude_l0",
  "vote_location_snapshot_at",
  "vote_location_snapshot_version",
] as const;

type PartialVoteRow = Omit<
  VoteRow,
  | "vote_latitude_l0"
  | "vote_longitude_l0"
  | "vote_location_snapshot_at"
  | "vote_location_snapshot_version"
> &
  Partial<
    Pick<
      VoteRow,
      | "vote_latitude_l0"
      | "vote_longitude_l0"
      | "vote_location_snapshot_at"
      | "vote_location_snapshot_version"
    >
  >;

export type PollMapRebuildVoteRow = Pick<
  VoteRow,
  | "id"
  | "option_id"
  | "submitted_at"
  | "vote_latitude_l0"
  | "vote_longitude_l0"
>;

const withSnapshotDefaults = (row: PartialVoteRow): VoteRow => ({
  ...row,
  vote_latitude_l0: row.vote_latitude_l0 ?? null,
  vote_longitude_l0: row.vote_longitude_l0 ?? null,
  vote_location_snapshot_at: row.vote_location_snapshot_at ?? null,
  vote_location_snapshot_version: row.vote_location_snapshot_version ?? 1,
});

const hasValidVoteAtOffset = async (params: {
  supabase: ReturnType<typeof requireSupabaseAdminClient>;
  pollId: string;
  offset: number;
  requireSnapshot: boolean;
  optionId?: string;
}): Promise<boolean> => {
  const { supabase, pollId, offset, requireSnapshot, optionId } = params;
  const normalizedOffset = Math.max(0, Math.trunc(offset));

  let query = supabase
    .from("votes")
    .select("id")
    .eq("poll_id", pollId)
    .eq("is_valid", true);

  if (optionId) {
    query = query.eq("option_id", optionId);
  }

  if (requireSnapshot) {
    query = query
      .not("vote_latitude_l0", "is", null)
      .not("vote_longitude_l0", "is", null);
  }

  query = query.range(normalizedOffset, normalizedOffset);

  const { data, error } = await query;
  if (error) {
    throw error;
  }

  return Array.isArray(data) && data.length > 0;
};

const countValidVotesWithProbe = async (params: {
  supabase: ReturnType<typeof requireSupabaseAdminClient>;
  pollId: string;
  hintedCount: number;
  requireSnapshot: boolean;
  optionId?: string;
}): Promise<number> => {
  const { supabase, pollId, hintedCount, requireSnapshot, optionId } = params;
  const normalizedHint = Math.max(0, Math.trunc(hintedCount));

  if (normalizedHint === 0) {
    return 0;
  }

  const hasVoteAtHint = await hasValidVoteAtOffset({
    supabase,
    pollId,
    offset: normalizedHint,
    requireSnapshot,
    optionId,
  });
  if (!hasVoteAtHint) {
    return normalizedHint;
  }

  let lowerBound = normalizedHint;
  let upperBound = Math.max(normalizedHint + 1, normalizedHint * 2);

  while (
    await hasValidVoteAtOffset({
      supabase,
      pollId,
      offset: upperBound,
      requireSnapshot,
      optionId,
    })
  ) {
    lowerBound = upperBound;
    upperBound *= 2;
  }

  while (lowerBound + 1 < upperBound) {
    const midpoint = Math.floor((lowerBound + upperBound) / 2);
    const hasVoteAtMidpoint = await hasValidVoteAtOffset({
      supabase,
      pollId,
      offset: midpoint,
      requireSnapshot,
      optionId,
    });

    if (hasVoteAtMidpoint) {
      lowerBound = midpoint;
    } else {
      upperBound = midpoint;
    }
  }

  return lowerBound + 1;
};

const isMissingSnapshotVoteColumnError = (error: unknown): boolean => {
  if (!error || typeof error !== "object") {
    return false;
  }

  const code = (error as { code?: unknown }).code;
  if (typeof code !== "string") {
    return false;
  }

  const normalizedCode = code.trim().toUpperCase();
  if (
    normalizedCode !== "42703" &&
    normalizedCode !== "PGRST204" &&
    normalizedCode !== "PGRST205"
  ) {
    return false;
  }

  const message = (error as { message?: unknown }).message;
  if (typeof message !== "string") {
    return false;
  }

  const normalized = message.toLowerCase();
  return SNAPSHOT_VOTE_COLUMN_NAMES.some((columnName) =>
    normalized.includes(columnName),
  );
};

export const voteRepository = {
  async getByUserIdAndPollId(userId: string, pollId: string): Promise<VoteRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .select(BASE_VOTE_COLUMNS)
      .eq("user_id", userId)
      .eq("poll_id", pollId)
      .maybeSingle<PartialVoteRow>();

    if (error) {
      throw error;
    }

    return data ? withSnapshotDefaults(data) : null;
  },

  async getByVerifiedIdentityIdAndPollId(
    verifiedIdentityId: string,
    pollId: string,
  ): Promise<VoteRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .select(BASE_VOTE_COLUMNS)
      .eq("verified_identity_id", verifiedIdentityId)
      .eq("poll_id", pollId)
      .maybeSingle<PartialVoteRow>();

    if (error) {
      throw error;
    }

    return data ? withSnapshotDefaults(data) : null;
  },

  async getValidByPollId(pollId: string): Promise<VoteRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .select(BASE_VOTE_COLUMNS)
      .eq("poll_id", pollId)
      .eq("is_valid", true);

    if (error) {
      throw error;
    }

    return ((data || []) as PartialVoteRow[]).map(withSnapshotDefaults);
  },

  async getValidByPollIdPage(
    pollId: string,
    fromInclusive: number,
    toInclusive: number,
  ): Promise<VoteRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .select(VOTE_COLUMNS_WITH_SNAPSHOT)
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

  async getValidWithSnapshotByPollIdPage(
    pollId: string,
    fromInclusive: number,
    toInclusive: number,
  ): Promise<VoteRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .select(VOTE_COLUMNS_WITH_SNAPSHOT)
      .eq("poll_id", pollId)
      .eq("is_valid", true)
      .not("vote_latitude_l0", "is", null)
      .not("vote_longitude_l0", "is", null)
      .order("created_at", { ascending: true })
      .order("id", { ascending: true })
      .range(fromInclusive, toInclusive);

    if (error) {
      throw error;
    }

    return (data || []) as VoteRow[];
  },

  async getValidWithSnapshotByPollIdKeysetPage(
    pollId: string,
    afterVoteId: string | null,
    limit: number,
  ): Promise<PollMapRebuildVoteRow[]> {
    const supabase = requireSupabaseAdminClient();
    const normalizedLimit = Math.max(1, Math.trunc(limit));

    let query = supabase
      .from("votes")
      .select(MAP_CACHE_REBUILD_VOTE_COLUMNS)
      .eq("poll_id", pollId)
      .eq("is_valid", true)
      .not("vote_latitude_l0", "is", null)
      .not("vote_longitude_l0", "is", null)
      .order("id", { ascending: true })
      .limit(normalizedLimit);

    if (afterVoteId && afterVoteId.trim().length > 0) {
      query = query.gt("id", afterVoteId.trim());
    }

    const { data, error } = await query;

    if (error) {
      throw error;
    }

    return (data || []) as PollMapRebuildVoteRow[];
  },

  async getByPollId(pollId: string): Promise<VoteRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .select(BASE_VOTE_COLUMNS)
      .eq("poll_id", pollId);

    if (error) {
      throw error;
    }

    return ((data || []) as PartialVoteRow[]).map(withSnapshotDefaults);
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

    return countValidVotesWithProbe({
      supabase,
      pollId,
      hintedCount: count || 0,
      requireSnapshot: false,
    });
  },

  async countValidWithSnapshotByPollId(pollId: string): Promise<number> {
    const supabase = requireSupabaseAdminClient();

    const { count, error } = await supabase
      .from("votes")
      .select("id", { head: true, count: "exact" })
      .eq("poll_id", pollId)
      .eq("is_valid", true)
      .not("vote_latitude_l0", "is", null)
      .not("vote_longitude_l0", "is", null);

    if (error) {
      throw error;
    }

    return countValidVotesWithProbe({
      supabase,
      pollId,
      hintedCount: count || 0,
      requireSnapshot: true,
    });
  },

  async countValidByPollIdAndOptionId(
    pollId: string,
    optionId: string,
  ): Promise<number> {
    const supabase = requireSupabaseAdminClient();

    const { count, error } = await supabase
      .from("votes")
      .select("id", { head: true, count: "exact" })
      .eq("poll_id", pollId)
      .eq("option_id", optionId)
      .eq("is_valid", true);

    if (error) {
      throw error;
    }

    return countValidVotesWithProbe({
      supabase,
      pollId,
      hintedCount: count || 0,
      requireSnapshot: false,
      optionId,
    });
  },

  async getLatestValidSubmittedAtByPollId(pollId: string): Promise<string | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .select("submitted_at")
      .eq("poll_id", pollId)
      .eq("is_valid", true)
      .order("submitted_at", { ascending: false })
      .order("id", { ascending: false })
      .limit(1)
      .maybeSingle<{ submitted_at: string }>();

    if (error) {
      throw error;
    }

    return data?.submitted_at ?? null;
  },

  async getValidByPollIds(pollIds: string[]): Promise<VoteRow[]> {
    if (pollIds.length === 0) {
      return [];
    }

    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .select(BASE_VOTE_COLUMNS)
      .in("poll_id", pollIds)
      .eq("is_valid", true);

    if (error) {
      throw error;
    }

    return ((data || []) as PartialVoteRow[]).map(withSnapshotDefaults);
  },

  async getViewerVotesByPollIds(userId: string, pollIds: string[]): Promise<VoteRow[]> {
    if (pollIds.length === 0) {
      return [];
    }

    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("votes")
      .select(BASE_VOTE_COLUMNS)
      .eq("user_id", userId)
      .in("poll_id", pollIds);

    if (error) {
      throw error;
    }

    return ((data || []) as PartialVoteRow[]).map(withSnapshotDefaults);
  },

  async insert(input: NewVoteRow): Promise<VoteRow> {
    const supabase = requireSupabaseAdminClient();

    const baseInsertPayload = {
      poll_id: input.poll_id,
      option_id: input.option_id,
      user_id: input.user_id,
      verified_identity_id: input.verified_identity_id ?? null,
      submitted_at: input.submitted_at,
      is_valid: input.is_valid ?? true,
      invalid_reason: input.invalid_reason ?? null,
    };

    const snapshotInsertPayload = {
      ...baseInsertPayload,
      vote_latitude_l0: input.vote_latitude_l0 ?? null,
      vote_longitude_l0: input.vote_longitude_l0 ?? null,
      vote_location_snapshot_at: input.vote_location_snapshot_at ?? null,
      vote_location_snapshot_version: input.vote_location_snapshot_version ?? 1,
    };

    const { data, error } = await supabase
      .from("votes")
      .insert(snapshotInsertPayload)
      .select(VOTE_COLUMNS_WITH_SNAPSHOT)
      .single<VoteRow>();

    if (!error) {
      return data;
    }

    if (!isMissingSnapshotVoteColumnError(error)) {
      throw error;
    }

    console.warn(
      "[voteRepository] vote snapshot columns missing; retrying insert without snapshot fields",
      {
        pollId: input.poll_id,
        userId: input.user_id,
        error,
      },
    );

    const fallbackInsert = await supabase
      .from("votes")
      .insert(baseInsertPayload)
      .select(BASE_VOTE_COLUMNS)
      .single<PartialVoteRow>();

    if (fallbackInsert.error) {
      throw fallbackInsert.error;
    }

    return withSnapshotDefaults(fallbackInsert.data);
  },
};

export default voteRepository;
