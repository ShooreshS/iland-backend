import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  NewPollMapMarkerCacheRow,
  PollMapMarkerCacheRow,
} from "../types/db";

const POLL_MAP_MARKER_CACHE_COLUMNS =
  "poll_id,markers_level1_json,schema_version,marker_count,total_votes,last_vote_submitted_at,refreshed_at,created_at,updated_at";

type PollMapMarkerCacheRepositoryDependencies = {
  getSupabaseAdminClient?: () => ReturnType<typeof requireSupabaseAdminClient>;
};

const createUpsertPayload = (
  input: NewPollMapMarkerCacheRow,
): Record<string, unknown> => ({
  poll_id: input.poll_id,
  ...(input.markers_level1_json !== undefined
    ? { markers_level1_json: input.markers_level1_json }
    : null),
  ...(input.schema_version !== undefined
    ? { schema_version: input.schema_version }
    : null),
  ...(input.marker_count !== undefined ? { marker_count: input.marker_count } : null),
  ...(input.total_votes !== undefined ? { total_votes: input.total_votes } : null),
  ...(input.last_vote_submitted_at !== undefined
    ? { last_vote_submitted_at: input.last_vote_submitted_at }
    : null),
  ...(input.refreshed_at !== undefined ? { refreshed_at: input.refreshed_at } : null),
});

export const createPollMapMarkerCacheRepository = (
  dependencies: PollMapMarkerCacheRepositoryDependencies = {},
) => {
  const getSupabaseAdminClient =
    dependencies.getSupabaseAdminClient || requireSupabaseAdminClient;

  return {
    async getByPollId(pollId: string): Promise<PollMapMarkerCacheRow | null> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("poll_map_marker_cache")
        .select(POLL_MAP_MARKER_CACHE_COLUMNS)
        .eq("poll_id", pollId)
        .maybeSingle<PollMapMarkerCacheRow>();

      if (error) {
        throw error;
      }

      return data || null;
    },

    async listByPollIds(pollIds: string[]): Promise<PollMapMarkerCacheRow[]> {
      if (pollIds.length === 0) {
        return [];
      }

      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("poll_map_marker_cache")
        .select(POLL_MAP_MARKER_CACHE_COLUMNS)
        .in("poll_id", pollIds);

      if (error) {
        throw error;
      }

      return (data || []) as PollMapMarkerCacheRow[];
    },

    async upsertCacheRow(
      input: NewPollMapMarkerCacheRow,
    ): Promise<PollMapMarkerCacheRow> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("poll_map_marker_cache")
        .upsert(createUpsertPayload(input), {
          onConflict: "poll_id",
        })
        .select(POLL_MAP_MARKER_CACHE_COLUMNS)
        .single<PollMapMarkerCacheRow>();

      if (error) {
        throw error;
      }

      return data;
    },

    async deleteByPollId(pollId: string): Promise<boolean> {
      const supabase = getSupabaseAdminClient();

      const { error } = await supabase
        .from("poll_map_marker_cache")
        .delete()
        .eq("poll_id", pollId);

      if (error) {
        throw error;
      }

      return true;
    },
  };
};

export const pollMapMarkerCacheRepository = createPollMapMarkerCacheRepository();

export default pollMapMarkerCacheRepository;
