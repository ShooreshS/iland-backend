import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type { PollMapRefreshQueueRow } from "../types/db";

const POLL_MAP_REFRESH_QUEUE_COLUMNS =
  "poll_id,pending_vote_events,first_enqueued_at,last_enqueued_at,last_processed_at,last_error,created_at,updated_at";

type ListPollMapRefreshCandidatesInput = {
  limit?: number;
  minPendingVoteEvents?: number;
};

type PollMapRefreshQueueRepositoryDependencies = {
  getSupabaseAdminClient?: () => ReturnType<typeof requireSupabaseAdminClient>;
};

const getByPollIdInternal = async (
  getSupabaseAdminClient: () => ReturnType<typeof requireSupabaseAdminClient>,
  pollId: string,
): Promise<PollMapRefreshQueueRow | null> => {
  const supabase = getSupabaseAdminClient();

  const { data, error } = await supabase
    .from("poll_map_refresh_queue")
    .select(POLL_MAP_REFRESH_QUEUE_COLUMNS)
    .eq("poll_id", pollId)
    .maybeSingle<PollMapRefreshQueueRow>();

  if (error) {
    throw error;
  }

  return data || null;
};

export const createPollMapRefreshQueueRepository = (
  dependencies: PollMapRefreshQueueRepositoryDependencies = {},
) => {
  const getSupabaseAdminClient =
    dependencies.getSupabaseAdminClient || requireSupabaseAdminClient;

  return {
    async enqueuePoll(pollId: string): Promise<PollMapRefreshQueueRow> {
      const supabase = getSupabaseAdminClient();

      const { error } = await supabase.rpc("enqueue_poll_map_refresh", {
        p_poll_id: pollId,
      });

      if (error) {
        throw error;
      }

      const queuedRow = await getByPollIdInternal(getSupabaseAdminClient, pollId);
      if (!queuedRow) {
        throw new Error("Failed to load poll map refresh queue row after enqueue.");
      }

      return queuedRow;
    },

    async getByPollId(pollId: string): Promise<PollMapRefreshQueueRow | null> {
      return getByPollIdInternal(getSupabaseAdminClient, pollId);
    },

    async listCandidates(
      input: ListPollMapRefreshCandidatesInput = {},
    ): Promise<PollMapRefreshQueueRow[]> {
      const resolvedMinPendingVoteEvents =
        input.minPendingVoteEvents !== undefined
          ? Math.max(0, Math.trunc(input.minPendingVoteEvents))
          : 1;
      const resolvedLimit =
        input.limit !== undefined ? Math.max(1, Math.trunc(input.limit)) : 100;

      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("poll_map_refresh_queue")
        .select(POLL_MAP_REFRESH_QUEUE_COLUMNS)
        .gte("pending_vote_events", resolvedMinPendingVoteEvents)
        .order("first_enqueued_at", { ascending: true })
        .order("last_enqueued_at", { ascending: true })
        .limit(resolvedLimit);

      if (error) {
        throw error;
      }

      return (data || []) as PollMapRefreshQueueRow[];
    },

    async ackPoll(pollId: string): Promise<PollMapRefreshQueueRow | null> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("poll_map_refresh_queue")
        .update({
          pending_vote_events: 0,
          last_processed_at: new Date().toISOString(),
          last_error: null,
        })
        .eq("poll_id", pollId)
        .select(POLL_MAP_REFRESH_QUEUE_COLUMNS)
        .maybeSingle<PollMapRefreshQueueRow>();

      if (error) {
        throw error;
      }

      return data || null;
    },

    async failPoll(
      pollId: string,
      errorMessage: string,
    ): Promise<PollMapRefreshQueueRow | null> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("poll_map_refresh_queue")
        .update({
          last_error: errorMessage,
        })
        .eq("poll_id", pollId)
        .select(POLL_MAP_REFRESH_QUEUE_COLUMNS)
        .maybeSingle<PollMapRefreshQueueRow>();

      if (error) {
        throw error;
      }

      return data || null;
    },
  };
};

export const pollMapRefreshQueueRepository =
  createPollMapRefreshQueueRepository();

export default pollMapRefreshQueueRepository;
