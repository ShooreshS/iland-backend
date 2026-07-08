import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  NewPollAuditEventRow,
  NewPollRootRow,
  PollAuditEventRow,
  PollRootRow,
} from "../types/db";

const POLL_ROOT_COLUMNS =
  "id,poll_id,batch_id,previous_nullifier_root,nullifier_root,previous_vote_commitment_root,vote_commitment_root,previous_encrypted_vote_root,encrypted_vote_root,accepted_count,solana_tx_signature,created_at";
const POLL_AUDIT_EVENT_COLUMNS =
  "id,poll_id,event_type,payload_hash,payload_json,solana_tx_signature,created_at";

export const pollAuditRepository = {
  async listRootsByPollId(pollId: string): Promise<PollRootRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_roots")
      .select(POLL_ROOT_COLUMNS)
      .eq("poll_id", pollId)
      .order("created_at", { ascending: true });

    if (error) {
      throw error;
    }

    return (data || []) as PollRootRow[];
  },

  async getRootByPollIdAndBatchId(
    pollId: string,
    batchId: string,
  ): Promise<PollRootRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_roots")
      .select(POLL_ROOT_COLUMNS)
      .eq("poll_id", pollId)
      .eq("batch_id", batchId)
      .maybeSingle<PollRootRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insertRoot(input: NewPollRootRow): Promise<PollRootRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_roots")
      .insert({
        poll_id: input.poll_id,
        batch_id: input.batch_id,
        previous_nullifier_root: input.previous_nullifier_root ?? null,
        nullifier_root: input.nullifier_root,
        previous_vote_commitment_root: input.previous_vote_commitment_root ?? null,
        vote_commitment_root: input.vote_commitment_root,
        previous_encrypted_vote_root: input.previous_encrypted_vote_root ?? null,
        encrypted_vote_root: input.encrypted_vote_root,
        accepted_count: input.accepted_count,
        solana_tx_signature: input.solana_tx_signature ?? null,
      })
      .select(POLL_ROOT_COLUMNS)
      .single<PollRootRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async insertAuditEvent(
    input: NewPollAuditEventRow,
  ): Promise<PollAuditEventRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_audit_events")
      .insert({
        poll_id: input.poll_id ?? null,
        event_type: input.event_type,
        payload_hash: input.payload_hash,
        payload_json: input.payload_json ?? null,
        solana_tx_signature: input.solana_tx_signature ?? null,
      })
      .select(POLL_AUDIT_EVENT_COLUMNS)
      .single<PollAuditEventRow>();

    if (error) {
      throw error;
    }

    return data;
  },
};

export default pollAuditRepository;
