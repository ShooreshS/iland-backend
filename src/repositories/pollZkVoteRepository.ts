import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type { NewPollZkVoteRow, PollZkVoteRow } from "../types/db";

const POLL_ZK_VOTE_COLUMNS =
  "id,poll_id,nullifier,vote_commitment,encrypted_vote,encrypted_vote_hash,encrypted_vote_commitment,proof_hash,proof_system_version,verification_method_version,proof_verification_status,proof_public_inputs_json,proof_envelope_hash,verifier_key_hash,circuit_id,accepted_at,batch_id,created_at";

export type PublicZkAuditVoteRecordRow = Pick<
  PollZkVoteRow,
  | "id"
  | "poll_id"
  | "nullifier"
  | "vote_commitment"
  | "encrypted_vote_hash"
  | "encrypted_vote_commitment"
  | "proof_hash"
  | "accepted_at"
  | "batch_id"
  | "created_at"
>;

export const pollZkVoteRepository = {
  async getByPollIdAndNullifier(
    pollId: string,
    nullifier: string,
  ): Promise<PollZkVoteRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_zk_votes")
      .select(POLL_ZK_VOTE_COLUMNS)
      .eq("poll_id", pollId)
      .eq("nullifier", nullifier)
      .maybeSingle<PollZkVoteRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insertVerified(input: NewPollZkVoteRow): Promise<PollZkVoteRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_zk_votes")
      .insert({
        poll_id: input.poll_id,
        nullifier: input.nullifier,
        vote_commitment: input.vote_commitment,
        encrypted_vote: input.encrypted_vote,
        encrypted_vote_hash: input.encrypted_vote_hash,
        encrypted_vote_commitment: input.encrypted_vote_commitment,
        proof_hash: input.proof_hash,
        proof_system_version: input.proof_system_version,
        verification_method_version: input.verification_method_version,
        proof_verification_status: input.proof_verification_status ?? "verified",
        proof_public_inputs_json: input.proof_public_inputs_json,
        proof_envelope_hash: input.proof_envelope_hash,
        verifier_key_hash: input.verifier_key_hash,
        circuit_id: input.circuit_id,
        accepted_at: input.accepted_at ?? new Date().toISOString(),
        batch_id: input.batch_id ?? null,
      })
      .select(POLL_ZK_VOTE_COLUMNS)
      .single<PollZkVoteRow>();

    if (error) {
      throw error;
    }

    return data;
  },

  async getAcceptedAuditRecordsByPollId(
    pollId: string,
  ): Promise<PublicZkAuditVoteRecordRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_zk_votes")
      .select(
        "id,poll_id,nullifier,vote_commitment,encrypted_vote_hash,encrypted_vote_commitment,proof_hash,accepted_at,batch_id,created_at",
      )
      .eq("poll_id", pollId)
      .eq("proof_verification_status", "verified")
      .order("accepted_at", { ascending: true })
      .order("id", { ascending: true });

    if (error) {
      throw error;
    }

    return (data || []) as PublicZkAuditVoteRecordRow[];
  },

  async getAcceptedByPollId(pollId: string): Promise<PollZkVoteRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_zk_votes")
      .select(POLL_ZK_VOTE_COLUMNS)
      .eq("poll_id", pollId)
      .eq("proof_verification_status", "verified")
      .order("accepted_at", { ascending: true })
      .order("id", { ascending: true });

    if (error) {
      throw error;
    }

    return (data || []) as PollZkVoteRow[];
  },

  async markAcceptedAuditRecordsBatch(input: {
    pollId: string;
    batchId: string;
    recordIds?: readonly string[];
  }): Promise<void> {
    const supabase = requireSupabaseAdminClient();

    let query = supabase
      .from("poll_zk_votes")
      .update({ batch_id: input.batchId })
      .eq("poll_id", input.pollId)
      .eq("proof_verification_status", "verified")
      .is("batch_id", null);
    if (input.recordIds) {
      query = query.in("id", [...input.recordIds]);
    }

    const { error } = await query;

    if (error) {
      throw error;
    }
  },

  async countAcceptedByPollId(pollId: string): Promise<number> {
    const supabase = requireSupabaseAdminClient();

    const { count, error } = await supabase
      .from("poll_zk_votes")
      .select("id", { head: true, count: "exact" })
      .eq("poll_id", pollId)
      .eq("proof_verification_status", "verified");

    if (error) {
      throw error;
    }

    return count || 0;
  },

  async countAcceptedByPollIds(pollIds: string[]): Promise<number> {
    if (pollIds.length === 0) {
      return 0;
    }

    const supabase = requireSupabaseAdminClient();

    const { count, error } = await supabase
      .from("poll_zk_votes")
      .select("id", { head: true, count: "exact" })
      .in("poll_id", pollIds)
      .eq("proof_verification_status", "verified");

    if (error) {
      throw error;
    }

    return count || 0;
  },
};

export default pollZkVoteRepository;
