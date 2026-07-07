import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type { NewPollTallyProofRow, PollTallyProofRow } from "../types/db";

const POLL_TALLY_PROOF_COLUMNS =
  "id,poll_id,result_hash,tally_proof_hash,tally_public_inputs_hash,tally_verifier_key_hash,tally_circuit_id,nullifier_root,vote_commitment_root,encrypted_vote_root,accepted_count,proof_envelope_json,verified_at,created_at";

export const pollTallyProofRepository = {
  async listByPollId(pollId: string): Promise<PollTallyProofRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_tally_proofs")
      .select(POLL_TALLY_PROOF_COLUMNS)
      .eq("poll_id", pollId)
      .order("created_at", { ascending: true });

    if (error) {
      throw error;
    }

    return (data || []) as PollTallyProofRow[];
  },

  async getLatestByPollId(pollId: string): Promise<PollTallyProofRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_tally_proofs")
      .select(POLL_TALLY_PROOF_COLUMNS)
      .eq("poll_id", pollId)
      .order("created_at", { ascending: false })
      .order("id", { ascending: false })
      .limit(1)
      .maybeSingle<PollTallyProofRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insertVerified(input: NewPollTallyProofRow): Promise<PollTallyProofRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_tally_proofs")
      .insert({
        poll_id: input.poll_id,
        result_hash: input.result_hash,
        tally_proof_hash: input.tally_proof_hash,
        tally_public_inputs_hash: input.tally_public_inputs_hash,
        tally_verifier_key_hash: input.tally_verifier_key_hash,
        tally_circuit_id: input.tally_circuit_id,
        nullifier_root: input.nullifier_root,
        vote_commitment_root: input.vote_commitment_root,
        encrypted_vote_root: input.encrypted_vote_root,
        accepted_count: input.accepted_count,
        proof_envelope_json: input.proof_envelope_json,
        verified_at: input.verified_at ?? new Date().toISOString(),
      })
      .select(POLL_TALLY_PROOF_COLUMNS)
      .single<PollTallyProofRow>();

    if (error) {
      throw error;
    }

    return data;
  },
};

export default pollTallyProofRepository;
