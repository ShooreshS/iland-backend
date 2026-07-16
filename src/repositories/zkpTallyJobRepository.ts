import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  ZkpTallyJobRow,
  ZkpTallyJobStatus,
  ZkpTallyWorkerHeartbeatRow,
  ZkpTallyWorkerHeartbeatStatus,
} from "../types/db";

const ZKP_TALLY_JOB_COLUMNS =
  "id,poll_id,status,priority,attempts,max_attempts,locked_by,locked_at,next_attempt_at,proof_public_inputs_hash,tally_proof_hash,result_hash,error_code,error_message,created_at,updated_at";

const ZKP_TALLY_WORKER_HEARTBEAT_COLUMNS =
  "worker_id,host,status,current_job_id,message,first_seen_at,last_seen_at";

export type ZkpTallyQueueStatusCounts = Record<ZkpTallyJobStatus, number>;

const EMPTY_COUNTS: ZkpTallyQueueStatusCounts = {
  pending: 0,
  running: 0,
  succeeded: 0,
  failed: 0,
  cancelled: 0,
};

const toRpcRow = (data: unknown): ZkpTallyJobRow | null => {
  if (Array.isArray(data)) {
    return toRpcRow(data[0]);
  }

  if (!data || typeof data !== "object") {
    return null;
  }
  return data as ZkpTallyJobRow;
};

export const zkpTallyJobRepository = {
  async enqueue(input: {
    pollId: string;
    priority?: number;
    maxAttempts?: number;
  }): Promise<ZkpTallyJobRow> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase.rpc("enqueue_zkp_tally_job", {
      p_poll_id: input.pollId,
      p_priority: input.priority ?? 100,
      p_max_attempts: input.maxAttempts ?? 3,
    });

    if (error) {
      throw error;
    }

    const row = toRpcRow(data);
    if (!row) {
      throw new Error("Tally job enqueue did not return a row.");
    }
    return row;
  },

  async claim(input: {
    workerId: string;
    lockTimeoutSeconds: number;
  }): Promise<ZkpTallyJobRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase.rpc("claim_zkp_tally_job", {
      p_worker_id: input.workerId,
      p_lock_timeout_seconds: input.lockTimeoutSeconds,
    });

    if (error) {
      throw error;
    }

    return toRpcRow(data);
  },

  async complete(input: {
    jobId: string;
    workerId: string;
    proofPublicInputsHash: string;
    tallyProofHash: string;
    resultHash: string;
  }): Promise<ZkpTallyJobRow> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase.rpc("complete_zkp_tally_job", {
      p_job_id: input.jobId,
      p_worker_id: input.workerId,
      p_proof_public_inputs_hash: input.proofPublicInputsHash,
      p_tally_proof_hash: input.tallyProofHash,
      p_result_hash: input.resultHash,
    });

    if (error) {
      throw error;
    }

    const row = toRpcRow(data);
    if (!row) {
      throw new Error("Tally job completion did not update a running job.");
    }
    return row;
  },

  async fail(input: {
    jobId: string;
    workerId: string;
    errorCode: string;
    errorMessage: string;
    retryAfterSeconds: number;
    retryable: boolean;
  }): Promise<ZkpTallyJobRow> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase.rpc("fail_zkp_tally_job", {
      p_job_id: input.jobId,
      p_worker_id: input.workerId,
      p_error_code: input.errorCode,
      p_error_message: input.errorMessage,
      p_retry_after_seconds: input.retryAfterSeconds,
      p_retryable: input.retryable,
    });

    if (error) {
      throw error;
    }

    const row = toRpcRow(data);
    if (!row) {
      throw new Error("Tally job failure did not update a running job.");
    }
    return row;
  },

  async getLatestByPollId(pollId: string): Promise<ZkpTallyJobRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("zkp_tally_jobs")
      .select(ZKP_TALLY_JOB_COLUMNS)
      .eq("poll_id", pollId)
      .order("updated_at", { ascending: false })
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle<ZkpTallyJobRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getQueueCounts(): Promise<ZkpTallyQueueStatusCounts> {
    const supabase = requireSupabaseAdminClient();
    const counts = { ...EMPTY_COUNTS };

    await Promise.all(
      (Object.keys(counts) as ZkpTallyJobStatus[]).map(async (status) => {
        const { count, error } = await supabase
          .from("zkp_tally_jobs")
          .select("id", { count: "exact", head: true })
          .eq("status", status);

        if (error) {
          throw error;
        }

        counts[status] = count ?? 0;
      }),
    );

    return counts;
  },

  async getOldestPendingJob(): Promise<ZkpTallyJobRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("zkp_tally_jobs")
      .select(ZKP_TALLY_JOB_COLUMNS)
      .eq("status", "pending")
      .order("created_at", { ascending: true })
      .limit(1)
      .maybeSingle<ZkpTallyJobRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async heartbeat(input: {
    workerId: string;
    host?: string | null;
    status: ZkpTallyWorkerHeartbeatStatus;
    currentJobId?: string | null;
    message?: string | null;
  }): Promise<ZkpTallyWorkerHeartbeatRow> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase.rpc("heartbeat_zkp_tally_worker", {
      p_worker_id: input.workerId,
      p_host: input.host ?? null,
      p_status: input.status,
      p_current_job_id: input.currentJobId ?? null,
      p_message: input.message ?? null,
    });

    if (error) {
      throw error;
    }

    const row = Array.isArray(data) ? data[0] : data;
    if (!row || typeof row !== "object") {
      throw new Error("Tally worker heartbeat did not return a row.");
    }
    return row as ZkpTallyWorkerHeartbeatRow;
  },

  async getLatestHeartbeat(): Promise<ZkpTallyWorkerHeartbeatRow | null> {
    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("zkp_tally_worker_heartbeats")
      .select(ZKP_TALLY_WORKER_HEARTBEAT_COLUMNS)
      .order("last_seen_at", { ascending: false })
      .limit(1)
      .maybeSingle<ZkpTallyWorkerHeartbeatRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },
};

export default zkpTallyJobRepository;
