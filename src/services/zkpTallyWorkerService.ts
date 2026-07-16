import { randomUUID } from "node:crypto";
import { hostname } from "node:os";

import { env } from "../config/env";
import pollRepository from "../repositories/pollRepository";
import pollTallyProofRepository from "../repositories/pollTallyProofRepository";
import zkpTallyJobRepository from "../repositories/zkpTallyJobRepository";
import type { ZkpTallyJobRow } from "../types/db";
import groth16TallyProverService, {
  getGroth16TallyProverArtifactStatus,
} from "./groth16TallyProverService";
import pollPublicAuditService from "./pollPublicAuditService";

export type ZkpTallyWorkerCycleResult =
  | Readonly<{
      claimed: false;
      message: string;
    }>
  | Readonly<{
      claimed: true;
      jobId: string;
      pollId: string;
      status: "succeeded" | "failed" | "pending";
      message: string;
    }>;

export type ZkpTallyWorkerDependencies = Readonly<{
  repositoryLike?: Pick<
    typeof zkpTallyJobRepository,
    "claim" | "complete" | "fail" | "heartbeat"
  > &
    Partial<Pick<typeof zkpTallyJobRepository, "requeueRecoverableFailed">>;
  pollRepositoryLike?: Pick<
    typeof pollRepository,
    "getById" | "getOptionsByPollId"
  > &
    Partial<Pick<typeof pollRepository, "closeExpiredPolls" | "getByIdWithoutStatusRefresh">>;
  pollTallyProofRepositoryLike?: Pick<
    typeof pollTallyProofRepository,
    "getLatestByPollId"
  >;
  tallyProverLike?: Pick<typeof groth16TallyProverService, "generateProofForPoll">;
  publicAuditServiceLike?: Pick<typeof pollPublicAuditService, "submitTallyProof">;
  sleepFn?: (ms: number) => Promise<void>;
}>;

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

const truncateMessage = (value: string, maxLength = 1_000): string =>
  value.length > maxLength ? `${value.slice(0, maxLength)}...` : value;

const toErrorMessage = (error: unknown): string => {
  if (error instanceof Error) {
    return error.message;
  }

  if (error && typeof error === "object") {
    const record = error as Record<string, unknown>;
    const message = typeof record.message === "string" ? record.message : null;
    const code = typeof record.code === "string" ? record.code : null;
    const details = typeof record.details === "string" ? record.details : null;
    const hint = typeof record.hint === "string" ? record.hint : null;
    const parts = [
      code ? `code=${code}` : null,
      message,
      details ? `details=${details}` : null,
      hint ? `hint=${hint}` : null,
    ].filter(Boolean);
    if (parts.length > 0) {
      return parts.join("; ");
    }

    try {
      return JSON.stringify(error);
    } catch {
      return String(error);
    }
  }

  return String(error);
};

const withWorkerStep = async <T>(
  step: string,
  fn: () => Promise<T>,
): Promise<T> => {
  try {
    return await fn();
  } catch (error) {
    throw new Error(`${step} failed: ${toErrorMessage(error)}`);
  }
};

const classifyRetryable = (errorCode: string, message: string): boolean => {
  if (
    errorCode === "TALLY_PROOF_GENERATION_FAILED" ||
    errorCode === "TALLY_PROVER_UNCONFIGURED"
  ) {
    return true;
  }

  const normalized = message.toLowerCase();
  return (
    normalized.includes("sigkill") ||
    normalized.includes("timeout") ||
    normalized.includes("temporar") ||
    normalized.includes("network") ||
    normalized.includes("fetch")
  );
};

const RECOVERABLE_FAILED_JOB_ERROR_CODES = [
  "TALLY_PROVER_UNCONFIGURED",
  "TALLY_PROOF_GENERATION_FAILED",
] as const;

const failJob = async (input: {
  repository: Pick<typeof zkpTallyJobRepository, "fail">;
  job: ZkpTallyJobRow;
  workerId: string;
  errorCode: string;
  message: string;
  retryable: boolean;
}): Promise<ZkpTallyJobRow> =>
  input.repository.fail({
    jobId: input.job.id,
    workerId: input.workerId,
    errorCode: input.errorCode,
    errorMessage: truncateMessage(input.message),
    retryAfterSeconds: Math.ceil(env.zkp.tallyWorker.retryDelayMs / 1_000),
    retryable: input.retryable,
  });

export const createZkpTallyWorkerService = (
  dependencies: ZkpTallyWorkerDependencies = {},
) => {
  const repository = dependencies.repositoryLike ?? zkpTallyJobRepository;
  const polls = dependencies.pollRepositoryLike ?? pollRepository;
  const tallyProofs =
    dependencies.pollTallyProofRepositoryLike ?? pollTallyProofRepository;
  const tallyProver =
    dependencies.tallyProverLike ?? groth16TallyProverService;
  const publicAudit =
    dependencies.publicAuditServiceLike ?? pollPublicAuditService;
  const sleepImpl = dependencies.sleepFn ?? sleep;
  const workerId =
    env.zkp.tallyWorker.workerId ||
    `iland-zkp-tally-worker:${hostname()}:${process.pid}:${randomUUID()}`;

  const heartbeat = async (input: {
    status: "starting" | "running" | "idle" | "stopping" | "stopped" | "error";
    currentJobId?: string | null;
    message?: string | null;
  }): Promise<void> => {
    await repository.heartbeat({
      workerId,
      host: hostname(),
      status: input.status,
      currentJobId: input.currentJobId ?? null,
      message: input.message ?? null,
    });
  };

  return {
    workerId,

    async requeueRecoverableFailedJobs(): Promise<ZkpTallyJobRow[]> {
      const requeueRecoverableFailed = repository.requeueRecoverableFailed;
      if (!requeueRecoverableFailed) {
        return [];
      }

      return withWorkerStep("requeue recoverable failed tally jobs", () =>
        requeueRecoverableFailed({
          errorCodes: [...RECOVERABLE_FAILED_JOB_ERROR_CODES],
          maxAttempts: env.zkp.tallyWorker.maxAttempts,
          limit: 25,
        }),
      );
    },

    async processNextJob(): Promise<ZkpTallyWorkerCycleResult> {
      try {
        await polls.closeExpiredPolls?.();
      } catch (error) {
        console.warn("[zkpTallyWorker] closeExpiredPolls failed; continuing", {
          message: toErrorMessage(error),
        });
      }

      const job = await withWorkerStep("claim_zkp_tally_job", () =>
        repository.claim({
          workerId,
          lockTimeoutSeconds: Math.ceil(env.zkp.tallyWorker.lockTimeoutMs / 1_000),
        }),
      );

      if (!job) {
        await withWorkerStep("heartbeat idle", () =>
          heartbeat({
            status: "idle",
            message: "No pending ZKP tally jobs.",
          }),
        );
        return {
          claimed: false,
          message: "No pending ZKP tally jobs.",
        };
      }

      await withWorkerStep("heartbeat running", () =>
        heartbeat({
          status: "running",
          currentJobId: job.id,
          message: `Processing poll ${job.poll_id}.`,
        }),
      );

      const loadPollById = polls.getByIdWithoutStatusRefresh ?? polls.getById;
      const poll = await withWorkerStep("load poll", () =>
        loadPollById(job.poll_id),
      );
      if (!poll) {
        const failed = await failJob({
          repository,
          job,
          workerId,
          errorCode: "POLL_NOT_FOUND",
          message: "The queued poll no longer exists.",
          retryable: false,
        });
        return {
          claimed: true,
          jobId: job.id,
          pollId: job.poll_id,
          status: failed.status === "failed" ? "failed" : "pending",
          message: "The queued poll no longer exists.",
        };
      }

      if (!poll.created_by_user_id) {
        const failed = await failJob({
          repository,
          job,
          workerId,
          errorCode: "POLL_OWNER_MISSING",
          message: "Poll owner is missing; worker cannot submit tally proof.",
          retryable: false,
        });
        return {
          claimed: true,
          jobId: job.id,
          pollId: poll.id,
          status: failed.status === "failed" ? "failed" : "pending",
          message: "Poll owner is missing.",
        };
      }

      const existingTallyProof = await tallyProofs.getLatestByPollId(poll.id);
      if (existingTallyProof) {
        const completed = await repository.complete({
          jobId: job.id,
          workerId,
          proofPublicInputsHash: existingTallyProof.tally_public_inputs_hash,
          tallyProofHash: existingTallyProof.tally_proof_hash,
          resultHash: existingTallyProof.result_hash,
        });
        return {
          claimed: true,
          jobId: completed.id,
          pollId: completed.poll_id,
          status: "succeeded",
          message: "Verified tally proof was already recorded; final publication is delegated to the main backend.",
        };
      }

      const options = await polls.getOptionsByPollId(poll.id);
      const generated = await tallyProver.generateProofForPoll({
        poll,
        options,
      });
      if (!generated.success) {
        const failed = await failJob({
          repository,
          job,
          workerId,
          errorCode: generated.errorCode,
          message: generated.message,
          retryable: classifyRetryable(generated.errorCode, generated.message),
        });
        return {
          claimed: true,
          jobId: job.id,
          pollId: poll.id,
          status: failed.status === "failed" ? "failed" : "pending",
          message: generated.message,
        };
      }

      const submitted = await publicAudit.submitTallyProof({
        pollId: poll.id,
        viewerUserId: poll.created_by_user_id,
        proof: generated.proof,
      });
      if (!submitted.success) {
        const failed = await failJob({
          repository,
          job,
          workerId,
          errorCode: submitted.errorCode,
          message: submitted.message,
          retryable: classifyRetryable(submitted.errorCode, submitted.message),
        });
        return {
          claimed: true,
          jobId: job.id,
          pollId: poll.id,
          status: failed.status === "failed" ? "failed" : "pending",
          message: submitted.message,
        };
      }

      const completed = await repository.complete({
        jobId: job.id,
        workerId,
        proofPublicInputsHash: submitted.tallyProof.tallyPublicInputsHash,
        tallyProofHash: submitted.tallyProof.tallyProofHash,
        resultHash: submitted.tallyProof.resultHash,
      });

      await heartbeat({
        status: "idle",
        message: `Completed tally proof for poll ${poll.id}.`,
      });

      return {
        claimed: true,
        jobId: completed.id,
        pollId: completed.poll_id,
        status: "succeeded",
        message: "Tally proof was verified and recorded; final publication is delegated to the main backend.",
      };
    },

    async startLoop(): Promise<void> {
      if (!env.zkp.tallyWorker.enabled) {
        throw new Error("ZKP_TALLY_WORKER_ENABLED must be true for the worker.");
      }
      if (env.zkp.tallyWorker.proverMode !== "worker") {
        throw new Error("ZKP_TALLY_PROVER_MODE must be worker for the worker.");
      }
      if (!env.supabase.enabled) {
        throw new Error(
          "ZKP tally worker requires SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY. Copy both variables into the Railway worker service.",
        );
      }
      const tallyProverStatus = getGroth16TallyProverArtifactStatus();
      if (!tallyProverStatus.configured) {
        throw new Error(
          `ZKP tally worker prover is not configured: ${
            tallyProverStatus.message ?? "unknown artifact/configuration error"
          }`,
        );
      }

      let stopping = false;
      const stop = async (signal: NodeJS.Signals) => {
        if (stopping) {
          return;
        }
        stopping = true;
        console.info(`[zkpTallyWorker] received ${signal}; stopping`);
        try {
          await heartbeat({
            status: "stopping",
            message: `Received ${signal}; stopping after current cycle.`,
          });
        } catch (error) {
          console.warn("[zkpTallyWorker] heartbeat during stop failed", {
            message: toErrorMessage(error),
          });
        }
      };

      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);

      await heartbeat({
        status: "starting",
        message: "ZKP tally worker starting.",
      });

      const requeued = await this.requeueRecoverableFailedJobs();
      if (requeued.length > 0) {
        console.info("[zkpTallyWorker] requeued recoverable failed jobs", {
          count: requeued.length,
          pollIds: requeued.map((job) => job.poll_id),
          errorCodes: [...RECOVERABLE_FAILED_JOB_ERROR_CODES],
        });
      }

      console.info("[zkpTallyWorker] started", {
        workerId,
        pollIntervalMs: env.zkp.tallyWorker.pollIntervalMs,
        lockTimeoutMs: env.zkp.tallyWorker.lockTimeoutMs,
      });

      while (!stopping) {
        try {
          const result = await this.processNextJob();
          if (result.claimed) {
            console.info("[zkpTallyWorker] processed job", result);
          }
        } catch (error) {
          console.error("[zkpTallyWorker] cycle failed", {
            message: toErrorMessage(error),
          });
          try {
            await heartbeat({
              status: "error",
              message: truncateMessage(toErrorMessage(error)),
            });
          } catch {
            // Keep the worker alive even if the heartbeat table is temporarily unavailable.
          }
        }

        if (!stopping) {
          await sleepImpl(env.zkp.tallyWorker.pollIntervalMs);
        }
      }

      await heartbeat({
        status: "stopped",
        message: "ZKP tally worker stopped.",
      });
      console.info("[zkpTallyWorker] stopped", { workerId });
    },
  };
};

export const zkpTallyWorkerService = createZkpTallyWorkerService();

export default zkpTallyWorkerService;
