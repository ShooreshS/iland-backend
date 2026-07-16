import { randomUUID } from "node:crypto";
import { hostname } from "node:os";

import { env } from "../config/env";
import pollRepository from "../repositories/pollRepository";
import pollTallyProofRepository from "../repositories/pollTallyProofRepository";
import zkpTallyJobRepository from "../repositories/zkpTallyJobRepository";
import type { ZkpTallyJobRow } from "../types/db";
import groth16TallyProverService from "./groth16TallyProverService";
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
  >;
  pollRepositoryLike?: Pick<
    typeof pollRepository,
    "getById" | "getOptionsByPollId"
  > &
    Partial<Pick<typeof pollRepository, "closeExpiredPolls">>;
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

const toErrorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

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

    async processNextJob(): Promise<ZkpTallyWorkerCycleResult> {
      await polls.closeExpiredPolls?.();

      const job = await repository.claim({
        workerId,
        lockTimeoutSeconds: Math.ceil(env.zkp.tallyWorker.lockTimeoutMs / 1_000),
      });

      if (!job) {
        await heartbeat({
          status: "idle",
          message: "No pending ZKP tally jobs.",
        });
        return {
          claimed: false,
          message: "No pending ZKP tally jobs.",
        };
      }

      await heartbeat({
        status: "running",
        currentJobId: job.id,
        message: `Processing poll ${job.poll_id}.`,
      });

      const poll = await polls.getById(job.poll_id);
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
