import { env } from "../config/env";
import zkpTallyJobRepository, {
  type ZkpTallyQueueStatusCounts,
} from "../repositories/zkpTallyJobRepository";
import type {
  PublicAuditTallyJobDto,
  PublicAuditTallyProofStatus,
} from "../types/contracts";
import type {
  ZkpTallyJobRow,
  ZkpTallyWorkerHeartbeatRow,
} from "../types/db";

export type ZkpTallyJobServiceDependencies = Readonly<{
  repositoryLike?: Pick<
    typeof zkpTallyJobRepository,
    | "enqueue"
    | "getLatestByPollId"
    | "getQueueCounts"
    | "getOldestPendingJob"
    | "getLatestHeartbeat"
  >;
  nowMsFn?: () => number;
}>;

export type ZkpTallyQueueHealth = Readonly<{
  configured: boolean;
  proverMode: "inline" | "worker" | "disabled";
  workerEnabled: boolean;
  workerRequiredForProduction: boolean;
  concurrency: number;
  pollIntervalMs: number;
  lockTimeoutMs: number;
  maxAttempts: number;
  retryDelayMs: number;
  heartbeatStaleMs: number;
  queueCounts: ZkpTallyQueueStatusCounts | null;
  oldestPendingJobAgeMs: number | null;
  latestHeartbeat: ZkpTallyWorkerHeartbeatRow | null;
  latestHeartbeatAgeMs: number | null;
  workerHeartbeatFresh: boolean | null;
  message: string | null;
}>;

const sanitizeErrorMessage = (value: string | null): string | null => {
  if (!value) {
    return null;
  }

  return value.length > 300 ? `${value.slice(0, 300)}...` : value;
};

const toTimestampMs = (value: string | null | undefined): number | null => {
  if (!value) {
    return null;
  }

  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
};

export const mapZkpTallyJobToPublicDto = (
  job: ZkpTallyJobRow | null,
): PublicAuditTallyJobDto | null =>
  job
    ? {
        status: job.status,
        attempts: Math.max(0, Math.trunc(job.attempts)),
        maxAttempts: Math.max(1, Math.trunc(job.max_attempts)),
        nextAttemptAt: job.next_attempt_at ?? null,
        updatedAt: job.updated_at,
        errorCode: job.error_code,
        errorMessage: sanitizeErrorMessage(job.error_message),
      }
    : null;

export const resolvePublicTallyProofStatus = (input: {
  productionPoll: boolean;
  finalResultPublishable: boolean;
  acceptedVoteCount: number;
  hasVerifiedTallyProof: boolean;
  job: ZkpTallyJobRow | null;
}): PublicAuditTallyProofStatus => {
  if (
    !input.productionPoll ||
    !input.finalResultPublishable ||
    input.acceptedVoteCount <= 0
  ) {
    return "not_required";
  }

  if (input.hasVerifiedTallyProof) {
    return "verified";
  }

  if (input.job?.status === "running") {
    return "running";
  }

  if (input.job?.status === "failed" || input.job?.status === "cancelled") {
    return "failed";
  }

  return "pending";
};

export const createZkpTallyJobService = (
  dependencies: ZkpTallyJobServiceDependencies = {},
) => {
  const repository = dependencies.repositoryLike ?? zkpTallyJobRepository;
  const nowMs = dependencies.nowMsFn ?? (() => Date.now());

  return {
    async enqueueForPoll(input: {
      pollId: string;
      priority?: number;
    }): Promise<ZkpTallyJobRow> {
      return repository.enqueue({
        pollId: input.pollId,
        priority: input.priority ?? 100,
        maxAttempts: env.zkp.tallyWorker.maxAttempts,
      });
    },

    async getLatestPublicJobForPoll(
      pollId: string,
    ): Promise<PublicAuditTallyJobDto | null> {
      if (env.zkp.tallyWorker.proverMode !== "worker") {
        return null;
      }

      return mapZkpTallyJobToPublicDto(
        await repository.getLatestByPollId(pollId),
      );
    },

    async getLatestJobForPoll(pollId: string): Promise<ZkpTallyJobRow | null> {
      if (env.zkp.tallyWorker.proverMode !== "worker") {
        return null;
      }

      return repository.getLatestByPollId(pollId);
    },

    async getQueueHealth(): Promise<ZkpTallyQueueHealth> {
      if (env.zkp.tallyWorker.proverMode !== "worker") {
        return {
          configured: true,
          proverMode: env.zkp.tallyWorker.proverMode,
          workerEnabled: env.zkp.tallyWorker.enabled,
          workerRequiredForProduction:
            env.zkp.tallyWorker.requiredForProduction,
          concurrency: env.zkp.tallyWorker.concurrency,
          pollIntervalMs: env.zkp.tallyWorker.pollIntervalMs,
          lockTimeoutMs: env.zkp.tallyWorker.lockTimeoutMs,
          maxAttempts: env.zkp.tallyWorker.maxAttempts,
          retryDelayMs: env.zkp.tallyWorker.retryDelayMs,
          heartbeatStaleMs: env.zkp.tallyWorker.heartbeatStaleMs,
          queueCounts: null,
          oldestPendingJobAgeMs: null,
          latestHeartbeat: null,
          latestHeartbeatAgeMs: null,
          workerHeartbeatFresh: null,
          message: "Tally worker queue is inactive outside worker prover mode.",
        };
      }

      try {
        const [queueCounts, oldestPendingJob, latestHeartbeat] =
          await Promise.all([
            repository.getQueueCounts(),
            repository.getOldestPendingJob(),
            repository.getLatestHeartbeat(),
          ]);
        const now = nowMs();
        const oldestPendingCreatedAtMs = toTimestampMs(
          oldestPendingJob?.created_at,
        );
        const latestHeartbeatMs = toTimestampMs(latestHeartbeat?.last_seen_at);
        const latestHeartbeatAgeMs =
          latestHeartbeatMs === null ? null : Math.max(0, now - latestHeartbeatMs);
        const workerHeartbeatFresh =
          latestHeartbeatAgeMs === null
            ? false
            : latestHeartbeatAgeMs <= env.zkp.tallyWorker.heartbeatStaleMs;

        return {
          configured: true,
          proverMode: env.zkp.tallyWorker.proverMode,
          workerEnabled: env.zkp.tallyWorker.enabled,
          workerRequiredForProduction:
            env.zkp.tallyWorker.requiredForProduction,
          concurrency: env.zkp.tallyWorker.concurrency,
          pollIntervalMs: env.zkp.tallyWorker.pollIntervalMs,
          lockTimeoutMs: env.zkp.tallyWorker.lockTimeoutMs,
          maxAttempts: env.zkp.tallyWorker.maxAttempts,
          retryDelayMs: env.zkp.tallyWorker.retryDelayMs,
          heartbeatStaleMs: env.zkp.tallyWorker.heartbeatStaleMs,
          queueCounts,
          oldestPendingJobAgeMs:
            oldestPendingCreatedAtMs === null
              ? null
              : Math.max(0, now - oldestPendingCreatedAtMs),
          latestHeartbeat,
          latestHeartbeatAgeMs,
          workerHeartbeatFresh,
          message: workerHeartbeatFresh
            ? null
            : "No recent ZKP tally worker heartbeat was found.",
        };
      } catch (error) {
        return {
          configured: false,
          proverMode: env.zkp.tallyWorker.proverMode,
          workerEnabled: env.zkp.tallyWorker.enabled,
          workerRequiredForProduction:
            env.zkp.tallyWorker.requiredForProduction,
          concurrency: env.zkp.tallyWorker.concurrency,
          pollIntervalMs: env.zkp.tallyWorker.pollIntervalMs,
          lockTimeoutMs: env.zkp.tallyWorker.lockTimeoutMs,
          maxAttempts: env.zkp.tallyWorker.maxAttempts,
          retryDelayMs: env.zkp.tallyWorker.retryDelayMs,
          heartbeatStaleMs: env.zkp.tallyWorker.heartbeatStaleMs,
          queueCounts: null,
          oldestPendingJobAgeMs: null,
          latestHeartbeat: null,
          latestHeartbeatAgeMs: null,
          workerHeartbeatFresh: false,
          message:
            error instanceof Error
              ? error.message
              : "ZKP tally worker queue health could not be loaded.",
        };
      }
    },
  };
};

export const zkpTallyJobService = createZkpTallyJobService();

export default zkpTallyJobService;
