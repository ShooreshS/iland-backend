import pollMapRefreshQueueRepository from "../repositories/pollMapRefreshQueueRepository";
import pollMapCacheRefreshService from "./pollMapCacheRefreshService";
import type { PollMapRefreshQueueRow } from "../types/db";

export type PollMapRefreshWorkerConfig = {
  intervalMs: number;
  pendingVoteThreshold: number;
  maxQueueAgeMs: number;
  maxPollsPerCycle: number;
};

type PollMapRefreshWorkerDependencies = {
  queueRepositoryLike?: Pick<
    typeof pollMapRefreshQueueRepository,
    "listCandidates" | "ackPoll" | "failPoll"
  >;
  cacheRefreshServiceLike?: Pick<
    typeof pollMapCacheRefreshService,
    "rebuildPollMapCache"
  >;
  nowMsFn?: () => number;
};

export type PollMapRefreshWorkerCycleResult = {
  skippedDueToOverlap: boolean;
  listedCandidateCount: number;
  eligibleCandidateCount: number;
  processedCount: number;
  ackedCount: number;
  failedCount: number;
};

const DEFAULT_WORKER_CONFIG: PollMapRefreshWorkerConfig = {
  intervalMs: 10_000,
  pendingVoteThreshold: 10,
  maxQueueAgeMs: 60_000,
  maxPollsPerCycle: 20,
};

const normalizeConfig = (
  input: Partial<PollMapRefreshWorkerConfig> | undefined,
): PollMapRefreshWorkerConfig => {
  const source = input || {};
  return {
    intervalMs:
      source.intervalMs !== undefined && source.intervalMs > 0
        ? Math.trunc(source.intervalMs)
        : DEFAULT_WORKER_CONFIG.intervalMs,
    pendingVoteThreshold:
      source.pendingVoteThreshold !== undefined && source.pendingVoteThreshold > 0
        ? Math.trunc(source.pendingVoteThreshold)
        : DEFAULT_WORKER_CONFIG.pendingVoteThreshold,
    maxQueueAgeMs:
      source.maxQueueAgeMs !== undefined && source.maxQueueAgeMs >= 0
        ? Math.trunc(source.maxQueueAgeMs)
        : DEFAULT_WORKER_CONFIG.maxQueueAgeMs,
    maxPollsPerCycle:
      source.maxPollsPerCycle !== undefined && source.maxPollsPerCycle > 0
        ? Math.trunc(source.maxPollsPerCycle)
        : DEFAULT_WORKER_CONFIG.maxPollsPerCycle,
  };
};

const toTimestampMs = (isoTimestamp: string | null): number | null => {
  if (!isoTimestamp) {
    return null;
  }

  const parsed = Date.parse(isoTimestamp);
  return Number.isFinite(parsed) ? parsed : null;
};

const isEligibleCandidate = (
  row: PollMapRefreshQueueRow,
  nowMs: number,
  config: PollMapRefreshWorkerConfig,
): boolean => {
  if (row.pending_vote_events >= config.pendingVoteThreshold) {
    return true;
  }

  const firstEnqueuedAtMs = toTimestampMs(row.first_enqueued_at);
  if (firstEnqueuedAtMs === null) {
    return false;
  }

  return nowMs - firstEnqueuedAtMs >= config.maxQueueAgeMs;
};

const toErrorMessage = (error: unknown): string => {
  if (error instanceof Error) {
    return `${error.name}: ${error.message}`;
  }

  return String(error);
};

export const createPollMapRefreshWorker = (
  configInput?: Partial<PollMapRefreshWorkerConfig>,
  dependencies: PollMapRefreshWorkerDependencies = {},
) => {
  const config = normalizeConfig(configInput);
  const queueRepositoryLike =
    dependencies.queueRepositoryLike || pollMapRefreshQueueRepository;
  const cacheRefreshServiceLike =
    dependencies.cacheRefreshServiceLike || pollMapCacheRefreshService;
  const nowMsFn = dependencies.nowMsFn || (() => Date.now());

  let activeCyclePromise: Promise<PollMapRefreshWorkerCycleResult> | null = null;
  let intervalId: ReturnType<typeof setInterval> | null = null;

  const runCycle = async (): Promise<PollMapRefreshWorkerCycleResult> => {
    if (activeCyclePromise) {
      return {
        skippedDueToOverlap: true,
        listedCandidateCount: 0,
        eligibleCandidateCount: 0,
        processedCount: 0,
        ackedCount: 0,
        failedCount: 0,
      };
    }

    activeCyclePromise = (async () => {
      const nowMs = nowMsFn();
      console.info("[pollMapRefreshWorker] cycle started");

      const candidates = await queueRepositoryLike.listCandidates({
        minPendingVoteEvents: 1,
        limit: config.maxPollsPerCycle,
      });
      const eligibleCandidates = candidates.filter((row) =>
        isEligibleCandidate(row, nowMs, config),
      );

      console.info("[pollMapRefreshWorker] cycle candidates", {
        listedCandidates: candidates.length,
        eligibleCandidates: eligibleCandidates.length,
      });

      let ackedCount = 0;
      let failedCount = 0;

      for (const candidate of eligibleCandidates) {
        try {
          const rebuild = await cacheRefreshServiceLike.rebuildPollMapCache(
            candidate.poll_id,
          );
          await queueRepositoryLike.ackPoll(candidate.poll_id);
          ackedCount += 1;

          console.info("[pollMapRefreshWorker] poll refreshed", {
            pollId: candidate.poll_id,
            markerCount: rebuild.markerCount,
            totalVotes: rebuild.totalVotes,
            ignoredVotesMissingSnapshot: rebuild.ignoredVotesMissingSnapshot,
          });
        } catch (error) {
          failedCount += 1;
          const errorMessage = toErrorMessage(error);

          try {
            await queueRepositoryLike.failPoll(candidate.poll_id, errorMessage);
          } catch (failError) {
            console.error("[pollMapRefreshWorker] failed to persist poll refresh error", {
              pollId: candidate.poll_id,
              error: failError,
            });
          }

          console.error("[pollMapRefreshWorker] poll refresh failed", {
            pollId: candidate.poll_id,
            error: errorMessage,
          });
        }
      }

      const result: PollMapRefreshWorkerCycleResult = {
        skippedDueToOverlap: false,
        listedCandidateCount: candidates.length,
        eligibleCandidateCount: eligibleCandidates.length,
        processedCount: eligibleCandidates.length,
        ackedCount,
        failedCount,
      };

      console.info("[pollMapRefreshWorker] cycle completed", result);
      return result;
    })();

    try {
      return await activeCyclePromise;
    } finally {
      activeCyclePromise = null;
    }
  };

  const start = (): void => {
    if (intervalId) {
      return;
    }

    console.info("[pollMapRefreshWorker] starting", config);
    void runCycle();
    intervalId = setInterval(() => {
      void runCycle();
    }, config.intervalMs);
  };

  const stop = (): void => {
    if (!intervalId) {
      return;
    }

    clearInterval(intervalId);
    intervalId = null;
    console.info("[pollMapRefreshWorker] stopped");
  };

  return {
    runCycle,
    start,
    stop,
  };
};

export default createPollMapRefreshWorker;
