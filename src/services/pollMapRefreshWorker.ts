import pollMapMarkerCacheRepository from "../repositories/pollMapMarkerCacheRepository";
import pollMapRefreshQueueRepository from "../repositories/pollMapRefreshQueueRepository";
import pollRepository from "../repositories/pollRepository";
import pollMapCacheRefreshService from "./pollMapCacheRefreshService";
import type { PollMapRefreshQueueRow } from "../types/db";

export type PollMapRefreshWorkerConfig = {
  intervalMs: number;
  pendingVoteThreshold: number;
  maxQueueAgeMs: number;
  maxPollsPerCycle: number;
  failureRetryCooldownMs: number;
};

type PollMapRefreshWorkerDependencies = {
  queueRepositoryLike?: Pick<
    typeof pollMapRefreshQueueRepository,
    "listCandidates" | "ackPoll" | "failPoll"
  >;
  queueBootstrapRepositoryLike?: Pick<
    typeof pollMapRefreshQueueRepository,
    "enqueuePoll" | "getByPollId"
  >;
  pollRepositoryLike?: Pick<typeof pollRepository, "listAll">;
  pollMapMarkerCacheRepositoryLike?: Pick<
    typeof pollMapMarkerCacheRepository,
    "listByPollIds"
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

export type PollMapRefreshBootstrapResult = {
  checkedPollCount: number;
  cachedPollCount: number;
  missingCachePollCount: number;
  alreadyQueuedCount: number;
  enqueuedCount: number;
  enqueueFailedCount: number;
  skipped: boolean;
};

const DEFAULT_WORKER_CONFIG: PollMapRefreshWorkerConfig = {
  intervalMs: 10_000,
  pendingVoteThreshold: 10,
  maxQueueAgeMs: 60_000,
  maxPollsPerCycle: 20,
  failureRetryCooldownMs: 120_000,
};

const BOOTSTRAP_CACHE_CHECK_CHUNK_SIZE = 1_000;

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
    failureRetryCooldownMs:
      source.failureRetryCooldownMs !== undefined &&
      source.failureRetryCooldownMs >= 0
        ? Math.trunc(source.failureRetryCooldownMs)
        : DEFAULT_WORKER_CONFIG.failureRetryCooldownMs,
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
  if (row.last_error) {
    const failureAnchorMs =
      toTimestampMs(row.last_processed_at) ?? toTimestampMs(row.updated_at);
    if (
      failureAnchorMs !== null &&
      nowMs - failureAnchorMs < config.failureRetryCooldownMs
    ) {
      return false;
    }
  }

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
  const normalized = toNormalizedErrorLog(error);
  return normalized.message;
};

const normalizeText = (value: unknown): string | null => {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
};

const isMissingTableSchemaCacheError = (
  error: unknown,
  tableName: string,
): boolean => {
  if (!error || typeof error !== "object") {
    return false;
  }

  const code = (error as { code?: unknown }).code;
  if (typeof code === "string" && code.trim().toUpperCase() === "PGRST205") {
    return true;
  }

  const message = normalizeText((error as { message?: unknown }).message);
  if (!message) {
    return false;
  }

  const normalizedMessage = message.toLowerCase();
  return (
    normalizedMessage.includes("could not find the table") &&
    normalizedMessage.includes(tableName.toLowerCase())
  );
};

const toNormalizedErrorLog = (error: unknown): {
  name: string;
  message: string;
  stack: string | null;
  payload: unknown;
  context: unknown;
} => {
  if (error instanceof Error) {
    const errorWithExtra = error as Error & {
      rawError?: unknown;
      context?: unknown;
    };
    return {
      name: error.name || "Error",
      message: `${error.name || "Error"}: ${error.message}`,
      stack: error.stack || null,
      payload: errorWithExtra.rawError ?? null,
      context: errorWithExtra.context ?? null,
    };
  }

  if (error && typeof error === "object") {
    const errorLike = error as {
      code?: unknown;
      message?: unknown;
      details?: unknown;
      hint?: unknown;
      context?: unknown;
      rawError?: unknown;
      stack?: unknown;
    };
    const code = normalizeText(errorLike.code);
    const message = normalizeText(errorLike.message);
    const details = normalizeText(errorLike.details);
    const hint = normalizeText(errorLike.hint);
    const resolvedMessage =
      [
        code ? `[${code}]` : null,
        message,
        details ? `details=${details}` : null,
        hint ? `hint=${hint}` : null,
      ]
        .filter(Boolean)
        .join(" ") ||
      (() => {
        try {
          return JSON.stringify(errorLike);
        } catch {
          return String(errorLike);
        }
      })();

    return {
      name: "NonErrorObject",
      message: resolvedMessage,
      stack:
        typeof errorLike.stack === "string" && errorLike.stack.trim().length > 0
          ? errorLike.stack
          : null,
      payload: errorLike.rawError ?? error,
      context: errorLike.context ?? null,
    };
  }

  return {
    name: "UnknownErrorValue",
    message: String(error),
    stack: null,
    payload: error ?? null,
    context: null,
  };
};

export const createPollMapRefreshWorker = (
  configInput?: Partial<PollMapRefreshWorkerConfig>,
  dependencies: PollMapRefreshWorkerDependencies = {},
) => {
  const config = normalizeConfig(configInput);
  const queueRepositoryLike =
    dependencies.queueRepositoryLike || pollMapRefreshQueueRepository;
  const queueBootstrapRepositoryLike =
    dependencies.queueBootstrapRepositoryLike || pollMapRefreshQueueRepository;
  const pollRepositoryLike = dependencies.pollRepositoryLike || pollRepository;
  const pollMapMarkerCacheRepositoryLike =
    dependencies.pollMapMarkerCacheRepositoryLike || pollMapMarkerCacheRepository;
  const cacheRefreshServiceLike =
    dependencies.cacheRefreshServiceLike || pollMapCacheRefreshService;
  const nowMsFn = dependencies.nowMsFn || (() => Date.now());

  let activeCyclePromise: Promise<PollMapRefreshWorkerCycleResult> | null = null;
  let intervalId: ReturnType<typeof setInterval> | null = null;
  let queueSchemaUnavailable = false;
  let queueSchemaUnavailableLogged = false;
  let bootstrapPromise: Promise<PollMapRefreshBootstrapResult> | null = null;
  let bootstrapCompleted = false;
  let bootstrapResult: PollMapRefreshBootstrapResult | null = null;

  const createEmptyBootstrapResult = (
    overrides: Partial<PollMapRefreshBootstrapResult> = {},
  ): PollMapRefreshBootstrapResult => ({
    checkedPollCount: 0,
    cachedPollCount: 0,
    missingCachePollCount: 0,
    alreadyQueuedCount: 0,
    enqueuedCount: 0,
    enqueueFailedCount: 0,
    skipped: false,
    ...overrides,
  });

  const chunkPollIds = (pollIds: string[], chunkSize: number): string[][] => {
    const chunks: string[][] = [];
    for (let index = 0; index < pollIds.length; index += chunkSize) {
      chunks.push(pollIds.slice(index, index + chunkSize));
    }
    return chunks;
  };

  const runBootstrapSync = async (): Promise<PollMapRefreshBootstrapResult> => {
    if (bootstrapCompleted && bootstrapResult) {
      return bootstrapResult;
    }

    if (bootstrapPromise) {
      return bootstrapPromise;
    }

    bootstrapPromise = (async () => {
      if (queueSchemaUnavailable) {
        const result = createEmptyBootstrapResult({ skipped: true });
        bootstrapResult = result;
        return result;
      }

      try {
        const polls = await pollRepositoryLike.listAll();
        const checkedPollCount = polls.length;

        if (checkedPollCount === 0) {
          const result = createEmptyBootstrapResult({ checkedPollCount });
          console.info("[pollMapRefreshWorker] bootstrap cache sync completed", result);
          bootstrapResult = result;
          return result;
        }

        const pollIds = polls.map((poll) => poll.id);
        const cachedPollIdSet = new Set<string>();

        for (const pollIdChunk of chunkPollIds(
          pollIds,
          BOOTSTRAP_CACHE_CHECK_CHUNK_SIZE,
        )) {
          const cachedRows =
            await pollMapMarkerCacheRepositoryLike.listByPollIds(pollIdChunk);
          for (const row of cachedRows) {
            cachedPollIdSet.add(row.poll_id);
          }
        }

        const missingCachePollIds = pollIds.filter(
          (pollId) => !cachedPollIdSet.has(pollId),
        );

        let alreadyQueuedCount = 0;
        let enqueuedCount = 0;
        let enqueueFailedCount = 0;

        for (const pollId of missingCachePollIds) {
          let existingQueueRow: PollMapRefreshQueueRow | null = null;
          try {
            existingQueueRow = await queueBootstrapRepositoryLike.getByPollId(pollId);
          } catch (error) {
            if (
              isMissingTableSchemaCacheError(
                error,
                "public.poll_map_refresh_queue",
              )
            ) {
              queueSchemaUnavailable = true;
              if (!queueSchemaUnavailableLogged) {
                queueSchemaUnavailableLogged = true;
                console.warn(
                  "[pollMapRefreshWorker] poll_map_refresh_queue table missing during bootstrap; skipping bootstrap enqueue",
                  { error },
                );
              }
              const result = createEmptyBootstrapResult({
                checkedPollCount,
                cachedPollCount: cachedPollIdSet.size,
                missingCachePollCount: missingCachePollIds.length,
                skipped: true,
              });
              bootstrapResult = result;
              return result;
            }
            throw error;
          }

          if (existingQueueRow && existingQueueRow.pending_vote_events > 0) {
            alreadyQueuedCount += 1;
            continue;
          }

          try {
            await queueBootstrapRepositoryLike.enqueuePoll(pollId);
            enqueuedCount += 1;
          } catch (error) {
            if (
              isMissingTableSchemaCacheError(
                error,
                "public.poll_map_refresh_queue",
              )
            ) {
              queueSchemaUnavailable = true;
              if (!queueSchemaUnavailableLogged) {
                queueSchemaUnavailableLogged = true;
                console.warn(
                  "[pollMapRefreshWorker] poll_map_refresh_queue table missing during bootstrap enqueue; skipping remaining bootstrap work",
                  { error },
                );
              }
              const result = createEmptyBootstrapResult({
                checkedPollCount,
                cachedPollCount: cachedPollIdSet.size,
                missingCachePollCount: missingCachePollIds.length,
                alreadyQueuedCount,
                enqueuedCount,
                enqueueFailedCount,
                skipped: true,
              });
              bootstrapResult = result;
              return result;
            }

            enqueueFailedCount += 1;
            const normalizedError = toNormalizedErrorLog(error);
            console.error("[pollMapRefreshWorker] bootstrap enqueue failed", {
              pollId,
              error: normalizedError.message,
              errorPayload: normalizedError.payload,
            });
          }
        }

        const result = createEmptyBootstrapResult({
          checkedPollCount,
          cachedPollCount: cachedPollIdSet.size,
          missingCachePollCount: missingCachePollIds.length,
          alreadyQueuedCount,
          enqueuedCount,
          enqueueFailedCount,
        });
        console.info("[pollMapRefreshWorker] bootstrap cache sync completed", result);
        bootstrapResult = result;
        return result;
      } catch (error) {
        const normalizedError = toNormalizedErrorLog(error);
        const result = createEmptyBootstrapResult({ skipped: true });
        console.error("[pollMapRefreshWorker] bootstrap cache sync failed", {
          error: normalizedError.message,
          errorPayload: normalizedError.payload,
          errorStack: normalizedError.stack,
        });
        bootstrapResult = result;
        return result;
      } finally {
        bootstrapCompleted = true;
      }
    })();

    try {
      return await bootstrapPromise;
    } finally {
      bootstrapPromise = null;
    }
  };

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

    if (queueSchemaUnavailable) {
      return {
        skippedDueToOverlap: false,
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

      let candidates: PollMapRefreshQueueRow[];
      try {
        candidates = await queueRepositoryLike.listCandidates({
          minPendingVoteEvents: 1,
          limit: Math.max(config.maxPollsPerCycle, config.maxPollsPerCycle * 5),
        });
      } catch (error) {
        if (
          isMissingTableSchemaCacheError(
            error,
            "public.poll_map_refresh_queue",
          )
        ) {
          queueSchemaUnavailable = true;
          if (!queueSchemaUnavailableLogged) {
            queueSchemaUnavailableLogged = true;
            console.warn(
              "[pollMapRefreshWorker] poll_map_refresh_queue table missing; skipping refresh cycles until restart",
              {
                error,
              },
            );
          }

          return {
            skippedDueToOverlap: false,
            listedCandidateCount: 0,
            eligibleCandidateCount: 0,
            processedCount: 0,
            ackedCount: 0,
            failedCount: 0,
          };
        }

        throw error;
      }
      const eligibleCandidates = candidates.filter((row) =>
        isEligibleCandidate(row, nowMs, config),
      );
      const selectedCandidates = eligibleCandidates.slice(0, config.maxPollsPerCycle);
      const skippedByEligibilityCount =
        candidates.length - eligibleCandidates.length;

      console.info("[pollMapRefreshWorker] cycle candidates", {
        listedCandidates: candidates.length,
        eligibleCandidates: eligibleCandidates.length,
        selectedCandidates: selectedCandidates.length,
        skippedByEligibilityCount,
      });

      let ackedCount = 0;
      let failedCount = 0;

      for (const candidate of selectedCandidates) {
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
          const normalizedError = toNormalizedErrorLog(error);
          const errorMessage = toErrorMessage(error);

          try {
            await queueRepositoryLike.failPoll(candidate.poll_id, errorMessage);
          } catch (failError) {
            const normalizedFailError = toNormalizedErrorLog(failError);
            console.error("[pollMapRefreshWorker] failed to persist poll refresh error", {
              pollId: candidate.poll_id,
              error: normalizedFailError.message,
              errorPayload: normalizedFailError.payload,
              errorStack: normalizedFailError.stack,
            });
          }

          console.error("[pollMapRefreshWorker] poll refresh failed", {
            pollId: candidate.poll_id,
            error: errorMessage,
            errorName: normalizedError.name,
            errorContext: normalizedError.context,
            errorPayload: normalizedError.payload,
            errorStack: normalizedError.stack,
          });
        }
      }

      const result: PollMapRefreshWorkerCycleResult = {
        skippedDueToOverlap: false,
        listedCandidateCount: candidates.length,
        eligibleCandidateCount: selectedCandidates.length,
        processedCount: selectedCandidates.length,
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

  const runCycleSafe = async (): Promise<void> => {
    try {
      await runCycle();
    } catch (error) {
      console.error("[pollMapRefreshWorker] cycle crashed", { error });
    }
  };

  const start = (): void => {
    if (intervalId) {
      return;
    }

    console.info("[pollMapRefreshWorker] starting", config);
    intervalId = setInterval(() => {
      void runCycleSafe();
    }, config.intervalMs);
    void (async () => {
      await runBootstrapSync();
      await runCycleSafe();
    })();
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
    runBootstrapSync,
    runCycle,
    start,
    stop,
  };
};

export default createPollMapRefreshWorker;
