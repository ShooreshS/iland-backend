import { describe, expect, it } from "bun:test";
import { createPollMapRefreshWorker } from "./pollMapRefreshWorker";
import type { PollMapRefreshQueueRow, PollRow } from "../types/db";

const FIXED_TIME = "2026-04-08T12:00:00.000Z";

const createQueueRow = (
  overrides: Partial<PollMapRefreshQueueRow> = {},
): PollMapRefreshQueueRow => ({
  poll_id: "poll-1",
  pending_vote_events: 1,
  first_enqueued_at: FIXED_TIME,
  last_enqueued_at: FIXED_TIME,
  last_processed_at: null,
  last_error: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createPollRow = (id: string): PollRow => ({
  id,
  slug: `slug-${id}`,
  created_by_user_id: null,
  title: `Poll ${id}`,
  description: null,
  status: "active",
  jurisdiction_type: "global",
  jurisdiction_country_code: null,
  jurisdiction_area_ids: [],
  jurisdiction_land_ids: [],
  requires_verified_identity: false,
  allowed_document_country_codes: [],
  allowed_home_area_ids: [],
  allowed_land_ids: [],
  minimum_age: null,
  starts_at: null,
  ends_at: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
});

describe("pollMapRefreshWorker", () => {
  it("skips overlapping cycles", async () => {
    let listCandidatesCalls = 0;
    let resolveRebuild: (value?: void) => void = () => {};

    const rebuildWait = new Promise<void>((resolve) => {
      resolveRebuild = resolve;
    });

    const worker = createPollMapRefreshWorker(
      {
        intervalMs: 1000,
        pendingVoteThreshold: 1,
        maxQueueAgeMs: 60_000,
        maxPollsPerCycle: 10,
      },
      {
        queueRepositoryLike: {
          async listCandidates() {
            listCandidatesCalls += 1;
            return [createQueueRow({ poll_id: "poll-1", pending_vote_events: 2 })];
          },
          async ackPoll() {
            return createQueueRow({ poll_id: "poll-1", pending_vote_events: 0 });
          },
          async failPoll() {
            return createQueueRow({ poll_id: "poll-1", last_error: "x" });
          },
        },
        cacheRefreshServiceLike: {
          async rebuildPollMapCache() {
            await rebuildWait;
            return {
              pollId: "poll-1",
              pollFound: true,
              scannedVotes: 0,
              includedVotes: 0,
              ignoredVotesMissingSnapshot: 0,
              markerCount: 0,
              totalVotes: 0,
              lastVoteSubmittedAt: null,
              refreshedAt: FIXED_TIME,
              markers: [],
            };
          },
        },
      },
    );

    const firstRunPromise = worker.runCycle();
    const secondRun = await worker.runCycle();

    expect(secondRun.skippedDueToOverlap).toBe(true);
    expect(listCandidatesCalls).toBe(1);

    resolveRebuild();
    const firstRun = await firstRunPromise;
    expect(firstRun.skippedDueToOverlap).toBe(false);
  });

  it("processes candidates eligible by threshold or age and ignores fresh low-pending rows", async () => {
    const nowMs = Date.parse("2026-04-08T12:01:00.000Z");
    const rebuildPollIds: string[] = [];
    const ackPollIds: string[] = [];

    const worker = createPollMapRefreshWorker(
      {
        intervalMs: 1000,
        pendingVoteThreshold: 5,
        maxQueueAgeMs: 30_000,
        maxPollsPerCycle: 10,
      },
      {
        nowMsFn: () => nowMs,
        queueRepositoryLike: {
          async listCandidates() {
            return [
              createQueueRow({
                poll_id: "poll-threshold",
                pending_vote_events: 7,
                first_enqueued_at: "2026-04-08T12:00:50.000Z",
              }),
              createQueueRow({
                poll_id: "poll-aged",
                pending_vote_events: 1,
                first_enqueued_at: "2026-04-08T12:00:00.000Z",
              }),
              createQueueRow({
                poll_id: "poll-fresh",
                pending_vote_events: 1,
                first_enqueued_at: "2026-04-08T12:00:50.000Z",
              }),
            ];
          },
          async ackPoll(pollId: string) {
            ackPollIds.push(pollId);
            return createQueueRow({ poll_id: pollId, pending_vote_events: 0 });
          },
          async failPoll() {
            return null;
          },
        },
        cacheRefreshServiceLike: {
          async rebuildPollMapCache(pollId: string) {
            rebuildPollIds.push(pollId);
            return {
              pollId,
              pollFound: true,
              scannedVotes: 1,
              includedVotes: 1,
              ignoredVotesMissingSnapshot: 0,
              markerCount: 1,
              totalVotes: 1,
              lastVoteSubmittedAt: FIXED_TIME,
              refreshedAt: FIXED_TIME,
              markers: [],
            };
          },
        },
      },
    );

    const result = await worker.runCycle();
    expect(result.skippedDueToOverlap).toBe(false);
    expect(result.listedCandidateCount).toBe(3);
    expect(result.eligibleCandidateCount).toBe(2);
    expect(result.processedCount).toBe(2);
    expect(result.ackedCount).toBe(2);
    expect(result.failedCount).toBe(0);

    expect(rebuildPollIds).toEqual(["poll-threshold", "poll-aged"]);
    expect(ackPollIds).toEqual(["poll-threshold", "poll-aged"]);
  });

  it("applies failure retry cooldown before retrying failed polls", async () => {
    const nowMs = Date.parse("2026-04-08T12:01:00.000Z");
    const rebuildPollIds: string[] = [];
    const ackPollIds: string[] = [];

    const worker = createPollMapRefreshWorker(
      {
        intervalMs: 1000,
        pendingVoteThreshold: 1,
        maxQueueAgeMs: 60_000,
        maxPollsPerCycle: 10,
        failureRetryCooldownMs: 30_000,
      },
      {
        nowMsFn: () => nowMs,
        queueRepositoryLike: {
          async listCandidates() {
            return [
              createQueueRow({
                poll_id: "poll-failed-recently",
                pending_vote_events: 12,
                last_error: "timeout",
                last_processed_at: "2026-04-08T12:00:45.000Z",
                updated_at: "2026-04-08T12:00:45.000Z",
              }),
              createQueueRow({
                poll_id: "poll-failed-old",
                pending_vote_events: 12,
                last_error: "timeout",
                last_processed_at: "2026-04-08T11:59:00.000Z",
                updated_at: "2026-04-08T11:59:00.000Z",
              }),
              createQueueRow({
                poll_id: "poll-clean",
                pending_vote_events: 3,
                last_error: null,
              }),
            ];
          },
          async ackPoll(pollId: string) {
            ackPollIds.push(pollId);
            return createQueueRow({ poll_id: pollId, pending_vote_events: 0 });
          },
          async failPoll() {
            return null;
          },
        },
        cacheRefreshServiceLike: {
          async rebuildPollMapCache(pollId: string) {
            rebuildPollIds.push(pollId);
            return {
              pollId,
              pollFound: true,
              scannedVotes: 1,
              includedVotes: 1,
              ignoredVotesMissingSnapshot: 0,
              markerCount: 1,
              totalVotes: 1,
              lastVoteSubmittedAt: FIXED_TIME,
              refreshedAt: FIXED_TIME,
              markers: [],
            };
          },
        },
      },
    );

    const result = await worker.runCycle();
    expect(result.skippedDueToOverlap).toBe(false);
    expect(result.listedCandidateCount).toBe(3);
    expect(result.eligibleCandidateCount).toBe(2);
    expect(result.processedCount).toBe(2);
    expect(result.ackedCount).toBe(2);
    expect(result.failedCount).toBe(0);

    expect(rebuildPollIds).toEqual(["poll-failed-old", "poll-clean"]);
    expect(ackPollIds).toEqual(["poll-failed-old", "poll-clean"]);
  });

  it("records queue failure when rebuild fails", async () => {
    const failRecords: Array<{ pollId: string; message: string }> = [];
    const ackPollIds: string[] = [];

    const worker = createPollMapRefreshWorker(
      {
        intervalMs: 1000,
        pendingVoteThreshold: 1,
        maxQueueAgeMs: 60_000,
        maxPollsPerCycle: 10,
      },
      {
        queueRepositoryLike: {
          async listCandidates() {
            return [createQueueRow({ poll_id: "poll-fail", pending_vote_events: 2 })];
          },
          async ackPoll(pollId: string) {
            ackPollIds.push(pollId);
            return createQueueRow({ poll_id: pollId, pending_vote_events: 0 });
          },
          async failPoll(pollId: string, errorMessage: string) {
            failRecords.push({ pollId, message: errorMessage });
            return createQueueRow({ poll_id: pollId, last_error: errorMessage });
          },
        },
        cacheRefreshServiceLike: {
          async rebuildPollMapCache() {
            throw new Error("refresh exploded");
          },
        },
      },
    );

    const result = await worker.runCycle();

    expect(result.ackedCount).toBe(0);
    expect(result.failedCount).toBe(1);
    expect(ackPollIds).toEqual([]);
    expect(failRecords.length).toBe(1);
    expect(failRecords[0]?.pollId).toBe("poll-fail");
    expect(failRecords[0]?.message).toContain("refresh exploded");
  });

  it("formats object-shaped rebuild errors into actionable queue failure messages", async () => {
    const failRecords: Array<{ pollId: string; message: string }> = [];

    const worker = createPollMapRefreshWorker(
      {
        intervalMs: 1000,
        pendingVoteThreshold: 1,
        maxQueueAgeMs: 60_000,
        maxPollsPerCycle: 10,
      },
      {
        queueRepositoryLike: {
          async listCandidates() {
            return [createQueueRow({ poll_id: "poll-object-error", pending_vote_events: 3 })];
          },
          async ackPoll() {
            throw new Error("ack should not be called for failed rebuild");
          },
          async failPoll(pollId: string, errorMessage: string) {
            failRecords.push({ pollId, message: errorMessage });
            return createQueueRow({ poll_id: pollId, last_error: errorMessage });
          },
        },
        cacheRefreshServiceLike: {
          async rebuildPollMapCache() {
            throw {
              code: "57014",
              message: "canceling statement due to statement timeout",
              details: "while reading vote page",
            };
          },
        },
      },
    );

    const result = await worker.runCycle();
    expect(result.failedCount).toBe(1);
    expect(result.ackedCount).toBe(0);
    expect(failRecords.length).toBe(1);
    expect(failRecords[0]?.pollId).toBe("poll-object-error");
    expect(failRecords[0]?.message).toContain("[57014]");
    expect(failRecords[0]?.message).toContain(
      "canceling statement due to statement timeout",
    );
    expect(failRecords[0]?.message).not.toBe("[object Object]");
  });

  it("gracefully skips cycles when queue table is missing from schema cache", async () => {
    let listCandidatesCalls = 0;

    const worker = createPollMapRefreshWorker(
      {
        intervalMs: 1000,
        pendingVoteThreshold: 1,
        maxQueueAgeMs: 60_000,
        maxPollsPerCycle: 10,
      },
      {
        queueRepositoryLike: {
          async listCandidates() {
            listCandidatesCalls += 1;
            throw {
              code: "PGRST205",
              message:
                "Could not find the table 'public.poll_map_refresh_queue' in the schema cache",
            };
          },
          async ackPoll() {
            return createQueueRow({ pending_vote_events: 0 });
          },
          async failPoll() {
            return createQueueRow({ last_error: "x" });
          },
        },
        cacheRefreshServiceLike: {
          async rebuildPollMapCache() {
            throw new Error("should not rebuild without queue table");
          },
        },
      },
    );

    const firstRun = await worker.runCycle();
    const secondRun = await worker.runCycle();

    expect(firstRun.skippedDueToOverlap).toBe(false);
    expect(firstRun.listedCandidateCount).toBe(0);
    expect(firstRun.eligibleCandidateCount).toBe(0);
    expect(firstRun.processedCount).toBe(0);
    expect(firstRun.ackedCount).toBe(0);
    expect(firstRun.failedCount).toBe(0);

    expect(secondRun.skippedDueToOverlap).toBe(false);
    expect(secondRun.processedCount).toBe(0);
    expect(listCandidatesCalls).toBe(1);
  });

  it("bootstraps and enqueues polls missing cache rows", async () => {
    const queuedRows = new Map<string, PollMapRefreshQueueRow>();

    const worker = createPollMapRefreshWorker(
      {
        intervalMs: 1000,
        pendingVoteThreshold: 1,
        maxQueueAgeMs: 60_000,
        maxPollsPerCycle: 10,
      },
      {
        pollRepositoryLike: {
          async listAll() {
            return [
              createPollRow("poll-1"),
              createPollRow("poll-2"),
              createPollRow("poll-3"),
            ];
          },
        },
        pollMapMarkerCacheRepositoryLike: {
          async listByPollIds(pollIds: string[]) {
            return pollIds
              .filter((pollId) => pollId === "poll-1")
              .map((pollId) => ({
                poll_id: pollId,
                markers_level1_json: [],
                schema_version: 1,
                marker_count: 0,
                total_votes: 0,
                last_vote_submitted_at: null,
                refreshed_at: FIXED_TIME,
                created_at: FIXED_TIME,
                updated_at: FIXED_TIME,
              }));
          },
        },
        queueBootstrapRepositoryLike: {
          async getByPollId(pollId: string) {
            return queuedRows.get(pollId) || null;
          },
          async enqueuePoll(pollId: string) {
            const current = queuedRows.get(pollId);
            const next = createQueueRow({
              poll_id: pollId,
              pending_vote_events: (current?.pending_vote_events || 0) + 1,
            });
            queuedRows.set(pollId, next);
            return next;
          },
        },
        queueRepositoryLike: {
          async listCandidates() {
            return [];
          },
          async ackPoll() {
            return null;
          },
          async failPoll() {
            return null;
          },
        },
        cacheRefreshServiceLike: {
          async rebuildPollMapCache() {
            throw new Error("should not rebuild in bootstrap-only test");
          },
        },
      },
    );

    const result = await worker.runBootstrapSync();

    expect(result.checkedPollCount).toBe(3);
    expect(result.cachedPollCount).toBe(1);
    expect(result.missingCachePollCount).toBe(2);
    expect(result.enqueuedCount).toBe(2);
    expect(result.alreadyQueuedCount).toBe(0);
    expect(result.enqueueFailedCount).toBe(0);
    expect(queuedRows.get("poll-2")?.pending_vote_events).toBe(1);
    expect(queuedRows.get("poll-3")?.pending_vote_events).toBe(1);
  });

  it("runs bootstrap once and does not repeatedly inflate queue rows", async () => {
    let listAllCalls = 0;
    let enqueueCalls = 0;
    const queueRow = createQueueRow({
      poll_id: "poll-uncached",
      pending_vote_events: 1,
    });

    const worker = createPollMapRefreshWorker(
      {
        intervalMs: 1000,
        pendingVoteThreshold: 1,
        maxQueueAgeMs: 60_000,
        maxPollsPerCycle: 10,
      },
      {
        pollRepositoryLike: {
          async listAll() {
            listAllCalls += 1;
            return [createPollRow("poll-uncached")];
          },
        },
        pollMapMarkerCacheRepositoryLike: {
          async listByPollIds() {
            return [];
          },
        },
        queueBootstrapRepositoryLike: {
          async getByPollId() {
            return queueRow;
          },
          async enqueuePoll() {
            enqueueCalls += 1;
            return queueRow;
          },
        },
        queueRepositoryLike: {
          async listCandidates() {
            return [];
          },
          async ackPoll() {
            return null;
          },
          async failPoll() {
            return null;
          },
        },
        cacheRefreshServiceLike: {
          async rebuildPollMapCache() {
            throw new Error("should not rebuild in bootstrap idempotency test");
          },
        },
      },
    );

    const first = await worker.runBootstrapSync();
    const second = await worker.runBootstrapSync();

    expect(first.alreadyQueuedCount).toBe(1);
    expect(first.enqueuedCount).toBe(0);
    expect(second.alreadyQueuedCount).toBe(1);
    expect(second.enqueuedCount).toBe(0);
    expect(listAllCalls).toBe(1);
    expect(enqueueCalls).toBe(0);
  });
});
