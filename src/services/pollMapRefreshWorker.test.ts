import { describe, expect, it } from "bun:test";
import { createPollMapRefreshWorker } from "./pollMapRefreshWorker";
import type { PollMapRefreshQueueRow } from "../types/db";

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
});
