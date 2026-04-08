import { describe, expect, it } from "bun:test";
import pollRepository from "../repositories/pollRepository";
import voteRepository from "../repositories/voteRepository";
import { pollVotingService } from "./pollVotingService";
import type { PollOptionRow, PollRow, VoteRow } from "../types/db";

const FIXED_TIME = "2026-04-08T12:00:00.000Z";

const createPoll = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "poll-1",
  slug: "poll-1",
  created_by_user_id: "owner-1",
  title: "Test Poll",
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
  ...overrides,
});

const createOption = (overrides: Partial<PollOptionRow> = {}): PollOptionRow => ({
  id: "option-1",
  poll_id: "poll-1",
  label: "Option A",
  description: null,
  color: null,
  display_order: 0,
  is_active: true,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createVote = (overrides: Partial<VoteRow> = {}): VoteRow => ({
  id: "vote-1",
  poll_id: "poll-1",
  option_id: "option-1",
  user_id: "user-1",
  verified_identity_id: null,
  submitted_at: FIXED_TIME,
  is_valid: true,
  invalid_reason: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const patchMethod = <T extends object, K extends keyof T>(
  target: T,
  key: K,
  implementation: T[K],
): (() => void) => {
  const original = target[key];
  target[key] = implementation;

  return () => {
    target[key] = original;
  };
};

describe("pollVotingService read paths", () => {
  it("uses exact valid vote count for poll details totalVotes", async () => {
    const poll = createPoll();
    const optionA = createOption({ id: "option-a", label: "Option A", display_order: 0 });
    const optionB = createOption({ id: "option-b", label: "Option B", display_order: 1 });
    const sampledVotes = [
      ...Array.from({ length: 700 }, (_, index) =>
        createVote({
          id: `vote-a-${index}`,
          user_id: `user-a-${index}`,
          option_id: optionA.id,
          submitted_at: `2026-04-08T12:${String(index % 60).padStart(2, "0")}:00.000Z`,
        }),
      ),
      ...Array.from({ length: 300 }, (_, index) =>
        createVote({
          id: `vote-b-${index}`,
          user_id: `user-b-${index}`,
          option_id: optionB.id,
          submitted_at: `2026-04-08T13:${String(index % 60).padStart(2, "0")}:00.000Z`,
        }),
      ),
    ];

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionsByPollId", async () => [optionA, optionB]),
      patchMethod(voteRepository, "getValidByPollId", async () => sampledVotes),
      patchMethod(voteRepository, "getByUserIdAndPollId", async () => null),
      patchMethod(voteRepository, "countValidByPollId", async () => 1_000_000),
    ];

    try {
      const details = await pollVotingService.getPollDetails(poll.id, "viewer-user-1");

      expect(details).not.toBeNull();
      expect(details?.totalVotes).toBe(1_000_000);
      expect(details?.results.totalVotes).toBe(1_000_000);
      expect(details?.results.optionResults.find((entry) => entry.optionId === optionA.id)?.count).toBe(
        700,
      );
      expect(details?.results.optionResults.find((entry) => entry.optionId === optionB.id)?.count).toBe(
        300,
      );
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("uses exact valid vote count for poll summaries totalVotes", async () => {
    const pollA = createPoll({ id: "poll-a", slug: "poll-a", title: "Poll A" });
    const pollB = createPoll({ id: "poll-b", slug: "poll-b", title: "Poll B" });

    const restoreFns = [
      patchMethod(pollRepository, "listAll", async () => [pollA, pollB]),
      patchMethod(pollRepository, "getOptionsByPollIds", async () => [
        createOption({ id: "poll-a-option-1", poll_id: pollA.id }),
        createOption({ id: "poll-b-option-1", poll_id: pollB.id }),
        createOption({ id: "poll-b-option-2", poll_id: pollB.id, display_order: 1 }),
      ]),
      patchMethod(voteRepository, "getViewerVotesByPollIds", async () => [
        createVote({ poll_id: pollA.id, option_id: "poll-a-option-1" }),
      ]),
      patchMethod(voteRepository, "countValidByPollId", async (pollId: string) =>
        pollId === pollA.id ? 1_000_000 : 42,
      ),
    ];

    try {
      const summaries = await pollVotingService.getPollSummaries("viewer-user-1");
      const pollASummary = summaries.find((summary) => summary.poll.id === pollA.id);
      const pollBSummary = summaries.find((summary) => summary.poll.id === pollB.id);

      expect(pollASummary?.totalVotes).toBe(1_000_000);
      expect(pollASummary?.hasViewerVoted).toBe(true);
      expect(pollBSummary?.totalVotes).toBe(42);
      expect(pollBSummary?.hasViewerVoted).toBe(false);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });
});
