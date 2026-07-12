import { describe, expect, it } from "bun:test";
import pollRepository from "../repositories/pollRepository";
import pollTallyProofRepository from "../repositories/pollTallyProofRepository";
import pollZkVoteRepository from "../repositories/pollZkVoteRepository";
import voteRepository from "../repositories/voteRepository";
import pollEncryptedTallyService from "./pollEncryptedTallyService";
import { pollVotingService } from "./pollVotingService";
import type { PollOptionRow, PollRow, PollTallyProofRow, VoteRow } from "../types/db";

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
  vote_privacy_mode: "legacy_identity_linked",
  option_set_hash: null,
  poll_encryption_key_id: null,
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
  nullifier: null,
  vote_commitment: null,
  encrypted_vote: null,
  proof_hash: null,
  proof_system_version: null,
  verification_method_version: null,
  proof_verification_status: null,
  proof_public_inputs_json: null,
  proof_envelope_json: null,
  accepted_at: null,
  batch_id: null,
  vote_latitude_l0: null,
  vote_longitude_l0: null,
  vote_location_snapshot_at: null,
  vote_location_snapshot_version: 1,
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
  it("reports an active poll as closed after its voting window ends", async () => {
    const poll = createPoll({
      status: "active",
      ends_at: "2000-01-01T00:00:00.000Z",
    });
    const option = createOption();
    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionsByPollId", async () => [option]),
      patchMethod(voteRepository, "getByUserIdAndPollId", async () => null),
      patchMethod(voteRepository, "countValidByPollId", async () => 0),
      patchMethod(voteRepository, "countValidByPollIdAndOptionId", async () => 0),
      patchMethod(voteRepository, "getLatestValidSubmittedAtByPollId", async () => null),
    ];

    try {
      const details = await pollVotingService.getPollDetails(poll.id, "viewer-user-1");

      expect(details?.poll.status).toBe("closed");
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("uses exact valid vote count for poll details totalVotes", async () => {
    const poll = createPoll();
    const optionA = createOption({ id: "option-a", label: "Option A", display_order: 0 });
    const optionB = createOption({ id: "option-b", label: "Option B", display_order: 1 });

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionsByPollId", async () => [optionA, optionB]),
      patchMethod(voteRepository, "getByUserIdAndPollId", async () => null),
      patchMethod(voteRepository, "countValidByPollId", async () => 1_000_000),
      patchMethod(voteRepository, "countValidByPollIdAndOptionId", async (_pollId, optionId) =>
        optionId === optionA.id ? 700_000 : 300_000,
      ),
      patchMethod(
        voteRepository,
        "getLatestValidSubmittedAtByPollId",
        async () => "2026-04-08T13:59:00.000Z",
      ),
    ];

    try {
      const details = await pollVotingService.getPollDetails(poll.id, "viewer-user-1");

      expect(details).not.toBeNull();
      expect(details?.totalVotes).toBe(1_000_000);
      expect(details?.results.totalVotes).toBe(1_000_000);
      expect(details?.results.optionResults.find((entry) => entry.optionId === optionA.id)?.count).toBe(
        700_000,
      );
      expect(details?.results.optionResults.find((entry) => entry.optionId === optionB.id)?.count).toBe(
        300_000,
      );
      expect(
        details?.results.optionResults.reduce((sum, entry) => sum + entry.count, 0),
      ).toBe(1_000_000);
      expect(details?.results.updatedAt).toBe("2026-04-08T13:59:00.000Z");
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("does not derive poll details option counts from capped getValidByPollId arrays", async () => {
    const poll = createPoll();
    const optionA = createOption({ id: "option-a", label: "Option A", display_order: 0 });
    const optionB = createOption({ id: "option-b", label: "Option B", display_order: 1 });
    const cappedSampleRows = [
      ...Array.from({ length: 700 }, (_, index) =>
        createVote({
          id: `vote-a-${index}`,
          user_id: `user-a-${index}`,
          option_id: optionA.id,
        }),
      ),
      ...Array.from({ length: 300 }, (_, index) =>
        createVote({
          id: `vote-b-${index}`,
          user_id: `user-b-${index}`,
          option_id: optionB.id,
        }),
      ),
    ];

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionsByPollId", async () => [optionA, optionB]),
      patchMethod(voteRepository, "getValidByPollId", async () => cappedSampleRows),
      patchMethod(voteRepository, "getByUserIdAndPollId", async () => null),
      patchMethod(voteRepository, "countValidByPollId", async () => 1_000_000),
      patchMethod(voteRepository, "countValidByPollIdAndOptionId", async (_pollId, optionId) =>
        optionId === optionA.id ? 900_000 : 100_000,
      ),
      patchMethod(
        voteRepository,
        "getLatestValidSubmittedAtByPollId",
        async () => "2026-04-08T14:00:00.000Z",
      ),
    ];

    try {
      const details = await pollVotingService.getPollDetails(poll.id, "viewer-user-1");

      expect(details).not.toBeNull();
      expect(details?.results.totalVotes).toBe(1_000_000);
      expect(details?.results.optionResults.find((entry) => entry.optionId === optionA.id)?.count).toBe(
        900_000,
      );
      expect(details?.results.optionResults.find((entry) => entry.optionId === optionB.id)?.count).toBe(
        100_000,
      );
      expect(
        details?.results.optionResults.reduce((sum, entry) => sum + entry.count, 0),
      ).toBe(1_000_000);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("returns provisional and verified result summaries for production secret ballot polls", async () => {
    const poll = createPoll({
      vote_privacy_mode: "zk_secret_ballot_v1",
      option_set_hash: "a".repeat(64),
      poll_encryption_key_id: "poll-key-1",
    });
    const optionA = createOption({ id: "option-a", label: "Yes", display_order: 0 });
    const optionB = createOption({ id: "option-b", label: "No", display_order: 1 });
    const tallyProof: PollTallyProofRow = {
      id: "tally-proof-1",
      poll_id: poll.id,
      result_hash: "1".repeat(64),
      tally_proof_hash: "2".repeat(64),
      tally_public_inputs_hash: "3".repeat(64),
      tally_verifier_key_hash: "4".repeat(64),
      tally_circuit_id: "civicos-groth16-tally-circuit-v1",
      nullifier_root: "5".repeat(64),
      vote_commitment_root: "6".repeat(64),
      encrypted_vote_root: "7".repeat(64),
      accepted_count: 2,
      proof_envelope_json: {
        publicInputs: {
          optionResults: [
            { optionId: optionA.id, count: 1 },
            { optionId: optionB.id, count: 1 },
          ],
        },
      },
      verified_at: "2026-04-08T14:00:00.000Z",
      created_at: "2026-04-08T14:00:00.000Z",
    };

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionsByPollId", async () => [optionA, optionB]),
      patchMethod(pollZkVoteRepository, "countAcceptedByPollId", async () => 3),
      patchMethod(pollEncryptedTallyService, "getProvisionalTally", async () => ({
        countsByOptionId: {
          [optionA.id]: 2,
          [optionB.id]: 1,
        },
        totalVotes: 3,
        updatedAt: "2026-04-08T13:59:00.000Z",
      })),
      patchMethod(pollTallyProofRepository, "getLatestByPollId", async () => tallyProof),
    ];

    try {
      const details = await pollVotingService.getPollDetails(poll.id, "viewer-user-1");

      expect(details).not.toBeNull();
      expect(details?.viewerVote).toBeNull();
      expect(details?.totalVotes).toBe(3);
      expect(details?.provisionalResults?.totalVotes).toBe(3);
      expect(
        details?.provisionalResults?.optionResults.find((entry) => entry.optionId === optionA.id)?.count,
      ).toBe(2);
      expect(details?.verifiedResults?.totalVotes).toBe(2);
      expect(
        details?.verifiedResults?.optionResults.find((entry) => entry.optionId === optionB.id)?.count,
      ).toBe(1);
      expect(details?.results.totalVotes).toBe(2);
      expect(details?.results.updatedAt).toBe("2026-04-08T14:00:00.000Z");
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

  it("keeps draft polls private to their creator in summary and detail reads", async () => {
    const activePoll = createPoll({
      id: "poll-active",
      slug: "poll-active",
      title: "Active poll",
      status: "active",
      created_by_user_id: "owner-1",
    });
    const viewerDraft = createPoll({
      id: "poll-viewer-draft",
      slug: "poll-viewer-draft",
      title: "Viewer draft",
      status: "draft",
      created_by_user_id: "viewer-user-1",
    });
    const otherDraft = createPoll({
      id: "poll-other-draft",
      slug: "poll-other-draft",
      title: "Other draft",
      status: "draft",
      created_by_user_id: "other-user-1",
    });

    const restoreFns = [
      patchMethod(pollRepository, "listAll", async () => [
        activePoll,
        viewerDraft,
        otherDraft,
      ]),
      patchMethod(pollRepository, "getById", async (pollId: string) => (
        pollId === otherDraft.id ? otherDraft : activePoll
      )),
      patchMethod(pollRepository, "getOptionsByPollIds", async (pollIds: string[]) =>
        pollIds.map((pollId, index) =>
          createOption({
            id: `${pollId}-option`,
            poll_id: pollId,
            display_order: index,
          }),
        ),
      ),
      patchMethod(pollRepository, "getOptionsByPollId", async (pollId: string) => [
        createOption({ id: `${pollId}-option`, poll_id: pollId }),
      ]),
      patchMethod(voteRepository, "getViewerVotesByPollIds", async () => []),
      patchMethod(voteRepository, "getByUserIdAndPollId", async () => null),
      patchMethod(voteRepository, "countValidByPollId", async () => 0),
      patchMethod(voteRepository, "countValidByPollIdAndOptionId", async () => 0),
      patchMethod(voteRepository, "getLatestValidSubmittedAtByPollId", async () => null),
    ];

    try {
      const summaries = await pollVotingService.getPollSummaries("viewer-user-1");

      expect(summaries.map((summary) => summary.poll.id)).toEqual([
        activePoll.id,
        viewerDraft.id,
      ]);

      const hiddenDraftDetails = await pollVotingService.getPollDetails(
        otherDraft.id,
        "viewer-user-1",
      );
      expect(hiddenDraftDetails).toBeNull();
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });
});
