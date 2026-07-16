import { describe, expect, it } from "bun:test";

import type { PollOptionRow, PollRow, ZkpTallyJobRow } from "../types/db";

process.env.ILAND_ENV_VALIDATION_SCOPE = "supabase-admin-script";
process.env.SOLANA_AUDIT_TRANSACTIONS_ENABLED = "false";

const { createZkpTallyWorkerService } = await import("./zkpTallyWorkerService");

const FIXED_TIME = "2026-07-16T10:00:00.000Z";
const HEX_A = "a".repeat(64);
const HEX_B = "b".repeat(64);
const HEX_C = "c".repeat(64);

const createPoll = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "4a2de6fa-94c4-4e1a-ac78-bda1aa17e11f",
  slug: "worker-test",
  created_by_user_id: "owner-1",
  title: "Worker test",
  description: null,
  status: "closed",
  jurisdiction_type: "global",
  jurisdiction_country_code: null,
  jurisdiction_area_ids: [],
  jurisdiction_land_ids: [],
  requires_verified_identity: true,
  allowed_document_country_codes: [],
  allowed_home_area_ids: [],
  allowed_land_ids: [],
  minimum_age: null,
  starts_at: null,
  ends_at: "2026-07-16T09:00:00.000Z",
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  poll_policy_json: null,
  poll_policy_hash: HEX_A,
  credential_schema_json: null,
  credential_schema_hash: HEX_B,
  vote_privacy_mode: "zk_secret_ballot_v1",
  option_set_hash: HEX_C,
  poll_encryption_key_id: "poll-key-1",
  ...overrides,
});

const createOption = (overrides: Partial<PollOptionRow> = {}): PollOptionRow => ({
  id: "option-1",
  poll_id: "4a2de6fa-94c4-4e1a-ac78-bda1aa17e11f",
  label: "Yes",
  description: null,
  color: null,
  display_order: 0,
  is_active: true,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createJob = (overrides: Partial<ZkpTallyJobRow> = {}): ZkpTallyJobRow => ({
  id: "11111111-1111-4111-8111-111111111111",
  poll_id: "4a2de6fa-94c4-4e1a-ac78-bda1aa17e11f",
  status: "running",
  priority: 100,
  attempts: 1,
  max_attempts: 3,
  locked_by: "worker-1",
  locked_at: FIXED_TIME,
  next_attempt_at: FIXED_TIME,
  proof_public_inputs_hash: null,
  tally_proof_hash: null,
  result_hash: null,
  error_code: null,
  error_message: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

describe("zkp tally worker service", () => {
  it("generates, submits, and completes one claimed tally job", async () => {
    const job = createJob();
    const completedJob = createJob({
      status: "succeeded",
      proof_public_inputs_hash: HEX_A,
      tally_proof_hash: HEX_B,
      result_hash: HEX_C,
    });
    let completedInput: unknown = null;

    const service = createZkpTallyWorkerService({
      repositoryLike: {
        claim: async () => job,
        complete: async (input) => {
          completedInput = input;
          return completedJob;
        },
        fail: async () => {
          throw new Error("fail should not be called");
        },
        heartbeat: async () => ({
          worker_id: "worker-1",
          host: "test",
          status: "running",
          current_job_id: job.id,
          message: null,
          first_seen_at: FIXED_TIME,
          last_seen_at: FIXED_TIME,
        }),
      },
      pollRepositoryLike: {
        getById: async () => createPoll(),
        getOptionsByPollId: async () => [createOption()],
      },
      pollTallyProofRepositoryLike: {
        getLatestByPollId: async () => null,
      },
      tallyProverLike: {
        generateProofForPoll: async () => ({
          success: true,
          proof: { publicInputsHash: HEX_A } as never,
          countsByOptionId: { "option-1": 1 },
          acceptedVoteCount: 1,
        }),
      },
      publicAuditServiceLike: {
        submitTallyProof: async () => ({
          success: true,
          message: "ok",
          tallyProof: {
            resultHash: HEX_C,
            tallyProofHash: HEX_B,
            tallyPublicInputsHash: HEX_A,
            tallyVerifierKeyHash: HEX_A,
            tallyCircuitId: "circuit",
            nullifierRoot: HEX_A,
            voteCommitmentRoot: HEX_B,
            encryptedVoteRoot: HEX_C,
            acceptedCount: 1,
            verifiedAt: FIXED_TIME,
          },
          audit: null as never,
        }),
      },
    });

    const result = await service.processNextJob();

    expect(result).toMatchObject({
      claimed: true,
      jobId: job.id,
      pollId: job.poll_id,
      status: "succeeded",
    });
    expect(completedInput).toMatchObject({
      jobId: job.id,
      proofPublicInputsHash: HEX_A,
      tallyProofHash: HEX_B,
      resultHash: HEX_C,
    });
    expect(result.message).toContain("final publication is delegated to the main backend");
  });

  it("marks deterministic prover failures as non-retryable", async () => {
    const job = createJob();
    let failedInput: unknown = null;

    const service = createZkpTallyWorkerService({
      repositoryLike: {
        claim: async () => job,
        complete: async () => {
          throw new Error("complete should not be called");
        },
        fail: async (input) => {
          failedInput = input;
          return createJob({ status: "failed" });
        },
        heartbeat: async () => ({
          worker_id: "worker-1",
          host: "test",
          status: "running",
          current_job_id: job.id,
          message: null,
          first_seen_at: FIXED_TIME,
          last_seen_at: FIXED_TIME,
        }),
      },
      pollRepositoryLike: {
        getById: async () => createPoll(),
        getOptionsByPollId: async () => [createOption()],
      },
      pollTallyProofRepositoryLike: {
        getLatestByPollId: async () => null,
      },
      tallyProverLike: {
        generateProofForPoll: async () => ({
          success: false,
          errorCode: "TALLY_WITNESS_INVALID",
          message: "At least one accepted encrypted vote cannot be decrypted.",
        }),
      },
      publicAuditServiceLike: {
        submitTallyProof: async () => {
          throw new Error("submit should not be called");
        },
      },
    });

    const result = await service.processNextJob();

    expect(result).toMatchObject({
      claimed: true,
      status: "failed",
    });
    expect(failedInput).toMatchObject({
      jobId: job.id,
      errorCode: "TALLY_WITNESS_INVALID",
      retryable: false,
    });
  });
});
