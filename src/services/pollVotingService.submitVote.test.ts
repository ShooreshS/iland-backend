import { describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import identityProfileRepository from "../repositories/identityProfileRepository";
import pollMapRefreshQueueRepository from "../repositories/pollMapRefreshQueueRepository";
import pollRepository from "../repositories/pollRepository";
import pollZkVoteRepository from "../repositories/pollZkVoteRepository";
import verifiedIdentityRepository from "../repositories/verifiedIdentityRepository";
import voteRepository from "../repositories/voteRepository";
import {
  CIVIC_PRODUCTION_HASH_SUITE,
  CIVIC_PRODUCTION_PROOF_ENVELOPE_VERSION,
  CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
  CIVIC_PRODUCTION_PROOF_PROTOCOL,
  CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
  CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
  hashEncryptedVotePayload,
  hashGroth16VotePublicInputs,
  type Groth16VoteProofEnvelopeDto,
  type Groth16VotePublicInputsDto,
} from "./groth16ProofVerifierService";
import { canonicalizeJson } from "./pollPolicyService";
import { createPollVotingService, pollVotingService } from "./pollVotingService";
import type {
  IdentityProfileRow,
  PollMapRefreshQueueRow,
  PollOptionRow,
  PollRow,
  PollZkVoteRow,
  UserRow,
  VerifiedIdentityRow,
  VoteRow,
} from "../types/db";
import type { ProductionVotePrivacyPayloadDto } from "../types/contracts";

const FIXED_TIME = "2026-04-06T12:00:00.000Z";
const POLL_POLICY_HASH = "1".repeat(64);
const CREDENTIAL_SCHEMA_HASH = "2".repeat(64);
const NULLIFIER = "3".repeat(64);
const OPTION_SET_HASH = "4".repeat(64);
const PRODUCTION_NULLIFIER = "5".repeat(64);
const PRODUCTION_VOTE_COMMITMENT = "6".repeat(64);
const PRODUCTION_CREDENTIAL_ROOT = "7".repeat(64);
const PRODUCTION_VERIFIER_KEY_HASH = "8".repeat(64);
const PRODUCTION_PROOF_HASH = "9".repeat(64);
const PRODUCTION_CIRCUIT_ID = "civicos-groth16-vote-circuit-v1";

const sha256Hex = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

const createViewer = (overrides: Partial<UserRow> = {}): UserRow => {
  const next = {
    id: "viewer-user-1",
    username: null,
    display_name: null,
    public_nickname: null,
    onboarding_status: "identity_pending",
    verification_level: "nid_verified",
    has_wallet: false,
    wallet_credential_id: null,
    selected_land_id: null,
    preferred_language: null,
    auth_generation: 1,
    account_status: "active" as const,
    created_at: FIXED_TIME,
    updated_at: FIXED_TIME,
    ...overrides,
  };

  return {
    ...next,
    auth_generation: next.auth_generation ?? 1,
    account_status: next.account_status ?? "active",
  };
};

const createPoll = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "poll-1",
  slug: "poll-1",
  created_by_user_id: null,
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

const createIdentityProfile = (
  overrides: Partial<IdentityProfileRow> = {},
): IdentityProfileRow => ({
  id: "identity-profile-1",
  user_id: "viewer-user-1",
  passport_scan_completed: true,
  passport_nfc_completed: true,
  national_id_scan_completed: false,
  face_scan_completed: false,
  face_bound_to_identity: false,
  passport_verified_at: null,
  national_id_verified_at: null,
  face_verified_at: null,
  document_country_code: null,
  issuing_country_code: null,
  home_country_code: null,
  home_area_id: null,
  home_approx_latitude: null,
  home_approx_longitude: null,
  home_location_source: "user_selected",
  home_location_updated_at: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createVerifiedIdentity = (
  overrides: Partial<VerifiedIdentityRow> = {},
): VerifiedIdentityRow => ({
  id: "verified-identity-1",
  user_id: "viewer-user-1",
  canonical_identity_key: "canonical-key-1",
  normalization_version: 1,
  verification_method: "passport_nfc",
  verified_at: FIXED_TIME,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createVote = (overrides: Partial<VoteRow> = {}): VoteRow => ({
  id: "vote-1",
  poll_id: "poll-1",
  option_id: "option-1",
  user_id: "viewer-user-1",
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

const createPollZkVote = (
  overrides: Partial<PollZkVoteRow> = {},
): PollZkVoteRow => ({
  id: "zk-vote-1",
  poll_id: "poll-1",
  nullifier: PRODUCTION_NULLIFIER,
  vote_commitment: PRODUCTION_VOTE_COMMITMENT,
  encrypted_vote: createEncryptedVotePayload(),
  encrypted_vote_hash: hashEncryptedVotePayload(createEncryptedVotePayload()),
  proof_hash: PRODUCTION_PROOF_HASH,
  proof_system_version: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
  verification_method_version: "civicos-mobile-verification-v1",
  proof_verification_status: "verified",
  proof_public_inputs_json: {},
  proof_envelope_hash: PRODUCTION_PROOF_HASH,
  verifier_key_hash: PRODUCTION_VERIFIER_KEY_HASH,
  circuit_id: PRODUCTION_CIRCUIT_ID,
  accepted_at: FIXED_TIME,
  batch_id: null,
  created_at: FIXED_TIME,
  ...overrides,
});

const createVotePrivacyPayload = (
  overrides: {
    pollId?: string;
    pollPolicyHash?: string;
    credentialSchemaHash?: string;
    nullifier?: string;
  } = {},
) => {
  const publicInputs = {
    pollId: overrides.pollId ?? "poll-1",
    pollPolicyHash: overrides.pollPolicyHash ?? POLL_POLICY_HASH,
    credentialSchemaHash:
      overrides.credentialSchemaHash ?? CREDENTIAL_SCHEMA_HASH,
    nullifier: overrides.nullifier ?? NULLIFIER,
    verificationMethodVersion: "civicos-mobile-verification-v1",
    proofSystemVersion: "civicos-zk-proof-v1-preprover",
  };

  return {
    version: "civicos-vote-privacy-v1",
    hashSuite: "sha256-sha512-preposeidon-v1",
    nullifier: publicInputs.nullifier,
    proof: {
      version: "civicos-proof-envelope-v1",
      proofSystemVersion: "civicos-zk-proof-v1-preprover",
      status: "not_generated",
      reason: "prover_not_integrated",
      publicInputs,
      publicInputsHash: sha256Hex(
        `org.civicos.identity|proof-public-inputs|${canonicalizeJson(publicInputs)}`,
      ),
    },
  };
};

const createEncryptedVotePayload = () => ({
  version: "civicos-encrypted-vote-v1" as const,
  pollEncryptionKeyId: "poll-key-1",
  ciphertext: "base64:ciphertext",
  nonce: "base64:nonce",
  algorithm: "xchacha20-poly1305-v1",
  optionSetHash: OPTION_SET_HASH,
});

const createProductionVotePrivacyPayload = (
  encryptedVoteHash: string,
): ProductionVotePrivacyPayloadDto => {
  const publicInputs: Groth16VotePublicInputsDto = {
    version: CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
    pollId: "poll-1",
    pollPolicyHash: POLL_POLICY_HASH,
    credentialSchemaHash: CREDENTIAL_SCHEMA_HASH,
    optionSetHash: OPTION_SET_HASH,
    credentialRoot: PRODUCTION_CREDENTIAL_ROOT,
    nullifier: PRODUCTION_NULLIFIER,
    voteCommitment: PRODUCTION_VOTE_COMMITMENT,
    encryptedVoteHash,
    verificationMethodVersion: "civicos-mobile-verification-v1",
    proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
    hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
    circuitId: PRODUCTION_CIRCUIT_ID,
    verifierKeyHash: PRODUCTION_VERIFIER_KEY_HASH,
    publicInputSchemaVersion: CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
  };
  const proof: Groth16VoteProofEnvelopeDto = {
    version: CIVIC_PRODUCTION_PROOF_ENVELOPE_VERSION,
    protocol: CIVIC_PRODUCTION_PROOF_PROTOCOL,
    proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
    status: CIVIC_PRODUCTION_PROOF_GENERATED_STATUS,
    hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
    circuitId: PRODUCTION_CIRCUIT_ID,
    verifierKeyHash: PRODUCTION_VERIFIER_KEY_HASH,
    publicInputSchemaVersion: CIVIC_PRODUCTION_PUBLIC_INPUT_SCHEMA_VERSION,
    proof: {
      pi_a: ["1", "2", "1"],
      pi_b: [
        ["3", "4"],
        ["5", "6"],
        ["1", "0"],
      ],
      pi_c: ["7", "8", "1"],
    },
    publicInputs,
    publicInputsHash: hashGroth16VotePublicInputs(publicInputs),
  };

  return {
    version: "civicos-vote-privacy-v1" as const,
    votePrivacyMode: "zk_secret_ballot_v1" as const,
    hashSuite: CIVIC_PRODUCTION_HASH_SUITE,
    nullifier: PRODUCTION_NULLIFIER,
    voteCommitment: PRODUCTION_VOTE_COMMITMENT,
    encryptedVoteHash,
    proof: proof as unknown as ProductionVotePrivacyPayloadDto["proof"],
  };
};

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

describe("pollVotingService.submitVote", () => {
  it("rejects verified poll vote when viewer has no linked verified identity", async () => {
    const viewer = createViewer();
    const poll = createPoll({ requires_verified_identity: true });
    const option = createOption();

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionByIdForPoll", async () => option),
      patchMethod(verifiedIdentityRepository, "getByUserId", async () => null),
    ];

    try {
      const result = await pollVotingService.submitVote({
        pollId: poll.id,
        optionId: option.id,
        viewer,
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errorCode).toBe("ELIGIBILITY_FAILED");
        expect(result.message).toContain("linked verified identity");
      }
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("accepts first verified vote, persists rounded snapshot coordinates, and enqueues refresh", async () => {
    const viewer = createViewer();
    const poll = createPoll({ requires_verified_identity: true });
    const option = createOption();
    const verifiedIdentity = createVerifiedIdentity();
    const identityProfile = createIdentityProfile({
      home_approx_latitude: 35.756,
      home_approx_longitude: 51.444,
    });

    let insertedPayload: unknown = null;
    let enqueueCalls = 0;

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionByIdForPoll", async () => option),
      patchMethod(
        verifiedIdentityRepository,
        "getByUserId",
        async () => verifiedIdentity,
      ),
      patchMethod(
        voteRepository,
        "getByVerifiedIdentityIdAndPollId",
        async () => null,
      ),
      patchMethod(identityProfileRepository, "getByUserId", async () => identityProfile),
      patchMethod(
        pollMapRefreshQueueRepository,
        "enqueuePoll",
        async (pollId: string) => {
          enqueueCalls += 1;
          return createQueueRow({
            poll_id: pollId,
            pending_vote_events: enqueueCalls,
          });
        },
      ),
      patchMethod(voteRepository, "insert", async (input) => {
        insertedPayload = input;
        return createVote({
          poll_id: input.poll_id,
          option_id: input.option_id,
          user_id: input.user_id,
          verified_identity_id: input.verified_identity_id ?? null,
          submitted_at: input.submitted_at,
        });
      }),
    ];

    try {
      const result = await pollVotingService.submitVote({
        pollId: poll.id,
        optionId: option.id,
        viewer,
      });

      expect(result.success).toBe(true);
      expect(insertedPayload).toMatchObject({
        poll_id: poll.id,
        option_id: option.id,
        user_id: viewer.id,
        verified_identity_id: verifiedIdentity.id,
        vote_latitude_l0: 35.76,
        vote_longitude_l0: 51.44,
        vote_location_snapshot_version: 1,
      });
      expect(
        (
          insertedPayload as {
            vote_location_snapshot_at?: string | null;
          }
        ).vote_location_snapshot_at,
      ).toBeTruthy();
      expect(enqueueCalls).toBe(1);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("accepts proof-enabled verified vote and persists proof audit metadata", async () => {
    const viewer = createViewer();
    const poll = createPoll({
      requires_verified_identity: true,
      poll_policy_hash: POLL_POLICY_HASH,
      credential_schema_hash: CREDENTIAL_SCHEMA_HASH,
    });
    const option = createOption();
    const verifiedIdentity = createVerifiedIdentity();
    const identityProfile = createIdentityProfile();
    const privacy = createVotePrivacyPayload();

    let insertedPayload: unknown = null;
    let enqueueCalls = 0;
    let duplicateNullifierLookup:
      | { pollId: string; nullifier: string }
      | undefined;

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionByIdForPoll", async () => option),
      patchMethod(
        verifiedIdentityRepository,
        "getByUserId",
        async () => verifiedIdentity,
      ),
      patchMethod(
        voteRepository,
        "getByVerifiedIdentityIdAndPollId",
        async () => null,
      ),
      patchMethod(identityProfileRepository, "getByUserId", async () => identityProfile),
      patchMethod(
        voteRepository,
        "getByPollIdAndNullifier",
        async (pollId: string, nullifier: string) => {
          duplicateNullifierLookup = { pollId, nullifier };
          return null;
        },
      ),
      patchMethod(
        pollMapRefreshQueueRepository,
        "enqueuePoll",
        async (pollId: string) => {
          enqueueCalls += 1;
          return createQueueRow({
            poll_id: pollId,
            pending_vote_events: enqueueCalls,
          });
        },
      ),
      patchMethod(voteRepository, "insert", async (input) => {
        insertedPayload = input;
        return createVote({
          poll_id: input.poll_id,
          option_id: input.option_id,
          user_id: input.user_id,
          verified_identity_id: input.verified_identity_id ?? null,
          nullifier: input.nullifier ?? null,
          vote_commitment: input.vote_commitment ?? null,
          proof_hash: input.proof_hash ?? null,
          proof_system_version: input.proof_system_version ?? null,
          verification_method_version: input.verification_method_version ?? null,
          proof_verification_status: input.proof_verification_status ?? null,
          proof_public_inputs_json: input.proof_public_inputs_json ?? null,
          proof_envelope_json: input.proof_envelope_json ?? null,
          accepted_at: input.accepted_at ?? null,
          submitted_at: input.submitted_at,
        });
      }),
    ];

    try {
      const result = await pollVotingService.submitVote({
        pollId: poll.id,
        optionId: option.id,
        viewer,
        privacy,
      });

      expect(result.success).toBe(true);
      expect(duplicateNullifierLookup).toEqual({
        pollId: poll.id,
        nullifier: NULLIFIER,
      });
      expect(insertedPayload).toMatchObject({
        poll_id: poll.id,
        option_id: option.id,
        user_id: viewer.id,
        verified_identity_id: verifiedIdentity.id,
        nullifier: NULLIFIER,
        proof_system_version: "civicos-zk-proof-v1-preprover",
        verification_method_version: "civicos-mobile-verification-v1",
        proof_verification_status: "preprover_accepted",
        proof_public_inputs_json: privacy.proof.publicInputs,
        proof_envelope_json: privacy.proof,
      });
      expect(
        (insertedPayload as { proof_hash?: string | null }).proof_hash,
      ).toMatch(/^[0-9a-f]{64}$/);
      expect(
        (insertedPayload as { vote_commitment?: string | null }).vote_commitment,
      ).toMatch(/^[0-9a-f]{64}$/);
      expect(
        (insertedPayload as { accepted_at?: string | null }).accepted_at,
      ).toBeTruthy();
      if (!result.success) {
        throw new Error("Expected successful vote.");
      }
      expect(result.receipt).toMatchObject({
        version: "civicos-vote-receipt-v1",
        pollId: poll.id,
        optionId: option.id,
        batchStatus: "pending",
        batchId: null,
        solanaRootTransaction: null,
        auditUrl: `/polls/${poll.id}/audit`,
      });
      expect(result.receipt?.voteCommitment).toMatch(/^[0-9a-f]{64}$/);
      expect(result.receipt?.voteCommitmentLeafHash).toMatch(/^[0-9a-f]{64}$/);
      expect(result.receipt?.proofHash).toMatch(/^[0-9a-f]{64}$/);
      expect(enqueueCalls).toBe(1);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("routes production ZKP votes to anonymous poll_zk_votes storage", async () => {
    const viewer = createViewer();
    const poll = createPoll({
      requires_verified_identity: true,
      poll_policy_hash: POLL_POLICY_HASH,
      credential_schema_hash: CREDENTIAL_SCHEMA_HASH,
      vote_privacy_mode: "zk_secret_ballot_v1",
      option_set_hash: OPTION_SET_HASH,
      poll_encryption_key_id: "poll-key-1",
    });
    const option = createOption();
    const verifiedIdentity = createVerifiedIdentity();
    const identityProfile = createIdentityProfile();
    const encryptedVote = createEncryptedVotePayload();
    const encryptedVoteHash = hashEncryptedVotePayload(encryptedVote);
    const privacy = createProductionVotePrivacyPayload(encryptedVoteHash);
    const service = createPollVotingService({
      verifyGroth16VoteProofForPoll: async (input) => {
        expect(input.poll.id).toBe(poll.id);
        expect(input.encryptedVoteHash).toBe(encryptedVoteHash);
        expect(input.expectedVoteCommitment).toBe(PRODUCTION_VOTE_COMMITMENT);
        return {
          ok: true,
          auditMaterial: {
            nullifier: PRODUCTION_NULLIFIER,
            voteCommitment: PRODUCTION_VOTE_COMMITMENT,
            encryptedVoteHash,
            proofHash: PRODUCTION_PROOF_HASH,
            proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
            verificationMethodVersion: "civicos-mobile-verification-v1",
            proofVerificationStatus: "verified",
            proofPublicInputsJson: privacy.proof.publicInputs,
            proofEnvelopeHash: PRODUCTION_PROOF_HASH,
            verifierKeyHash: PRODUCTION_VERIFIER_KEY_HASH,
            circuitId: PRODUCTION_CIRCUIT_ID,
          },
        };
      },
    });

    let insertedPayload: Record<string, unknown> | null = null;
    let legacyInsertCalls = 0;
    let verifiedIdentityDuplicateChecks = 0;

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionByIdForPoll", async () => option),
      patchMethod(
        verifiedIdentityRepository,
        "getByUserId",
        async () => verifiedIdentity,
      ),
      patchMethod(
        voteRepository,
        "getByVerifiedIdentityIdAndPollId",
        async () => {
          verifiedIdentityDuplicateChecks += 1;
          return null;
        },
      ),
      patchMethod(identityProfileRepository, "getByUserId", async () => identityProfile),
      patchMethod(
        pollZkVoteRepository,
        "getByPollIdAndNullifier",
        async () => null,
      ),
      patchMethod(voteRepository, "insert", async (input) => {
        legacyInsertCalls += 1;
        return createVote({
          poll_id: input.poll_id,
          option_id: input.option_id,
          user_id: input.user_id,
        });
      }),
      patchMethod(pollZkVoteRepository, "insertVerified", async (input) => {
        insertedPayload = input as Record<string, unknown>;
        return createPollZkVote({
          poll_id: input.poll_id,
          nullifier: input.nullifier,
          vote_commitment: input.vote_commitment,
          encrypted_vote: input.encrypted_vote,
          encrypted_vote_hash: input.encrypted_vote_hash,
          proof_hash: input.proof_hash,
          proof_system_version: input.proof_system_version,
          verification_method_version: input.verification_method_version,
          proof_verification_status: input.proof_verification_status ?? "verified",
          proof_public_inputs_json: input.proof_public_inputs_json,
          proof_envelope_hash: input.proof_envelope_hash,
          verifier_key_hash: input.verifier_key_hash,
          circuit_id: input.circuit_id,
          accepted_at: input.accepted_at ?? FIXED_TIME,
          batch_id: input.batch_id ?? null,
        });
      }),
    ];

    try {
      const result = await service.submitVote({
        pollId: poll.id,
        optionId: option.id,
        viewer,
        privacy,
        encryptedVote,
        expectedVoteCommitment: PRODUCTION_VOTE_COMMITMENT,
      });

      expect(result.success).toBe(true);
      expect(legacyInsertCalls).toBe(0);
      expect(verifiedIdentityDuplicateChecks).toBe(0);
      const insertedRecord = insertedPayload as Record<string, unknown> | null;
      expect(insertedRecord).toMatchObject({
        poll_id: poll.id,
        nullifier: PRODUCTION_NULLIFIER,
        vote_commitment: PRODUCTION_VOTE_COMMITMENT,
        encrypted_vote: encryptedVote,
        encrypted_vote_hash: encryptedVoteHash,
        proof_hash: PRODUCTION_PROOF_HASH,
        proof_system_version: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
        proof_verification_status: "verified",
        proof_envelope_hash: PRODUCTION_PROOF_HASH,
        verifier_key_hash: PRODUCTION_VERIFIER_KEY_HASH,
        circuit_id: PRODUCTION_CIRCUIT_ID,
        batch_id: null,
      });
      expect(insertedRecord?.user_id).toBeUndefined();
      expect(insertedRecord?.verified_identity_id).toBeUndefined();
      expect(insertedRecord?.option_id).toBeUndefined();
      expect(insertedRecord?.vote_latitude_l0).toBeUndefined();
      if (!result.success) {
        throw new Error("Expected production vote success.");
      }
      expect(result.receipt).toMatchObject({
        pollId: poll.id,
        optionId: option.id,
        voteCommitment: PRODUCTION_VOTE_COMMITMENT,
        proofHash: PRODUCTION_PROOF_HASH,
      });
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("rejects production ZKP encrypted vote hash mismatch before inserting", async () => {
    const viewer = createViewer();
    const poll = createPoll({
      requires_verified_identity: true,
      poll_policy_hash: POLL_POLICY_HASH,
      credential_schema_hash: CREDENTIAL_SCHEMA_HASH,
      vote_privacy_mode: "zk_secret_ballot_v1",
      option_set_hash: OPTION_SET_HASH,
      poll_encryption_key_id: "poll-key-1",
    });
    const option = createOption();
    const verifiedIdentity = createVerifiedIdentity();
    const identityProfile = createIdentityProfile();
    const encryptedVote = createEncryptedVotePayload();
    const privacy = createProductionVotePrivacyPayload("a".repeat(64));
    const service = createPollVotingService({
      verifyGroth16VoteProofForPoll: async () => {
        throw new Error("Verifier should not be called for encrypted vote mismatch.");
      },
    });
    let insertCalls = 0;

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionByIdForPoll", async () => option),
      patchMethod(
        verifiedIdentityRepository,
        "getByUserId",
        async () => verifiedIdentity,
      ),
      patchMethod(identityProfileRepository, "getByUserId", async () => identityProfile),
      patchMethod(pollZkVoteRepository, "insertVerified", async (input) => {
        insertCalls += 1;
        return createPollZkVote({
          poll_id: input.poll_id,
          nullifier: input.nullifier,
        });
      }),
    ];

    try {
      const result = await service.submitVote({
        pollId: poll.id,
        optionId: option.id,
        viewer,
        privacy,
        encryptedVote,
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errorCode).toBe("PROOF_INVALID");
        expect(result.message).toContain("Encrypted vote hash");
      }
      expect(insertCalls).toBe(0);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("rejects duplicate production ZKP nullifier before inserting", async () => {
    const viewer = createViewer();
    const poll = createPoll({
      requires_verified_identity: true,
      poll_policy_hash: POLL_POLICY_HASH,
      credential_schema_hash: CREDENTIAL_SCHEMA_HASH,
      vote_privacy_mode: "zk_secret_ballot_v1",
      option_set_hash: OPTION_SET_HASH,
      poll_encryption_key_id: "poll-key-1",
    });
    const option = createOption();
    const verifiedIdentity = createVerifiedIdentity();
    const identityProfile = createIdentityProfile();
    const encryptedVote = createEncryptedVotePayload();
    const encryptedVoteHash = hashEncryptedVotePayload(encryptedVote);
    const privacy = createProductionVotePrivacyPayload(encryptedVoteHash);
    const service = createPollVotingService({
      verifyGroth16VoteProofForPoll: async () => ({
        ok: true,
        auditMaterial: {
          nullifier: PRODUCTION_NULLIFIER,
          voteCommitment: PRODUCTION_VOTE_COMMITMENT,
          encryptedVoteHash,
          proofHash: PRODUCTION_PROOF_HASH,
          proofSystemVersion: CIVIC_PRODUCTION_PROOF_SYSTEM_VERSION,
          verificationMethodVersion: "civicos-mobile-verification-v1",
          proofVerificationStatus: "verified",
          proofPublicInputsJson: privacy.proof.publicInputs,
          proofEnvelopeHash: PRODUCTION_PROOF_HASH,
          verifierKeyHash: PRODUCTION_VERIFIER_KEY_HASH,
          circuitId: PRODUCTION_CIRCUIT_ID,
        },
      }),
    });
    let insertCalls = 0;

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionByIdForPoll", async () => option),
      patchMethod(
        verifiedIdentityRepository,
        "getByUserId",
        async () => verifiedIdentity,
      ),
      patchMethod(identityProfileRepository, "getByUserId", async () => identityProfile),
      patchMethod(
        pollZkVoteRepository,
        "getByPollIdAndNullifier",
        async () => createPollZkVote(),
      ),
      patchMethod(pollZkVoteRepository, "insertVerified", async (input) => {
        insertCalls += 1;
        return createPollZkVote({
          poll_id: input.poll_id,
          nullifier: input.nullifier,
        });
      }),
    ];

    try {
      const result = await service.submitVote({
        pollId: poll.id,
        optionId: option.id,
        viewer,
        privacy,
        encryptedVote,
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errorCode).toBe("ALREADY_VOTED");
        expect(result.message).toContain("proof nullifier");
      }
      expect(insertCalls).toBe(0);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("rejects duplicate proof nullifier before inserting a vote", async () => {
    const viewer = createViewer();
    const poll = createPoll({
      requires_verified_identity: true,
      poll_policy_hash: POLL_POLICY_HASH,
      credential_schema_hash: CREDENTIAL_SCHEMA_HASH,
    });
    const option = createOption();
    const verifiedIdentity = createVerifiedIdentity();
    const identityProfile = createIdentityProfile();
    let insertCalls = 0;

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionByIdForPoll", async () => option),
      patchMethod(
        verifiedIdentityRepository,
        "getByUserId",
        async () => verifiedIdentity,
      ),
      patchMethod(
        voteRepository,
        "getByVerifiedIdentityIdAndPollId",
        async () => null,
      ),
      patchMethod(identityProfileRepository, "getByUserId", async () => identityProfile),
      patchMethod(voteRepository, "getByPollIdAndNullifier", async () =>
        createVote({
          poll_id: poll.id,
          nullifier: NULLIFIER,
        }),
      ),
      patchMethod(voteRepository, "insert", async (input) => {
        insertCalls += 1;
        return createVote({
          poll_id: input.poll_id,
          option_id: input.option_id,
          user_id: input.user_id,
        });
      }),
    ];

    try {
      const result = await pollVotingService.submitVote({
        pollId: poll.id,
        optionId: option.id,
        viewer,
        privacy: createVotePrivacyPayload(),
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errorCode).toBe("ALREADY_VOTED");
        expect(result.message).toContain("proof nullifier");
      }
      expect(insertCalls).toBe(0);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("rejects proof when policy hash does not match the registered poll policy", async () => {
    const viewer = createViewer();
    const poll = createPoll({
      requires_verified_identity: true,
      poll_policy_hash: POLL_POLICY_HASH,
      credential_schema_hash: CREDENTIAL_SCHEMA_HASH,
    });
    const option = createOption();
    const verifiedIdentity = createVerifiedIdentity();
    const identityProfile = createIdentityProfile();

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionByIdForPoll", async () => option),
      patchMethod(
        verifiedIdentityRepository,
        "getByUserId",
        async () => verifiedIdentity,
      ),
      patchMethod(
        voteRepository,
        "getByVerifiedIdentityIdAndPollId",
        async () => null,
      ),
      patchMethod(identityProfileRepository, "getByUserId", async () => identityProfile),
    ];

    try {
      const result = await pollVotingService.submitVote({
        pollId: poll.id,
        optionId: option.id,
        viewer,
        privacy: createVotePrivacyPayload({
          pollPolicyHash: "9".repeat(64),
        }),
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errorCode).toBe("PROOF_INVALID");
        expect(result.message).toContain("poll policy hash");
      }
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("rejects second verified vote from the same verified identity", async () => {
    const viewer = createViewer();
    const poll = createPoll({ requires_verified_identity: true });
    const option = createOption();
    const verifiedIdentity = createVerifiedIdentity();

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionByIdForPoll", async () => option),
      patchMethod(
        verifiedIdentityRepository,
        "getByUserId",
        async () => verifiedIdentity,
      ),
      patchMethod(voteRepository, "getByVerifiedIdentityIdAndPollId", async () =>
        createVote({
          verified_identity_id: verifiedIdentity.id,
        }),
      ),
    ];

    try {
      const result = await pollVotingService.submitVote({
        pollId: poll.id,
        optionId: option.id,
        viewer,
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errorCode).toBe("ALREADY_VOTED");
        expect(result.message).toContain("verified identity");
      }
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("enforces verified uniqueness by verified_identity_id even when prior vote user_id differs", async () => {
    const viewer = createViewer({
      id: "viewer-user-2",
    });
    const poll = createPoll({ requires_verified_identity: true });
    const option = createOption();
    const verifiedIdentity = createVerifiedIdentity({
      id: "verified-identity-shared-1",
      user_id: viewer.id,
    });

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionByIdForPoll", async () => option),
      patchMethod(
        verifiedIdentityRepository,
        "getByUserId",
        async () => verifiedIdentity,
      ),
      patchMethod(voteRepository, "getByVerifiedIdentityIdAndPollId", async () =>
        createVote({
          user_id: "canonical-user-1",
          verified_identity_id: verifiedIdentity.id,
        }),
      ),
    ];

    try {
      const result = await pollVotingService.submitVote({
        pollId: poll.id,
        optionId: option.id,
        viewer,
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errorCode).toBe("ALREADY_VOTED");
        expect(result.message).toContain("verified identity");
      }
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("keeps provisional non-verified poll vote behavior unchanged", async () => {
    const viewer = createViewer({
      verification_level: "anonymous",
    });
    const poll = createPoll({ requires_verified_identity: false });
    const option = createOption();

    let insertedPayload: unknown = null;
    let enqueueCalls = 0;

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionByIdForPoll", async () => option),
      patchMethod(voteRepository, "getByUserIdAndPollId", async () => null),
      patchMethod(identityProfileRepository, "getByUserId", async () => null),
      patchMethod(
        pollMapRefreshQueueRepository,
        "enqueuePoll",
        async (pollId: string) => {
          enqueueCalls += 1;
          return createQueueRow({
            poll_id: pollId,
            pending_vote_events: enqueueCalls,
          });
        },
      ),
      patchMethod(voteRepository, "insert", async (input) => {
        insertedPayload = input;
        return createVote({
          poll_id: input.poll_id,
          option_id: input.option_id,
          user_id: input.user_id,
          verified_identity_id: input.verified_identity_id ?? null,
          submitted_at: input.submitted_at,
        });
      }),
    ];

    try {
      const result = await pollVotingService.submitVote({
        pollId: poll.id,
        optionId: option.id,
        viewer,
      });

      expect(result.success).toBe(true);
      expect(insertedPayload).toMatchObject({
        poll_id: poll.id,
        option_id: option.id,
        user_id: viewer.id,
        verified_identity_id: null,
      });
      expect(enqueueCalls).toBe(1);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("keeps snapshot fields null when profile coordinates are invalid", async () => {
    const viewer = createViewer({
      verification_level: "anonymous",
    });
    const poll = createPoll({ requires_verified_identity: false });
    const option = createOption();
    const identityProfile = createIdentityProfile({
      home_approx_latitude: 120,
      home_approx_longitude: -222,
    });

    let insertedPayload: unknown = null;
    let enqueueCalls = 0;

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionByIdForPoll", async () => option),
      patchMethod(voteRepository, "getByUserIdAndPollId", async () => null),
      patchMethod(identityProfileRepository, "getByUserId", async () => identityProfile),
      patchMethod(
        pollMapRefreshQueueRepository,
        "enqueuePoll",
        async (pollId: string) => {
          enqueueCalls += 1;
          return createQueueRow({
            poll_id: pollId,
            pending_vote_events: enqueueCalls,
          });
        },
      ),
      patchMethod(voteRepository, "insert", async (input) => {
        insertedPayload = input;
        return createVote({
          poll_id: input.poll_id,
          option_id: input.option_id,
          user_id: input.user_id,
          verified_identity_id: input.verified_identity_id ?? null,
          vote_latitude_l0: input.vote_latitude_l0 ?? null,
          vote_longitude_l0: input.vote_longitude_l0 ?? null,
          vote_location_snapshot_at: input.vote_location_snapshot_at ?? null,
          vote_location_snapshot_version: input.vote_location_snapshot_version ?? 1,
          submitted_at: input.submitted_at,
        });
      }),
    ];

    try {
      const result = await pollVotingService.submitVote({
        pollId: poll.id,
        optionId: option.id,
        viewer,
      });

      expect(result.success).toBe(true);
      expect(insertedPayload).toMatchObject({
        poll_id: poll.id,
        option_id: option.id,
        user_id: viewer.id,
        vote_latitude_l0: null,
        vote_longitude_l0: null,
        vote_location_snapshot_at: null,
        vote_location_snapshot_version: 1,
      });
      expect(enqueueCalls).toBe(1);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("maps verified-vote DB uniqueness conflict to ALREADY_VOTED", async () => {
    const viewer = createViewer();
    const poll = createPoll({ requires_verified_identity: true });
    const option = createOption();
    const verifiedIdentity = createVerifiedIdentity();
    const identityProfile = createIdentityProfile();
    let enqueueCalls = 0;

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionByIdForPoll", async () => option),
      patchMethod(
        verifiedIdentityRepository,
        "getByUserId",
        async () => verifiedIdentity,
      ),
      patchMethod(voteRepository, "getByVerifiedIdentityIdAndPollId", async () => null),
      patchMethod(identityProfileRepository, "getByUserId", async () => identityProfile),
      patchMethod(
        pollMapRefreshQueueRepository,
        "enqueuePoll",
        async (pollId: string) => {
          enqueueCalls += 1;
          return createQueueRow({
            poll_id: pollId,
            pending_vote_events: enqueueCalls,
          });
        },
      ),
      patchMethod(voteRepository, "insert", async () => {
        throw Object.assign(new Error("duplicate key"), {
          code: "23505",
        });
      }),
    ];

    try {
      const result = await pollVotingService.submitVote({
        pollId: poll.id,
        optionId: option.id,
        viewer,
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errorCode).toBe("ALREADY_VOTED");
        expect(result.message).toContain("verified identity");
      }
      expect(enqueueCalls).toBe(0);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });
});
