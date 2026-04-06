import { describe, expect, it } from "bun:test";
import identityProfileRepository from "../repositories/identityProfileRepository";
import pollRepository from "../repositories/pollRepository";
import verifiedIdentityRepository from "../repositories/verifiedIdentityRepository";
import voteRepository from "../repositories/voteRepository";
import { pollVotingService } from "./pollVotingService";
import type {
  IdentityProfileRow,
  PollOptionRow,
  PollRow,
  UserRow,
  VerifiedIdentityRow,
  VoteRow,
} from "../types/db";

const FIXED_TIME = "2026-04-06T12:00:00.000Z";

const createViewer = (overrides: Partial<UserRow> = {}): UserRow => ({
  id: "viewer-user-1",
  username: null,
  display_name: null,
  onboarding_status: "identity_pending",
  verification_level: "nid_verified",
  has_wallet: false,
  wallet_credential_id: null,
  selected_land_id: null,
  preferred_language: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

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

  it("accepts first verified vote and persists verified_identity_id", async () => {
    const viewer = createViewer();
    const poll = createPoll({ requires_verified_identity: true });
    const option = createOption();
    const verifiedIdentity = createVerifiedIdentity();
    const identityProfile = createIdentityProfile();

    let insertedPayload: unknown = null;

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
      });
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

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionByIdForPoll", async () => option),
      patchMethod(voteRepository, "getByUserIdAndPollId", async () => null),
      patchMethod(identityProfileRepository, "getByUserId", async () => null),
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
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });
});
