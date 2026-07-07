import { describe, expect, it } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import type {
  NewPollOptionRow,
  NewPollRow,
  PollOptionRow,
  PollRow,
} from "../types/db";
import type { CivicCredentialSchema, CivicPollPolicy } from "./pollPolicyService";

const { privateKey: googleOAuthPrivateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

process.env.AUTH_IOS_TEAM_ID = "DJWBN8658Q";
process.env.AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS = "true";
process.env.AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_CLIENT_EMAIL =
  "play-integrity-test@example.iam.gserviceaccount.com";
process.env.AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY = googleOAuthPrivateKey
  .export({ format: "pem", type: "pkcs8" })
  .toString();
process.env.AUTH_ANDROID_ALLOWED_SIGNING_CERT_DIGESTS =
  "23e31a67fd079259091c31ab079846a30d07f18e66ae675863b18a0a77e66763";

const pollRepository = (await import("../repositories/pollRepository")).default;
const voteRepository = (await import("../repositories/voteRepository")).default;
const { pollDraftService } = await import("./pollDraftService");

const FIXED_TIME = "2026-07-04T12:00:00.000Z";

const createPoll = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "poll-1",
  slug: "poll-1",
  created_by_user_id: "creator-1",
  title: "Test Poll",
  description: null,
  status: "draft",
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
  poll_policy_json: null,
  poll_policy_hash: null,
  credential_schema_json: null,
  credential_schema_hash: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createOption = (
  overrides: Partial<PollOptionRow> = {},
): PollOptionRow => ({
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

const rowFromNewPoll = (input: NewPollRow): PollRow =>
  createPoll({
    id: input.id || "poll-1",
    slug: input.slug,
    created_by_user_id: input.created_by_user_id,
    title: input.title,
    description: input.description,
    status: input.status,
    jurisdiction_type: input.jurisdiction_type,
    jurisdiction_country_code: input.jurisdiction_country_code,
    jurisdiction_area_ids: input.jurisdiction_area_ids,
    jurisdiction_land_ids: input.jurisdiction_land_ids,
    requires_verified_identity: input.requires_verified_identity,
    allowed_document_country_codes: input.allowed_document_country_codes,
    allowed_home_area_ids: input.allowed_home_area_ids,
    allowed_land_ids: input.allowed_land_ids,
    minimum_age: input.minimum_age,
    starts_at: input.starts_at,
    ends_at: input.ends_at,
    poll_policy_json: input.poll_policy_json,
    poll_policy_hash: input.poll_policy_hash,
    credential_schema_json: input.credential_schema_json,
    credential_schema_hash: input.credential_schema_hash,
    vote_privacy_mode: input.vote_privacy_mode,
    option_set_hash: input.option_set_hash,
    poll_encryption_key_id: input.poll_encryption_key_id,
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

describe("pollDraftService ZKP audit material", () => {
  it("stores canonical poll policy and credential schema when creating a poll", async () => {
    let insertedPoll: NewPollRow | null = null;

    const restoreFns = [
      patchMethod(pollRepository, "insert", async (input: NewPollRow) => {
        insertedPoll = input;
        return rowFromNewPoll(input);
      }),
      patchMethod(
        pollRepository,
        "insertOptions",
        async (options: NewPollOptionRow[]) =>
          options.map((option, index) =>
            createOption({
              id: `option-${index + 1}`,
              poll_id: option.poll_id,
              label: option.label,
              description: option.description,
              color: option.color,
              display_order: option.display_order,
              is_active: option.is_active,
              created_at: option.created_at || FIXED_TIME,
            }),
          ),
      ),
    ];

    try {
      const result = await pollDraftService.createPoll(
        {
          title: "Country poll",
          options: ["Yes", "No"],
          status: "draft",
          jurisdictionType: "real_country",
          jurisdictionCountryCode: " ir ",
          eligibilityRule: {
            minimumAge: 18,
          },
        },
        "creator-1",
      );

      expect(result.success).toBe(true);
      expect(insertedPoll).not.toBeNull();
      const insertedPayload = insertedPoll as NewPollRow | null;
      if (!insertedPayload || !result.poll) {
        throw new Error("Expected created poll payload.");
      }

      const policy = insertedPayload.poll_policy_json as CivicPollPolicy;
      const credentialSchema =
        insertedPayload.credential_schema_json as CivicCredentialSchema;
      const insertedPollId = insertedPayload.id;
      const pollPolicyHash = insertedPayload.poll_policy_hash;
      const credentialSchemaHash = insertedPayload.credential_schema_hash;
      const optionSetHash = insertedPayload.option_set_hash;

      if (!insertedPollId || !pollPolicyHash || !credentialSchemaHash || !optionSetHash) {
        throw new Error("Expected poll audit identifiers.");
      }

      expect(insertedPollId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
      expect(pollPolicyHash).toMatch(/^[0-9a-f]{64}$/);
      expect(credentialSchemaHash).toMatch(/^[0-9a-f]{64}$/);
      expect(optionSetHash).toMatch(/^[0-9a-f]{64}$/);
      expect(insertedPayload.vote_privacy_mode).toBe("zk_preprover_audit");
      expect(insertedPayload.poll_encryption_key_id).toBeNull();
      expect(insertedPayload.jurisdiction_country_code).toBe("IR");
      expect(insertedPayload.allowed_document_country_codes).toEqual(["IR"]);
      expect(policy.pollId).toBe(insertedPollId);
      expect(policy.eligibilityRules).toMatchObject({
        requiresVerifiedIdentity: true,
        acceptedDocumentCountryCodes: ["IR"],
        minimumAge: 18,
      });
      expect(credentialSchema.derivedClaims.eligibilityPolicyHash).toBe(
        pollPolicyHash,
      );
      expect(result.poll.pollPolicyHash).toBe(pollPolicyHash);
      expect(result.poll.credentialSchemaHash).toBe(credentialSchemaHash);
      expect(result.poll.optionSetHash).toBe(optionSetHash);
      expect(result.poll.votePrivacyMode).toBe("zk_preprover_audit");
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("rejects production ZKP poll creation without an encryption key id", async () => {
    const result = await pollDraftService.createPoll(
      {
        title: "Secret ballot poll",
        options: ["Yes", "No"],
        status: "draft",
        votePrivacyMode: "zk_secret_ballot_v1",
        eligibilityRule: {
          requiresVerifiedIdentity: true,
        },
      },
      "creator-1",
    );

    expect(result).toMatchObject({
      success: false,
      errorCode: "VALIDATION_FAILED",
    });
    expect(result.message).toContain("poll encryption key id");
  });

  it("stores production ZKP poll contract metadata when encryption key id is present", async () => {
    let insertedPoll: NewPollRow | null = null;

    const restoreFns = [
      patchMethod(pollRepository, "insert", async (input: NewPollRow) => {
        insertedPoll = input;
        return rowFromNewPoll(input);
      }),
      patchMethod(
        pollRepository,
        "insertOptions",
        async (options: NewPollOptionRow[]) =>
          options.map((option, index) =>
            createOption({
              id: option.id || `option-${index + 1}`,
              poll_id: option.poll_id,
              label: option.label,
              description: option.description,
              color: option.color,
              display_order: option.display_order,
              is_active: option.is_active,
              created_at: option.created_at || FIXED_TIME,
            }),
          ),
      ),
    ];

    try {
      const result = await pollDraftService.createPoll(
        {
          title: "Secret ballot poll",
          options: ["Yes", "No"],
          status: "draft",
          votePrivacyMode: "zk_secret_ballot_v1",
          pollEncryptionKeyId: "poll-key-1",
          eligibilityRule: {
            requiresVerifiedIdentity: true,
          },
        },
        "creator-1",
      );

      expect(result.success).toBe(true);
      const insertedPayload = insertedPoll as NewPollRow | null;
      if (!insertedPayload || !result.poll) {
        throw new Error("Expected created poll payload.");
      }

      expect(insertedPayload.vote_privacy_mode).toBe("zk_secret_ballot_v1");
      expect(insertedPayload.poll_encryption_key_id).toBe("poll-key-1");
      const optionSetHash = insertedPayload.option_set_hash;
      if (!optionSetHash) {
        throw new Error("Expected option set hash.");
      }
      expect(optionSetHash).toMatch(/^[0-9a-f]{64}$/);
      expect(insertedPayload.requires_verified_identity).toBe(true);
      expect(result.poll.votePrivacyMode).toBe("zk_secret_ballot_v1");
      expect(result.poll.pollEncryptionKeyId).toBe("poll-key-1");
      expect(result.poll.optionSetHash).toBe(optionSetHash);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("freezes final policy material when publishing a draft", async () => {
    const existingPoll = createPoll({
      id: "22222222-2222-4222-8222-222222222222",
      status: "draft",
      jurisdiction_type: "real_area",
      jurisdiction_area_ids: ["area-b", "area-a"],
      requires_verified_identity: true,
      allowed_home_area_ids: ["area-b", "area-a"],
      starts_at: null,
    });
    const existingOptions = [
      createOption({ id: "option-a", label: "A" }),
      createOption({ id: "option-b", label: "B", display_order: 1 }),
    ];
    let updatedPoll: NewPollRow | null = null;

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => existingPoll),
      patchMethod(pollRepository, "getOptionsByPollId", async () => existingOptions),
      patchMethod(voteRepository, "countByPollId", async () => 0),
      patchMethod(pollRepository, "updateById", async (_pollId, input) => {
        updatedPoll = input;
        return rowFromNewPoll(input);
      }),
    ];

    try {
      const result = await pollDraftService.publishDraftPoll(
        existingPoll.id,
        "creator-1",
      );

      expect(result.success).toBe(true);
      expect(updatedPoll).not.toBeNull();
      const updatedPayload = updatedPoll as NewPollRow | null;
      if (!updatedPayload || !result.poll) {
        throw new Error("Expected published poll payload.");
      }

      const policy = updatedPayload.poll_policy_json as CivicPollPolicy;
      const startsAt = updatedPayload.starts_at;
      const pollPolicyHash = updatedPayload.poll_policy_hash;
      const credentialSchemaHash = updatedPayload.credential_schema_hash;
      const optionSetHash = updatedPayload.option_set_hash;

      if (!startsAt || !pollPolicyHash || !credentialSchemaHash || !optionSetHash) {
        throw new Error("Expected published poll audit material.");
      }

      expect(updatedPayload.id).toBe(existingPoll.id);
      expect(updatedPayload.status).toBe("active");
      expect(startsAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
      expect(pollPolicyHash).toMatch(/^[0-9a-f]{64}$/);
      expect(credentialSchemaHash).toMatch(/^[0-9a-f]{64}$/);
      expect(optionSetHash).toMatch(/^[0-9a-f]{64}$/);
      expect(policy.pollId).toBe(existingPoll.id);
      expect(policy.votingWindow.opensAt).toBe(startsAt);
      expect(policy.eligibilityRules.acceptedHomeAreaIds).toEqual([
        "area-a",
        "area-b",
      ]);
      expect(result.poll.pollPolicyHash).toBe(pollPolicyHash);
      expect(result.poll.optionSetHash).toBe(optionSetHash);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("rejects publishing a production ZKP draft without an encryption key id", async () => {
    const existingPoll = createPoll({
      id: "33333333-3333-4333-8333-333333333333",
      status: "draft",
      requires_verified_identity: true,
      vote_privacy_mode: "zk_secret_ballot_v1",
      poll_encryption_key_id: null,
    });
    const existingOptions = [
      createOption({ id: "option-a", label: "A" }),
      createOption({ id: "option-b", label: "B", display_order: 1 }),
    ];

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => existingPoll),
      patchMethod(pollRepository, "getOptionsByPollId", async () => existingOptions),
      patchMethod(voteRepository, "countByPollId", async () => 0),
    ];

    try {
      const result = await pollDraftService.publishDraftPoll(
        existingPoll.id,
        "creator-1",
      );

      expect(result).toMatchObject({
        success: false,
        errorCode: "VALIDATION_FAILED",
      });
      expect(result.message).toContain("poll encryption key id");
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });
});
