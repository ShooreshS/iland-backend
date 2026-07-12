import { describe, expect, it } from "bun:test";

import type {
  NewPollEncryptionKeyRow,
  PollEncryptionKeyRow,
  PollRow,
} from "../types/db";
import {
  CIVIC_ENCRYPTED_VOTE_ALGORITHM,
  CIVIC_ENCRYPTED_VOTE_CIPHER,
  CIVIC_ENCRYPTED_VOTE_KEY_AGREEMENT,
  CIVIC_ENCRYPTED_VOTE_KDF,
  CIVIC_POLL_ENCRYPTION_CUSTODY_MODEL,
  buildBallotCustodyPolicy,
  createPollEncryptionKeyService,
  hashPollEncryptionPublicKey,
} from "./pollEncryptionKeyService";

const FIXED_TIME = "2026-07-08T14:00:00.000Z";

const createPoll = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "poll-1",
  slug: "poll-1",
  created_by_user_id: "user-1",
  title: "Production ZKP poll",
  description: null,
  status: "active",
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
  ends_at: null,
  poll_policy_json: null,
  poll_policy_hash: "1".repeat(64),
  credential_schema_json: null,
  credential_schema_hash: "2".repeat(64),
  vote_privacy_mode: "zk_secret_ballot_v1",
  option_set_hash: "3".repeat(64),
  poll_encryption_key_id: "poll-key-1",
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createMockRepository = () => {
  const rows: PollEncryptionKeyRow[] = [];

  return {
    rows,
    async getByKeyId(keyId: string): Promise<PollEncryptionKeyRow | null> {
      return rows.find((row) => row.key_id === keyId) || null;
    },
    async getByPollId(pollId: string): Promise<PollEncryptionKeyRow | null> {
      return rows.find((row) => row.poll_id === pollId) || null;
    },
    async insert(input: NewPollEncryptionKeyRow): Promise<PollEncryptionKeyRow> {
      if (
        rows.some(
          (row) => row.key_id === input.key_id || row.poll_id === input.poll_id,
        )
      ) {
        throw { code: "23505", message: "duplicate poll encryption key" };
      }

      const row: PollEncryptionKeyRow = {
        id: `poll-encryption-key-${rows.length + 1}`,
        key_id: input.key_id,
        poll_id: input.poll_id ?? null,
        status: input.status ?? "active",
        algorithm: input.algorithm,
        key_agreement: input.key_agreement,
        kdf: input.kdf,
        cipher: input.cipher,
        public_key_jwk: input.public_key_jwk,
        public_key_hash: input.public_key_hash,
        private_key_jwk: input.private_key_jwk,
        custody_model: input.custody_model ?? CIVIC_POLL_ENCRYPTION_CUSTODY_MODEL,
        created_at: FIXED_TIME,
        revoked_at: null,
        revocation_reason: null,
      };
      rows.push(row);
      return row;
    },
  };
};

describe("pollEncryptionKeyService", () => {
  it("generates and returns a public X25519 poll encryption key", async () => {
    const repository = createMockRepository();
    const service = createPollEncryptionKeyService({
      pollEncryptionKeyRepository: repository,
      pollRepository: {
        getById: async () => createPoll(),
      },
    });

    const result = await service.getOrCreatePublicKeyForPoll("poll-1");

    expect(result.success).toBe(true);
    if (!result.success) {
      throw new Error("Expected key generation success.");
    }

    expect(result.key).toMatchObject({
      version: "civicos-poll-encryption-key-v1",
      pollId: "poll-1",
      pollEncryptionKeyId: "poll-key-1",
      algorithm: CIVIC_ENCRYPTED_VOTE_ALGORITHM,
      keyAgreement: CIVIC_ENCRYPTED_VOTE_KEY_AGREEMENT,
      kdf: CIVIC_ENCRYPTED_VOTE_KDF,
      cipher: CIVIC_ENCRYPTED_VOTE_CIPHER,
      custody: {
        mode: "operator_trusted_private_beta",
        releaseMode: "private_beta",
        decryptor: "backend_service",
        operatorTrusted: true,
        privateKeyMaterialExposedByApi: false,
        threshold: false,
        liveProvisionalPerOptionResults: true,
        acceptedVoteCountPublicDuringVoting: true,
        publicSecretBallotClaimAllowed: false,
      },
    });
    expect(result.key.publicKeyJwk).toMatchObject({
      kty: "OKP",
      crv: "X25519",
    });
    expect(result.key.publicKeyHash).toMatch(/^[0-9a-f]{64}$/);
    expect(result.key.publicKeyHash).toBe(
      hashPollEncryptionPublicKey({
        keyId: "poll-key-1",
        algorithm: CIVIC_ENCRYPTED_VOTE_ALGORITHM,
        keyAgreement: CIVIC_ENCRYPTED_VOTE_KEY_AGREEMENT,
        kdf: CIVIC_ENCRYPTED_VOTE_KDF,
        cipher: CIVIC_ENCRYPTED_VOTE_CIPHER,
        publicKeyJwk: result.key.publicKeyJwk,
      }),
    );
    expect(repository.rows[0].private_key_jwk).toMatchObject({
      kty: "OKP",
      crv: "X25519",
    });
    expect(repository.rows[0].custody_model).toBe(
      CIVIC_POLL_ENCRYPTION_CUSTODY_MODEL,
    );
  });

  it("accepts legacy backend-db custody rows under the private beta policy", async () => {
    const repository = createMockRepository();
    const service = createPollEncryptionKeyService({
      pollEncryptionKeyRepository: repository,
      pollRepository: {
        getById: async () => createPoll(),
      },
    });

    const first = await service.getOrCreatePublicKeyForPoll("poll-1");
    expect(first.success).toBe(true);
    repository.rows[0].custody_model = "backend-db-service-role-v1";

    const second = await service.getOrCreatePublicKeyForPoll("poll-1");

    expect(second.success).toBe(true);
    if (second.success) {
      expect(second.key.custody.model).toBe("backend-db-service-role-v1");
      expect(second.key.custody.mode).toBe("operator_trusted_private_beta");
    }
  });

  it("fails closed when threshold custody is selected before trustee key generation exists", async () => {
    const repository = createMockRepository();
    const service = createPollEncryptionKeyService({
      pollEncryptionKeyRepository: repository,
      pollRepository: {
        getById: async () => createPoll(),
      },
      ballotCustodyPolicy: buildBallotCustodyPolicy({
        mode: "threshold_trustee_v1",
        liveProvisionalResultsEnabled: false,
      }),
    });

    const result = await service.getOrCreatePublicKeyForPoll("poll-1");

    expect(result).toMatchObject({
      success: false,
      errorCode: "ENCRYPTION_CUSTODY_NOT_SUPPORTED",
    });
    expect(repository.rows).toHaveLength(0);
  });

  it("is idempotent for an existing poll key", async () => {
    const repository = createMockRepository();
    const service = createPollEncryptionKeyService({
      pollEncryptionKeyRepository: repository,
      pollRepository: {
        getById: async () => createPoll(),
      },
    });

    const first = await service.getOrCreatePublicKeyForPoll("poll-1");
    const second = await service.getOrCreatePublicKeyForPoll("poll-1");

    expect(first.success).toBe(true);
    expect(second.success).toBe(true);
    expect(repository.rows).toHaveLength(1);
    if (first.success && second.success) {
      expect(second.key.publicKeyHash).toBe(first.key.publicKeyHash);
    }
  });

  it("rejects non-production polls", async () => {
    const service = createPollEncryptionKeyService({
      pollEncryptionKeyRepository: createMockRepository(),
      pollRepository: {
        getById: async () =>
          createPoll({ vote_privacy_mode: "zk_preprover_audit" }),
      },
    });

    const result = await service.getOrCreatePublicKeyForPoll("poll-1");

    expect(result).toMatchObject({
      success: false,
      errorCode: "ENCRYPTION_KEY_NOT_REQUIRED",
    });
  });
});
