import { describe, expect, it } from "bun:test";
import {
  createCipheriv,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
} from "node:crypto";
import { createPollEncryptedTallyService } from "./pollEncryptedTallyService";
import {
  CIVIC_ENCRYPTED_VOTE_ALGORITHM,
  CIVIC_ENCRYPTED_VOTE_CIPHER,
  CIVIC_ENCRYPTED_VOTE_KDF,
  CIVIC_ENCRYPTED_VOTE_KEY_AGREEMENT,
} from "./pollEncryptionKeyService";
import { canonicalizeJson } from "./pollPolicyService";
import type {
  PollEncryptionKeyRow,
  PollOptionRow,
  PollRow,
  PollZkVoteRow,
} from "../types/db";
import type { JsonValue } from "../types/json";

const FIXED_TIME = "2026-07-11T10:00:00.000Z";

const base64Url = (value: Buffer): string =>
  value
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

const createPoll = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "poll-1",
  slug: "poll-1",
  created_by_user_id: "owner-1",
  title: "Encrypted Poll",
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
  vote_privacy_mode: "zk_secret_ballot_v1",
  option_set_hash: "a".repeat(64),
  poll_encryption_key_id: "poll-key-1",
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

const createVote = (overrides: Partial<PollZkVoteRow> = {}): PollZkVoteRow => ({
  id: "vote-1",
  poll_id: "poll-1",
  nullifier: "1".repeat(64),
  vote_commitment: "2".repeat(64),
  encrypted_vote: {},
  encrypted_vote_hash: "3".repeat(64),
  encrypted_vote_commitment: "4".repeat(64),
  proof_hash: "5".repeat(64),
  proof_system_version: "groth16",
  verification_method_version: "civicos-mobile-verification-v1",
  proof_verification_status: "verified",
  proof_public_inputs_json: {},
  proof_envelope_hash: "6".repeat(64),
  verifier_key_hash: "7".repeat(64),
  circuit_id: "civicos-groth16-vote-circuit-v1",
  accepted_at: FIXED_TIME,
  batch_id: null,
  created_at: FIXED_TIME,
  ...overrides,
});

const createPollKeyRow = (
  poll: PollRow,
): { keyRow: PollEncryptionKeyRow; publicKeyJwk: JsonValue } => {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  const publicKeyJwk = publicKey.export({ format: "jwk" }) as JsonValue;
  const privateKeyJwk = privateKey.export({ format: "jwk" }) as JsonValue;

  return {
    publicKeyJwk,
    keyRow: {
      id: "poll-key-row-1",
      key_id: poll.poll_encryption_key_id || "poll-key-1",
      poll_id: poll.id,
      status: "active",
      algorithm: CIVIC_ENCRYPTED_VOTE_ALGORITHM,
      key_agreement: CIVIC_ENCRYPTED_VOTE_KEY_AGREEMENT,
      kdf: CIVIC_ENCRYPTED_VOTE_KDF,
      cipher: CIVIC_ENCRYPTED_VOTE_CIPHER,
      public_key_jwk: publicKeyJwk,
      public_key_hash: "8".repeat(64),
      private_key_jwk: privateKeyJwk,
      custody_model: "backend-db-service-role-v1",
      created_at: FIXED_TIME,
      revoked_at: null,
      revocation_reason: null,
    },
  };
};

const encryptOpening = (input: {
  poll: PollRow;
  publicKeyJwk: JsonValue;
  encryptedVoteCommitment: string;
  optionIndex: number;
}): JsonValue => {
  const pollEncryptionKeyId = input.poll.poll_encryption_key_id || "";
  const optionSetHash = input.poll.option_set_hash || "";
  const { privateKey: ephemeralPrivateKey, publicKey: ephemeralPublicKey } =
    generateKeyPairSync("x25519");
  const pollPublicKey = createPublicKey({
    key: input.publicKeyJwk as JsonWebKey,
    format: "jwk",
  });
  const sharedSecret = diffieHellman({
    privateKey: ephemeralPrivateKey,
    publicKey: pollPublicKey,
  });
  const nonce = Buffer.alloc(12, 7);
  const info = Buffer.from(
    `CivicOS encrypted vote:${input.poll.id}:${optionSetHash}`,
    "utf8",
  );
  const key = Buffer.from(hkdfSync("sha256", sharedSecret, nonce, info, 32));
  const aad = Buffer.from(
    canonicalizeJson({
      version: "civicos-encrypted-vote-aad-v1",
      pollId: input.poll.id,
      optionSetHash,
      pollEncryptionKeyId,
    }),
    "utf8",
  );
  const opening = canonicalizeJson({
    version: "civicos-encrypted-vote-opening-v1",
    pollId: input.poll.id,
    optionIndex: input.optionIndex,
    optionSetHash,
    encryptedVoteRandomness: "9".repeat(64),
    encryptedVoteCommitment: input.encryptedVoteCommitment,
  });
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(opening, "utf8")),
    cipher.final(),
  ]);

  return {
    version: "civicos-encrypted-vote-v1",
    pollEncryptionKeyId,
    pollEncryptionKeyHash: "8".repeat(64),
    encryptedVoteCommitment: input.encryptedVoteCommitment,
    ciphertext: base64Url(ciphertext),
    nonce: base64Url(nonce),
    authTag: base64Url(cipher.getAuthTag()),
    algorithm: CIVIC_ENCRYPTED_VOTE_ALGORITHM,
    keyAgreement: CIVIC_ENCRYPTED_VOTE_KEY_AGREEMENT,
    kdf: CIVIC_ENCRYPTED_VOTE_KDF,
    cipher: CIVIC_ENCRYPTED_VOTE_CIPHER,
    ephemeralPublicKey: base64Url(
      Buffer.from(
        ((ephemeralPublicKey.export({ format: "jwk" }) as JsonWebKey).x || "")
          .replace(/-/g, "+")
          .replace(/_/g, "/"),
        "base64",
      ),
    ),
    optionSetHash,
  };
};

describe("pollEncryptedTallyService", () => {
  it("decrypts accepted encrypted votes into provisional option counts", async () => {
    const poll = createPoll();
    const optionA = createOption({ id: "option-a", label: "Yes", display_order: 0 });
    const optionB = createOption({ id: "option-b", label: "No", display_order: 1 });
    const { keyRow, publicKeyJwk } = createPollKeyRow(poll);
    const encryptedVoteCommitment = "b".repeat(64);
    const encryptedVote = encryptOpening({
      poll,
      publicKeyJwk,
      encryptedVoteCommitment,
      optionIndex: 1,
    });
    const vote = createVote({
      encrypted_vote: encryptedVote,
      encrypted_vote_commitment: encryptedVoteCommitment,
      accepted_at: "2026-07-11T10:01:00.000Z",
    });
    const tamperedVote = createVote({
      id: "vote-2",
      encrypted_vote: encryptedVote,
      encrypted_vote_commitment: "c".repeat(64),
      accepted_at: "2026-07-11T10:02:00.000Z",
    });
    const service = createPollEncryptedTallyService({
      pollEncryptionKeys: {
        getByPollId: async () => keyRow,
      },
      pollZkVotes: {
        getAcceptedByPollId: async () => [vote, tamperedVote],
      },
    });

    const tally = await service.getProvisionalTally({
      poll,
      options: [optionB, optionA],
    });

    expect(tally.totalVotes).toBe(1);
    expect(tally.countsByOptionId[optionA.id]).toBe(0);
    expect(tally.countsByOptionId[optionB.id]).toBe(1);
    expect(tally.updatedAt).toBe("2026-07-11T10:01:00.000Z");
  });
});
