import { createHash, generateKeyPairSync } from "node:crypto";

import pollEncryptionKeyRepository from "../repositories/pollEncryptionKeyRepository";
import pollRepository from "../repositories/pollRepository";
import type {
  PollEncryptionKeyDto,
  PollEncryptionKeyResultDto,
} from "../types/contracts";
import type {
  NewPollEncryptionKeyRow,
  PollEncryptionKeyRow,
  PollRow,
} from "../types/db";
import type { JsonValue } from "../types/json";
import {
  type BallotCustodyPolicy,
  OPERATOR_TRUSTED_BACKEND_DB_CUSTODY_MODEL,
  buildBallotCustodyPolicy,
  getBallotCustodyPolicy,
  isAcceptedPollEncryptionCustodyModel,
} from "./ballotCustodyPolicyService";
import { canonicalizeJson } from "./pollPolicyService";

export const CIVIC_POLL_ENCRYPTION_KEY_VERSION =
  "civicos-poll-encryption-key-v1" as const;
export const CIVIC_ENCRYPTED_VOTE_OPENING_VERSION =
  "civicos-encrypted-vote-opening-v1" as const;
export const CIVIC_ENCRYPTED_VOTE_ALGORITHM =
  "x25519-hkdf-sha256-aes-256-gcm-v1" as const;
export const CIVIC_ENCRYPTED_VOTE_KEY_AGREEMENT = "x25519" as const;
export const CIVIC_ENCRYPTED_VOTE_KDF = "hkdf-sha256" as const;
export const CIVIC_ENCRYPTED_VOTE_CIPHER = "aes-256-gcm" as const;
export const CIVIC_ENCRYPTED_VOTE_COMMITMENT_SCHEME =
  "poseidon-encrypted-vote-opening-v1" as const;
export const CIVIC_POLL_ENCRYPTION_CUSTODY_MODEL =
  OPERATOR_TRUSTED_BACKEND_DB_CUSTODY_MODEL;

type PollEncryptionKeyRepositoryPort = Pick<
  typeof pollEncryptionKeyRepository,
  "getByKeyId" | "getByPollId" | "insert"
>;

type PollRepositoryPort = Pick<typeof pollRepository, "getById">;

const normalizeOptionalString = (value: unknown): string | null => {
  const normalized = typeof value === "string" ? value.trim() : "";
  return normalized.length > 0 ? normalized : null;
};

const isProductionZkpPoll = (poll: PollRow): boolean =>
  poll.vote_privacy_mode === "zk_secret_ballot_v1";

const isUniqueViolation = (error: unknown): boolean =>
  Boolean(
    error &&
      typeof error === "object" &&
      (error as { code?: unknown }).code === "23505",
  );

const failure = (
  errorCode: Extract<PollEncryptionKeyResultDto, { success: false }>["errorCode"],
  message: string,
): PollEncryptionKeyResultDto => ({
  success: false,
  errorCode,
  message,
});

const normalizeX25519PublicJwk = (value: JsonValue): {
  kty: "OKP";
  crv: "X25519";
  x: string;
} => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Poll encryption public key must be a JWK object.");
  }
  const record = value as Record<string, JsonValue>;
  if (
    record.kty !== "OKP" ||
    record.crv !== "X25519" ||
    typeof record.x !== "string" ||
    !record.x
  ) {
    throw new Error("Poll encryption public key must be an X25519 JWK.");
  }

  return {
    kty: "OKP",
    crv: "X25519",
    x: record.x,
  };
};

const normalizeX25519PrivateJwk = (value: JsonValue): JsonValue => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Poll encryption private key must be a JWK object.");
  }
  const record = value as Record<string, JsonValue>;
  if (
    record.kty !== "OKP" ||
    record.crv !== "X25519" ||
    typeof record.x !== "string" ||
    typeof record.d !== "string" ||
    !record.x ||
    !record.d
  ) {
    throw new Error("Poll encryption private key must be an X25519 JWK.");
  }

  return {
    kty: "OKP",
    crv: "X25519",
    x: record.x,
    d: record.d,
  };
};

export const hashPollEncryptionPublicKey = (input: {
  keyId: string;
  algorithm: string;
  keyAgreement: string;
  kdf: string;
  cipher: string;
  publicKeyJwk: JsonValue;
}): string =>
  createHash("sha256")
    .update(
      canonicalizeJson({
        version: CIVIC_POLL_ENCRYPTION_KEY_VERSION,
        pollEncryptionKeyId: input.keyId,
        algorithm: input.algorithm,
        keyAgreement: input.keyAgreement,
        kdf: input.kdf,
        cipher: input.cipher,
        publicKeyJwk: normalizeX25519PublicJwk(input.publicKeyJwk),
      }),
      "utf8",
    )
    .digest("hex");

const generatePollEncryptionKey = (input: {
  keyId: string;
  pollId: string;
  custodyModel: string;
}): NewPollEncryptionKeyRow => {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  const publicKeyJwk = normalizeX25519PublicJwk(
    publicKey.export({ format: "jwk" }) as JsonValue,
  );
  const privateKeyJwk = normalizeX25519PrivateJwk(
    privateKey.export({ format: "jwk" }) as JsonValue,
  );
  const publicKeyHash = hashPollEncryptionPublicKey({
    keyId: input.keyId,
    algorithm: CIVIC_ENCRYPTED_VOTE_ALGORITHM,
    keyAgreement: CIVIC_ENCRYPTED_VOTE_KEY_AGREEMENT,
    kdf: CIVIC_ENCRYPTED_VOTE_KDF,
    cipher: CIVIC_ENCRYPTED_VOTE_CIPHER,
    publicKeyJwk,
  });

  return {
    key_id: input.keyId,
    poll_id: input.pollId,
    status: "active",
    algorithm: CIVIC_ENCRYPTED_VOTE_ALGORITHM,
    key_agreement: CIVIC_ENCRYPTED_VOTE_KEY_AGREEMENT,
    kdf: CIVIC_ENCRYPTED_VOTE_KDF,
    cipher: CIVIC_ENCRYPTED_VOTE_CIPHER,
    public_key_jwk: publicKeyJwk,
    public_key_hash: publicKeyHash,
    private_key_jwk: privateKeyJwk,
    custody_model: input.custodyModel,
  };
};

const mapRowToDto = (
  row: PollEncryptionKeyRow,
  pollId: string,
  custodyPolicy: BallotCustodyPolicy,
): PollEncryptionKeyDto => ({
  version: CIVIC_POLL_ENCRYPTION_KEY_VERSION,
  pollId,
  pollEncryptionKeyId: row.key_id,
  status: row.status,
  algorithm: CIVIC_ENCRYPTED_VOTE_ALGORITHM,
  keyAgreement: CIVIC_ENCRYPTED_VOTE_KEY_AGREEMENT,
  kdf: CIVIC_ENCRYPTED_VOTE_KDF,
  cipher: CIVIC_ENCRYPTED_VOTE_CIPHER,
  publicKeyJwk: normalizeX25519PublicJwk(row.public_key_jwk),
  publicKeyHash: row.public_key_hash,
  encryptedVoteVersion: "civicos-encrypted-vote-v1",
  encryptedVoteOpeningVersion: CIVIC_ENCRYPTED_VOTE_OPENING_VERSION,
  encryptedVoteCommitmentScheme: CIVIC_ENCRYPTED_VOTE_COMMITMENT_SCHEME,
  custody: {
    model: row.custody_model,
    mode: custodyPolicy.mode,
    releaseMode: custodyPolicy.releaseMode,
    threshold: custodyPolicy.threshold,
    decryptor: custodyPolicy.decryptor,
    operatorTrusted: custodyPolicy.operatorTrusted,
    liveProvisionalPerOptionResults:
      custodyPolicy.liveProvisionalPerOptionResults,
    acceptedVoteCountPublicDuringVoting:
      custodyPolicy.acceptedVoteCountPublicDuringVoting,
    publicSecretBallotClaimAllowed:
      custodyPolicy.publicSecretBallotClaimAllowed,
    privateKeyMaterialExposedByApi: false,
    claim: custodyPolicy.claim,
  },
  createdAt: row.created_at,
});

const rowMatchesContract = (
  row: PollEncryptionKeyRow,
  custodyPolicy: BallotCustodyPolicy,
): boolean =>
  row.status === "active" &&
  isAcceptedPollEncryptionCustodyModel(row.custody_model, custodyPolicy) &&
  row.algorithm === CIVIC_ENCRYPTED_VOTE_ALGORITHM &&
  row.key_agreement === CIVIC_ENCRYPTED_VOTE_KEY_AGREEMENT &&
  row.kdf === CIVIC_ENCRYPTED_VOTE_KDF &&
  row.cipher === CIVIC_ENCRYPTED_VOTE_CIPHER &&
  row.public_key_hash ===
    hashPollEncryptionPublicKey({
      keyId: row.key_id,
      algorithm: row.algorithm,
      keyAgreement: row.key_agreement,
      kdf: row.kdf,
      cipher: row.cipher,
      publicKeyJwk: row.public_key_jwk,
    });

export const createPollEncryptionKeyService = (
  overrides: Partial<{
    pollEncryptionKeyRepository: PollEncryptionKeyRepositoryPort;
    pollRepository: PollRepositoryPort;
    ballotCustodyPolicy: BallotCustodyPolicy;
  }> = {},
) => {
  const keyRepository =
    overrides.pollEncryptionKeyRepository ?? pollEncryptionKeyRepository;
  const polls = overrides.pollRepository ?? pollRepository;
  const getCustodyPolicy = () =>
    overrides.ballotCustodyPolicy ?? getBallotCustodyPolicy();

  return {
    async getOrCreatePublicKeyForPoll(
      pollIdInput: string,
    ): Promise<PollEncryptionKeyResultDto> {
      const pollId = normalizeOptionalString(pollIdInput);
      if (!pollId) {
        return failure("INVALID_INPUT", "Poll id is required.");
      }

      const poll = await polls.getById(pollId);
      if (!poll) {
        return failure("POLL_NOT_FOUND", "The requested poll does not exist.");
      }

      if (!isProductionZkpPoll(poll)) {
        return failure(
          "ENCRYPTION_KEY_NOT_REQUIRED",
          "Only production ZKP polls publish a poll encryption key.",
        );
      }

      const pollEncryptionKeyId = normalizeOptionalString(
        poll.poll_encryption_key_id,
      );
      if (!pollEncryptionKeyId) {
        return failure(
          "ENCRYPTION_KEY_NOT_CONFIGURED",
          "This production ZKP poll does not have a poll encryption key id.",
        );
      }

      const custodyPolicy = getCustodyPolicy();
      if (!custodyPolicy.backendKeyGenerationSupported) {
        return failure(
          "ENCRYPTION_CUSTODY_NOT_SUPPORTED",
          "This ballot custody mode requires an external trustee key service before poll encryption keys can be created.",
        );
      }

      const existingByPoll = await keyRepository.getByPollId(pollId);
      if (
        existingByPoll &&
        existingByPoll.key_id !== pollEncryptionKeyId
      ) {
        return failure(
          "ENCRYPTION_KEY_CONFLICT",
          "This poll is already associated with a different encryption key.",
        );
      }

      const existingByKey = await keyRepository.getByKeyId(pollEncryptionKeyId);
      if (existingByKey) {
        if (existingByKey.poll_id && existingByKey.poll_id !== pollId) {
          return failure(
            "ENCRYPTION_KEY_CONFLICT",
            "This poll encryption key id is already associated with a different poll.",
          );
        }

        if (!rowMatchesContract(existingByKey, custodyPolicy)) {
          return failure(
            "ENCRYPTION_KEY_CONFLICT",
            "This poll encryption key does not match the production encryption contract.",
          );
        }

        return {
          success: true,
          key: mapRowToDto(existingByKey, pollId, custodyPolicy),
        };
      }

      try {
        const inserted = await keyRepository.insert(
          generatePollEncryptionKey({
            keyId: pollEncryptionKeyId,
            pollId,
            custodyModel: custodyPolicy.pollEncryptionKeyCustodyModel,
          }),
        );
        return {
          success: true,
          key: mapRowToDto(inserted, pollId, custodyPolicy),
        };
      } catch (error) {
        if (!isUniqueViolation(error)) {
          throw error;
        }

        const raced = await keyRepository.getByKeyId(pollEncryptionKeyId);
        if (!raced || !rowMatchesContract(raced, custodyPolicy)) {
          return failure(
            "ENCRYPTION_KEY_CONFLICT",
            "The poll encryption key could not be safely created.",
          );
        }

        return {
          success: true,
          key: mapRowToDto(raced, pollId, custodyPolicy),
        };
      }
    },
  };
};

export { buildBallotCustodyPolicy };

export const pollEncryptionKeyService = createPollEncryptionKeyService();

export default pollEncryptionKeyService;
