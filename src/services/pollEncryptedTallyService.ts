import {
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
} from "node:crypto";

import pollEncryptionKeyRepository from "../repositories/pollEncryptionKeyRepository";
import pollZkVoteRepository from "../repositories/pollZkVoteRepository";
import type { PollOptionRow, PollRow, PollZkVoteRow } from "../types/db";
import type { JsonValue } from "../types/json";
import {
  type BallotCustodyPolicy,
  canBackendDecryptPollEncryptionCustodyModel,
  getBallotCustodyPolicy,
} from "./ballotCustodyPolicyService";
import { canonicalizeJson } from "./pollPolicyService";

const ENCRYPTED_VOTE_AAD_VERSION = "civicos-encrypted-vote-aad-v1";
const ENCRYPTED_VOTE_OPENING_VERSION = "civicos-encrypted-vote-opening-v1";
const ENCRYPTED_VOTE_ALGORITHM = "x25519-hkdf-sha256-aes-256-gcm-v1";
const ENCRYPTED_VOTE_KEY_AGREEMENT = "x25519";
const ENCRYPTED_VOTE_KDF = "hkdf-sha256";
const ENCRYPTED_VOTE_CIPHER = "aes-256-gcm";

type PollEncryptedTallyRepositoryDeps = Readonly<{
  pollEncryptionKeys?: Pick<typeof pollEncryptionKeyRepository, "getByPollId">;
  pollZkVotes?: Pick<typeof pollZkVoteRepository, "getAcceptedByPollId">;
  ballotCustodyPolicy?: BallotCustodyPolicy;
}>;

export type ProvisionalEncryptedTally = Readonly<{
  countsByOptionId: Record<string, number>;
  totalVotes: number;
  updatedAt: string | null;
}>;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const asString = (value: unknown): string =>
  typeof value === "string" ? value.trim() : "";

const base64UrlToBuffer = (value: string): Buffer => {
  const normalized = value.trim().replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return Buffer.from(padded, "base64");
};

const normalizePrivateJwk = (value: JsonValue): Record<string, string> => {
  if (!isRecord(value)) {
    throw new Error("Poll encryption private key is unavailable.");
  }

  const kty = asString(value.kty);
  const crv = asString(value.crv);
  const x = asString(value.x);
  const d = asString(value.d);
  if (kty !== "OKP" || crv !== "X25519" || !x || !d) {
    throw new Error("Poll encryption private key is not an X25519 JWK.");
  }

  return { kty, crv, x, d };
};

const decryptVoteOpening = (input: {
  encryptedVote: JsonValue;
  privateKeyJwk: JsonValue;
  poll: PollRow;
}): Record<string, unknown> | null => {
  if (!isRecord(input.encryptedVote)) {
    return null;
  }

  const encryptedVote = input.encryptedVote;
  if (
    asString(encryptedVote.algorithm) !== ENCRYPTED_VOTE_ALGORITHM ||
    asString(encryptedVote.keyAgreement) !== ENCRYPTED_VOTE_KEY_AGREEMENT ||
    asString(encryptedVote.kdf) !== ENCRYPTED_VOTE_KDF ||
    asString(encryptedVote.cipher) !== ENCRYPTED_VOTE_CIPHER ||
    asString(encryptedVote.pollEncryptionKeyId) !==
      asString(input.poll.poll_encryption_key_id)
  ) {
    return null;
  }

  const privateKey = createPrivateKey({
    key: normalizePrivateJwk(input.privateKeyJwk),
    format: "jwk",
  });
  const ephemeralPublicKeyBytes = base64UrlToBuffer(
    asString(encryptedVote.ephemeralPublicKey),
  );
  if (ephemeralPublicKeyBytes.length !== 32) {
    return null;
  }
  const ephemeralPublicKey = createPublicKey({
    key: {
      kty: "OKP",
      crv: "X25519",
      x: asString(encryptedVote.ephemeralPublicKey),
    },
    format: "jwk",
  });
  const nonce = base64UrlToBuffer(asString(encryptedVote.nonce));
  if (nonce.length !== 12) {
    return null;
  }

  const sharedSecret = diffieHellman({
    privateKey,
    publicKey: ephemeralPublicKey,
  });
  const info = Buffer.from(
    `CivicOS encrypted vote:${input.poll.id}:${asString(
      input.poll.option_set_hash,
    )}`,
    "utf8",
  );
  const key = Buffer.from(hkdfSync("sha256", sharedSecret, nonce, info, 32));
  const aad = Buffer.from(
    canonicalizeJson({
      version: ENCRYPTED_VOTE_AAD_VERSION,
      pollId: input.poll.id,
      optionSetHash: asString(input.poll.option_set_hash),
      pollEncryptionKeyId: asString(input.poll.poll_encryption_key_id),
    }),
    "utf8",
  );
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(base64UrlToBuffer(asString(encryptedVote.authTag)));
  const decrypted = Buffer.concat([
    decipher.update(base64UrlToBuffer(asString(encryptedVote.ciphertext))),
    decipher.final(),
  ]).toString("utf8");
  const parsed = JSON.parse(decrypted) as unknown;
  return isRecord(parsed) ? parsed : null;
};

const optionIdsByIndex = (options: readonly PollOptionRow[]): string[] =>
  [...options]
    .filter((option) => option.is_active !== false)
    .sort((left, right) => left.display_order - right.display_order)
    .map((option) => option.id);

const countDecryptedVote = (input: {
  poll: PollRow;
  options: readonly PollOptionRow[];
  countsByOptionId: Record<string, number>;
  vote: PollZkVoteRow;
  privateKeyJwk: JsonValue;
}): boolean => {
  let opening: Record<string, unknown> | null = null;
  try {
    opening = decryptVoteOpening({
      encryptedVote: input.vote.encrypted_vote,
      privateKeyJwk: input.privateKeyJwk,
      poll: input.poll,
    });
  } catch {
    return false;
  }

  if (
    !opening ||
    asString(opening.version) !== ENCRYPTED_VOTE_OPENING_VERSION ||
    asString(opening.pollId) !== input.poll.id ||
    asString(opening.optionSetHash) !== asString(input.poll.option_set_hash) ||
    asString(opening.encryptedVoteCommitment) !==
      input.vote.encrypted_vote_commitment
  ) {
    return false;
  }

  const optionIndex =
    typeof opening.optionIndex === "number"
      ? Math.trunc(opening.optionIndex)
      : Number(asString(opening.optionIndex));
  const optionIds = optionIdsByIndex(input.options);
  const optionId = Number.isInteger(optionIndex)
    ? optionIds[optionIndex]
    : undefined;
  if (!optionId) {
    return false;
  }

  input.countsByOptionId[optionId] =
    (input.countsByOptionId[optionId] || 0) + 1;
  return true;
};

export const createPollEncryptedTallyService = (
  dependencies: PollEncryptedTallyRepositoryDeps = {},
) => {
  const pollEncryptionKeys =
    dependencies.pollEncryptionKeys ?? pollEncryptionKeyRepository;
  const pollZkVotes = dependencies.pollZkVotes ?? pollZkVoteRepository;
  const getCustodyPolicy = () =>
    dependencies.ballotCustodyPolicy ?? getBallotCustodyPolicy();

  return {
    async getProvisionalTally(input: {
      poll: PollRow;
      options: readonly PollOptionRow[];
    }): Promise<ProvisionalEncryptedTally> {
      const countsByOptionId = Object.fromEntries(
        input.options.map((option) => [option.id, 0]),
      ) as Record<string, number>;

      if (!input.poll.poll_encryption_key_id || !input.poll.option_set_hash) {
        return { countsByOptionId, totalVotes: 0, updatedAt: null };
      }

      const [keyRow, votes] = await Promise.all([
        pollEncryptionKeys.getByPollId(input.poll.id),
        pollZkVotes.getAcceptedByPollId(input.poll.id),
      ]);
      if (!keyRow || keyRow.key_id !== input.poll.poll_encryption_key_id) {
        return { countsByOptionId, totalVotes: 0, updatedAt: null };
      }

      const custodyPolicy = getCustodyPolicy();
      if (
        !custodyPolicy.liveProvisionalPerOptionResults ||
        !canBackendDecryptPollEncryptionCustodyModel(
          keyRow.custody_model,
          custodyPolicy,
        )
      ) {
        return { countsByOptionId, totalVotes: 0, updatedAt: null };
      }

      let countedVotes = 0;
      let updatedAt: string | null = null;
      for (const vote of votes) {
        if (
          countDecryptedVote({
            poll: input.poll,
            options: input.options,
            countsByOptionId,
            vote,
            privateKeyJwk: keyRow.private_key_jwk,
          })
        ) {
          countedVotes += 1;
          updatedAt = vote.accepted_at;
        }
      }

      return {
        countsByOptionId,
        totalVotes: countedVotes,
        updatedAt,
      };
    },
  };
};

export const pollEncryptedTallyService = createPollEncryptedTallyService();

export default pollEncryptedTallyService;
