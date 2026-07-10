import { describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import {
  type AccountInfo,
  Keypair,
  PublicKey,
  SystemProgram,
} from "@solana/web3.js";

import type { PollRow } from "../types/db";
import {
  createSolanaAuditPublisherService,
  derivePollIdHash,
  type SolanaAuditConnection,
} from "./solanaAuditPublisherService";

const FIXED_TIME = "2026-07-10T00:00:00.000Z";
const POLL_POLICY_HASH = "1".repeat(64);
const CREDENTIAL_SCHEMA_HASH = "2".repeat(64);
const PREVIOUS_ROOT = "0".repeat(64);
const NULLIFIER_ROOT = "3".repeat(64);
const VOTE_COMMITMENT_ROOT = "4".repeat(64);
const ENCRYPTED_VOTE_ROOT = "5".repeat(64);
const RESULT_HASH = "6".repeat(64);
const RECOVERED_ROOT_SIGNATURE =
  "4YHeA1YVcraxnDLwG5UNRRnUPWz1XgRqRZf6ahck2nssmDmJiFyyo8qFmxUzBGBtuLyYx7KtH6E96fK9RoXynjdx";

const writeU64 = (value: number | bigint): Buffer => {
  const output = Buffer.alloc(8);
  output.writeBigUInt64LE(BigInt(value));
  return output;
};

const anchorAccountDiscriminator = (accountName: string): Buffer =>
  createHash("sha256").update(`account:${accountName}`).digest().subarray(0, 8);

const createPoll = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "poll-1",
  slug: "poll-1",
  created_by_user_id: "owner-1",
  title: "Phase 7 Poll",
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
  starts_at: "2026-07-09T00:00:00.000Z",
  ends_at: "2026-07-09T01:00:00.000Z",
  poll_policy_hash: POLL_POLICY_HASH,
  credential_schema_hash: CREDENTIAL_SCHEMA_HASH,
  vote_privacy_mode: "zk_secret_ballot_v1",
  option_set_hash: "7".repeat(64),
  poll_encryption_key_id: "poll-key-1",
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createAuditEnv = (
  programId: PublicKey,
  feePayer: PublicKey,
  registryAuthority: PublicKey,
) =>
  ({
    cluster: "devnet",
    rpcUrl: "https://api.devnet.solana.com",
    programId: programId.toBase58(),
    tokenMint: "GJRpZhWZcLGP8ZUKggxDTw7y5N3LGXa2gWqKRSLDWiBq",
    tokenProgram: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
    tokenSymbol: "SHOLAN",
    tokenDecimals: 9,
    registryAuthority: registryAuthority.toBase58(),
    rootPublisherPublicKey: feePayer.toBase58(),
    treasury: null,
    feePayerPublicKey: feePayer.toBase58(),
    feePayerSecretKey: null,
    defaultFeeMode: "civicos-sponsored",
    sponsorshipEnabled: true,
    userPaidFeesEnabled: false,
    mainnetConfirmed: false,
    networkFeeCurrency: "SOL",
    baseFeeLamportsPerSignature: 5_000,
    tokenRequiredForBackendProcessing: false,
    transactionsEnabled: true,
  }) as const;

const createAccountInfo = (input: {
  owner: PublicKey;
  accountName: string;
  executable?: boolean;
  registryAuthority?: PublicKey;
  rootPublisher?: PublicKey;
}): AccountInfo<Buffer> => ({
  data: input.executable
    ? Buffer.alloc(0)
    : input.accountName === "PollRegistry"
      ? Buffer.concat([
          anchorAccountDiscriminator(input.accountName),
          (input.registryAuthority ?? Keypair.generate().publicKey).toBuffer(),
          (input.rootPublisher ?? Keypair.generate().publicKey).toBuffer(),
          Buffer.alloc(64),
        ])
      : Buffer.concat([
          anchorAccountDiscriminator(input.accountName),
          Buffer.alloc(16),
        ]),
  executable: input.executable ?? false,
  lamports: 1,
  owner: input.owner,
  rentEpoch: 0,
});

const buildPublicationInput = (poll = createPoll()) => ({
  poll,
  batchCommits: [
    {
      batchIndex: 0,
      previousNullifierRoot: PREVIOUS_ROOT,
      nullifierRoot: NULLIFIER_ROOT,
      previousVoteCommitmentRoot: PREVIOUS_ROOT,
      voteCommitmentRoot: VOTE_COMMITMENT_ROOT,
      previousEncryptedVoteRoot: PREVIOUS_ROOT,
      encryptedVoteRoot: ENCRYPTED_VOTE_ROOT,
      acceptedCountDelta: 1,
    },
  ],
  finalNullifierRoot: NULLIFIER_ROOT,
  finalVoteCommitmentRoot: VOTE_COMMITMENT_ROOT,
  finalEncryptedVoteRoot: ENCRYPTED_VOTE_ROOT,
  acceptedVoteCount: 1,
  resultHash: RESULT_HASH,
  tallyProofHash: null,
  publishFinalResult: false,
});

const createConnection = (input: {
  getAccountInfo: (address: PublicKey) => Promise<AccountInfo<Buffer> | null>;
  getSignaturesForAddress: (
    address: PublicKey,
  ) => Promise<
    {
      signature: string;
      slot: number;
      err: null;
      memo: string | null;
      blockTime: number | null;
      confirmationStatus: "confirmed";
    }[]
  >;
}): SolanaAuditConnection =>
  ({
    getAccountInfo: input.getAccountInfo,
    getSignaturesForAddress: input.getSignaturesForAddress,
    getLatestBlockhash: async () => ({
      blockhash: Keypair.generate().publicKey.toBase58(),
      lastValidBlockHeight: 1,
    }),
    simulateTransaction: async () => ({ value: { err: null } }),
  }) as unknown as SolanaAuditConnection;

describe("Phase 7 Solana audit publisher", () => {
  it("recovers an existing root PDA signature so DB retries can complete", async () => {
    const feePayer = Keypair.generate();
    const registryAuthority = Keypair.generate().publicKey;
    const programId = Keypair.generate().publicKey;
    const poll = createPoll();
    const pollIdHash = derivePollIdHash(poll.id);
    const registryAddress = PublicKey.findProgramAddressSync(
      [Buffer.from("registry")],
      programId,
    )[0];
    const pollAddress = PublicKey.findProgramAddressSync(
      [Buffer.from("poll"), pollIdHash],
      programId,
    )[0];
    const rootAddress = PublicKey.findProgramAddressSync(
      [Buffer.from("poll-root"), pollAddress.toBuffer(), writeU64(0)],
      programId,
    )[0];
    const accounts = new Map<string, AccountInfo<Buffer>>([
      [
        programId.toBase58(),
        createAccountInfo({
          owner: SystemProgram.programId,
          accountName: "Program",
          executable: true,
        }),
      ],
      [
        registryAddress.toBase58(),
        createAccountInfo({
          owner: programId,
          accountName: "PollRegistry",
          registryAuthority,
          rootPublisher: feePayer.publicKey,
        }),
      ],
      [
        pollAddress.toBase58(),
        createAccountInfo({ owner: programId, accountName: "PollAccount" }),
      ],
      [
        rootAddress.toBase58(),
        createAccountInfo({ owner: programId, accountName: "PollRootAccount" }),
      ],
    ]);
    const sentLabels: string[] = [];
    const signatureLookups: string[] = [];
    const service = createSolanaAuditPublisherService({
      solanaAuditEnv: createAuditEnv(
        programId,
        feePayer.publicKey,
        registryAuthority,
      ),
      getBackendFeePayer: () => feePayer,
      getConnection: () =>
        createConnection({
          getAccountInfo: async (address: PublicKey) =>
            accounts.get(address.toBase58()) ?? null,
          getSignaturesForAddress: async (address: PublicKey) => {
            signatureLookups.push(address.toBase58());
            return [
              {
                signature: RECOVERED_ROOT_SIGNATURE,
                slot: 1,
                err: null,
                memo: null,
                blockTime: null,
                confirmationStatus: "confirmed",
              },
            ];
          },
        }),
      sendTransaction: async ({ label }) => {
        sentLabels.push(label);
        return `${label}-signature`;
      },
    });

    const result = await service.publishPollAudit(buildPublicationInput(poll));

    expect(sentLabels).toEqual([]);
    expect(signatureLookups).toEqual([rootAddress.toBase58()]);
    expect(result.rootCommits).toEqual([
      {
        batchIndex: 0,
        rootAddress: rootAddress.toBase58(),
        signature: RECOVERED_ROOT_SIGNATURE,
      },
    ]);
    expect(result.rootCommitSignature).toBe(RECOVERED_ROOT_SIGNATURE);
    expect(result.registrySignature).toBeNull();
    expect(result.pollRegistrationSignature).toBeNull();
    expect(result.explorerUrls.rootCommit).toBe(
      `https://explorer.solana.com/tx/${RECOVERED_ROOT_SIGNATURE}?cluster=devnet`,
    );
  });

  it("rejects an existing root PDA that is not owned by the audit program", async () => {
    const feePayer = Keypair.generate();
    const registryAuthority = Keypair.generate().publicKey;
    const programId = Keypair.generate().publicKey;
    const wrongOwner = Keypair.generate().publicKey;
    const poll = createPoll();
    const pollIdHash = derivePollIdHash(poll.id);
    const registryAddress = PublicKey.findProgramAddressSync(
      [Buffer.from("registry")],
      programId,
    )[0];
    const pollAddress = PublicKey.findProgramAddressSync(
      [Buffer.from("poll"), pollIdHash],
      programId,
    )[0];
    const rootAddress = PublicKey.findProgramAddressSync(
      [Buffer.from("poll-root"), pollAddress.toBuffer(), writeU64(0)],
      programId,
    )[0];
    const accounts = new Map<string, AccountInfo<Buffer>>([
      [
        programId.toBase58(),
        createAccountInfo({
          owner: SystemProgram.programId,
          accountName: "Program",
          executable: true,
        }),
      ],
      [
        registryAddress.toBase58(),
        createAccountInfo({
          owner: programId,
          accountName: "PollRegistry",
          registryAuthority,
          rootPublisher: feePayer.publicKey,
        }),
      ],
      [
        pollAddress.toBase58(),
        createAccountInfo({ owner: programId, accountName: "PollAccount" }),
      ],
      [
        rootAddress.toBase58(),
        createAccountInfo({ owner: wrongOwner, accountName: "PollRootAccount" }),
      ],
    ]);
    const service = createSolanaAuditPublisherService({
      solanaAuditEnv: createAuditEnv(
        programId,
        feePayer.publicKey,
        registryAuthority,
      ),
      getBackendFeePayer: () => feePayer,
      getConnection: () =>
        createConnection({
          getAccountInfo: async (address: PublicKey) =>
            accounts.get(address.toBase58()) ?? null,
          getSignaturesForAddress: async () => [],
        }),
      sendTransaction: async ({ label }) => `${label}-signature`,
    });

    await expect(
      service.publishPollAudit(buildPublicationInput(poll)),
    ).rejects.toThrow("is not owned by program");
  });
});
