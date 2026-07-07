import { createHash } from "node:crypto";
import {
  clusterApiUrl,
  Connection,
  Keypair,
  PublicKey,
  sendAndConfirmRawTransaction,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";

import env from "../config/env";
import type { PollRow } from "../types/db";

const ANCHOR_GLOBAL_NAMESPACE = "global";
const POLL_ID_HASH_DOMAIN = "org.civicos.audit:poll-id:v1";
const DEFAULT_LOCALNET_RPC_URL = "http://127.0.0.1:8899";
const DEFAULT_OPEN_POLL_SECONDS = 365 * 24 * 60 * 60;
const ZERO_ROOT = "0".repeat(64);

export type SolanaAuditPublicationInput = Readonly<{
  poll: PollRow;
  nullifierRoot: string;
  voteCommitmentRoot: string;
  acceptedVoteCount: number;
  resultHash: string;
  tallyProofHash?: string | null;
  publishFinalResult: boolean;
}>;

export type SolanaAuditPublicationResult = Readonly<{
  cluster: string;
  programId: string;
  registryAddress: string;
  pollAddress: string;
  rootAddress: string | null;
  finalResultAddress: string | null;
  registrySignature: string | null;
  pollRegistrationSignature: string | null;
  rootCommitSignature: string | null;
  finalResultSignature: string | null;
  feePayerPublicKey: string;
  explorerUrls: Readonly<{
    registry: string | null;
    pollRegistration: string | null;
    rootCommit: string | null;
    finalResult: string | null;
  }>;
}>;

const sha256 = (value: string | Buffer): Buffer =>
  createHash("sha256").update(value).digest();

const anchorDiscriminator = (instructionName: string): Buffer =>
  sha256(`${ANCHOR_GLOBAL_NAMESPACE}:${instructionName}`).subarray(0, 8);

const normalizeSecretKeyBytes = (value: string): Uint8Array => {
  const trimmed = value.trim();

  if (trimmed.startsWith("[")) {
    const parsed = JSON.parse(trimmed) as unknown;
    if (
      Array.isArray(parsed) &&
      parsed.length === 64 &&
      parsed.every((entry) => Number.isInteger(entry) && entry >= 0 && entry <= 255)
    ) {
      return Uint8Array.from(parsed as number[]);
    }
  }

  if (/^\d+(,\d+)+$/u.test(trimmed)) {
    const bytes = trimmed.split(",").map((entry) => Number.parseInt(entry, 10));
    if (
      bytes.length === 64 &&
      bytes.every((entry) => Number.isInteger(entry) && entry >= 0 && entry <= 255)
    ) {
      return Uint8Array.from(bytes);
    }
  }

  const decoded = Buffer.from(trimmed, "base64");
  if (decoded.length === 64) {
    return Uint8Array.from(decoded);
  }

  throw new Error(
    "SOLANA_AUDIT_FEE_PAYER_SECRET_KEY must be a 64-byte Solana keypair encoded as JSON bytes, comma-separated bytes, or base64 bytes.",
  );
};

const getBackendFeePayer = (): Keypair => {
  if (!env.solanaAudit.feePayerSecretKey) {
    throw new Error("Solana audit fee payer secret is not configured.");
  }

  const keypair = Keypair.fromSecretKey(
    normalizeSecretKeyBytes(env.solanaAudit.feePayerSecretKey),
  );
  const publicKey = keypair.publicKey.toBase58();

  if (
    env.solanaAudit.feePayerPublicKey &&
    env.solanaAudit.feePayerPublicKey !== publicKey
  ) {
    throw new Error(
      "Configured Solana audit fee payer public key does not match the secret key.",
    );
  }

  return keypair;
};

const resolveRpcUrl = (): string => {
  if (env.solanaAudit.rpcUrl) {
    return env.solanaAudit.rpcUrl;
  }

  if (env.solanaAudit.cluster === "localnet") {
    return DEFAULT_LOCALNET_RPC_URL;
  }

  return clusterApiUrl(env.solanaAudit.cluster);
};

const getConnection = (): Connection =>
  new Connection(resolveRpcUrl(), {
    commitment: "confirmed",
  });

const writeU64 = (value: number | bigint): Buffer => {
  const output = Buffer.alloc(8);
  output.writeBigUInt64LE(BigInt(value));
  return output;
};

const writeI64 = (value: number | bigint): Buffer => {
  const output = Buffer.alloc(8);
  output.writeBigInt64LE(BigInt(value));
  return output;
};

const writeOptionPubkey = (value: PublicKey | null): Buffer =>
  value ? Buffer.concat([Buffer.from([1]), value.toBuffer()]) : Buffer.from([0]);

const writeOptionBytes32 = (value: Buffer | null): Buffer =>
  value ? Buffer.concat([Buffer.from([1]), value]) : Buffer.from([0]);

const hex32 = (value: string): Buffer => {
  const normalized = value.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/u.test(normalized)) {
    throw new Error("Expected a 32-byte hex string.");
  }
  return Buffer.from(normalized, "hex");
};

export const derivePollIdHash = (pollId: string): Buffer => {
  const hash = createHash("sha256");
  hash.update(POLL_ID_HASH_DOMAIN, "utf8");
  hash.update("\0", "utf8");
  hash.update(pollId, "utf8");
  return hash.digest();
};

const deriveRegistryAddress = (programId: PublicKey): PublicKey =>
  PublicKey.findProgramAddressSync([Buffer.from("registry")], programId)[0];

const derivePollAddress = (programId: PublicKey, pollIdHash: Buffer): PublicKey =>
  PublicKey.findProgramAddressSync(
    [Buffer.from("poll"), pollIdHash],
    programId,
  )[0];

const derivePollRootAddress = (
  programId: PublicKey,
  pollAddress: PublicKey,
  batchIndex: number,
): PublicKey =>
  PublicKey.findProgramAddressSync(
    [Buffer.from("poll-root"), pollAddress.toBuffer(), writeU64(batchIndex)],
    programId,
  )[0];

const deriveFinalResultAddress = (
  programId: PublicKey,
  pollAddress: PublicKey,
): PublicKey =>
  PublicKey.findProgramAddressSync(
    [Buffer.from("final-result"), pollAddress.toBuffer()],
    programId,
  )[0];

const buildExplorerUrl = (signature: string | null): string | null => {
  if (!signature) {
    return null;
  }

  if (env.solanaAudit.cluster === "mainnet-beta") {
    return `https://explorer.solana.com/tx/${signature}`;
  }

  const cluster =
    env.solanaAudit.cluster === "localnet" ? "custom" : env.solanaAudit.cluster;
  return `https://explorer.solana.com/tx/${signature}?cluster=${cluster}`;
};

const getUnixTimestampSeconds = (value: string | null | undefined): number | null => {
  if (!value) {
    return null;
  }

  const parsed = new Date(value).getTime();
  if (!Number.isFinite(parsed)) {
    return null;
  }

  return Math.floor(parsed / 1000);
};

const isFinalizablePoll = (poll: PollRow): boolean => {
  if (poll.status === "closed" || poll.status === "archived") {
    return true;
  }

  const endsAt = getUnixTimestampSeconds(poll.ends_at);
  return endsAt !== null && endsAt <= Math.floor(Date.now() / 1000);
};

const resolveOnChainPollWindow = (poll: PollRow): {
  opensAt: number;
  closesAt: number;
} => {
  const now = Math.floor(Date.now() / 1000);
  const finalizable = isFinalizablePoll(poll);
  let opensAt =
    getUnixTimestampSeconds(poll.starts_at) ??
    getUnixTimestampSeconds(poll.created_at) ??
    now - 60;
  let closesAt =
    getUnixTimestampSeconds(poll.ends_at) ??
    (finalizable ? now - 1 : now + DEFAULT_OPEN_POLL_SECONDS);

  if (closesAt <= opensAt) {
    if (finalizable) {
      opensAt = closesAt - 1;
    } else {
      closesAt = opensAt + 1;
    }
  }

  return { opensAt, closesAt };
};

const buildInitializeRegistryInstruction = (input: {
  programId: PublicKey;
  registryAddress: PublicKey;
  authority: PublicKey;
  payer: PublicKey;
}): TransactionInstruction => {
  const treasury = env.solanaAudit.treasury
    ? new PublicKey(env.solanaAudit.treasury)
    : input.authority;
  const tokenMint = env.solanaAudit.tokenMint
    ? new PublicKey(env.solanaAudit.tokenMint)
    : null;
  const tokenProgram = env.solanaAudit.tokenProgram
    ? new PublicKey(env.solanaAudit.tokenProgram)
    : null;

  return new TransactionInstruction({
    programId: input.programId,
    keys: [
      { pubkey: input.registryAddress, isSigner: false, isWritable: true },
      { pubkey: input.authority, isSigner: true, isWritable: false },
      { pubkey: input.payer, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      anchorDiscriminator("initialize_registry"),
      treasury.toBuffer(),
      writeOptionPubkey(tokenMint),
      writeOptionPubkey(tokenProgram),
    ]),
  });
};

const buildCreatePollInstruction = (input: {
  programId: PublicKey;
  registryAddress: PublicKey;
  pollAddress: PublicKey;
  authority: PublicKey;
  pollIdHash: Buffer;
  pollPolicyHash: Buffer;
  credentialSchemaHash: Buffer;
  opensAt: number;
  closesAt: number;
}): TransactionInstruction =>
  new TransactionInstruction({
    programId: input.programId,
    keys: [
      { pubkey: input.registryAddress, isSigner: false, isWritable: false },
      { pubkey: input.pollAddress, isSigner: false, isWritable: true },
      { pubkey: input.authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      anchorDiscriminator("create_poll"),
      input.pollIdHash,
      input.pollPolicyHash,
      input.credentialSchemaHash,
      writeI64(input.opensAt),
      writeI64(input.closesAt),
    ]),
  });

const buildCommitRootsInstruction = (input: {
  programId: PublicKey;
  registryAddress: PublicKey;
  pollAddress: PublicKey;
  pollRootAddress: PublicKey;
  authority: PublicKey;
  batchIndex: number;
  previousNullifierRoot: Buffer;
  nullifierRoot: Buffer;
  previousVoteCommitmentRoot: Buffer;
  voteCommitmentRoot: Buffer;
  acceptedCountDelta: number;
}): TransactionInstruction =>
  new TransactionInstruction({
    programId: input.programId,
    keys: [
      { pubkey: input.registryAddress, isSigner: false, isWritable: false },
      { pubkey: input.pollAddress, isSigner: false, isWritable: true },
      { pubkey: input.pollRootAddress, isSigner: false, isWritable: true },
      { pubkey: input.authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      anchorDiscriminator("commit_roots"),
      writeU64(input.batchIndex),
      input.previousNullifierRoot,
      input.nullifierRoot,
      input.previousVoteCommitmentRoot,
      input.voteCommitmentRoot,
      writeU64(input.acceptedCountDelta),
    ]),
  });

const buildFinalizePollInstruction = (input: {
  programId: PublicKey;
  registryAddress: PublicKey;
  pollAddress: PublicKey;
  finalResultAddress: PublicKey;
  authority: PublicKey;
  voteCommitmentRoot: Buffer;
  nullifierRoot: Buffer;
  resultHash: Buffer;
  tallyProofHash: Buffer | null;
}): TransactionInstruction =>
  new TransactionInstruction({
    programId: input.programId,
    keys: [
      { pubkey: input.registryAddress, isSigner: false, isWritable: false },
      { pubkey: input.pollAddress, isSigner: false, isWritable: true },
      { pubkey: input.finalResultAddress, isSigner: false, isWritable: true },
      { pubkey: input.authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      anchorDiscriminator("finalize_poll"),
      input.voteCommitmentRoot,
      input.nullifierRoot,
      input.resultHash,
      writeOptionBytes32(input.tallyProofHash),
    ]),
  });

const sendSimulatedTransaction = async (input: {
  connection: Connection;
  signer: Keypair;
  instructions: TransactionInstruction[];
  label: string;
}): Promise<string> => {
  const latestBlockhash = await input.connection.getLatestBlockhash("confirmed");
  const transaction = new Transaction({
    feePayer: input.signer.publicKey,
    blockhash: latestBlockhash.blockhash,
    lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
  }).add(...input.instructions);

  transaction.sign(input.signer);

  const simulation = await input.connection.simulateTransaction(transaction);
  if (simulation.value.err) {
    throw new Error(
      `Solana ${input.label} simulation failed: ${JSON.stringify(simulation.value.err)}`,
    );
  }

  const signature = await sendAndConfirmRawTransaction(
    input.connection,
    transaction.serialize(),
    {
      commitment: "confirmed",
      maxRetries: 3,
    },
  );

  return signature;
};

export const solanaAuditPublisherService = {
  async publishPollAudit(
    input: SolanaAuditPublicationInput,
  ): Promise<SolanaAuditPublicationResult> {
    if (!env.solanaAudit.transactionsEnabled) {
      throw new Error("Solana audit transactions are not enabled.");
    }

    const connection = getConnection();
    const signer = getBackendFeePayer();
    const programId = new PublicKey(env.solanaAudit.programId);
    const programAccount = await connection.getAccountInfo(programId);
    if (!programAccount) {
      throw new Error(
        `CivicOS audit program ${programId.toBase58()} is not deployed on ${env.solanaAudit.cluster}.`,
      );
    }

    const registryAddress = deriveRegistryAddress(programId);
    const pollIdHash = derivePollIdHash(input.poll.id);
    const pollAddress = derivePollAddress(programId, pollIdHash);
    const rootAddress =
      input.acceptedVoteCount > 0
        ? derivePollRootAddress(programId, pollAddress, 0)
        : null;
    const finalResultAddress =
      input.publishFinalResult && input.acceptedVoteCount > 0
        ? deriveFinalResultAddress(programId, pollAddress)
        : null;

    const [registryAccount, pollAccount] = await Promise.all([
      connection.getAccountInfo(registryAddress),
      connection.getAccountInfo(pollAddress),
    ]);

    let registrySignature: string | null = null;
    if (!registryAccount) {
      registrySignature = await sendSimulatedTransaction({
        connection,
        signer,
        label: "initialize_registry",
        instructions: [
          buildInitializeRegistryInstruction({
            programId,
            registryAddress,
            authority: signer.publicKey,
            payer: signer.publicKey,
          }),
        ],
      });
    }

    let pollRegistrationSignature: string | null = null;
    if (!pollAccount) {
      const { opensAt, closesAt } = resolveOnChainPollWindow(input.poll);
      pollRegistrationSignature = await sendSimulatedTransaction({
        connection,
        signer,
        label: "create_poll",
        instructions: [
          buildCreatePollInstruction({
            programId,
            registryAddress,
            pollAddress,
            authority: signer.publicKey,
            pollIdHash,
            pollPolicyHash: hex32(input.poll.poll_policy_hash ?? ZERO_ROOT),
            credentialSchemaHash: hex32(
              input.poll.credential_schema_hash ?? ZERO_ROOT,
            ),
            opensAt,
            closesAt,
          }),
        ],
      });
    }

    let rootCommitSignature: string | null = null;
    if (rootAddress) {
      const rootAccount = await connection.getAccountInfo(rootAddress);
      if (!rootAccount) {
        rootCommitSignature = await sendSimulatedTransaction({
          connection,
          signer,
          label: "commit_roots",
          instructions: [
            buildCommitRootsInstruction({
              programId,
              registryAddress,
              pollAddress,
              pollRootAddress: rootAddress,
              authority: signer.publicKey,
              batchIndex: 0,
              previousNullifierRoot: hex32(ZERO_ROOT),
              nullifierRoot: hex32(input.nullifierRoot),
              previousVoteCommitmentRoot: hex32(ZERO_ROOT),
              voteCommitmentRoot: hex32(input.voteCommitmentRoot),
              acceptedCountDelta: input.acceptedVoteCount,
            }),
          ],
        });
      }
    }

    let finalResultSignature: string | null = null;
    if (finalResultAddress) {
      const finalResultAccount = await connection.getAccountInfo(finalResultAddress);
      if (!finalResultAccount) {
        finalResultSignature = await sendSimulatedTransaction({
          connection,
          signer,
          label: "finalize_poll",
          instructions: [
            buildFinalizePollInstruction({
              programId,
              registryAddress,
              pollAddress,
              finalResultAddress,
              authority: signer.publicKey,
              voteCommitmentRoot: hex32(input.voteCommitmentRoot),
              nullifierRoot: hex32(input.nullifierRoot),
              resultHash: hex32(input.resultHash),
              tallyProofHash: input.tallyProofHash ? hex32(input.tallyProofHash) : null,
            }),
          ],
        });
      }
    }

    return Object.freeze({
      cluster: env.solanaAudit.cluster,
      programId: programId.toBase58(),
      registryAddress: registryAddress.toBase58(),
      pollAddress: pollAddress.toBase58(),
      rootAddress: rootAddress?.toBase58() ?? null,
      finalResultAddress: finalResultAddress?.toBase58() ?? null,
      registrySignature,
      pollRegistrationSignature,
      rootCommitSignature,
      finalResultSignature,
      feePayerPublicKey: signer.publicKey.toBase58(),
      explorerUrls: Object.freeze({
        registry: buildExplorerUrl(registrySignature),
        pollRegistration: buildExplorerUrl(pollRegistrationSignature),
        rootCommit: buildExplorerUrl(rootCommitSignature),
        finalResult: buildExplorerUrl(finalResultSignature),
      }),
    });
  },
};

export default solanaAuditPublisherService;
