import { createHash } from "node:crypto";
import {
  type AccountInfo,
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
const ANCHOR_ACCOUNT_NAMESPACE = "account";
const POLL_ID_HASH_DOMAIN = "org.civicos.audit:poll-id:v1";
const DEFAULT_LOCALNET_RPC_URL = "http://127.0.0.1:8899";
const DEFAULT_OPEN_POLL_SECONDS = 365 * 24 * 60 * 60;
const ZERO_ROOT = "0".repeat(64);
const RECOVERED_EXISTING_ACCOUNT_SIGNATURE_LIMIT = 1;

export type SolanaAuditBatchCommitInput = Readonly<{
  batchIndex: number;
  previousNullifierRoot: string;
  nullifierRoot: string;
  previousVoteCommitmentRoot: string;
  voteCommitmentRoot: string;
  previousEncryptedVoteRoot: string;
  encryptedVoteRoot: string;
  acceptedCountDelta: number;
}>;

export type SolanaAuditBatchCommitResult = Readonly<{
  batchIndex: number;
  rootAddress: string;
  signature: string | null;
}>;

export type SolanaAuditPublicationInput = Readonly<{
  poll: PollRow;
  batchCommits: readonly SolanaAuditBatchCommitInput[];
  finalNullifierRoot: string;
  finalVoteCommitmentRoot: string;
  finalEncryptedVoteRoot: string;
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
  rootCommits: readonly SolanaAuditBatchCommitResult[];
  rootCommitSignature: string | null;
  finalResultSignature: string | null;
  feePayerPublicKey: string;
  rootPublisherPublicKey: string;
  explorerUrls: Readonly<{
    registry: string | null;
    pollRegistration: string | null;
    rootCommit: string | null;
    finalResult: string | null;
  }>;
}>;

type SolanaAuditEnv = typeof env.solanaAudit;

export type SolanaAuditConnection = Pick<
  Connection,
  | "getAccountInfo"
  | "getLatestBlockhash"
  | "getSignaturesForAddress"
  | "simulateTransaction"
>;

export type SendSolanaTransaction = (input: {
  connection: SolanaAuditConnection;
  signer: Keypair;
  instructions: TransactionInstruction[];
  label: string;
}) => Promise<string>;

export type SolanaAuditPublisherDeps = Readonly<{
  solanaAuditEnv?: SolanaAuditEnv;
  getConnection?: () => SolanaAuditConnection;
  getBackendFeePayer?: () => Keypair;
  sendTransaction?: SendSolanaTransaction;
}>;

const sha256 = (value: string | Buffer): Buffer =>
  createHash("sha256").update(value).digest();

const anchorDiscriminator = (instructionName: string): Buffer =>
  sha256(`${ANCHOR_GLOBAL_NAMESPACE}:${instructionName}`).subarray(0, 8);

const anchorAccountDiscriminator = (accountName: string): Buffer =>
  sha256(`${ANCHOR_ACCOUNT_NAMESPACE}:${accountName}`).subarray(0, 8);

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

const getBackendFeePayer = (solanaAuditEnv: SolanaAuditEnv): Keypair => {
  if (!solanaAuditEnv.feePayerSecretKey) {
    throw new Error("Solana audit fee payer secret is not configured.");
  }

  const keypair = Keypair.fromSecretKey(
    normalizeSecretKeyBytes(solanaAuditEnv.feePayerSecretKey),
  );
  const publicKey = keypair.publicKey.toBase58();

  if (
    solanaAuditEnv.feePayerPublicKey &&
    solanaAuditEnv.feePayerPublicKey !== publicKey
  ) {
    throw new Error(
      "Configured Solana audit fee payer public key does not match the secret key.",
    );
  }

  return keypair;
};

const resolveRpcUrl = (solanaAuditEnv: SolanaAuditEnv): string => {
  if (solanaAuditEnv.rpcUrl) {
    return solanaAuditEnv.rpcUrl;
  }

  if (solanaAuditEnv.cluster === "localnet") {
    return DEFAULT_LOCALNET_RPC_URL;
  }

  return clusterApiUrl(solanaAuditEnv.cluster);
};

const getConnection = (solanaAuditEnv: SolanaAuditEnv): Connection =>
  new Connection(resolveRpcUrl(solanaAuditEnv), {
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

const buildExplorerUrl = (
  signature: string | null,
  solanaAuditEnv: SolanaAuditEnv,
): string | null => {
  if (!signature) {
    return null;
  }

  if (solanaAuditEnv.cluster === "mainnet-beta") {
    return `https://explorer.solana.com/tx/${signature}`;
  }

  const cluster =
    solanaAuditEnv.cluster === "localnet" ? "custom" : solanaAuditEnv.cluster;
  return `https://explorer.solana.com/tx/${signature}?cluster=${cluster}`;
};

const assertProgramAccount = (
  account: AccountInfo<Buffer> | null,
  programId: PublicKey,
  cluster: string,
) => {
  if (!account) {
    throw new Error(
      `CivicOS audit program ${programId.toBase58()} is not deployed on ${cluster}.`,
    );
  }

  if (!account.executable) {
    throw new Error(
      `CivicOS audit program ${programId.toBase58()} exists on ${cluster}, but the account is not executable.`,
    );
  }
};

const assertAnchorPdaAccount = (input: {
  account: AccountInfo<Buffer>;
  accountName: string;
  address: PublicKey;
  programId: PublicKey;
  label: string;
}) => {
  if (!input.account.owner.equals(input.programId)) {
    throw new Error(
      `Solana ${input.label} account ${input.address.toBase58()} is not owned by program ${input.programId.toBase58()}.`,
    );
  }

  const data = Buffer.from(input.account.data);
  const expected = anchorAccountDiscriminator(input.accountName);
  if (data.length < expected.length || !data.subarray(0, expected.length).equals(expected)) {
    throw new Error(
      `Solana ${input.label} account ${input.address.toBase58()} does not match Anchor account ${input.accountName}.`,
    );
  }
};

const assertRegistryGovernance = (input: {
  account: AccountInfo<Buffer>;
  registryAuthority: PublicKey | null;
  rootPublisher: PublicKey;
}) => {
  const data = Buffer.from(input.account.data);
  const offset = anchorAccountDiscriminator("PollRegistry").length;
  const authorityOffset = offset;
  const rootPublisherOffset = authorityOffset + 32;
  const requiredLength = rootPublisherOffset + 32;

  if (data.length < requiredLength) {
    throw new Error("Solana registry account is too small for Phase 8 governance.");
  }

  const authority = new PublicKey(
    data.subarray(authorityOffset, authorityOffset + 32),
  );
  const rootPublisher = new PublicKey(
    data.subarray(rootPublisherOffset, rootPublisherOffset + 32),
  );

  if (input.registryAuthority && !authority.equals(input.registryAuthority)) {
    throw new Error(
      `Solana registry authority mismatch: expected ${input.registryAuthority.toBase58()}, found ${authority.toBase58()}.`,
    );
  }

  if (!rootPublisher.equals(input.rootPublisher)) {
    throw new Error(
      `Solana registry root publisher mismatch: expected ${input.rootPublisher.toBase58()}, found ${rootPublisher.toBase58()}.`,
    );
  }
};

const recoverExistingAccountSignature = async (input: {
  connection: SolanaAuditConnection;
  address: PublicKey;
  label: string;
}): Promise<string> => {
  const signatures = await input.connection.getSignaturesForAddress(
    input.address,
    { limit: RECOVERED_EXISTING_ACCOUNT_SIGNATURE_LIMIT },
    "confirmed",
  );
  const signature = signatures.find((entry) => !entry.err)?.signature ?? null;
  if (!signature) {
    throw new Error(
      `Solana ${input.label} account ${input.address.toBase58()} already exists, but no confirmed transaction signature could be recovered.`,
    );
  }
  return signature;
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
  rootPublisher: PublicKey;
  solanaAuditEnv: SolanaAuditEnv;
}): TransactionInstruction => {
  const treasury = input.solanaAuditEnv.treasury
    ? new PublicKey(input.solanaAuditEnv.treasury)
    : input.authority;
  const tokenMint = input.solanaAuditEnv.tokenMint
    ? new PublicKey(input.solanaAuditEnv.tokenMint)
    : null;
  const tokenProgram = input.solanaAuditEnv.tokenProgram
    ? new PublicKey(input.solanaAuditEnv.tokenProgram)
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
      input.rootPublisher.toBuffer(),
    ]),
  });
};

const buildCreatePollInstruction = (input: {
  programId: PublicKey;
  registryAddress: PublicKey;
  pollAddress: PublicKey;
  rootPublisher: PublicKey;
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
      { pubkey: input.rootPublisher, isSigner: true, isWritable: true },
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
  rootPublisher: PublicKey;
  batchIndex: number;
  previousNullifierRoot: Buffer;
  nullifierRoot: Buffer;
  previousVoteCommitmentRoot: Buffer;
  voteCommitmentRoot: Buffer;
  previousEncryptedVoteRoot: Buffer;
  encryptedVoteRoot: Buffer;
  acceptedCountDelta: number;
}): TransactionInstruction =>
  new TransactionInstruction({
    programId: input.programId,
    keys: [
      { pubkey: input.registryAddress, isSigner: false, isWritable: false },
      { pubkey: input.pollAddress, isSigner: false, isWritable: true },
      { pubkey: input.pollRootAddress, isSigner: false, isWritable: true },
      { pubkey: input.rootPublisher, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      anchorDiscriminator("commit_roots"),
      writeU64(input.batchIndex),
      input.previousNullifierRoot,
      input.nullifierRoot,
      input.previousVoteCommitmentRoot,
      input.voteCommitmentRoot,
      input.previousEncryptedVoteRoot,
      input.encryptedVoteRoot,
      writeU64(input.acceptedCountDelta),
    ]),
  });

const buildFinalizePollInstruction = (input: {
  programId: PublicKey;
  registryAddress: PublicKey;
  pollAddress: PublicKey;
  finalResultAddress: PublicKey;
  rootPublisher: PublicKey;
  voteCommitmentRoot: Buffer;
  nullifierRoot: Buffer;
  encryptedVoteRoot: Buffer;
  resultHash: Buffer;
  tallyProofHash: Buffer | null;
}): TransactionInstruction =>
  new TransactionInstruction({
    programId: input.programId,
    keys: [
      { pubkey: input.registryAddress, isSigner: false, isWritable: false },
      { pubkey: input.pollAddress, isSigner: false, isWritable: true },
      { pubkey: input.finalResultAddress, isSigner: false, isWritable: true },
      { pubkey: input.rootPublisher, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      anchorDiscriminator("finalize_poll"),
      input.voteCommitmentRoot,
      input.nullifierRoot,
      input.encryptedVoteRoot,
      input.resultHash,
      writeOptionBytes32(input.tallyProofHash),
    ]),
  });

const sendSimulatedTransaction: SendSolanaTransaction = async (input) => {
  const connection = input.connection as Connection;
  const latestBlockhash = await connection.getLatestBlockhash("confirmed");
  const transaction = new Transaction({
    feePayer: input.signer.publicKey,
    blockhash: latestBlockhash.blockhash,
    lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
  }).add(...input.instructions);

  transaction.sign(input.signer);

  const simulation = await connection.simulateTransaction(transaction);
  if (simulation.value.err) {
    throw new Error(
      `Solana ${input.label} simulation failed: ${JSON.stringify(simulation.value.err)}`,
    );
  }

  const signature = await sendAndConfirmRawTransaction(
    connection,
    transaction.serialize(),
    {
      commitment: "confirmed",
      maxRetries: 3,
    },
  );

  return signature;
};

export const createSolanaAuditPublisherService = (
  deps: SolanaAuditPublisherDeps = {},
) => {
  const solanaAuditEnv = deps.solanaAuditEnv ?? env.solanaAudit;
  const resolveConnection = deps.getConnection ?? (() => getConnection(solanaAuditEnv));
  const resolveFeePayer =
    deps.getBackendFeePayer ?? (() => getBackendFeePayer(solanaAuditEnv));
  const sendTransaction = deps.sendTransaction ?? sendSimulatedTransaction;

  return Object.freeze({
    async publishPollAudit(
      input: SolanaAuditPublicationInput,
    ): Promise<SolanaAuditPublicationResult> {
      if (!solanaAuditEnv.transactionsEnabled) {
        throw new Error("Solana audit transactions are not enabled.");
      }

      const connection = resolveConnection();
      const signer = resolveFeePayer();
      const programId = new PublicKey(solanaAuditEnv.programId);
      const rootPublisher = solanaAuditEnv.rootPublisherPublicKey
        ? new PublicKey(solanaAuditEnv.rootPublisherPublicKey)
        : signer.publicKey;
      const registryAuthority = solanaAuditEnv.registryAuthority
        ? new PublicKey(solanaAuditEnv.registryAuthority)
        : signer.publicKey;

      if (!rootPublisher.equals(signer.publicKey)) {
        throw new Error(
          "Configured Solana audit root publisher does not match the backend signing key.",
        );
      }

      if (registryAuthority.equals(rootPublisher)) {
        throw new Error(
          "Solana audit registry authority and root publisher must be different keys.",
        );
      }

      const programAccount = await connection.getAccountInfo(programId);
      assertProgramAccount(programAccount, programId, solanaAuditEnv.cluster);

      const registryAddress = deriveRegistryAddress(programId);
      const pollIdHash = derivePollIdHash(input.poll.id);
      const pollAddress = derivePollAddress(programId, pollIdHash);
      const orderedBatchCommits = [...input.batchCommits].sort(
        (left, right) => left.batchIndex - right.batchIndex,
      );
      const finalResultAddress =
        input.publishFinalResult && input.acceptedVoteCount > 0
          ? deriveFinalResultAddress(programId, pollAddress)
          : null;

      const [registryAccount, pollAccount] = await Promise.all([
        connection.getAccountInfo(registryAddress),
        connection.getAccountInfo(pollAddress),
      ]);

      let registrySignature: string | null = null;
      if (registryAccount) {
        assertAnchorPdaAccount({
          account: registryAccount,
          accountName: "PollRegistry",
          address: registryAddress,
          programId,
          label: "registry",
        });
        assertRegistryGovernance({
          account: registryAccount,
          registryAuthority,
          rootPublisher,
        });
      } else {
        if (!registryAuthority.equals(signer.publicKey)) {
          throw new Error(
            "Solana audit registry is not initialized. Initialize it externally with SOLANA_AUDIT_REGISTRY_AUTHORITY before backend publication.",
          );
        }

        registrySignature = await sendTransaction({
          connection,
          signer,
          label: "initialize_registry",
          instructions: [
            buildInitializeRegistryInstruction({
              programId,
              registryAddress,
              authority: registryAuthority,
              payer: signer.publicKey,
              rootPublisher,
              solanaAuditEnv,
            }),
          ],
        });
      }

      let pollRegistrationSignature: string | null = null;
      if (pollAccount) {
        assertAnchorPdaAccount({
          account: pollAccount,
          accountName: "PollAccount",
          address: pollAddress,
          programId,
          label: "poll",
        });
      } else {
        const { opensAt, closesAt } = resolveOnChainPollWindow(input.poll);
        pollRegistrationSignature = await sendTransaction({
          connection,
          signer,
          label: "create_poll",
          instructions: [
            buildCreatePollInstruction({
              programId,
              registryAddress,
              pollAddress,
              rootPublisher,
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

      const rootCommits: SolanaAuditBatchCommitResult[] = [];
      for (const batchCommit of orderedBatchCommits) {
        const batchRootAddress = derivePollRootAddress(
          programId,
          pollAddress,
          batchCommit.batchIndex,
        );
        const rootAccount = await connection.getAccountInfo(batchRootAddress);
        if (rootAccount) {
          assertAnchorPdaAccount({
            account: rootAccount,
            accountName: "PollRootAccount",
            address: batchRootAddress,
            programId,
            label: `root batch ${batchCommit.batchIndex}`,
          });
          rootCommits.push({
            batchIndex: batchCommit.batchIndex,
            rootAddress: batchRootAddress.toBase58(),
            signature: await recoverExistingAccountSignature({
              connection,
              address: batchRootAddress,
              label: `root batch ${batchCommit.batchIndex}`,
            }),
          });
          continue;
        }

        const signature = await sendTransaction({
          connection,
          signer,
          label: `commit_roots[batch ${batchCommit.batchIndex}]`,
          instructions: [
            buildCommitRootsInstruction({
              programId,
              registryAddress,
              pollAddress,
              pollRootAddress: batchRootAddress,
              rootPublisher,
              batchIndex: batchCommit.batchIndex,
              previousNullifierRoot: hex32(batchCommit.previousNullifierRoot),
              nullifierRoot: hex32(batchCommit.nullifierRoot),
              previousVoteCommitmentRoot: hex32(
                batchCommit.previousVoteCommitmentRoot,
              ),
              voteCommitmentRoot: hex32(batchCommit.voteCommitmentRoot),
              previousEncryptedVoteRoot: hex32(
                batchCommit.previousEncryptedVoteRoot,
              ),
              encryptedVoteRoot: hex32(batchCommit.encryptedVoteRoot),
              acceptedCountDelta: batchCommit.acceptedCountDelta,
            }),
          ],
        });
        rootCommits.push({
          batchIndex: batchCommit.batchIndex,
          rootAddress: batchRootAddress.toBase58(),
          signature,
        });
      }

      const lastRootCommit = rootCommits[rootCommits.length - 1] ?? null;
      const rootCommitSignature =
        [...rootCommits].reverse().find((commit) => commit.signature)?.signature ??
        null;

      let finalResultSignature: string | null = null;
      if (finalResultAddress) {
        const finalResultAccount =
          await connection.getAccountInfo(finalResultAddress);
        if (finalResultAccount) {
          assertAnchorPdaAccount({
            account: finalResultAccount,
            accountName: "FinalResultAccount",
            address: finalResultAddress,
            programId,
            label: "final result",
          });
          finalResultSignature = await recoverExistingAccountSignature({
            connection,
            address: finalResultAddress,
            label: "final result",
          });
        } else {
          finalResultSignature = await sendTransaction({
            connection,
            signer,
            label: "finalize_poll",
            instructions: [
              buildFinalizePollInstruction({
                programId,
                registryAddress,
                pollAddress,
                finalResultAddress,
                rootPublisher,
                voteCommitmentRoot: hex32(input.finalVoteCommitmentRoot),
                nullifierRoot: hex32(input.finalNullifierRoot),
                encryptedVoteRoot: hex32(input.finalEncryptedVoteRoot),
                resultHash: hex32(input.resultHash),
                tallyProofHash: input.tallyProofHash
                  ? hex32(input.tallyProofHash)
                  : null,
              }),
            ],
          });
        }
      }

      return Object.freeze({
        cluster: solanaAuditEnv.cluster,
        programId: programId.toBase58(),
        registryAddress: registryAddress.toBase58(),
        pollAddress: pollAddress.toBase58(),
        rootAddress: lastRootCommit?.rootAddress ?? null,
        finalResultAddress: finalResultAddress?.toBase58() ?? null,
        registrySignature,
        pollRegistrationSignature,
        rootCommits: Object.freeze(rootCommits),
        rootCommitSignature,
        finalResultSignature,
        feePayerPublicKey: signer.publicKey.toBase58(),
        rootPublisherPublicKey: rootPublisher.toBase58(),
        explorerUrls: Object.freeze({
          registry: buildExplorerUrl(registrySignature, solanaAuditEnv),
          pollRegistration: buildExplorerUrl(
            pollRegistrationSignature,
            solanaAuditEnv,
          ),
          rootCommit: buildExplorerUrl(rootCommitSignature, solanaAuditEnv),
          finalResult: buildExplorerUrl(finalResultSignature, solanaAuditEnv),
        }),
      });
    },
  });
};

export const solanaAuditPublisherService = createSolanaAuditPublisherService();

export default solanaAuditPublisherService;
