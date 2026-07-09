import { createHash } from "node:crypto";

import env from "../config/env";
import pollAuditRepository from "../repositories/pollAuditRepository";
import pollRepository from "../repositories/pollRepository";
import pollTallyProofRepository from "../repositories/pollTallyProofRepository";
import pollZkVoteRepository from "../repositories/pollZkVoteRepository";
import voteRepository from "../repositories/voteRepository";
import type {
  PollOptionResultDto,
  PollResultsSummaryDto,
  PublicAuditRootCommitDto,
  PublicAuditInclusionProofResultDto,
  PublicAuditMerkleProofStepDto,
  PublicAuditTallyProofSummaryDto,
  PublicAuditTreeKind,
  PublicAuditTreeSummaryDto,
  PublicVoteReceiptLookupDto,
  PublicPollAuditDto,
} from "../types/contracts";
import type {
  PollOptionRow,
  PollRootRow,
  PollRow,
  PollTallyProofRow,
} from "../types/db";
import type { JsonValue } from "../types/json";
import { CIVIC_PRODUCTION_VOTE_PRIVACY_MODE } from "./groth16ProofVerifierService";
import {
  hashGroth16TallyProofEnvelope,
  verifyGroth16TallyProofForPoll,
  type Groth16TallyProofEnvelopeDto,
} from "./groth16TallyProofVerifierService";
import {
  buildPoseidonAuditMerkleProof,
  buildPoseidonAuditMerkleTree,
  hashPoseidonAuditLeaf,
  POSEIDON_AUDIT_HASH_ALGORITHM,
  POSEIDON_AUDIT_LEAF_DOMAIN,
  POSEIDON_AUDIT_NODE_DOMAIN,
  POSEIDON_AUDIT_TREE_DEPTH,
  POSEIDON_AUDIT_TREE_LEAF_CAPACITY,
  type PoseidonAuditTree,
} from "./poseidonAuditTreeService";
import { hashCanonicalJson } from "./pollPolicyService";
import solanaAuditPublisherService, {
  type SolanaAuditPublicationResult,
} from "./solanaAuditPublisherService";
import zkpAuditEventService, {
  ZKP_AUDIT_REJECTION_REASON_CODES,
  type ZkpAuditRejectionReasonCode,
} from "./zkpAuditEventService";

export const PUBLIC_AUDIT_VERSION = "civicos-public-audit-v1" as const;
export const PUBLIC_AUDIT_RESULT_HASH_VERSION =
  "civicos-public-audit-result-v1" as const;
export const PUBLIC_AUDIT_MERKLE_LEAF_DOMAIN =
  "org.civicos.audit:merkle-leaf:v1" as const;
export const PUBLIC_AUDIT_MERKLE_NODE_DOMAIN =
  "org.civicos.audit:merkle-node:v1" as const;
export const PUBLIC_AUDIT_ZERO_ROOT = "0".repeat(64);

const HEX_64_PATTERN = /^[0-9a-f]{64}$/;

export type PublicAuditMerkleTree = Readonly<{
  root: string;
  leafHashes: readonly string[];
  levels: readonly (readonly string[])[];
}>;

type AuditMerkleTree = PublicAuditMerkleTree | PoseidonAuditTree;

const normalizeHex64 = (value: string): string | null => {
  const normalized = value.trim().toLowerCase();
  return HEX_64_PATTERN.test(normalized) ? normalized : null;
};

const sha256Hex = (parts: readonly string[]): string => {
  const hash = createHash("sha256");
  parts.forEach((part) => {
    hash.update(part, "utf8");
    hash.update("\0", "utf8");
  });
  return hash.digest("hex");
};

export const hashPublicAuditLeaf = (
  kind: PublicAuditTreeKind,
  value: string,
): string =>
  sha256Hex([
    PUBLIC_AUDIT_MERKLE_LEAF_DOMAIN,
    kind,
    value.trim().toLowerCase(),
  ]);

export const hashPublicAuditNode = (left: string, right: string): string =>
  sha256Hex([
    PUBLIC_AUDIT_MERKLE_NODE_DOMAIN,
    left.trim().toLowerCase(),
    right.trim().toLowerCase(),
  ]);

export const buildPublicAuditMerkleTree = (
  leafHashes: readonly string[],
): PublicAuditMerkleTree => {
  if (leafHashes.length === 0) {
    return Object.freeze({
      root: PUBLIC_AUDIT_ZERO_ROOT,
      leafHashes: Object.freeze([]),
      levels: Object.freeze([Object.freeze([])]),
    });
  }

  const normalizedLeaves = leafHashes.map((leafHash) => {
    const normalized = normalizeHex64(leafHash);
    if (!normalized) {
      throw new TypeError("Public audit Merkle leaves must be 32-byte hex hashes.");
    }
    return normalized;
  });

  const levels: string[][] = [normalizedLeaves];
  let currentLevel = normalizedLeaves;

  while (currentLevel.length > 1) {
    const nextLevel: string[] = [];
    for (let index = 0; index < currentLevel.length; index += 2) {
      const left = currentLevel[index];
      const right = currentLevel[index + 1] ?? left;
      nextLevel.push(hashPublicAuditNode(left, right));
    }

    levels.push(nextLevel);
    currentLevel = nextLevel;
  }

  return Object.freeze({
    root: currentLevel[0],
    leafHashes: Object.freeze([...normalizedLeaves]),
    levels: Object.freeze(levels.map((level) => Object.freeze([...level]))),
  });
};

export const buildPublicAuditMerkleProof = (
  tree: PublicAuditMerkleTree,
  leafIndex: number,
): PublicAuditMerkleProofStepDto[] => {
  if (
    leafIndex < 0 ||
    !Number.isInteger(leafIndex) ||
    leafIndex >= tree.leafHashes.length
  ) {
    throw new RangeError("Public audit Merkle leaf index is out of range.");
  }

  const proof: PublicAuditMerkleProofStepDto[] = [];
  let indexAtLevel = leafIndex;

  for (let levelIndex = 0; levelIndex < tree.levels.length - 1; levelIndex += 1) {
    const level = tree.levels[levelIndex];
    const isRight = indexAtLevel % 2 === 1;
    const siblingIndex = isRight ? indexAtLevel - 1 : indexAtLevel + 1;
    const siblingHash = level[siblingIndex] ?? level[indexAtLevel];

    proof.push({
      position: isRight ? "left" : "right",
      hash: siblingHash,
    });

    indexAtLevel = Math.floor(indexAtLevel / 2);
  }

  return proof;
};

export const verifyPublicAuditMerkleProof = (input: {
  leafHash: string;
  root: string;
  proof: readonly PublicAuditMerkleProofStepDto[];
}): boolean => {
  const normalizedLeaf = normalizeHex64(input.leafHash);
  const normalizedRoot = normalizeHex64(input.root);
  if (!normalizedLeaf || !normalizedRoot) {
    return false;
  }

  const computedRoot = input.proof.reduce((acc, step) => {
    const sibling = normalizeHex64(step.hash);
    if (!sibling) {
      return "";
    }

    return step.position === "left"
      ? hashPublicAuditNode(sibling, acc)
      : hashPublicAuditNode(acc, sibling);
  }, normalizedLeaf);

  return computedRoot === normalizedRoot;
};

const buildTreeSummary = (
  kind: PublicAuditTreeKind,
  tree: AuditMerkleTree,
): PublicAuditTreeSummaryDto => {
  const poseidonTree = "leafCapacity" in tree;

  return {
    kind,
    root: tree.root,
    leafCount: tree.leafHashes.length,
    hashAlgorithm: poseidonTree ? POSEIDON_AUDIT_HASH_ALGORITHM : "sha256",
    leafHashDomain: poseidonTree
      ? POSEIDON_AUDIT_LEAF_DOMAIN
      : PUBLIC_AUDIT_MERKLE_LEAF_DOMAIN,
    nodeHashDomain: poseidonTree
      ? POSEIDON_AUDIT_NODE_DOMAIN
      : PUBLIC_AUDIT_MERKLE_NODE_DOMAIN,
    ...(poseidonTree
      ? {
          treeDepth: POSEIDON_AUDIT_TREE_DEPTH,
          leafCapacity: POSEIDON_AUDIT_TREE_LEAF_CAPACITY,
        }
      : null),
  };
};

const buildOptionResults = (
  options: readonly PollOptionRow[],
  params: {
    countsByOptionId: Record<string, number>;
    totalVotes: number;
  },
): PollOptionResultDto[] => {
  const totalVotes = Math.max(0, Math.trunc(params.totalVotes));

  return [...options]
    .sort((left, right) => left.display_order - right.display_order)
    .map((option) => {
      const count = Math.max(
        0,
        Math.trunc(params.countsByOptionId[option.id] || 0),
      );

      return {
        optionId: option.id,
        label: option.label,
        count,
        percentage: totalVotes > 0 ? (count / totalVotes) * 100 : 0,
      };
    });
};

const buildResultsSummary = (
  pollId: string,
  options: readonly PollOptionRow[],
  params: {
    countsByOptionId: Record<string, number>;
    totalVotes: number;
    updatedAt: string;
  },
): PollResultsSummaryDto => {
  const optionResults = buildOptionResults(options, params);
  const winningOption =
    params.totalVotes > 0 && optionResults.some((entry) => entry.count > 0)
      ? optionResults.reduce<PollOptionResultDto | null>((winner, candidate) => {
          if (!winner || candidate.count > winner.count) {
            return candidate;
          }

          return winner;
        }, null)
      : null;

  return {
    pollId,
    totalVotes: Math.max(0, Math.trunc(params.totalVotes)),
    optionResults,
    winningOptionId: winningOption?.optionId ?? null,
    winningOptionLabel: winningOption?.label ?? null,
    updatedAt: params.updatedAt,
  };
};

const buildResultHash = (input: {
  poll: PollRow;
  acceptedVoteCount: number;
  totalValidVoteCount: number;
  nullifierRoot: string;
  voteCommitmentRoot: string;
  encryptedVoteRoot: string;
  finalResult: PollResultsSummaryDto;
  tallyProof: Pick<
    PollTallyProofRow,
    | "tally_proof_hash"
    | "tally_public_inputs_hash"
    | "tally_verifier_key_hash"
    | "tally_circuit_id"
  > | null;
}): string =>
  hashCanonicalJson({
    version: PUBLIC_AUDIT_RESULT_HASH_VERSION,
    pollId: input.poll.id,
    pollStatus: input.poll.status,
    pollPolicyHash: input.poll.poll_policy_hash ?? null,
    credentialSchemaHash: input.poll.credential_schema_hash ?? null,
    optionSetHash: input.poll.option_set_hash ?? null,
    acceptedVoteCount: input.acceptedVoteCount,
    totalValidVoteCount: input.totalValidVoteCount,
    optionCount: input.finalResult.optionResults.length,
    finalNullifierRoot: input.nullifierRoot,
    finalVoteCommitmentRoot: input.voteCommitmentRoot,
    finalEncryptedVoteRoot: input.encryptedVoteRoot,
    tallyProofHash: input.tallyProof?.tally_proof_hash ?? null,
    tallyPublicInputsHash: input.tallyProof?.tally_public_inputs_hash ?? null,
    tallyVerifierKeyHash: input.tallyProof?.tally_verifier_key_hash ?? null,
    tallyCircuitId: input.tallyProof?.tally_circuit_id ?? null,
    result: {
      totalVotes: input.finalResult.totalVotes,
      optionResults: input.finalResult.optionResults.map((entry) => ({
        optionId: entry.optionId,
        label: entry.label,
        count: entry.count,
      })),
    },
  });

const buildWarnings = (input: {
  poll: PollRow;
  acceptedVoteCount: number;
  totalValidVoteCount: number;
  publishedRootCount: number;
  tallyProof: PollTallyProofRow | null;
}): string[] => {
  const warnings: string[] = [];

  if (!input.poll.poll_policy_hash || !input.poll.credential_schema_hash) {
    warnings.push("Poll proof policy hashes are not frozen for this poll.");
  }

  if (input.acceptedVoteCount !== input.totalValidVoteCount) {
    warnings.push(
      "Accepted audit record count differs from total valid vote count; legacy votes may not have proof audit material.",
    );
  }

  if (
    !env.solanaAudit.transactionsEnabled &&
    input.acceptedVoteCount > 0 &&
    input.publishedRootCount === 0
  ) {
    warnings.push("On-chain audit publication is not enabled yet.");
  }

  if (
    isProductionZkpPoll(input.poll) &&
    input.acceptedVoteCount > 0 &&
    !input.tallyProof
  ) {
    warnings.push("No verified tally proof has been recorded for this poll yet.");
  }

  return warnings;
};

const buildLegacyAuditTrees = (
  records: PublicAuditRecordRow[],
): {
  nullifierTree: PublicAuditMerkleTree;
  voteCommitmentTree: PublicAuditMerkleTree;
  encryptedVoteTree: PublicAuditMerkleTree;
} => {
  const nullifierLeafHashes = records.map((record) =>
    hashPublicAuditLeaf("nullifier", record.nullifier ?? ""),
  );
  const voteCommitmentLeafHashes = records.map((record) =>
    hashPublicAuditLeaf("vote_commitment", record.vote_commitment ?? ""),
  );
  const encryptedVoteLeafHashes = records
    .map(
      (record) =>
        record.encrypted_vote_commitment ?? record.encrypted_vote_hash ?? "",
    )
    .filter((encryptedVoteCommitment) => normalizeHex64(encryptedVoteCommitment))
    .map((encryptedVoteCommitment) =>
      hashPublicAuditLeaf("encrypted_vote", encryptedVoteCommitment),
    );

  return {
    nullifierTree: buildPublicAuditMerkleTree(nullifierLeafHashes),
    voteCommitmentTree: buildPublicAuditMerkleTree(voteCommitmentLeafHashes),
    encryptedVoteTree: buildPublicAuditMerkleTree(encryptedVoteLeafHashes),
  };
};

const requireAuditValue = (
  kind: PublicAuditTreeKind,
  value: string | null | undefined,
): string => {
  const normalized = normalizeHex64(value ?? "");
  if (!normalized) {
    throw new TypeError(
      `Production ZKP audit record is missing ${kind} material.`,
    );
  }
  return normalized;
};

/**
 * Frozen batch segmentation rule for production ZKP audit trees:
 * accepted records ordered by (accepted_at asc, id asc); the record at
 * position p belongs to batch floor(p / 64) at leaf index p % 64. A batch is
 * sealed (root immutable, eligible for on-chain anchoring) once it holds 64
 * leaves or the poll has reached its finalizable state.
 */
export const PUBLIC_AUDIT_BATCH_LEAF_CAPACITY =
  POSEIDON_AUDIT_TREE_LEAF_CAPACITY;

type PollAuditBatchMaterial = Readonly<{
  batchIndex: number;
  batchId: string;
  records: PublicAuditRecordRow[];
  acceptedCount: number;
  sealed: boolean;
  nullifierTree: AuditMerkleTree;
  voteCommitmentTree: AuditMerkleTree;
  encryptedVoteTree: AuditMerkleTree;
}>;

const segmentProductionAuditRecords = (
  records: PublicAuditRecordRow[],
): PublicAuditRecordRow[][] => {
  if (records.length === 0) {
    return [[]];
  }

  const segments: PublicAuditRecordRow[][] = [];
  for (
    let offset = 0;
    offset < records.length;
    offset += PUBLIC_AUDIT_BATCH_LEAF_CAPACITY
  ) {
    segments.push(
      records.slice(offset, offset + PUBLIC_AUDIT_BATCH_LEAF_CAPACITY),
    );
  }
  return segments;
};

const buildProductionPoseidonAuditTrees = async (
  records: PublicAuditRecordRow[],
): Promise<{
  nullifierTree: PoseidonAuditTree;
  voteCommitmentTree: PoseidonAuditTree;
  encryptedVoteTree: PoseidonAuditTree;
}> => {
  const nullifierLeafHashes = await Promise.all(
    records.map((record) =>
      hashPoseidonAuditLeaf(
        "nullifier",
        requireAuditValue("nullifier", record.nullifier),
      ),
    ),
  );
  const voteCommitmentLeafHashes = await Promise.all(
    records.map((record) =>
      hashPoseidonAuditLeaf(
        "vote_commitment",
        requireAuditValue("vote_commitment", record.vote_commitment),
      ),
    ),
  );
  const encryptedVoteLeafHashes = await Promise.all(
    records.map((record) =>
      hashPoseidonAuditLeaf(
        "encrypted_vote",
        requireAuditValue(
          "encrypted_vote",
          record.encrypted_vote_commitment,
        ),
      ),
    ),
  );

  return {
    nullifierTree: await buildPoseidonAuditMerkleTree(nullifierLeafHashes),
    voteCommitmentTree: await buildPoseidonAuditMerkleTree(
      voteCommitmentLeafHashes,
    ),
    encryptedVoteTree: await buildPoseidonAuditMerkleTree(
      encryptedVoteLeafHashes,
    ),
  };
};

const buildAuditBatches = async (
  poll: PollRow,
  records: PublicAuditRecordRow[],
): Promise<PollAuditBatchMaterial[]> => {
  if (!isProductionZkpPoll(poll)) {
    return [
      Object.freeze({
        batchIndex: 0,
        batchId: "0",
        records,
        acceptedCount: records.length,
        sealed: records.length > 0,
        ...buildLegacyAuditTrees(records),
      }),
    ];
  }

  const finalizable = isPollFinalResultPublishable(poll);
  const segments = segmentProductionAuditRecords(records);
  return Promise.all(
    segments.map(async (segment, batchIndex) =>
      Object.freeze({
        batchIndex,
        batchId: String(batchIndex),
        records: segment,
        acceptedCount: segment.length,
        sealed:
          segment.length > 0 &&
          (segment.length === PUBLIC_AUDIT_BATCH_LEAF_CAPACITY || finalizable),
        ...(await buildProductionPoseidonAuditTrees(segment)),
      }),
    ),
  );
};

type PublicAuditRecordRow = {
  id: string;
  poll_id: string;
  nullifier: string | null;
  vote_commitment: string | null;
  proof_hash: string | null;
  encrypted_vote_hash?: string | null;
  encrypted_vote_commitment?: string | null;
  accepted_at: string | null;
  batch_id: string | null;
  created_at: string;
};

type PollAuditMaterial = Readonly<{
  options: PollOptionRow[];
  auditRecords: PublicAuditRecordRow[];
  totalValidVoteCount: number;
  acceptedVoteCount: number;
  batches: readonly PollAuditBatchMaterial[];
  nullifierTree: AuditMerkleTree;
  voteCommitmentTree: AuditMerkleTree;
  encryptedVoteTree: AuditMerkleTree;
  tallyProof: PollTallyProofRow | null;
  finalResult: PollResultsSummaryDto;
  resultHash: string;
}>;

const buildSolanaExplorerUrl = (signature: string | null): string | null => {
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

const parseBatchIndex = (batchId: string): number => {
  const parsed = Number.parseInt(batchId, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
};

const mapRootCommit = (root: PollRootRow): PublicAuditRootCommitDto | null => {
  if (!root.solana_tx_signature) {
    return null;
  }

  return {
    status: "published_on_chain",
    batchIndex: parseBatchIndex(root.batch_id),
    acceptedCount: root.accepted_count,
    nullifierRoot: root.nullifier_root,
    voteCommitmentRoot: root.vote_commitment_root,
    encryptedVoteRoot: root.encrypted_vote_root,
    transactionSignature: root.solana_tx_signature,
    explorerUrl: buildSolanaExplorerUrl(root.solana_tx_signature) || "",
    submittedAt: root.created_at,
  };
};

const isPollFinalResultPublishable = (poll: PollRow): boolean => {
  if (poll.status === "closed" || poll.status === "archived") {
    return true;
  }

  if (!poll.ends_at) {
    return false;
  }

  return new Date(poll.ends_at).getTime() <= Date.now();
};

const isProductionZkpPoll = (poll: PollRow): boolean =>
  poll.vote_privacy_mode === CIVIC_PRODUCTION_VOTE_PRIVACY_MODE;

const mapTallyVerifierReasonToAuditReasonCode = (
  reason: string,
): ZkpAuditRejectionReasonCode => {
  switch (reason) {
    case "PROOF_REQUIRED":
      return ZKP_AUDIT_REJECTION_REASON_CODES.proofRequired;
    case "VERIFIER_KEY_MISMATCH":
      return ZKP_AUDIT_REJECTION_REASON_CODES.unknownVerifierKey;
    case "VERIFIER_DISABLED":
      return ZKP_AUDIT_REJECTION_REASON_CODES.verifierDisabled;
    case "VERIFIER_UNCONFIGURED":
      return ZKP_AUDIT_REJECTION_REASON_CODES.verifierUnconfigured;
    case "VERIFIER_REJECTED":
      return ZKP_AUDIT_REJECTION_REASON_CODES.verifierRejected;
    default:
      return ZKP_AUDIT_REJECTION_REASON_CODES.tallyProofInvalid;
  }
};

export const hashPublicAuditLeafForPoll = async (
  poll: PollRow,
  kind: PublicAuditTreeKind,
  value: string,
): Promise<string> =>
  isProductionZkpPoll(poll)
    ? hashPoseidonAuditLeaf(kind, value)
    : hashPublicAuditLeaf(kind, value);

const buildAuditMerkleProof = (
  tree: AuditMerkleTree,
  leafIndex: number,
): PublicAuditMerkleProofStepDto[] =>
  "leafCapacity" in tree
    ? buildPoseidonAuditMerkleProof(tree, leafIndex)
    : buildPublicAuditMerkleProof(tree, leafIndex);

const mapTallyProofSummary = (
  tallyProof: PollTallyProofRow | null,
): PublicAuditTallyProofSummaryDto | null =>
  tallyProof
    ? {
        resultHash: tallyProof.result_hash,
        tallyProofHash: tallyProof.tally_proof_hash,
        tallyPublicInputsHash: tallyProof.tally_public_inputs_hash,
        tallyVerifierKeyHash: tallyProof.tally_verifier_key_hash,
        tallyCircuitId: tallyProof.tally_circuit_id,
        nullifierRoot: tallyProof.nullifier_root,
        voteCommitmentRoot: tallyProof.vote_commitment_root,
        encryptedVoteRoot: tallyProof.encrypted_vote_root,
        acceptedCount: tallyProof.accepted_count,
        verifiedAt: tallyProof.verified_at,
      }
    : null;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const readTallyProofCounts = (
  tallyProof: PollTallyProofRow | null,
): Record<string, number> | null => {
  if (!tallyProof || !isRecord(tallyProof.proof_envelope_json)) {
    return null;
  }

  const publicInputs = tallyProof.proof_envelope_json.publicInputs;
  if (!isRecord(publicInputs) || !Array.isArray(publicInputs.optionResults)) {
    return null;
  }

  return publicInputs.optionResults.reduce<Record<string, number> | null>(
    (acc, entry) => {
      if (!acc || !isRecord(entry)) {
        return null;
      }

      const optionId =
        typeof entry.optionId === "string" ? entry.optionId.trim() : "";
      const count = typeof entry.count === "number" ? entry.count : NaN;
      if (!optionId || !Number.isInteger(count) || count < 0) {
        return null;
      }

      acc[optionId] = count;
      return acc;
    },
    {},
  );
};

const buildCountsFromOptionResults = (
  optionResults: readonly { optionId: string; count: number }[],
): Record<string, number> =>
  optionResults.reduce<Record<string, number>>((acc, entry) => {
    acc[entry.optionId] = Math.max(0, Math.trunc(entry.count));
    return acc;
  }, {});

const getAcceptedAuditRecordsByPoll = async (
  poll: PollRow,
): Promise<PublicAuditRecordRow[]> =>
  isProductionZkpPoll(poll)
    ? pollZkVoteRepository.getAcceptedAuditRecordsByPollId(poll.id)
    : voteRepository.getAcceptedAuditRecordsByPollId(poll.id);

const countValidVotesByPoll = async (poll: PollRow): Promise<number> =>
  isProductionZkpPoll(poll)
    ? pollZkVoteRepository.countAcceptedByPollId(poll.id)
    : voteRepository.countValidByPollId(poll.id);

const loadPollAuditMaterial = async (poll: PollRow): Promise<PollAuditMaterial> => {
  const productionPoll = isProductionZkpPoll(poll);
  const [
    options,
    auditRecords,
    totalValidVoteCount,
    latestSubmittedAt,
    tallyProof,
  ] =
    await Promise.all([
      pollRepository.getOptionsByPollId(poll.id),
      getAcceptedAuditRecordsByPoll(poll),
      countValidVotesByPoll(poll),
      productionPoll
        ? Promise.resolve(null)
        : voteRepository.getLatestValidSubmittedAtByPollId(poll.id),
      productionPoll
        ? pollTallyProofRepository.getLatestByPollId(poll.id)
        : Promise.resolve(null),
    ]);

  const tallyCounts = readTallyProofCounts(tallyProof);
  const optionCountEntries = productionPoll
    ? options.map((option) => [option.id, tallyCounts?.[option.id] ?? 0] as const)
    : await Promise.all(
        options.map(async (option) => [
          option.id,
          await voteRepository.countValidByPollIdAndOptionId(poll.id, option.id),
        ] as const),
      );
  const countsByOptionId = optionCountEntries.reduce<Record<string, number>>(
    (acc, [optionId, count]) => {
      acc[optionId] = count;
      return acc;
    },
    {},
  );

  const acceptedVoteCount = auditRecords.length;
  const batches = await buildAuditBatches(poll, auditRecords);
  const latestBatch = batches[batches.length - 1];
  const { nullifierTree, voteCommitmentTree, encryptedVoteTree } = latestBatch;
  const finalResult = buildResultsSummary(poll.id, options, {
    countsByOptionId,
    totalVotes: totalValidVoteCount,
    updatedAt: tallyProof?.verified_at || latestSubmittedAt || poll.updated_at,
  });
  const resultHash = buildResultHash({
    poll,
    acceptedVoteCount,
    totalValidVoteCount,
    nullifierRoot: nullifierTree.root,
    voteCommitmentRoot: voteCommitmentTree.root,
    encryptedVoteRoot: encryptedVoteTree.root,
    finalResult,
    tallyProof,
  });

  return Object.freeze({
    options,
    auditRecords,
    totalValidVoteCount,
    acceptedVoteCount,
    batches,
    nullifierTree,
    voteCommitmentTree,
    encryptedVoteTree,
    tallyProof,
    finalResult,
    resultHash,
  });
};

const getOrderedActivePollOptions = (
  options: readonly PollOptionRow[],
): PollOptionRow[] =>
  [...options]
    .filter((option) => option.is_active)
    .sort((left, right) => left.display_order - right.display_order);

const getOrderedActivePollOptionIds = (
  options: readonly PollOptionRow[],
): string[] => getOrderedActivePollOptions(options).map((option) => option.id);

export const pollPublicAuditService = {
  async getPublicPollAudit(pollId: string): Promise<PublicPollAuditDto | null> {
    const poll = await pollRepository.getById(pollId);
    if (!poll) {
      return null;
    }

    const [material, publishedRoots] = await Promise.all([
      loadPollAuditMaterial(poll),
      pollAuditRepository.listRootsByPollId(poll.id),
    ]);
    const rootCommits = publishedRoots
      .map((root) => mapRootCommit(root))
      .filter((entry): entry is PublicAuditRootCommitDto => Boolean(entry));
    const rootCommitsByBatchIndex = new Map(
      rootCommits.map((commit) => [commit.batchIndex, commit]),
    );
    const auditBatches = material.batches
      .filter((batch) => batch.acceptedCount > 0)
      .map((batch) => ({
        batchIndex: batch.batchIndex,
        acceptedCount: batch.acceptedCount,
        sealed: batch.sealed,
        nullifierRoot: batch.nullifierTree.root,
        voteCommitmentRoot: batch.voteCommitmentTree.root,
        encryptedVoteRoot: batch.encryptedVoteTree.root,
        publication: rootCommitsByBatchIndex.get(batch.batchIndex) ?? null,
      }));
    const currentBatch = material.batches[material.batches.length - 1];
    const generatedAt = new Date().toISOString();
    const publicationStatus =
      rootCommits.length > 0
        ? "published_on_chain"
        : material.acceptedVoteCount > 0
        ? "pending_on_chain_publication"
        : "not_applicable";

    return {
      version: PUBLIC_AUDIT_VERSION,
      pollId: poll.id,
      pollStatus: poll.status,
      pollPolicyHash: poll.poll_policy_hash ?? null,
      credentialSchemaHash: poll.credential_schema_hash ?? null,
      optionSetHash: poll.option_set_hash ?? null,
      generatedAt,
      publicationStatus,
      acceptedVoteCount: material.acceptedVoteCount,
      totalValidVoteCount: material.totalValidVoteCount,
      trees: {
        nullifier: buildTreeSummary("nullifier", material.nullifierTree),
        voteCommitment: buildTreeSummary(
          "vote_commitment",
          material.voteCommitmentTree,
        ),
        encryptedVote: buildTreeSummary(
          "encrypted_vote",
          material.encryptedVoteTree,
        ),
      },
      auditBatches,
      computedCurrentRootBatch:
        currentBatch.acceptedCount > 0 &&
        !rootCommitsByBatchIndex.has(currentBatch.batchIndex)
          ? {
              status: "pending_on_chain_publication",
              batchIndex: currentBatch.batchIndex,
              acceptedCount: currentBatch.acceptedCount,
              nullifierRoot: material.nullifierTree.root,
              voteCommitmentRoot: material.voteCommitmentTree.root,
              encryptedVoteRoot: material.encryptedVoteTree.root,
              transactionSignature: null,
              explorerUrl: null,
              submittedAt: null,
            }
          : null,
      rootCommits,
      resultHash: material.resultHash,
      tallyProofHash: material.tallyProof?.tally_proof_hash ?? null,
      tallyPublicInputsHash:
        material.tallyProof?.tally_public_inputs_hash ?? null,
      tallyProof: mapTallyProofSummary(material.tallyProof),
      finalResult: material.finalResult,
      solana: {
        cluster: env.solanaAudit.cluster,
        programId: env.solanaAudit.programId,
        transactionsEnabled: env.solanaAudit.transactionsEnabled,
      },
      inclusionCheck: {
        route: `/polls/${encodeURIComponent(poll.id)}/audit/inclusion`,
        acceptedTrees: ["vote_commitment", "nullifier", "encrypted_vote"],
        expectsLeafHash: true,
      },
      warnings: buildWarnings({
        poll,
        acceptedVoteCount: material.acceptedVoteCount,
        totalValidVoteCount: material.totalValidVoteCount,
        publishedRootCount: rootCommits.length,
        tallyProof: material.tallyProof,
      }),
    };
  },

  async publishPollAudit(input: {
    pollId: string;
    viewerUserId: string;
  }): Promise<
    | {
        success: true;
        message: string;
        publication: SolanaAuditPublicationResult;
        audit: PublicPollAuditDto;
      }
    | {
        success: false;
        errorCode:
          | "POLL_NOT_FOUND"
          | "POLL_NOT_OWNED"
          | "NO_ACCEPTED_AUDIT_VOTES"
          | "TRANSACTIONS_DISABLED"
          | "PUBLICATION_FAILED";
        message: string;
      }
  > {
    const poll = await pollRepository.getById(input.pollId);
    if (!poll) {
      return {
        success: false,
        errorCode: "POLL_NOT_FOUND",
        message: "The requested poll does not exist.",
      };
    }

    if (poll.created_by_user_id !== input.viewerUserId) {
      if (isProductionZkpPoll(poll)) {
        await zkpAuditEventService.appendPublicationRejected({
          pollId: poll.id,
          reasonCode: ZKP_AUDIT_REJECTION_REASON_CODES.pollNotOwned,
          errorCode: "POLL_NOT_OWNED",
        });
      }
      return {
        success: false,
        errorCode: "POLL_NOT_OWNED",
        message: "Only the poll creator can publish audit roots on-chain.",
      };
    }

    if (!env.solanaAudit.transactionsEnabled) {
      if (isProductionZkpPoll(poll)) {
        await zkpAuditEventService.appendPublicationRejected({
          pollId: poll.id,
          reasonCode: ZKP_AUDIT_REJECTION_REASON_CODES.transactionsDisabled,
          errorCode: "TRANSACTIONS_DISABLED",
        });
      }
      return {
        success: false,
        errorCode: "TRANSACTIONS_DISABLED",
        message: "Solana audit transactions are disabled for this backend.",
      };
    }

    const material = await loadPollAuditMaterial(poll);
    if (material.acceptedVoteCount <= 0) {
      if (isProductionZkpPoll(poll)) {
        await zkpAuditEventService.appendPublicationRejected({
          pollId: poll.id,
          reasonCode: ZKP_AUDIT_REJECTION_REASON_CODES.noAcceptedAuditVotes,
          errorCode: "NO_ACCEPTED_AUDIT_VOTES",
          acceptedVoteCount: material.acceptedVoteCount,
          resultHash: material.resultHash,
        });
      }
      return {
        success: false,
        errorCode: "NO_ACCEPTED_AUDIT_VOTES",
        message: "This poll has no accepted proof-backed votes to publish.",
      };
    }

    const existingRoots = await pollAuditRepository.listRootsByPollId(poll.id);
    const existingRootsByBatchId = new Map(
      existingRoots.map((root) => [root.batch_id, root]),
    );

    // Sealed batches are anchored in batch order; each commit chains from the
    // previous batch's committed roots so the on-chain previous-root checks
    // hold. An unsealed tail batch stays pending until it fills or the poll
    // becomes finalizable.
    type BatchCommitDescriptor = {
      batch: PollAuditBatchMaterial;
      previousNullifierRoot: string;
      previousVoteCommitmentRoot: string;
      previousEncryptedVoteRoot: string;
      cumulativeAcceptedCount: number;
    };
    const batchCommitDescriptors: BatchCommitDescriptor[] = [];
    let previousNullifierRoot = PUBLIC_AUDIT_ZERO_ROOT;
    let previousVoteCommitmentRoot = PUBLIC_AUDIT_ZERO_ROOT;
    let previousEncryptedVoteRoot = PUBLIC_AUDIT_ZERO_ROOT;
    let cumulativeAcceptedCount = 0;
    let uncommittedSealedRemainder = false;
    for (const batch of material.batches) {
      if (batch.acceptedCount <= 0) {
        continue;
      }
      cumulativeAcceptedCount += batch.acceptedCount;
      const existing = existingRootsByBatchId.get(batch.batchId);
      if (existing) {
        previousNullifierRoot = existing.nullifier_root;
        previousVoteCommitmentRoot = existing.vote_commitment_root;
        previousEncryptedVoteRoot = existing.encrypted_vote_root;
        continue;
      }
      if (!batch.sealed) {
        uncommittedSealedRemainder = true;
        break;
      }
      batchCommitDescriptors.push({
        batch,
        previousNullifierRoot,
        previousVoteCommitmentRoot,
        previousEncryptedVoteRoot,
        cumulativeAcceptedCount,
      });
      previousNullifierRoot = batch.nullifierTree.root;
      previousVoteCommitmentRoot = batch.voteCommitmentTree.root;
      previousEncryptedVoteRoot = batch.encryptedVoteTree.root;
    }

    const publishFinalResult =
      isPollFinalResultPublishable(poll) && !uncommittedSealedRemainder;

    try {
      const publication = await solanaAuditPublisherService.publishPollAudit({
        poll,
        batchCommits: batchCommitDescriptors.map((descriptor) => ({
          batchIndex: descriptor.batch.batchIndex,
          previousNullifierRoot: descriptor.previousNullifierRoot,
          nullifierRoot: descriptor.batch.nullifierTree.root,
          previousVoteCommitmentRoot: descriptor.previousVoteCommitmentRoot,
          voteCommitmentRoot: descriptor.batch.voteCommitmentTree.root,
          previousEncryptedVoteRoot: descriptor.previousEncryptedVoteRoot,
          encryptedVoteRoot: descriptor.batch.encryptedVoteTree.root,
          acceptedCountDelta: descriptor.batch.acceptedCount,
        })),
        finalNullifierRoot: material.nullifierTree.root,
        finalVoteCommitmentRoot: material.voteCommitmentTree.root,
        finalEncryptedVoteRoot: material.encryptedVoteTree.root,
        acceptedVoteCount: material.acceptedVoteCount,
        resultHash: material.resultHash,
        tallyProofHash: material.tallyProof?.tally_proof_hash ?? null,
        publishFinalResult,
      });

      const auditRecordRepository = isProductionZkpPoll(poll)
        ? pollZkVoteRepository
        : voteRepository;
      const committedByBatchIndex = new Map(
        publication.rootCommits.map((commit) => [commit.batchIndex, commit]),
      );
      for (const descriptor of batchCommitDescriptors) {
        const committed = committedByBatchIndex.get(
          descriptor.batch.batchIndex,
        );
        if (!committed?.signature) {
          continue;
        }

        await pollAuditRepository.insertRoot({
          poll_id: poll.id,
          batch_id: descriptor.batch.batchId,
          previous_nullifier_root: descriptor.previousNullifierRoot,
          nullifier_root: descriptor.batch.nullifierTree.root,
          previous_vote_commitment_root: descriptor.previousVoteCommitmentRoot,
          vote_commitment_root: descriptor.batch.voteCommitmentTree.root,
          previous_encrypted_vote_root: descriptor.previousEncryptedVoteRoot,
          encrypted_vote_root: descriptor.batch.encryptedVoteTree.root,
          accepted_count: descriptor.cumulativeAcceptedCount,
          solana_tx_signature: committed.signature,
        });
        await auditRecordRepository.markAcceptedAuditRecordsBatch({
          pollId: poll.id,
          batchId: descriptor.batch.batchId,
          recordIds: descriptor.batch.records.map((record) => record.id),
        });
        await pollAuditRepository.insertAuditEvent({
          poll_id: poll.id,
          event_type: "poll_root_published_on_chain",
          payload_hash: material.resultHash,
          payload_json: {
            batchIndex: descriptor.batch.batchIndex,
            batchAcceptedCount: descriptor.batch.acceptedCount,
            acceptedVoteCount: descriptor.cumulativeAcceptedCount,
            nullifierRoot: descriptor.batch.nullifierTree.root,
            voteCommitmentRoot: descriptor.batch.voteCommitmentTree.root,
            encryptedVoteRoot: descriptor.batch.encryptedVoteTree.root,
            tallyProofHash: material.tallyProof?.tally_proof_hash ?? null,
            tallyPublicInputsHash:
              material.tallyProof?.tally_public_inputs_hash ?? null,
            pollAddress: publication.pollAddress,
            rootAddress: committed.rootAddress,
          },
          solana_tx_signature: committed.signature,
        });
        if (isProductionZkpPoll(poll)) {
          await zkpAuditEventService.appendRootPublished({
            pollId: poll.id,
            batchIndex: descriptor.batch.batchIndex,
            batchId: descriptor.batch.batchId,
            acceptedCount: descriptor.batch.acceptedCount,
            cumulativeAcceptedCount: descriptor.cumulativeAcceptedCount,
            resultHash: material.resultHash,
            nullifierRoot: descriptor.batch.nullifierTree.root,
            voteCommitmentRoot: descriptor.batch.voteCommitmentTree.root,
            encryptedVoteRoot: descriptor.batch.encryptedVoteTree.root,
            tallyProofHash: material.tallyProof?.tally_proof_hash ?? null,
            tallyPublicInputsHash:
              material.tallyProof?.tally_public_inputs_hash ?? null,
            solanaTxSignature: committed.signature,
            pollAddress: publication.pollAddress,
            rootAddress: committed.rootAddress,
          });
        }
      }

      if (publication.finalResultSignature) {
        await pollAuditRepository.insertAuditEvent({
          poll_id: poll.id,
          event_type: "poll_final_result_published_on_chain",
          payload_hash: material.resultHash,
          payload_json: {
            resultHash: material.resultHash,
            finalResultAddress: publication.finalResultAddress,
            acceptedVoteCount: material.acceptedVoteCount,
            nullifierRoot: material.nullifierTree.root,
            voteCommitmentRoot: material.voteCommitmentTree.root,
            encryptedVoteRoot: material.encryptedVoteTree.root,
            tallyProofHash: material.tallyProof?.tally_proof_hash ?? null,
            tallyPublicInputsHash:
              material.tallyProof?.tally_public_inputs_hash ?? null,
          },
          solana_tx_signature: publication.finalResultSignature,
        });
        if (isProductionZkpPoll(poll)) {
          await zkpAuditEventService.appendFinalized({
            pollId: poll.id,
            resultHash: material.resultHash,
            acceptedVoteCount: material.acceptedVoteCount,
            nullifierRoot: material.nullifierTree.root,
            voteCommitmentRoot: material.voteCommitmentTree.root,
            encryptedVoteRoot: material.encryptedVoteTree.root,
            tallyProofHash: material.tallyProof?.tally_proof_hash ?? null,
            tallyPublicInputsHash:
              material.tallyProof?.tally_public_inputs_hash ?? null,
            solanaTxSignature: publication.finalResultSignature,
            finalResultAddress: publication.finalResultAddress,
          });
        }
      }

      const audit = await this.getPublicPollAudit(poll.id);
      if (!audit) {
        throw new Error("Published audit could not be reloaded.");
      }

      return {
        success: true,
        message:
          batchCommitDescriptors.length > 0 || publication.finalResultSignature
            ? "Poll audit roots were published on-chain."
            : "No sealed audit batches were ready to publish; the current batch stays pending until it fills or the poll closes.",
        publication,
        audit,
      };
    } catch (error) {
      if (isProductionZkpPoll(poll)) {
        await zkpAuditEventService.appendPublicationRejected({
          pollId: poll.id,
          reasonCode: ZKP_AUDIT_REJECTION_REASON_CODES.publicationFailed,
          errorCode: "PUBLICATION_FAILED",
          acceptedVoteCount: material.acceptedVoteCount,
          resultHash: material.resultHash,
        });
      }
      return {
        success: false,
        errorCode: "PUBLICATION_FAILED",
        message:
          error instanceof Error
            ? error.message
            : "Poll audit publication failed.",
      };
    }
  },

  async submitTallyProof(input: {
    pollId: string;
    viewerUserId: string;
    proof: Groth16TallyProofEnvelopeDto;
  }): Promise<
    | {
        success: true;
        message: string;
        tallyProof: PublicAuditTallyProofSummaryDto;
        audit: PublicPollAuditDto;
      }
    | {
        success: false;
        errorCode:
          | "POLL_NOT_FOUND"
          | "POLL_NOT_OWNED"
          | "POLL_NOT_PRODUCTION_ZKP"
          | "NO_ACCEPTED_AUDIT_VOTES"
          | "TALLY_BATCH_LIMIT_EXCEEDED"
          | "TALLY_PROOF_INVALID";
        reasonCode?: ZkpAuditRejectionReasonCode;
        message: string;
      }
  > {
    const poll = await pollRepository.getById(input.pollId);
    if (!poll) {
      return {
        success: false,
        errorCode: "POLL_NOT_FOUND",
        message: "The requested poll does not exist.",
      };
    }

    const rejectTallyProof = async (
      reasonCode: ZkpAuditRejectionReasonCode,
      errorCode:
        | "POLL_NOT_OWNED"
        | "POLL_NOT_PRODUCTION_ZKP"
        | "NO_ACCEPTED_AUDIT_VOTES"
        | "TALLY_BATCH_LIMIT_EXCEEDED"
        | "TALLY_PROOF_INVALID",
      message: string,
      auditPayload: Partial<
        Omit<
          Parameters<typeof zkpAuditEventService.appendTallyRejected>[0],
          "pollId" | "reasonCode" | "errorCode" | "occurredAt"
        >
      > = {},
    ) => {
      await zkpAuditEventService.appendTallyRejected({
        pollId: poll.id,
        reasonCode,
        errorCode,
        ...auditPayload,
      });
      return {
        success: false as const,
        errorCode,
        reasonCode,
        message,
      };
    };

    if (poll.created_by_user_id !== input.viewerUserId) {
      return rejectTallyProof(
        ZKP_AUDIT_REJECTION_REASON_CODES.pollNotOwned,
        "POLL_NOT_OWNED",
        "Only the poll creator can submit tally proofs.",
      );
    }

    if (!isProductionZkpPoll(poll)) {
      return rejectTallyProof(
        ZKP_AUDIT_REJECTION_REASON_CODES.pollNotProductionZkp,
        "POLL_NOT_PRODUCTION_ZKP",
        "Only production ZKP polls accept Groth16 tally proofs.",
      );
    }

    const material = await loadPollAuditMaterial(poll);
    const tallyProofHash = hashGroth16TallyProofEnvelope(input.proof);
    const tallyProofHints = {
      nullifierRoot: material.nullifierTree.root,
      voteCommitmentRoot: material.voteCommitmentTree.root,
      encryptedVoteRoot: material.encryptedVoteTree.root,
      acceptedCount: material.acceptedVoteCount,
      tallyProofHash,
      tallyPublicInputsHash: input.proof.publicInputsHash,
      tallyVerifierKeyHash: input.proof.verifierKeyHash,
      tallyCircuitId: input.proof.circuitId,
    };
    if (material.acceptedVoteCount <= 0) {
      return rejectTallyProof(
        ZKP_AUDIT_REJECTION_REASON_CODES.noAcceptedAuditVotes,
        "NO_ACCEPTED_AUDIT_VOTES",
        "This poll has no accepted proof-backed votes to tally.",
        tallyProofHints,
      );
    }

    if (material.acceptedVoteCount > PUBLIC_AUDIT_BATCH_LEAF_CAPACITY) {
      return rejectTallyProof(
        ZKP_AUDIT_REJECTION_REASON_CODES.tallyBatchLimitExceeded,
        "TALLY_BATCH_LIMIT_EXCEEDED",
        `This poll has ${material.acceptedVoteCount} accepted votes across ${material.batches.length} audit batches; the v1 tally circuit covers a single ${PUBLIC_AUDIT_BATCH_LEAF_CAPACITY}-vote batch, and chained batch tally proofs are not implemented yet.`,
        tallyProofHints,
      );
    }

    const verification = await verifyGroth16TallyProofForPoll({
      poll,
      proof: input.proof,
      nullifierRoot: material.nullifierTree.root,
      voteCommitmentRoot: material.voteCommitmentTree.root,
      encryptedVoteRoot: material.encryptedVoteTree.root,
      acceptedVoteCount: material.acceptedVoteCount,
      expectedOptionIds: getOrderedActivePollOptionIds(material.options),
    });
    if (!verification.ok) {
      return rejectTallyProof(
        mapTallyVerifierReasonToAuditReasonCode(verification.reason),
        "TALLY_PROOF_INVALID",
        verification.message,
        {
          ...tallyProofHints,
          verifierReason: verification.reason,
        },
      );
    }

    const tallyMaterial = verification.auditMaterial;
    const tallyCounts = buildCountsFromOptionResults(
      input.proof.publicInputs.optionResults,
    );
    const finalResult = buildResultsSummary(poll.id, material.options, {
      countsByOptionId: tallyCounts,
      totalVotes: material.totalValidVoteCount,
      updatedAt: new Date().toISOString(),
    });
    const resultHash = buildResultHash({
      poll,
      acceptedVoteCount: material.acceptedVoteCount,
      totalValidVoteCount: material.totalValidVoteCount,
      nullifierRoot: material.nullifierTree.root,
      voteCommitmentRoot: material.voteCommitmentTree.root,
      encryptedVoteRoot: material.encryptedVoteTree.root,
      finalResult,
      tallyProof: {
        tally_proof_hash: tallyMaterial.tallyProofHash,
        tally_public_inputs_hash: tallyMaterial.tallyPublicInputsHash,
        tally_verifier_key_hash: tallyMaterial.tallyVerifierKeyHash,
        tally_circuit_id: tallyMaterial.tallyCircuitId,
      },
    });

    const inserted = await pollTallyProofRepository.insertVerified({
      poll_id: poll.id,
      result_hash: resultHash,
      tally_proof_hash: tallyMaterial.tallyProofHash,
      tally_public_inputs_hash: tallyMaterial.tallyPublicInputsHash,
      tally_verifier_key_hash: tallyMaterial.tallyVerifierKeyHash,
      tally_circuit_id: tallyMaterial.tallyCircuitId,
      nullifier_root: tallyMaterial.nullifierRoot,
      vote_commitment_root: tallyMaterial.voteCommitmentRoot,
      encrypted_vote_root: tallyMaterial.encryptedVoteRoot,
      accepted_count: tallyMaterial.acceptedCount,
      proof_envelope_json: tallyMaterial.proofEnvelopeJson as unknown as JsonValue,
    });

    await zkpAuditEventService.appendTallyAccepted({
      pollId: poll.id,
      resultHash,
      tallyProofHash: tallyMaterial.tallyProofHash,
      tallyPublicInputsHash: tallyMaterial.tallyPublicInputsHash,
      tallyVerifierKeyHash: tallyMaterial.tallyVerifierKeyHash,
      tallyCircuitId: tallyMaterial.tallyCircuitId,
      nullifierRoot: tallyMaterial.nullifierRoot,
      voteCommitmentRoot: tallyMaterial.voteCommitmentRoot,
      encryptedVoteRoot: tallyMaterial.encryptedVoteRoot,
      acceptedCount: tallyMaterial.acceptedCount,
      occurredAt: inserted.verified_at,
    });

    const audit = await this.getPublicPollAudit(poll.id);
    if (!audit) {
      throw new Error("Verified tally proof could not be reloaded.");
    }

    return {
      success: true,
      message: "Poll tally proof was verified and recorded.",
      tallyProof: mapTallyProofSummary(inserted) || {
        resultHash: inserted.result_hash,
        tallyProofHash: inserted.tally_proof_hash,
        tallyPublicInputsHash: inserted.tally_public_inputs_hash,
        tallyVerifierKeyHash: inserted.tally_verifier_key_hash,
        tallyCircuitId: inserted.tally_circuit_id,
        nullifierRoot: inserted.nullifier_root,
        voteCommitmentRoot: inserted.vote_commitment_root,
        encryptedVoteRoot: inserted.encrypted_vote_root,
        acceptedCount: inserted.accepted_count,
        verifiedAt: inserted.verified_at,
      },
      audit,
    };
  },

  async getPublicPollAuditInclusionProof(input: {
    pollId: string;
    tree: PublicAuditTreeKind;
    leafHash: string;
  }): Promise<PublicAuditInclusionProofResultDto> {
    const poll = await pollRepository.getById(input.pollId);
    if (!poll) {
      return {
        success: false,
        errorCode: "POLL_NOT_FOUND",
        message: "The requested poll does not exist.",
      };
    }

    const normalizedLeafHash = normalizeHex64(input.leafHash);
    if (!normalizedLeafHash) {
      return {
        success: false,
        errorCode: "LEAF_NOT_FOUND",
        message: "No matching audit leaf was found for this poll.",
      };
    }

    const auditRecords = await getAcceptedAuditRecordsByPoll(poll);
    const batches = await buildAuditBatches(poll, auditRecords);
    const selectTree = (batch: PollAuditBatchMaterial): AuditMerkleTree =>
      input.tree === "nullifier"
        ? batch.nullifierTree
        : input.tree === "encrypted_vote"
          ? batch.encryptedVoteTree
          : batch.voteCommitmentTree;

    let matchingLeafCount = 0;
    let matchedBatch: PollAuditBatchMaterial | null = null;
    let matchedLeafIndex = -1;
    for (const batch of batches) {
      const leafHashes = selectTree(batch).leafHashes;
      for (let index = 0; index < leafHashes.length; index += 1) {
        if (leafHashes[index] !== normalizedLeafHash) {
          continue;
        }
        matchingLeafCount += 1;
        if (!matchedBatch) {
          matchedBatch = batch;
          matchedLeafIndex = index;
        }
      }
    }

    if (!matchedBatch || matchedLeafIndex < 0) {
      return {
        success: false,
        errorCode: "LEAF_NOT_FOUND",
        message: "No matching audit leaf was found for this poll.",
      };
    }

    const tree = selectTree(matchedBatch);
    return {
      success: true,
      pollId: poll.id,
      tree: input.tree,
      leafHash: normalizedLeafHash,
      batchIndex: matchedBatch.batchIndex,
      leafIndex: matchedLeafIndex,
      matchingLeafCount,
      root: tree.root,
      proof: buildAuditMerkleProof(tree, matchedLeafIndex),
    };
  },

  async getPublicVoteReceipt(input: {
    pollId: string;
    voteCommitment: string;
  }): Promise<PublicVoteReceiptLookupDto | null> {
    const poll = await pollRepository.getById(input.pollId);
    if (!poll) {
      return null;
    }

    const normalizedVoteCommitment = normalizeHex64(input.voteCommitment);
    const auditUrl = `/polls/${encodeURIComponent(poll.id)}/audit`;
    if (!normalizedVoteCommitment) {
      return {
        included: false,
        pollId: poll.id,
        voteCommitment: "",
        voteCommitmentLeafHash: "",
        batchStatus: "not_found",
        batchIndex: null,
        batchId: null,
        acceptedAt: null,
        proofHash: null,
        root: null,
        matchingLeafCount: 0,
        merklePath: [],
        solanaTx: null,
        solanaExplorerUrl: null,
        auditUrl,
      };
    }

    const voteCommitmentLeafHash = await hashPublicAuditLeafForPoll(
      poll,
      "vote_commitment",
      normalizedVoteCommitment,
    );
    const auditRecords = await getAcceptedAuditRecordsByPoll(poll);
    const batches = await buildAuditBatches(poll, auditRecords);

    let matchingLeafCount = 0;
    let matchedBatch: PollAuditBatchMaterial | null = null;
    let matchedLeafIndex = -1;
    for (const batch of batches) {
      const leafHashes = batch.voteCommitmentTree.leafHashes;
      for (let index = 0; index < leafHashes.length; index += 1) {
        if (leafHashes[index] !== voteCommitmentLeafHash) {
          continue;
        }
        matchingLeafCount += 1;
        if (!matchedBatch) {
          matchedBatch = batch;
          matchedLeafIndex = index;
        }
      }
    }

    if (!matchedBatch || matchedLeafIndex < 0) {
      const latestBatch = batches[batches.length - 1];
      return {
        included: false,
        pollId: poll.id,
        voteCommitment: normalizedVoteCommitment,
        voteCommitmentLeafHash,
        batchStatus: "not_found",
        batchIndex: null,
        batchId: null,
        acceptedAt: null,
        proofHash: null,
        root: latestBatch.voteCommitmentTree.root,
        matchingLeafCount: 0,
        merklePath: [],
        solanaTx: null,
        solanaExplorerUrl: null,
        auditUrl,
      };
    }

    const auditRecord = matchedBatch.records[matchedLeafIndex];
    const batchId = matchedBatch.batchId;
    const publishedRoot = await pollAuditRepository.getRootByPollIdAndBatchId(
      poll.id,
      batchId,
    );
    const solanaTx = publishedRoot?.solana_tx_signature ?? null;
    return {
      included: true,
      pollId: poll.id,
      voteCommitment: normalizedVoteCommitment,
      voteCommitmentLeafHash,
      batchStatus: solanaTx ? "published_on_chain" : "pending_on_chain_publication",
      batchIndex: matchedBatch.batchIndex,
      batchId,
      acceptedAt: auditRecord?.accepted_at ?? null,
      proofHash: auditRecord?.proof_hash ?? null,
      root: matchedBatch.voteCommitmentTree.root,
      matchingLeafCount,
      merklePath: buildAuditMerkleProof(
        matchedBatch.voteCommitmentTree,
        matchedLeafIndex,
      ),
      solanaTx,
      solanaExplorerUrl: buildSolanaExplorerUrl(solanaTx),
      auditUrl,
    };
  },
};

export default pollPublicAuditService;
