import { createHash } from "node:crypto";

import env from "../config/env";
import pollRepository from "../repositories/pollRepository";
import voteRepository from "../repositories/voteRepository";
import type {
  PollOptionResultDto,
  PollResultsSummaryDto,
  PublicAuditInclusionProofResultDto,
  PublicAuditMerkleProofStepDto,
  PublicAuditTreeKind,
  PublicAuditTreeSummaryDto,
  PublicVoteReceiptLookupDto,
  PublicPollAuditDto,
} from "../types/contracts";
import type { PollOptionRow, PollRow } from "../types/db";
import { hashCanonicalJson } from "./pollPolicyService";

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
  tree: PublicAuditMerkleTree,
): PublicAuditTreeSummaryDto => ({
  kind,
  root: tree.root,
  leafCount: tree.leafHashes.length,
  hashAlgorithm: "sha256",
  leafHashDomain: PUBLIC_AUDIT_MERKLE_LEAF_DOMAIN,
  nodeHashDomain: PUBLIC_AUDIT_MERKLE_NODE_DOMAIN,
});

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
    params.totalVotes > 0
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
  finalResult: PollResultsSummaryDto;
}): string =>
  hashCanonicalJson({
    version: PUBLIC_AUDIT_RESULT_HASH_VERSION,
    pollId: input.poll.id,
    pollStatus: input.poll.status,
    pollPolicyHash: input.poll.poll_policy_hash ?? null,
    credentialSchemaHash: input.poll.credential_schema_hash ?? null,
    acceptedVoteCount: input.acceptedVoteCount,
    totalValidVoteCount: input.totalValidVoteCount,
    finalNullifierRoot: input.nullifierRoot,
    finalVoteCommitmentRoot: input.voteCommitmentRoot,
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

  if (!env.solanaAudit.transactionsEnabled && input.acceptedVoteCount > 0) {
    warnings.push("On-chain audit publication is not enabled yet.");
  }

  return warnings;
};

const buildAuditTrees = (
  records: Awaited<
    ReturnType<typeof voteRepository.getAcceptedAuditRecordsByPollId>
  >,
): {
  nullifierTree: PublicAuditMerkleTree;
  voteCommitmentTree: PublicAuditMerkleTree;
} => {
  const nullifierLeafHashes = records.map((record) =>
    hashPublicAuditLeaf("nullifier", record.nullifier ?? ""),
  );
  const voteCommitmentLeafHashes = records.map((record) =>
    hashPublicAuditLeaf("vote_commitment", record.vote_commitment ?? ""),
  );

  return {
    nullifierTree: buildPublicAuditMerkleTree(nullifierLeafHashes),
    voteCommitmentTree: buildPublicAuditMerkleTree(voteCommitmentLeafHashes),
  };
};

export const pollPublicAuditService = {
  async getPublicPollAudit(pollId: string): Promise<PublicPollAuditDto | null> {
    const poll = await pollRepository.getById(pollId);
    if (!poll) {
      return null;
    }

    const [options, auditRecords, totalValidVoteCount, latestSubmittedAt] =
      await Promise.all([
        pollRepository.getOptionsByPollId(pollId),
        voteRepository.getAcceptedAuditRecordsByPollId(pollId),
        voteRepository.countValidByPollId(pollId),
        voteRepository.getLatestValidSubmittedAtByPollId(pollId),
      ]);

    const optionCountEntries = await Promise.all(
      options.map(async (option) => [
        option.id,
        await voteRepository.countValidByPollIdAndOptionId(pollId, option.id),
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
    const { nullifierTree, voteCommitmentTree } = buildAuditTrees(auditRecords);
    const finalResult = buildResultsSummary(poll.id, options, {
      countsByOptionId,
      totalVotes: totalValidVoteCount,
      updatedAt: latestSubmittedAt || poll.updated_at,
    });
    const resultHash = buildResultHash({
      poll,
      acceptedVoteCount,
      totalValidVoteCount,
      nullifierRoot: nullifierTree.root,
      voteCommitmentRoot: voteCommitmentTree.root,
      finalResult,
    });
    const generatedAt = new Date().toISOString();
    const publicationStatus =
      acceptedVoteCount > 0
        ? "pending_on_chain_publication"
        : "not_applicable";

    return {
      version: PUBLIC_AUDIT_VERSION,
      pollId: poll.id,
      pollStatus: poll.status,
      pollPolicyHash: poll.poll_policy_hash ?? null,
      credentialSchemaHash: poll.credential_schema_hash ?? null,
      generatedAt,
      publicationStatus,
      acceptedVoteCount,
      totalValidVoteCount,
      trees: {
        nullifier: buildTreeSummary("nullifier", nullifierTree),
        voteCommitment: buildTreeSummary(
          "vote_commitment",
          voteCommitmentTree,
        ),
      },
      computedCurrentRootBatch:
        acceptedVoteCount > 0
          ? {
              status: "pending_on_chain_publication",
              batchIndex: 0,
              acceptedCount: acceptedVoteCount,
              nullifierRoot: nullifierTree.root,
              voteCommitmentRoot: voteCommitmentTree.root,
              transactionSignature: null,
              explorerUrl: null,
              submittedAt: null,
            }
          : null,
      rootCommits: [],
      resultHash,
      tallyProofHash: null,
      finalResult,
      solana: {
        cluster: env.solanaAudit.cluster,
        programId: env.solanaAudit.programId,
        transactionsEnabled: env.solanaAudit.transactionsEnabled,
      },
      inclusionCheck: {
        route: `/polls/${encodeURIComponent(poll.id)}/audit/inclusion`,
        acceptedTrees: ["vote_commitment", "nullifier"],
        expectsLeafHash: true,
      },
      warnings: buildWarnings({
        poll,
        acceptedVoteCount,
        totalValidVoteCount,
      }),
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

    const auditRecords = await voteRepository.getAcceptedAuditRecordsByPollId(
      input.pollId,
    );
    const { nullifierTree, voteCommitmentTree } = buildAuditTrees(auditRecords);
    const tree =
      input.tree === "nullifier" ? nullifierTree : voteCommitmentTree;
    const leafIndex = tree.leafHashes.findIndex(
      (leafHash) => leafHash === normalizedLeafHash,
    );

    if (leafIndex < 0) {
      return {
        success: false,
        errorCode: "LEAF_NOT_FOUND",
        message: "No matching audit leaf was found for this poll.",
      };
    }

    return {
      success: true,
      pollId: poll.id,
      tree: input.tree,
      leafHash: normalizedLeafHash,
      leafIndex,
      matchingLeafCount: tree.leafHashes.filter(
        (leafHash) => leafHash === normalizedLeafHash,
      ).length,
      root: tree.root,
      proof: buildPublicAuditMerkleProof(tree, leafIndex),
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

    const voteCommitmentLeafHash = hashPublicAuditLeaf(
      "vote_commitment",
      normalizedVoteCommitment,
    );
    const auditRecords = await voteRepository.getAcceptedAuditRecordsByPollId(
      input.pollId,
    );
    const { voteCommitmentTree } = buildAuditTrees(auditRecords);
    const leafIndex = voteCommitmentTree.leafHashes.findIndex(
      (leafHash) => leafHash === voteCommitmentLeafHash,
    );

    if (leafIndex < 0) {
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
        root: voteCommitmentTree.root,
        matchingLeafCount: 0,
        merklePath: [],
        solanaTx: null,
        solanaExplorerUrl: null,
        auditUrl,
      };
    }

    const auditRecord = auditRecords[leafIndex];
    return {
      included: true,
      pollId: poll.id,
      voteCommitment: normalizedVoteCommitment,
      voteCommitmentLeafHash,
      batchStatus: "pending_on_chain_publication",
      batchIndex: 0,
      batchId: auditRecord?.batch_id ?? null,
      acceptedAt: auditRecord?.accepted_at ?? null,
      proofHash: auditRecord?.proof_hash ?? null,
      root: voteCommitmentTree.root,
      matchingLeafCount: voteCommitmentTree.leafHashes.filter(
        (leafHash) => leafHash === voteCommitmentLeafHash,
      ).length,
      merklePath: buildPublicAuditMerkleProof(voteCommitmentTree, leafIndex),
      solanaTx: null,
      solanaExplorerUrl: null,
      auditUrl,
    };
  },
};

export default pollPublicAuditService;
