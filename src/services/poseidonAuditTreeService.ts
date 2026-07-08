import type {
  PublicAuditMerkleProofStepDto,
  PublicAuditTreeKind,
} from "../types/contracts";
import { fieldElementToHex64, poseidonHashHex64 } from "./poseidonBn254Service";

export const POSEIDON_AUDIT_TREE_VERSION =
  "civicos-poseidon-audit-tree-v1" as const;
export const POSEIDON_AUDIT_HASH_ALGORITHM = "poseidon-bn254" as const;
export const POSEIDON_AUDIT_LEAF_DOMAIN =
  "org.civicos.audit:poseidon-fixed64-leaf:v1" as const;
export const POSEIDON_AUDIT_NODE_DOMAIN =
  "org.civicos.audit:poseidon-fixed64-node:v1" as const;
export const POSEIDON_AUDIT_TREE_DEPTH = 6 as const;
export const POSEIDON_AUDIT_TREE_LEAF_CAPACITY = 64 as const;
export const POSEIDON_AUDIT_ZERO_LEAF = "0".repeat(64);
export const POSEIDON_AUDIT_LEAF_TAGS: Record<PublicAuditTreeKind, number> =
  Object.freeze({
    nullifier: 1101,
    vote_commitment: 1102,
    encrypted_vote: 1103,
  });

const HEX_64_PATTERN = /^[0-9a-f]{64}$/;

export type PoseidonAuditTree = Readonly<{
  root: string;
  leafHashes: readonly string[];
  paddedLeafHashes: readonly string[];
  levels: readonly (readonly string[])[];
  leafCapacity: typeof POSEIDON_AUDIT_TREE_LEAF_CAPACITY;
  treeDepth: typeof POSEIDON_AUDIT_TREE_DEPTH;
}>;

const normalizeHex64 = (value: string): string => {
  const normalized = value.trim().toLowerCase();
  if (!HEX_64_PATTERN.test(normalized)) {
    throw new TypeError("Poseidon audit tree values must be 32-byte hex strings.");
  }
  return normalized;
};

export const hashPoseidonAuditLeaf = async (
  kind: PublicAuditTreeKind,
  value: string,
): Promise<string> =>
  poseidonHashHex64([
    POSEIDON_AUDIT_LEAF_TAGS[kind],
    normalizeHex64(value),
  ]);

export const hashPoseidonAuditNode = async (
  left: string,
  right: string,
): Promise<string> =>
  poseidonHashHex64([
    fieldElementToHex64(normalizeHex64(left)),
    fieldElementToHex64(normalizeHex64(right)),
  ]);

export const buildPoseidonAuditMerkleTree = async (
  leafHashes: readonly string[],
): Promise<PoseidonAuditTree> => {
  if (leafHashes.length > POSEIDON_AUDIT_TREE_LEAF_CAPACITY) {
    throw new RangeError(
      `Poseidon audit tree supports at most ${POSEIDON_AUDIT_TREE_LEAF_CAPACITY} leaves.`,
    );
  }

  const normalizedLeaves = leafHashes.map(normalizeHex64);
  const paddedLeaves = [
    ...normalizedLeaves,
    ...Array.from(
      {
        length: POSEIDON_AUDIT_TREE_LEAF_CAPACITY - normalizedLeaves.length,
      },
      () => POSEIDON_AUDIT_ZERO_LEAF,
    ),
  ];
  const levels: string[][] = [paddedLeaves];
  let currentLevel = paddedLeaves;

  for (let depth = 0; depth < POSEIDON_AUDIT_TREE_DEPTH; depth += 1) {
    const nextLevel: string[] = [];
    for (let index = 0; index < currentLevel.length; index += 2) {
      nextLevel.push(
        await hashPoseidonAuditNode(
          currentLevel[index],
          currentLevel[index + 1] ?? POSEIDON_AUDIT_ZERO_LEAF,
        ),
      );
    }
    levels.push(nextLevel);
    currentLevel = nextLevel;
  }

  return Object.freeze({
    root: currentLevel[0],
    leafHashes: Object.freeze([...normalizedLeaves]),
    paddedLeafHashes: Object.freeze([...paddedLeaves]),
    levels: Object.freeze(levels.map((level) => Object.freeze([...level]))),
    leafCapacity: POSEIDON_AUDIT_TREE_LEAF_CAPACITY,
    treeDepth: POSEIDON_AUDIT_TREE_DEPTH,
  });
};

export const buildPoseidonAuditMerkleProof = (
  tree: PoseidonAuditTree,
  leafIndex: number,
): PublicAuditMerkleProofStepDto[] => {
  if (
    leafIndex < 0 ||
    !Number.isInteger(leafIndex) ||
    leafIndex >= tree.leafHashes.length
  ) {
    throw new RangeError("Poseidon audit Merkle leaf index is out of range.");
  }

  const proof: PublicAuditMerkleProofStepDto[] = [];
  let indexAtLevel = leafIndex;

  for (let levelIndex = 0; levelIndex < tree.levels.length - 1; levelIndex += 1) {
    const level = tree.levels[levelIndex];
    const isRight = indexAtLevel % 2 === 1;
    const siblingIndex = isRight ? indexAtLevel - 1 : indexAtLevel + 1;
    const siblingHash = level[siblingIndex] ?? POSEIDON_AUDIT_ZERO_LEAF;

    proof.push({
      position: isRight ? "left" : "right",
      hash: siblingHash,
    });

    indexAtLevel = Math.floor(indexAtLevel / 2);
  }

  return proof;
};

export const verifyPoseidonAuditMerkleProof = async (input: {
  leafHash: string;
  root: string;
  proof: readonly PublicAuditMerkleProofStepDto[];
}): Promise<boolean> => {
  let computedRoot: string;
  try {
    computedRoot = normalizeHex64(input.leafHash);
    const normalizedRoot = normalizeHex64(input.root);
    if (input.proof.length !== POSEIDON_AUDIT_TREE_DEPTH) {
      return false;
    }

    for (const step of input.proof) {
      const sibling = normalizeHex64(step.hash);
      computedRoot =
        step.position === "left"
          ? await hashPoseidonAuditNode(sibling, computedRoot)
          : await hashPoseidonAuditNode(computedRoot, sibling);
    }

    return computedRoot === normalizedRoot;
  } catch (_error) {
    return false;
  }
};
