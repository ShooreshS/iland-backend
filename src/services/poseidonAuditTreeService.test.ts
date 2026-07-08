import { readFileSync } from "node:fs";

import { describe, expect, it } from "bun:test";

import { fieldElementToHex64, poseidonHashHex64 } from "./poseidonBn254Service";
import {
  buildPoseidonAuditMerkleProof,
  buildPoseidonAuditMerkleTree,
  hashPoseidonAuditLeaf,
  POSEIDON_AUDIT_TREE_DEPTH,
  POSEIDON_AUDIT_TREE_LEAF_CAPACITY,
  verifyPoseidonAuditMerkleProof,
} from "./poseidonAuditTreeService";

const vectorInputUrl = new URL(
  "../../zkp/circuits/test-vectors/encrypted_choice_tally.valid.input.json",
  import.meta.url,
);
const vectorPublicUrl = new URL(
  "../../zkp/circuits/test-vectors/encrypted_choice_tally.valid.public.named.json",
  import.meta.url,
);

type TallyVectorInput = {
  optionSetHash: string;
  isActive: string[];
  nullifiers: string[];
  encryptedVoteCommitments: string[];
  voteRandomness: string[];
};

type TallyVectorPublic = {
  nullifierRoot: string;
  voteCommitmentRoot: string;
  encryptedVoteRoot: string;
};

const readJson = <T>(url: URL): T =>
  JSON.parse(readFileSync(url, "utf8")) as T;

describe("poseidonAuditTreeService", () => {
  it("matches the encrypted_choice_tally circuit fixed Poseidon roots", async () => {
    const input = readJson<TallyVectorInput>(vectorInputUrl);
    const publicInputs = readJson<TallyVectorPublic>(vectorPublicUrl);
    const activeIndexes = input.isActive
      .map((value, index) => (value === "1" ? index : -1))
      .filter((index) => index >= 0);

    const nullifierLeaves = await Promise.all(
      activeIndexes.map((index) =>
        hashPoseidonAuditLeaf(
          "nullifier",
          fieldElementToHex64(input.nullifiers[index]),
        ),
      ),
    );
    const voteCommitmentLeaves = await Promise.all(
      activeIndexes.map(async (index) => {
        const voteCommitment = await poseidonHashHex64([
          input.nullifiers[index],
          input.encryptedVoteCommitments[index],
          input.optionSetHash,
          input.voteRandomness[index],
        ]);
        return hashPoseidonAuditLeaf("vote_commitment", voteCommitment);
      }),
    );
    const encryptedVoteLeaves = await Promise.all(
      activeIndexes.map((index) =>
        hashPoseidonAuditLeaf(
          "encrypted_vote",
          fieldElementToHex64(input.encryptedVoteCommitments[index]),
        ),
      ),
    );

    const nullifierTree = await buildPoseidonAuditMerkleTree(nullifierLeaves);
    const voteCommitmentTree =
      await buildPoseidonAuditMerkleTree(voteCommitmentLeaves);
    const encryptedVoteTree =
      await buildPoseidonAuditMerkleTree(encryptedVoteLeaves);

    expect(nullifierTree.root).toBe(fieldElementToHex64(publicInputs.nullifierRoot));
    expect(voteCommitmentTree.root).toBe(
      fieldElementToHex64(publicInputs.voteCommitmentRoot),
    );
    expect(encryptedVoteTree.root).toBe(
      fieldElementToHex64(publicInputs.encryptedVoteRoot),
    );
    expect(voteCommitmentTree.leafCapacity).toBe(
      POSEIDON_AUDIT_TREE_LEAF_CAPACITY,
    );

    const proof = buildPoseidonAuditMerkleProof(voteCommitmentTree, 1);
    expect(proof).toHaveLength(POSEIDON_AUDIT_TREE_DEPTH);
    await expect(
      verifyPoseidonAuditMerkleProof({
        leafHash: voteCommitmentTree.leafHashes[1],
        root: voteCommitmentTree.root,
        proof,
      }),
    ).resolves.toBe(true);
  });
});
