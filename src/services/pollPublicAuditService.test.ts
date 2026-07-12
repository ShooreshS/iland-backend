import { describe, expect, it } from "bun:test";

import pollAuditRepository from "../repositories/pollAuditRepository";
import pollRepository from "../repositories/pollRepository";
import pollTallyProofRepository from "../repositories/pollTallyProofRepository";
import pollZkVoteRepository, {
  type PublicZkAuditVoteRecordRow,
} from "../repositories/pollZkVoteRepository";
import voteRepository, {
  type PublicAuditVoteRecordRow,
} from "../repositories/voteRepository";
import type { PollOptionRow, PollRow } from "../types/db";
import {
  buildPoseidonAuditMerkleTree,
  hashPoseidonAuditLeaf,
  POSEIDON_AUDIT_HASH_ALGORITHM,
  POSEIDON_AUDIT_TREE_DEPTH,
  POSEIDON_AUDIT_TREE_LEAF_CAPACITY,
  verifyPoseidonAuditMerkleProof,
} from "./poseidonAuditTreeService";
import {
  buildPublicAuditMerkleTree,
  hashPublicAuditLeaf,
  pollPublicAuditService,
  PUBLIC_AUDIT_ZERO_ROOT,
  verifyPublicAuditMerkleProof,
} from "./pollPublicAuditService";
import zkpAuditEventService from "./zkpAuditEventService";

const FIXED_TIME = "2026-07-05T12:00:00.000Z";
const POLL_POLICY_HASH = "1".repeat(64);
const CREDENTIAL_SCHEMA_HASH = "2".repeat(64);
const NULLIFIER_A = "a".repeat(64);
const NULLIFIER_B = "b".repeat(64);
const VOTE_COMMITMENT_A = "c".repeat(64);
const VOTE_COMMITMENT_B = "d".repeat(64);
const ENCRYPTED_VOTE_COMMITMENT_A = "7".repeat(64);
const ENCRYPTED_VOTE_COMMITMENT_B = "8".repeat(64);
const PROOF_HASH_A = "e".repeat(64);
const PROOF_HASH_B = "f".repeat(64);

const createPoll = (overrides: Partial<PollRow> = {}): PollRow => ({
  id: "poll-1",
  slug: "poll-1",
  created_by_user_id: "owner-1",
  title: "Audit Poll",
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
  starts_at: null,
  ends_at: "2026-07-05T11:00:00.000Z",
  poll_policy_hash: POLL_POLICY_HASH,
  credential_schema_hash: CREDENTIAL_SCHEMA_HASH,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createOption = (
  overrides: Partial<PollOptionRow> = {},
): PollOptionRow => ({
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

const createAuditRecord = (
  overrides: Partial<PublicAuditVoteRecordRow> = {},
): PublicAuditVoteRecordRow => ({
  id: "vote-1",
  poll_id: "poll-1",
  nullifier: NULLIFIER_A,
  vote_commitment: VOTE_COMMITMENT_A,
  proof_hash: PROOF_HASH_A,
  accepted_at: "2026-07-05T10:00:00.000Z",
  batch_id: null,
  created_at: "2026-07-05T10:00:00.000Z",
  ...overrides,
});

const patchMethod = <T extends object, K extends keyof T>(
  target: T,
  key: K,
  implementation: T[K],
): (() => void) => {
  const original = target[key];
  target[key] = implementation;

  return () => {
    target[key] = original;
  };
};

describe("Phase 8 public poll audit service", () => {
  it("builds deterministic public audit roots without exposing raw nullifiers", async () => {
    const poll = createPoll();
    const optionA = createOption({
      id: "option-a",
      label: "Option A",
      display_order: 0,
    });
    const optionB = createOption({
      id: "option-b",
      label: "Option B",
      display_order: 1,
    });
    const auditRecords: PublicAuditVoteRecordRow[] = [
      createAuditRecord({
        id: "vote-a",
        nullifier: NULLIFIER_A,
        vote_commitment: VOTE_COMMITMENT_A,
        proof_hash: PROOF_HASH_A,
      }),
      createAuditRecord({
        id: "vote-b",
        nullifier: NULLIFIER_B,
        vote_commitment: VOTE_COMMITMENT_B,
        proof_hash: PROOF_HASH_B,
        accepted_at: "2026-07-05T10:01:00.000Z",
        created_at: "2026-07-05T10:01:00.000Z",
      }),
    ];
    const expectedNullifierTree = buildPublicAuditMerkleTree(
      auditRecords.map((record) =>
        hashPublicAuditLeaf("nullifier", record.nullifier ?? ""),
      ),
    );
    const expectedVoteCommitmentTree = buildPublicAuditMerkleTree(
      auditRecords.map((record) =>
        hashPublicAuditLeaf("vote_commitment", record.vote_commitment ?? ""),
      ),
    );

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionsByPollId", async () => [
        optionA,
        optionB,
      ]),
      patchMethod(voteRepository, "getAcceptedAuditRecordsByPollId", async () =>
        auditRecords,
      ),
      patchMethod(voteRepository, "countValidByPollId", async () => 2),
      patchMethod(
        voteRepository,
        "getLatestValidSubmittedAtByPollId",
        async () => "2026-07-05T10:01:00.000Z",
      ),
      patchMethod(voteRepository, "countValidByPollIdAndOptionId", async (_pollId, optionId) =>
        optionId === optionA.id ? 1 : 1,
      ),
      patchMethod(pollAuditRepository, "listRootsByPollId", async () => []),
    ];

    try {
      const audit = await pollPublicAuditService.getPublicPollAudit(poll.id);

      expect(audit).not.toBeNull();
      expect(audit?.version).toBe("civicos-public-audit-v1");
      expect(audit?.publicationStatus).toBe("pending_on_chain_publication");
      expect(audit?.acceptedVoteCount).toBe(2);
      expect(audit?.totalValidVoteCount).toBe(2);
      expect(audit?.trees.nullifier.root).toBe(expectedNullifierTree.root);
      expect(audit?.trees.voteCommitment.root).toBe(
        expectedVoteCommitmentTree.root,
      );
      expect(audit?.trees.encryptedVote.root).toBe(PUBLIC_AUDIT_ZERO_ROOT);
      expect(audit?.computedCurrentRootBatch).toMatchObject({
        status: "pending_on_chain_publication",
        batchIndex: 0,
        acceptedCount: 2,
        encryptedVoteRoot: PUBLIC_AUDIT_ZERO_ROOT,
        transactionSignature: null,
      });
      expect(audit?.rootCommits).toEqual([]);
      expect(audit?.tallyProofHash).toBeNull();
      expect(audit?.tallyPublicInputsHash).toBeNull();
      expect(audit?.tallyProof).toBeNull();
      expect(audit?.resultHash).toMatch(/^[0-9a-f]{64}$/);
      expect(audit?.finalResult.optionResults).toMatchObject([
        { optionId: optionA.id, label: "Option A", count: 1 },
        { optionId: optionB.id, label: "Option B", count: 1 },
      ]);
      expect(JSON.stringify(audit)).not.toContain(NULLIFIER_A);
      expect(JSON.stringify(audit)).not.toContain(NULLIFIER_B);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("returns a verifiable inclusion proof by public leaf hash", async () => {
    const poll = createPoll();
    const auditRecords = [
      createAuditRecord({
        id: "vote-a",
        vote_commitment: VOTE_COMMITMENT_A,
      }),
      createAuditRecord({
        id: "vote-b",
        nullifier: NULLIFIER_B,
        vote_commitment: VOTE_COMMITMENT_B,
        proof_hash: PROOF_HASH_B,
      }),
    ];
    const targetLeafHash = hashPublicAuditLeaf(
      "vote_commitment",
      VOTE_COMMITMENT_B,
    );

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(voteRepository, "getAcceptedAuditRecordsByPollId", async () =>
        auditRecords,
      ),
    ];

    try {
      const result =
        await pollPublicAuditService.getPublicPollAuditInclusionProof({
          pollId: poll.id,
          tree: "vote_commitment",
          leafHash: targetLeafHash,
        });

      expect(result.success).toBe(true);
      if (!result.success) {
        throw new Error("Expected inclusion proof.");
      }

      expect(result.leafIndex).toBe(1);
      expect(result.matchingLeafCount).toBe(1);
      expect(
        verifyPublicAuditMerkleProof({
          leafHash: targetLeafHash,
          root: result.root,
          proof: result.proof,
        }),
      ).toBe(true);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("uses the fixed Poseidon audit tree for production ZKP polls", async () => {
    const poll = createPoll({
      vote_privacy_mode: "zk_secret_ballot_v1",
      option_set_hash: "3".repeat(64),
      poll_encryption_key_id: "poll-key-1",
    });
    const auditRecords: PublicZkAuditVoteRecordRow[] = [
      createAuditRecord({
        id: "vote-a",
        nullifier: NULLIFIER_A,
        vote_commitment: VOTE_COMMITMENT_A,
        encrypted_vote_commitment: ENCRYPTED_VOTE_COMMITMENT_A,
        proof_hash: PROOF_HASH_A,
      }) as PublicZkAuditVoteRecordRow,
      createAuditRecord({
        id: "vote-b",
        nullifier: NULLIFIER_B,
        vote_commitment: VOTE_COMMITMENT_B,
        encrypted_vote_commitment: ENCRYPTED_VOTE_COMMITMENT_B,
        proof_hash: PROOF_HASH_B,
        accepted_at: "2026-07-05T10:01:00.000Z",
        created_at: "2026-07-05T10:01:00.000Z",
      }) as PublicZkAuditVoteRecordRow,
    ];
    const expectedNullifierTree = await buildPoseidonAuditMerkleTree([
      await hashPoseidonAuditLeaf("nullifier", NULLIFIER_A),
      await hashPoseidonAuditLeaf("nullifier", NULLIFIER_B),
    ]);
    const expectedVoteCommitmentTree = await buildPoseidonAuditMerkleTree([
      await hashPoseidonAuditLeaf("vote_commitment", VOTE_COMMITMENT_A),
      await hashPoseidonAuditLeaf("vote_commitment", VOTE_COMMITMENT_B),
    ]);
    const expectedEncryptedVoteTree = await buildPoseidonAuditMerkleTree([
      await hashPoseidonAuditLeaf(
        "encrypted_vote",
        ENCRYPTED_VOTE_COMMITMENT_A,
      ),
      await hashPoseidonAuditLeaf(
        "encrypted_vote",
        ENCRYPTED_VOTE_COMMITMENT_B,
      ),
    ]);
    const targetLeafHash = expectedVoteCommitmentTree.leafHashes[1];

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(pollRepository, "getOptionsByPollId", async () => [
        createOption({ id: "option-a", label: "Option A", display_order: 0 }),
        createOption({ id: "option-b", label: "Option B", display_order: 1 }),
      ]),
      patchMethod(
        pollZkVoteRepository,
        "getAcceptedAuditRecordsByPollId",
        async () => auditRecords,
      ),
      patchMethod(pollZkVoteRepository, "countAcceptedByPollId", async () => 2),
      patchMethod(pollTallyProofRepository, "getLatestByPollId", async () => null),
      patchMethod(pollAuditRepository, "listRootsByPollId", async () => []),
    ];

    try {
      const audit = await pollPublicAuditService.getPublicPollAudit(poll.id);
      expect(audit?.trees.nullifier).toMatchObject({
        root: expectedNullifierTree.root,
        hashAlgorithm: POSEIDON_AUDIT_HASH_ALGORITHM,
        treeDepth: POSEIDON_AUDIT_TREE_DEPTH,
        leafCapacity: POSEIDON_AUDIT_TREE_LEAF_CAPACITY,
      });
      expect(audit?.trees.voteCommitment.root).toBe(
        expectedVoteCommitmentTree.root,
      );
      expect(audit?.trees.encryptedVote.root).toBe(
        expectedEncryptedVoteTree.root,
      );
      expect(audit?.computedCurrentRootBatch?.encryptedVoteRoot).toBe(
        expectedEncryptedVoteTree.root,
      );

      const inclusion =
        await pollPublicAuditService.getPublicPollAuditInclusionProof({
          pollId: poll.id,
          tree: "vote_commitment",
          leafHash: targetLeafHash,
        });

      expect(inclusion.success).toBe(true);
      if (!inclusion.success) {
        throw new Error("Expected production inclusion proof.");
      }
      expect(inclusion.proof).toHaveLength(POSEIDON_AUDIT_TREE_DEPTH);
      await expect(
        verifyPoseidonAuditMerkleProof({
          leafHash: targetLeafHash,
          root: inclusion.root,
          proof: inclusion.proof,
        }),
      ).resolves.toBe(true);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("returns a receipt lookup by vote commitment without exposing nullifiers", async () => {
    const poll = createPoll();
    const auditRecords = [
      createAuditRecord({
        id: "vote-a",
        vote_commitment: VOTE_COMMITMENT_A,
      }),
      createAuditRecord({
        id: "vote-b",
        nullifier: NULLIFIER_B,
        vote_commitment: VOTE_COMMITMENT_B,
        proof_hash: PROOF_HASH_B,
      }),
    ];

    const restoreFns = [
      patchMethod(pollRepository, "getById", async () => poll),
      patchMethod(voteRepository, "getAcceptedAuditRecordsByPollId", async () =>
        auditRecords,
      ),
      patchMethod(pollAuditRepository, "getRootByPollIdAndBatchId", async () => null),
    ];

    try {
      const receipt = await pollPublicAuditService.getPublicVoteReceipt({
        pollId: poll.id,
        voteCommitment: VOTE_COMMITMENT_B,
      });

      expect(receipt).not.toBeNull();
      expect(receipt?.included).toBe(true);
      expect(receipt?.voteCommitment).toBe(VOTE_COMMITMENT_B);
      expect(receipt?.voteCommitmentLeafHash).toBe(
        hashPublicAuditLeaf("vote_commitment", VOTE_COMMITMENT_B),
      );
      expect(receipt?.batchStatus).toBe("pending_on_chain_publication");
      expect(receipt?.batchIndex).toBe(0);
      expect(receipt?.solanaTx).toBeNull();
      expect(JSON.stringify(receipt)).not.toContain(NULLIFIER_B);
      if (receipt?.included && receipt.root) {
        expect(
          verifyPublicAuditMerkleProof({
            leafHash: receipt.voteCommitmentLeafHash,
            root: receipt.root,
            proof: receipt.merklePath,
          }),
        ).toBe(true);
      }
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("uses the Anchor zero root for empty audit trees", () => {
    const tree = buildPublicAuditMerkleTree([]);

    expect(tree.root).toBe(PUBLIC_AUDIT_ZERO_ROOT);
    expect(tree.leafHashes).toEqual([]);
  });
});

describe("Phase 5 audit batch segmentation", () => {
  const fieldHex = (prefix: number, index: number): string =>
    `${prefix}${index.toString(16).padStart(63 - String(prefix).length + 1, "0")}`.slice(
      0,
      64,
    );

  const createProductionPoll = (overrides: Partial<PollRow> = {}): PollRow =>
    createPoll({
      vote_privacy_mode: "zk_secret_ballot_v1",
      option_set_hash: "3".repeat(64),
      poll_encryption_key_id: "poll-key-1",
      ...overrides,
    });

  const createProductionRecords = (
    count: number,
  ): PublicZkAuditVoteRecordRow[] =>
    Array.from({ length: count }, (_, index) => {
      const acceptedAt = new Date(
        Date.parse("2026-07-05T10:00:00.000Z") + index * 1000,
      ).toISOString();
      return createAuditRecord({
        id: `vote-${String(index).padStart(3, "0")}`,
        nullifier: fieldHex(1, index + 1),
        vote_commitment: fieldHex(2, index + 1),
        encrypted_vote_commitment: fieldHex(3, index + 1),
        proof_hash: fieldHex(4, index + 1),
        accepted_at: acceptedAt,
        created_at: acceptedAt,
      }) as PublicZkAuditVoteRecordRow;
    });

  const patchProductionRepositories = (
    poll: PollRow,
    records: PublicZkAuditVoteRecordRow[],
  ): (() => void)[] => [
    patchMethod(pollRepository, "getById", async () => poll),
    patchMethod(pollRepository, "getOptionsByPollId", async () => [
      createOption({ id: "option-a" }),
    ]),
    patchMethod(
      pollZkVoteRepository,
      "getAcceptedAuditRecordsByPollId",
      async () => records,
    ),
    patchMethod(
      pollZkVoteRepository,
      "countAcceptedByPollId",
      async () => records.length,
    ),
    patchMethod(pollTallyProofRepository, "getLatestByPollId", async () => null),
    patchMethod(pollAuditRepository, "listRootsByPollId", async () => []),
    patchMethod(
      pollAuditRepository,
      "getRootByPollIdAndBatchId",
      async () => null,
    ),
  ];

  it("reports an expired active poll as closed in public audit material", async () => {
    const poll = createProductionPoll({
      status: "active",
      ends_at: "2000-01-01T00:00:00.000Z",
    });
    const restoreFns = patchProductionRepositories(poll, createProductionRecords(1));

    try {
      const audit = await pollPublicAuditService.getPublicPollAudit(poll.id);

      expect(audit?.pollStatus).toBe("closed");
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("segments 65 production votes into two batches with verifiable batch proofs", async () => {
    const poll = createProductionPoll();
    const records = createProductionRecords(65);
    const restoreFns = patchProductionRepositories(poll, records);

    try {
      const audit = await pollPublicAuditService.getPublicPollAudit(poll.id);

      expect(audit).not.toBeNull();
      expect(audit?.acceptedVoteCount).toBe(65);
      expect(audit?.auditBatches).toHaveLength(2);
      expect(audit?.auditBatches[0]).toMatchObject({
        batchIndex: 0,
        acceptedCount: POSEIDON_AUDIT_TREE_LEAF_CAPACITY,
        sealed: true,
        publication: null,
      });
      expect(audit?.auditBatches[1]).toMatchObject({
        batchIndex: 1,
        acceptedCount: 1,
        sealed: true,
      });
      expect(audit?.auditBatches[0]?.nullifierRoot).not.toBe(
        audit?.auditBatches[1]?.nullifierRoot,
      );
      expect(audit?.trees.voteCommitment.root).toBe(
        audit?.auditBatches[1]?.voteCommitmentRoot,
      );
      expect(audit?.computedCurrentRootBatch).toMatchObject({
        batchIndex: 1,
        acceptedCount: 1,
      });

      const lastVoteCommitment = records[64].vote_commitment ?? "";
      const receipt = await pollPublicAuditService.getPublicVoteReceipt({
        pollId: poll.id,
        voteCommitment: lastVoteCommitment,
      });
      expect(receipt?.included).toBe(true);
      expect(receipt?.batchIndex).toBe(1);
      expect(receipt?.batchId).toBe("1");
      expect(receipt?.root).toBe(audit?.auditBatches[1]?.voteCommitmentRoot ?? "");
      expect(receipt?.merklePath).toHaveLength(POSEIDON_AUDIT_TREE_DEPTH);
      expect(
        await verifyPoseidonAuditMerkleProof({
          leafHash: receipt?.voteCommitmentLeafHash ?? "",
          root: receipt?.root ?? "",
          proof: receipt?.merklePath ?? [],
        }),
      ).toBe(true);

      const batchZeroLeafHash = await hashPoseidonAuditLeaf(
        "vote_commitment",
        records[10].vote_commitment ?? "",
      );
      const inclusion =
        await pollPublicAuditService.getPublicPollAuditInclusionProof({
          pollId: poll.id,
          tree: "vote_commitment",
          leafHash: batchZeroLeafHash,
        });
      expect(inclusion.success).toBe(true);
      if (!inclusion.success) {
        throw new Error("Expected inclusion proof.");
      }
      expect(inclusion.batchIndex).toBe(0);
      expect(inclusion.leafIndex).toBe(10);
      expect(inclusion.root).toBe(audit?.auditBatches[0]?.voteCommitmentRoot ?? "");
      expect(
        await verifyPoseidonAuditMerkleProof({
          leafHash: batchZeroLeafHash,
          root: inclusion.root,
          proof: inclusion.proof,
        }),
      ).toBe(true);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("keeps an open poll's partial tail batch unsealed", async () => {
    const poll = createProductionPoll({
      status: "active",
      ends_at: "2027-01-01T00:00:00.000Z",
    });
    const records = createProductionRecords(65);
    const restoreFns = patchProductionRepositories(poll, records);

    try {
      const audit = await pollPublicAuditService.getPublicPollAudit(poll.id);

      expect(audit?.auditBatches[0]?.sealed).toBe(true);
      expect(audit?.auditBatches[1]?.sealed).toBe(false);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("rejects tally proofs for polls that exceed one 64-vote batch", async () => {
    const poll = createProductionPoll();
    const records = createProductionRecords(65);
    const auditEvents: Record<string, unknown>[] = [];
    const restoreFns = [
      ...patchProductionRepositories(poll, records),
      patchMethod(
        zkpAuditEventService,
        "appendTallyRejected",
        async (input) => {
          auditEvents.push(input as Record<string, unknown>);
          return null;
        },
      ),
    ];

    try {
      const result = await pollPublicAuditService.submitTallyProof({
        pollId: poll.id,
        viewerUserId: "owner-1",
        proof: {} as never,
      });

      expect(result.success).toBe(false);
      if (result.success) {
        throw new Error("Expected tally rejection.");
      }
      expect(result.errorCode).toBe("TALLY_BATCH_LIMIT_EXCEEDED");
      expect(result.reasonCode).toBe("tally_batch_limit_exceeded");
      expect(auditEvents).toHaveLength(1);
      expect(auditEvents[0]).toMatchObject({
        pollId: poll.id,
        reasonCode: "tally_batch_limit_exceeded",
        errorCode: "TALLY_BATCH_LIMIT_EXCEEDED",
        acceptedCount: 65,
      });
      expect(JSON.stringify(auditEvents)).not.toContain("owner-1");
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });
});
