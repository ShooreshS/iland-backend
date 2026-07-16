import { describe, expect, it } from "bun:test";

import {
  createGetPollAuditInclusionRoute,
  createGetPollAuditRoute,
  createGetPollReceiptRoute,
} from "./polls";
import type {
  PublicAuditInclusionProofResultDto,
  PublicVoteReceiptLookupDto,
  PublicPollAuditDto,
} from "../types/contracts";

const VALID_POLL_ID = "4a2de6fa-94c4-4e1a-ac78-bda1aa17e11f";
const SOLANA_ADDRESS_LIKE_ID = "81J2jNR5tfjLo1HG2kttAfSX5ieS4q7k1WTbZKvtkEic";

const sampleAudit: PublicPollAuditDto = {
  version: "civicos-public-audit-v1",
  pollId: VALID_POLL_ID,
  pollStatus: "closed",
  pollPolicyHash: "1".repeat(64),
  credentialSchemaHash: "2".repeat(64),
  optionSetHash: "7".repeat(64),
  generatedAt: "2026-07-05T12:00:00.000Z",
  publicationStatus: "pending_on_chain_publication",
  acceptedVoteCount: 1,
  totalValidVoteCount: 1,
  trees: {
    nullifier: {
      kind: "nullifier",
      root: "3".repeat(64),
      leafCount: 1,
      hashAlgorithm: "sha256",
      leafHashDomain: "org.civicos.audit:merkle-leaf:v1",
      nodeHashDomain: "org.civicos.audit:merkle-node:v1",
    },
    voteCommitment: {
      kind: "vote_commitment",
      root: "4".repeat(64),
      leafCount: 1,
      hashAlgorithm: "sha256",
      leafHashDomain: "org.civicos.audit:merkle-leaf:v1",
      nodeHashDomain: "org.civicos.audit:merkle-node:v1",
    },
    encryptedVote: {
      kind: "encrypted_vote",
      root: "5".repeat(64),
      leafCount: 1,
      hashAlgorithm: "sha256",
      leafHashDomain: "org.civicos.audit:merkle-leaf:v1",
      nodeHashDomain: "org.civicos.audit:merkle-node:v1",
    },
  },
  auditBatches: [
    {
      batchIndex: 0,
      acceptedCount: 1,
      sealed: true,
      nullifierRoot: "3".repeat(64),
      voteCommitmentRoot: "4".repeat(64),
      encryptedVoteRoot: "5".repeat(64),
      publication: null,
    },
  ],
  computedCurrentRootBatch: {
    status: "pending_on_chain_publication",
    batchIndex: 0,
    acceptedCount: 1,
    nullifierRoot: "3".repeat(64),
    voteCommitmentRoot: "4".repeat(64),
    encryptedVoteRoot: "5".repeat(64),
    transactionSignature: null,
    explorerUrl: null,
    submittedAt: null,
  },
  rootCommits: [],
  resultHash: "6".repeat(64),
  tallyProofStatus: "pending",
  tallyJob: null,
  tallyProofHash: null,
  tallyPublicInputsHash: null,
  tallyProof: null,
  finalResultPublication: null,
  finalResult: {
    pollId: VALID_POLL_ID,
    totalVotes: 1,
    optionResults: [
      {
        optionId: "option-1",
        label: "Option A",
        count: 1,
        percentage: 100,
      },
    ],
    winningOptionId: "option-1",
    winningOptionLabel: "Option A",
    updatedAt: "2026-07-05T12:00:00.000Z",
  },
  solana: {
    cluster: "mainnet-beta",
    programId: "2hnBkFjtErxbLCtTevhiW2GGTjDp1EHctshX3ebPEfRt",
    transactionsEnabled: false,
  },
  inclusionCheck: {
    route: `/polls/${VALID_POLL_ID}/audit/inclusion`,
    acceptedTrees: ["vote_commitment", "nullifier", "encrypted_vote"],
    expectsLeafHash: true,
  },
  warnings: ["On-chain audit publication is not enabled yet."],
};

const invokeRoute = async (
  route: ReturnType<
    | typeof createGetPollAuditRoute
    | typeof createGetPollAuditInclusionRoute
    | typeof createGetPollReceiptRoute
  >,
  path: string,
  params: Record<string, string>,
): Promise<Response> => {
  const request = new Request(`http://127.0.0.1:3001${path}`, {
    method: "GET",
  });

  return route.handler({
    request,
    url: new URL(request.url),
    params,
  });
};

describe("GET /polls/:id/audit route", () => {
  it("returns public audit material without requiring viewer auth", async () => {
    let receivedPollId = "";
    const route = createGetPollAuditRoute({
      pollPublicAuditServiceLike: {
        getPublicPollAudit: async (pollId) => {
          receivedPollId = pollId;
          return sampleAudit;
        },
        getPublicPollAuditInclusionProof: async () => ({
          success: false,
          errorCode: "LEAF_NOT_FOUND",
          message: "No matching audit leaf was found for this poll.",
        }),
      },
    });

    const response = await invokeRoute(route, `/polls/${VALID_POLL_ID}/audit`, {
      id: VALID_POLL_ID,
    });

    expect(response.status).toBe(200);
    expect(receivedPollId).toBe(VALID_POLL_ID);
    expect(await response.json()).toEqual(sampleAudit);
  });

  it("rejects Solana-address-shaped values before hitting the audit service", async () => {
    let called = false;
    const route = createGetPollAuditRoute({
      pollPublicAuditServiceLike: {
        getPublicPollAudit: async () => {
          called = true;
          return sampleAudit;
        },
      },
    });

    const response = await invokeRoute(
      route,
      `/polls/${SOLANA_ADDRESS_LIKE_ID}/audit`,
      {
        id: SOLANA_ADDRESS_LIKE_ID,
      },
    );

    expect(response.status).toBe(400);
    expect(called).toBe(false);
    expect(await response.json()).toMatchObject({
      error: "invalid_poll_id",
    });
  });
});

describe("GET /polls/:id/audit/inclusion route", () => {
  it("validates tree and leafHash query parameters", async () => {
    const route = createGetPollAuditInclusionRoute({
      pollPublicAuditServiceLike: {
        getPublicPollAudit: async () => sampleAudit,
        getPublicPollAuditInclusionProof: async () => ({
          success: true,
          pollId: VALID_POLL_ID,
          tree: "vote_commitment",
          leafHash: "6".repeat(64),
          batchIndex: 0,
          leafIndex: 0,
          matchingLeafCount: 1,
          root: "4".repeat(64),
          proof: [],
        }),
      },
    });

    const response = await invokeRoute(
      route,
      `/polls/${VALID_POLL_ID}/audit/inclusion?tree=vote_commitment&leafHash=bad`,
      { id: VALID_POLL_ID },
    );

    expect(response.status).toBe(400);
  });

  it("returns an inclusion proof from the audit service", async () => {
    const expectedProof: PublicAuditInclusionProofResultDto = {
      success: true,
      pollId: VALID_POLL_ID,
      tree: "vote_commitment",
      leafHash: "6".repeat(64),
      batchIndex: 0,
      leafIndex: 0,
      matchingLeafCount: 1,
      root: "4".repeat(64),
      proof: [],
    };
    const route = createGetPollAuditInclusionRoute({
      pollPublicAuditServiceLike: {
        getPublicPollAudit: async () => sampleAudit,
        getPublicPollAuditInclusionProof: async (input) => ({
          ...expectedProof,
          pollId: input.pollId,
          tree: input.tree,
          leafHash: input.leafHash,
        }),
      },
    });

    const response = await invokeRoute(
      route,
      `/polls/${VALID_POLL_ID}/audit/inclusion?tree=vote_commitment&leafHash=${"6".repeat(
        64,
      )}`,
      { id: VALID_POLL_ID },
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(expectedProof);
  });
});

describe("GET /polls/:id/receipt/:voteCommitment route", () => {
  it("returns receipt inclusion status by vote commitment", async () => {
    const voteCommitment = "7".repeat(64);
    const expectedReceipt: PublicVoteReceiptLookupDto = {
      included: true,
      pollId: VALID_POLL_ID,
      voteCommitment,
      voteCommitmentLeafHash: "8".repeat(64),
      batchStatus: "pending_on_chain_publication",
      batchIndex: 0,
      batchId: null,
      acceptedAt: "2026-07-05T12:00:00.000Z",
      proofHash: "9".repeat(64),
      root: "4".repeat(64),
      matchingLeafCount: 1,
      merklePath: [],
      solanaTx: null,
      solanaExplorerUrl: null,
      auditUrl: "/polls/poll-1/audit",
    };
    const route = createGetPollReceiptRoute({
      pollPublicAuditServiceLike: {
        getPublicVoteReceipt: async (input) => ({
          ...expectedReceipt,
          pollId: input.pollId,
          voteCommitment: input.voteCommitment,
        }),
      },
    });

    const response = await invokeRoute(
      route,
      `/polls/${VALID_POLL_ID}/receipt/${voteCommitment}`,
      { id: VALID_POLL_ID, voteCommitment },
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(expectedReceipt);
  });

  it("validates vote commitment path parameter", async () => {
    const route = createGetPollReceiptRoute({
      pollPublicAuditServiceLike: {
        getPublicVoteReceipt: async () => null,
      },
    });

    const response = await invokeRoute(
      route,
      `/polls/${VALID_POLL_ID}/receipt/not-a-hash`,
      { id: VALID_POLL_ID, voteCommitment: "not-a-hash" },
    );

    expect(response.status).toBe(400);
  });
});
