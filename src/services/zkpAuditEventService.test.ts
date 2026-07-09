import { describe, expect, it } from "bun:test";

import {
  ZKP_AUDIT_EVENT_CONTRACT_VERSION,
  ZKP_AUDIT_EVENT_TYPES,
  ZKP_AUDIT_REJECTION_REASON_CODES,
  assertZkpAuditPayloadIsSafe,
  createZkpAuditEventService,
  hashZkpAuditIdentifier,
} from "./zkpAuditEventService";
import type { AppendBackendAuditEventInput } from "../repositories/backendAuditEventRepository";

describe("zkpAuditEventService", () => {
  it("hashes nullifiers before writing vote audit events", async () => {
    const appended: AppendBackendAuditEventInput[] = [];
    const service = createZkpAuditEventService({
      async append(input) {
        appended.push(input);
        return null;
      },
    });
    const nullifier = "a".repeat(64);

    await service.appendVoteAccepted({
      pollId: "poll-1",
      voteId: "vote-1",
      nullifier,
      voteCommitment: "b".repeat(64),
      encryptedVoteHash: "c".repeat(64),
      encryptedVoteCommitment: "d".repeat(64),
      proofHash: "e".repeat(64),
      proofEnvelopeHash: "f".repeat(64),
      proofVerificationStatus: "verified",
      verifierKeyHash: "1".repeat(64),
      circuitId: "civicos-groth16-vote-circuit-v1",
      occurredAt: "2026-07-05T12:00:00.000Z",
    });

    expect(appended).toHaveLength(1);
    expect(appended[0]).toMatchObject({
      streamId: "zkp:poll:poll-1",
      eventType: ZKP_AUDIT_EVENT_TYPES.voteAccepted,
      decision: "accepted",
      subjectType: "poll",
      subjectId: "poll-1",
    });
    expect(appended[0].payload).toMatchObject({
      version: ZKP_AUDIT_EVENT_CONTRACT_VERSION,
      pollId: "poll-1",
      nullifierHash: hashZkpAuditIdentifier(nullifier),
    });
    expect(JSON.stringify(appended[0].payload)).not.toContain(nullifier);
  });

  it("rejects identity, witness, network, and location material recursively", () => {
    expect(() =>
      assertZkpAuditPayloadIsSafe({
        reasonCode: ZKP_AUDIT_REJECTION_REASON_CODES.proofInvalid,
        nested: {
          verified_identity_id: "verified-identity-1",
        },
      }),
    ).toThrow("Unsafe ZKP audit payload key");

    expect(() =>
      assertZkpAuditPayloadIsSafe({
        receipt: {
          voteCommitment: "1".repeat(64),
          proofHash: "2".repeat(64),
        },
      }),
    ).not.toThrow();
  });
});
