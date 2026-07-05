import { describe, expect, it } from "bun:test";

import {
  GENESIS_BACKEND_AUDIT_EVENT_HASH,
  buildBackendAuditEventChain,
  buildBackendAuditEventHash,
} from "./backendAuditHashChainService";

const FIXED_TIME = "2026-07-05T12:00:00.000Z";

describe("backendAuditHashChainService", () => {
  it("hashes canonical event payloads independent of object key order", () => {
    const first = buildBackendAuditEventHash({
      eventType: "vote.accepted",
      decision: "accepted",
      subjectType: "poll",
      subjectId: "poll-1",
      occurredAt: FIXED_TIME,
      payload: {
        b: 2,
        a: 1,
      },
    });
    const second = buildBackendAuditEventHash({
      eventType: "vote.accepted",
      decision: "accepted",
      subjectType: "poll",
      subjectId: "poll-1",
      occurredAt: FIXED_TIME,
      payload: {
        a: 1,
        b: 2,
      },
    });

    expect(first.previousEventHash).toBe(GENESIS_BACKEND_AUDIT_EVENT_HASH);
    expect(first.eventHash).toBe(second.eventHash);
    expect(first.eventHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("binds each event hash to the previous event hash", () => {
    const first = buildBackendAuditEventHash({
      eventType: "vote.accepted",
      decision: "accepted",
      occurredAt: FIXED_TIME,
      payload: { voteCommitment: "1".repeat(64) },
    });
    const second = buildBackendAuditEventHash({
      previousEventHash: first.eventHash,
      eventType: "vote.accepted",
      decision: "accepted",
      occurredAt: FIXED_TIME,
      payload: { voteCommitment: "1".repeat(64) },
    });

    expect(second.previousEventHash).toBe(first.eventHash);
    expect(second.eventHash).not.toBe(first.eventHash);
  });

  it("builds a chain whose root is the final event hash", () => {
    const chain = buildBackendAuditEventChain([
      {
        eventType: "verification.proof.accepted",
        decision: "accepted",
        occurredAt: FIXED_TIME,
        payload: { credentialCommitment: "2".repeat(64) },
      },
      {
        eventType: "vote.accepted",
        decision: "accepted",
        occurredAt: "2026-07-05T12:01:00.000Z",
        payload: { voteCommitment: "3".repeat(64) },
      },
    ]);

    expect(chain.eventCount).toBe(2);
    expect(chain.events[0].previousEventHash).toBe(
      GENESIS_BACKEND_AUDIT_EVENT_HASH,
    );
    expect(chain.events[1].previousEventHash).toBe(chain.events[0].eventHash);
    expect(chain.rootHash).toBe(chain.events[1].eventHash);
  });

  it("rejects invalid previous hashes", () => {
    expect(() =>
      buildBackendAuditEventHash({
        previousEventHash: "not-a-hash",
        eventType: "vote.rejected",
        decision: "rejected",
        occurredAt: FIXED_TIME,
        payload: { reason: "duplicate_nullifier" },
      }),
    ).toThrow("previousEventHash");
  });
});
