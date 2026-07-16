import { describe, expect, it } from "bun:test";

process.env.ILAND_ENV_VALIDATION_SCOPE = "supabase-admin-script";
process.env.SOLANA_AUDIT_TRANSACTIONS_ENABLED = "false";

const { normalizeZkpTallyJobRpcRow } = await import("./zkpTallyJobRepository");

describe("zkp tally job repository", () => {
  it("treats all-null composite RPC rows as no claimable job", () => {
    expect(
      normalizeZkpTallyJobRpcRow({
        id: null,
        poll_id: null,
        status: null,
        priority: null,
        attempts: null,
        max_attempts: null,
      }),
    ).toBeNull();
  });

  it("normalizes array-wrapped job rows returned by PostgREST RPCs", () => {
    expect(
      normalizeZkpTallyJobRpcRow([
        {
          id: "11111111-1111-4111-8111-111111111111",
          poll_id: "22222222-2222-4222-8222-222222222222",
          status: "pending",
        },
      ]),
    ).toMatchObject({
      id: "11111111-1111-4111-8111-111111111111",
      poll_id: "22222222-2222-4222-8222-222222222222",
      status: "pending",
    });
  });
});
