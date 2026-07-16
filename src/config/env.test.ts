import { describe, expect, it } from "bun:test";

const withEnv = async <T>(
  values: Record<string, string | undefined>,
  fn: () => Promise<T>,
): Promise<T> => {
  const previous = new Map<string, string | undefined>();
  for (const key of Object.keys(values)) {
    previous.set(key, process.env[key]);
    const value = values[key];
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }

  try {
    return await fn();
  } finally {
    for (const [key, value] of previous.entries()) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
};

describe("env config", () => {
  it("parses quoted Railway tally worker env values", async () => {
    await withEnv(
      {
        ILAND_ENV_VALIDATION_SCOPE: "supabase-admin-script",
        SOLANA_AUDIT_TRANSACTIONS_ENABLED: '"false"',
        ZKP_TALLY_PROVER_MODE: '"worker"',
        ZKP_TALLY_WORKER_ENABLED: '"true"',
        ZKP_TALLY_WORKER_CONCURRENCY: '"1"',
        ZKP_TALLY_WORKER_POLL_INTERVAL_MS: '"5000"',
        ZKP_TALLY_WORKER_LOCK_TIMEOUT_MS: '"600000"',
        ZKP_TALLY_WORKER_MAX_ATTEMPTS: '"3"',
        ZKP_TALLY_WORKER_RETRY_DELAY_MS: '"60000"',
        ZKP_TALLY_WORKER_HEARTBEAT_STALE_MS: '"120000"',
      },
      async () => {
        const { env } = await import(`./env.ts?quoted-worker-env-${Date.now()}`);

        expect(env.zkp.tallyWorker.proverMode).toBe("worker");
        expect(env.zkp.tallyWorker.enabled).toBe(true);
        expect(env.zkp.tallyWorker.concurrency).toBe(1);
        expect(env.zkp.tallyWorker.pollIntervalMs).toBe(5_000);
        expect(env.zkp.tallyWorker.lockTimeoutMs).toBe(600_000);
        expect(env.zkp.tallyWorker.maxAttempts).toBe(3);
        expect(env.zkp.tallyWorker.retryDelayMs).toBe(60_000);
        expect(env.zkp.tallyWorker.heartbeatStaleMs).toBe(120_000);
        expect(env.solanaAudit.transactionsEnabled).toBe(false);
      },
    );
  });
});
