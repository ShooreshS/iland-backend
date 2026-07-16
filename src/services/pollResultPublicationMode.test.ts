import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const srcRoot = resolve(import.meta.dir, "..");
const projectRoot = resolve(import.meta.dir, "..", "..");

const readSrc = (...parts: string[]): string =>
  readFileSync(resolve(srcRoot, ...parts), "utf8");

const readProject = (...parts: string[]): string =>
  readFileSync(resolve(projectRoot, ...parts), "utf8");

describe("poll result publication mode contract", () => {
  it("persists auto-on-close vs creator-managed poll publication mode", () => {
    const contracts = readSrc("types", "contracts.ts");
    const repository = readSrc("repositories", "pollRepository.ts");
    const draftService = readSrc("services", "pollDraftService.ts");

    expect(contracts).toContain("export type PollResultPublicationMode");
    expect(contracts).toContain('"auto_on_close"');
    expect(contracts).toContain('"creator_managed"');
    expect(repository).toContain("result_publication_mode");
    expect(repository).toContain('input.result_publication_mode ?? "auto_on_close"');
    expect(draftService).toContain("resultPublicationMode");
    expect(draftService).toContain('DEFAULT_RESULT_PUBLICATION_MODE = "auto_on_close"');
  });

  it("queues automatic closed-poll tally jobs and keeps publication out of the tally worker", () => {
    const migration = readProject(
      "supabase",
      "migrations",
      "20260716150000_add_poll_result_publication_mode.sql",
    );
    const worker = readSrc("services", "zkpTallyWorkerService.ts");
    const publisher = readSrc("services", "zkpAutoResultPublisherService.ts");
    const server = readSrc("server.ts");

    expect(migration).toContain("polls_enqueue_auto_result_publication_tally_job");
    expect(migration).toContain("new.result_publication_mode = 'auto_on_close'");
    expect(migration).toContain("perform public.enqueue_zkp_tally_job");
    expect(worker).toContain("await polls.closeExpiredPolls?.()");
    expect(worker).not.toContain("publishPollAudit");
    expect(worker).toContain("final publication is delegated to the main backend");
    expect(publisher).toContain("publishPollAudit");
    expect(publisher).toContain('poll.result_publication_mode === "auto_on_close"');
    expect(server).toContain("createZkpAutoResultPublisherService");
    expect(server).toContain("env.solanaAudit.transactionsEnabled");
  });

  it("keeps worker runner from requiring Solana publication env", () => {
    const runner = readProject("scripts", "run-zkp-tally-worker.ts");
    const envSource = readSrc("config", "env.ts");

    expect(runner).toContain('process.env.ILAND_ENV_VALIDATION_SCOPE ||= "supabase-admin-script"');
    expect(runner).toContain('process.env.SOLANA_AUDIT_TRANSACTIONS_ENABLED = "false"');
    expect(runner).toContain('process.env.ZKP_TALLY_PROVER_MODE = "worker"');
    expect(runner).toContain('process.env.ZKP_TALLY_WORKER_ENABLED = "true"');
    expect(envSource).toContain("const stripWrappingQuotes");
    expect(envSource).toContain("ZKP_TALLY_WORKER_ENABLED: emptyToUndefined");
  });
});
