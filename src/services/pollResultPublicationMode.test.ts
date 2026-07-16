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

  it("queues automatic closed-poll tally jobs and worker publishes after proof", () => {
    const migration = readProject(
      "supabase",
      "migrations",
      "20260716150000_add_poll_result_publication_mode.sql",
    );
    const worker = readSrc("services", "zkpTallyWorkerService.ts");

    expect(migration).toContain("polls_enqueue_auto_result_publication_tally_job");
    expect(migration).toContain("new.result_publication_mode = 'auto_on_close'");
    expect(migration).toContain("perform public.enqueue_zkp_tally_job");
    expect(worker).toContain("await polls.closeExpiredPolls?.()");
    expect(worker).toContain("publishPollAudit");
    expect(worker).toContain("Tally proof was verified and recorded.");
  });
});
