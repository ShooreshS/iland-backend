import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dir, "..");

const readSource = (...segments: string[]): string =>
  readFileSync(join(root, ...segments), "utf8");

describe("ZKP Phase 0 production-mode policy", () => {
  it("defaults new/missing poll contracts to production ZKP", () => {
    const pollRepositorySource = readSource("repositories", "pollRepository.ts");
    const pollDraftSource = readSource("services", "pollDraftService.ts");

    expect(pollRepositorySource).toContain('return "zk_secret_ballot_v1";');
    expect(pollRepositorySource).toContain(
      'vote_privacy_mode: input.vote_privacy_mode ?? "zk_secret_ballot_v1"',
    );
    expect(pollDraftSource).toContain(
      "const DEFAULT_VOTE_PRIVACY_MODE = PRODUCTION_ZKP_VOTE_PRIVACY_MODE;",
    );
  });

  it("keeps legacy voting behind a non-production developer flag", () => {
    const pollVotingSource = readSource("services", "pollVotingService.ts");

    expect(pollVotingSource).toContain("isDevLegacyVotePathEnabled");
    expect(pollVotingSource).toContain('process.env.NODE_ENV !== "production"');
    expect(pollVotingSource).toContain(
      'process.env.CIVICOS_ENABLE_LEGACY_VOTE_PATH === "true"',
    );
    expect(pollVotingSource).toContain(
      "This backend only accepts production ZKP vote submissions.",
    );
  });
});
