import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "bun:test";

const scriptSource = () =>
  readFileSync(
    resolve(process.cwd(), "scripts/phase7-devnet-acceptance.mjs"),
    "utf8",
  );

describe("Phase 7 acceptance runner", () => {
  it("captures strict publication evidence and a public transcript", () => {
    const source = scriptSource();

    expect(source).toContain("PHASE7-TRANSCRIPT.md");
    expect(source).toContain("/health/zkp");
    expect(source).toContain("public-audit-verifier.txt");
    expect(source).toContain("publicationStatus=published_on_chain");
    expect(source).toContain("finalResultSignature");
    expect(source).toContain("CIVICOS_PHASE7_ALLOW_PARTIAL");
  });

  it("supports verifying a poll already published from the signed-in owner device", () => {
    const source = scriptSource();

    expect(source).toContain("CIVICOS_PHASE7_VERIFY_ONLY");
    expect(source).toContain("Verify-only mode: skipping backend audit publication route.");
    expect(source).toContain("audit publication was performed from the signed-in owner device");
  });

  it("supports duplicate-nullifier negative drill from a saved phone payload", () => {
    const source = scriptSource();

    expect(source).toContain("CIVICOS_PHASE7_DUPLICATE_VOTE_PAYLOAD_FILE");
    expect(source).toContain("duplicate-vote-response.json");
    expect(source).toContain("ALREADY_VOTED");
    expect(source).toContain("Duplicate vote drill unexpectedly succeeded");
  });
});
