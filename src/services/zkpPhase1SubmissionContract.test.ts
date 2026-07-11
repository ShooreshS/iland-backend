import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const sourceRoot = join(import.meta.dir, "..");

const readSource = (...segments: string[]): string =>
  readFileSync(join(sourceRoot, ...segments), "utf8");

describe("ZKP Phase 1 submission contract", () => {
  it("allows production vote requests without optionId and rejects plaintext option leakage", () => {
    const routeSource = readSource("routes", "polls.ts");

    expect(routeSource).toContain(
      "optionId: z.string().trim().min(1).optional()",
    );
    expect(routeSource).toContain("isProductionVotePrivacyPayload");
    expect(routeSource).toContain(
      "Production ZKP vote requests must not include plaintext optionId.",
    );
    expect(routeSource).toContain(
      "Legacy/dev vote requests must include optionId.",
    );
  });

  it("keeps production storage and receipts free of plaintext option ids", () => {
    const serviceSource = readSource("services", "pollVotingService.ts");

    expect(serviceSource).toContain("plaintextOptionSubmitted");
    expect(serviceSource).toContain(
      "Production ZKP vote submissions must not include plaintext option id.",
    );
    expect(serviceSource).toContain("viewerVote: null");
    expect(serviceSource).toContain(
      "...(input.optionId ? { optionId: input.optionId } : {})",
    );
    expect(serviceSource).toContain(
      "const proofVerification = await verifyProductionVoteProof({",
    );
    expect(serviceSource).toContain("expectedOptionCount: productionOptionCount");
  });
});
