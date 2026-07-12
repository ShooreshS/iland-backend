import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "bun:test";

describe("poll repository status persistence", () => {
  it("persists expired active/scheduled polls as closed before poll reads", () => {
    const source = readFileSync(
      resolve(process.cwd(), "src/repositories/pollRepository.ts"),
      "utf8",
    );

    expect(source).toContain("const closeExpiredPolls = async");
    expect(source).toContain('status: "closed"');
    expect(source).toContain('.in("status", ["active", "scheduled"])');
    expect(source).toContain('.lte("ends_at", nowIso)');
    expect(source).toMatch(/async listAll\(\)[\s\S]*await closeExpiredPolls\(\)/);
    expect(source).toMatch(/async getById\(pollId: string\)[\s\S]*await closeExpiredPolls\(\)/);
  });
});
