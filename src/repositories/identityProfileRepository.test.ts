import { describe, expect, it } from "bun:test";
import { normalizeIdentityProfileRepositoryError } from "./identityProfileRepository";

describe("normalizeIdentityProfileRepositoryError", () => {
  it("converts plain-object database errors into Error with context", () => {
    const error = normalizeIdentityProfileRepositoryError(
      { message: "Bad Request" },
      "identity_profiles map seed lookup failed",
    );

    expect(error instanceof Error).toBe(true);
    expect(error.message).toContain("identity_profiles map seed lookup failed");
    expect(error.message).toContain("Bad Request");
  });
});
