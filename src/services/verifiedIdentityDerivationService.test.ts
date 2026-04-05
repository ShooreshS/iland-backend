import { describe, expect, it } from "bun:test";
import { deriveCanonicalIdentityKey } from "./verifiedIdentityDerivationService";

const SAMPLE_NIDNH = "a".repeat(128);

describe("verifiedIdentityDerivationService", () => {
  it("returns the same canonical key for the same nidnh and pepper", () => {
    const pepper = "pepper-one";
    const first = deriveCanonicalIdentityKey({
      nidnh: SAMPLE_NIDNH,
      pepper,
    });
    const second = deriveCanonicalIdentityKey({
      nidnh: SAMPLE_NIDNH,
      pepper,
    });

    expect(first).toBe(second);
  });

  it("returns a different canonical key for the same nidnh and different peppers", () => {
    const first = deriveCanonicalIdentityKey({
      nidnh: SAMPLE_NIDNH,
      pepper: "pepper-one",
    });
    const second = deriveCanonicalIdentityKey({
      nidnh: SAMPLE_NIDNH,
      pepper: "pepper-two",
    });

    expect(first).not.toBe(second);
  });
});

