import { describe, expect, it } from "bun:test";
import {
  deriveCanonicalIdentityKey,
  isSupportedNormalizationVersion,
} from "./verifiedIdentityDerivationService";

const SAMPLE_NIDNH = "a".repeat(128);

describe("verifiedIdentityDerivationService", () => {
  it("supports legacy Iranian v1 and country-scoped Swedish v2", () => {
    expect(isSupportedNormalizationVersion(1)).toBe(true);
    expect(isSupportedNormalizationVersion(2)).toBe(true);
    expect(isSupportedNormalizationVersion(3)).toBe(false);
  });

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
