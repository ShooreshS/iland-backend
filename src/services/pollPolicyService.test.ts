import { describe, expect, it } from "bun:test";
import {
  buildPollAuditMaterial,
  canonicalizeJson,
} from "./pollPolicyService";

const basePolicyInput = {
  pollId: "11111111-1111-4111-8111-111111111111",
  jurisdictionType: "real_area" as const,
  jurisdictionCountryCode: " ir ",
  jurisdictionAreaIds: ["area-b", "area-a", "area-b"],
  jurisdictionLandIds: ["land-b", "land-a"],
  requiresVerifiedIdentity: true,
  allowedDocumentCountryCodes: ["ir", "DE", " ir "],
  allowedHomeAreaIds: [" area-2 ", "area-1", "area-2"],
  allowedLandIds: ["land-2", "land-1", "land-2"],
  minimumAge: 18,
  startsAt: "2026-07-04T12:00:00.000Z",
  endsAt: null,
};

describe("pollPolicyService", () => {
  it("canonicalizes object keys recursively", () => {
    expect(canonicalizeJson({ b: 1, a: { d: 4, c: 3 } })).toBe(
      '{"a":{"c":3,"d":4},"b":1}',
    );
  });

  it("builds stable hashes from normalized policy values", () => {
    const first = buildPollAuditMaterial(basePolicyInput);
    const second = buildPollAuditMaterial({
      ...basePolicyInput,
      jurisdictionAreaIds: ["area-a", "area-b"],
      jurisdictionLandIds: ["land-a", "land-b"],
      allowedDocumentCountryCodes: ["DE", "IR"],
      allowedHomeAreaIds: ["area-1", "area-2"],
      allowedLandIds: ["land-1", "land-2"],
    });

    expect(first.pollPolicyHash).toBe(second.pollPolicyHash);
    expect(first.credentialSchemaHash).toBe(second.credentialSchemaHash);
    expect(first.pollPolicy.jurisdiction.countryCode).toBe("IR");
    expect(first.pollPolicy.eligibilityRules.acceptedDocumentCountryCodes).toEqual([
      "DE",
      "IR",
    ]);
  });

  it("changes hashes when eligibility changes", () => {
    const first = buildPollAuditMaterial(basePolicyInput);
    const second = buildPollAuditMaterial({
      ...basePolicyInput,
      minimumAge: 21,
    });

    expect(first.pollPolicyHash).not.toBe(second.pollPolicyHash);
    expect(first.credentialSchemaHash).not.toBe(second.credentialSchemaHash);
  });

  it("binds the credential schema to the poll policy hash", () => {
    const material = buildPollAuditMaterial(basePolicyInput);

    expect(material.credentialSchema.derivedClaims.eligibilityPolicyHash).toBe(
      material.pollPolicyHash,
    );
    expect(material.pollPolicyHash).toMatch(/^[0-9a-f]{64}$/);
    expect(material.credentialSchemaHash).toMatch(/^[0-9a-f]{64}$/);
  });
});
