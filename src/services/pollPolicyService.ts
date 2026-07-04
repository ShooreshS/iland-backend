import { createHash } from "node:crypto";
import type { PollJurisdictionType } from "../types/contracts";
import type { JsonValue } from "../types/json";

export const CIVICOS_POLL_POLICY_VERSION = "civicos-poll-policy-v1" as const;
export const CIVICOS_CREDENTIAL_SCHEMA_VERSION = "civicos-identity-v1" as const;
const CIVICOS_SET_HASH_VERSION = "civicos-string-set-v1" as const;

export type PollPolicySource = {
  pollId: string;
  jurisdictionType: PollJurisdictionType;
  jurisdictionCountryCode: string | null | undefined;
  jurisdictionAreaIds: string[] | null | undefined;
  jurisdictionLandIds: string[] | null | undefined;
  requiresVerifiedIdentity: boolean;
  allowedDocumentCountryCodes: string[] | null | undefined;
  allowedHomeAreaIds: string[] | null | undefined;
  allowedLandIds: string[] | null | undefined;
  minimumAge: number | null | undefined;
  startsAt: string | null | undefined;
  endsAt: string | null | undefined;
};

export type CivicPollPolicy = {
  version: typeof CIVICOS_POLL_POLICY_VERSION;
  pollId: string;
  jurisdiction: {
    type: PollJurisdictionType;
    countryCode: string | null;
    areaIds: string[];
    landIds: string[];
  };
  eligibilityRules: {
    requiresVerifiedIdentity: boolean;
    acceptedDocumentCountryCodes: string[];
    acceptedHomeAreaIds: string[];
    acceptedLandIds: string[];
    minimumAge: number | null;
  };
  votingWindow: {
    opensAt: string | null;
    closesAt: string | null;
  };
};

export type CivicCredentialSchema = {
  version: typeof CIVICOS_CREDENTIAL_SCHEMA_VERSION;
  documentTypes: ["passport", "national_id"];
  checks: {
    documentAuthenticity: true;
    documentNotExpired: true;
    livenessPassed: true;
    faceMatchedDocument: true;
  };
  derivedClaims: {
    ageOver: number | null;
    acceptedDocumentCountrySetHash: string | null;
    acceptedHomeAreaSetHash: string | null;
    acceptedLandSetHash: string | null;
    eligibilityPolicyHash: string;
  };
};

const compareStrings = (left: string, right: string): number =>
  left < right ? -1 : left > right ? 1 : 0;

const normalizeOptionalString = (value: string | null | undefined): string | null => {
  const normalized = typeof value === "string" ? value.trim() : "";
  return normalized.length > 0 ? normalized : null;
};

export const normalizeCountryCode = (
  value: string | null | undefined,
): string | null => {
  const normalized = normalizeOptionalString(value);
  return normalized ? normalized.toUpperCase() : null;
};

const normalizeStringSet = (
  values: string[] | null | undefined,
  transform: (value: string) => string = (value) => value,
): string[] => {
  if (!Array.isArray(values)) {
    return [];
  }

  const seen = new Set<string>();
  values.forEach((value) => {
    if (typeof value !== "string") {
      return;
    }

    const normalized = transform(value.trim());
    if (normalized.length > 0) {
      seen.add(normalized);
    }
  });

  return [...seen].sort(compareStrings);
};

const normalizeCountryCodeSet = (values: string[] | null | undefined): string[] =>
  normalizeStringSet(values, (value) => value.toUpperCase());

const normalizeTimestamp = (value: string | null | undefined): string | null =>
  normalizeOptionalString(value);

export const normalizeMinimumAge = (
  value: number | null | undefined,
): number | null => {
  if (typeof value !== "number" || !Number.isFinite(value) || !Number.isInteger(value)) {
    return null;
  }

  return value >= 0 ? value : null;
};

const normalizeJsonValue = (value: unknown): JsonValue => {
  if (value === null) {
    return null;
  }

  if (typeof value === "string" || typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("Canonical JSON cannot encode non-finite numbers.");
    }

    return Object.is(value, -0) ? 0 : value;
  }

  if (Array.isArray(value)) {
    return value.map(normalizeJsonValue);
  }

  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.keys(record)
      .sort(compareStrings)
      .reduce<{ [key: string]: JsonValue }>((acc, key) => {
        if (record[key] !== undefined) {
          acc[key] = normalizeJsonValue(record[key]);
        }
        return acc;
      }, {});
  }

  throw new TypeError("Canonical JSON can only encode JSON-compatible values.");
};

export const canonicalizeJson = (value: unknown): string =>
  JSON.stringify(normalizeJsonValue(value));

export const hashCanonicalJson = (value: unknown): string =>
  createHash("sha256").update(canonicalizeJson(value), "utf8").digest("hex");

const hashStringSet = (kind: string, values: string[]): string | null =>
  values.length > 0
    ? hashCanonicalJson({
        version: CIVICOS_SET_HASH_VERSION,
        kind,
        values,
      })
    : null;

export const buildCivicPollPolicy = (
  input: PollPolicySource,
): CivicPollPolicy => ({
  version: CIVICOS_POLL_POLICY_VERSION,
  pollId: input.pollId,
  jurisdiction: {
    type: input.jurisdictionType,
    countryCode: normalizeCountryCode(input.jurisdictionCountryCode),
    areaIds: normalizeStringSet(input.jurisdictionAreaIds),
    landIds: normalizeStringSet(input.jurisdictionLandIds),
  },
  eligibilityRules: {
    requiresVerifiedIdentity: Boolean(input.requiresVerifiedIdentity),
    acceptedDocumentCountryCodes: normalizeCountryCodeSet(
      input.allowedDocumentCountryCodes,
    ),
    acceptedHomeAreaIds: normalizeStringSet(input.allowedHomeAreaIds),
    acceptedLandIds: normalizeStringSet(input.allowedLandIds),
    minimumAge: normalizeMinimumAge(input.minimumAge),
  },
  votingWindow: {
    opensAt: normalizeTimestamp(input.startsAt),
    closesAt: normalizeTimestamp(input.endsAt),
  },
});

export const buildCivicCredentialSchema = (
  policy: CivicPollPolicy,
  pollPolicyHash: string,
): CivicCredentialSchema => ({
  version: CIVICOS_CREDENTIAL_SCHEMA_VERSION,
  documentTypes: ["passport", "national_id"],
  checks: {
    documentAuthenticity: true,
    documentNotExpired: true,
    livenessPassed: true,
    faceMatchedDocument: true,
  },
  derivedClaims: {
    ageOver: policy.eligibilityRules.minimumAge,
    acceptedDocumentCountrySetHash: hashStringSet(
      "document_country",
      policy.eligibilityRules.acceptedDocumentCountryCodes,
    ),
    acceptedHomeAreaSetHash: hashStringSet(
      "home_area",
      policy.eligibilityRules.acceptedHomeAreaIds,
    ),
    acceptedLandSetHash: hashStringSet(
      "land",
      policy.eligibilityRules.acceptedLandIds,
    ),
    eligibilityPolicyHash: pollPolicyHash,
  },
});

export const buildPollAuditMaterial = (
  input: PollPolicySource,
): {
  pollPolicy: CivicPollPolicy;
  pollPolicyHash: string;
  credentialSchema: CivicCredentialSchema;
  credentialSchemaHash: string;
} => {
  const pollPolicy = buildCivicPollPolicy(input);
  const pollPolicyHash = hashCanonicalJson(pollPolicy);
  const credentialSchema = buildCivicCredentialSchema(pollPolicy, pollPolicyHash);

  return {
    pollPolicy,
    pollPolicyHash,
    credentialSchema,
    credentialSchemaHash: hashCanonicalJson(credentialSchema),
  };
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((entry) => typeof entry === "string");

export const isCivicPollPolicy = (value: unknown): value is CivicPollPolicy => {
  if (!isRecord(value)) {
    return false;
  }

  const jurisdiction = value.jurisdiction;
  const eligibilityRules = value.eligibilityRules;
  const votingWindow = value.votingWindow;

  return (
    value.version === CIVICOS_POLL_POLICY_VERSION &&
    typeof value.pollId === "string" &&
    isRecord(jurisdiction) &&
    typeof jurisdiction.type === "string" &&
    (typeof jurisdiction.countryCode === "string" ||
      jurisdiction.countryCode === null) &&
    isStringArray(jurisdiction.areaIds) &&
    isStringArray(jurisdiction.landIds) &&
    isRecord(eligibilityRules) &&
    typeof eligibilityRules.requiresVerifiedIdentity === "boolean" &&
    isStringArray(eligibilityRules.acceptedDocumentCountryCodes) &&
    isStringArray(eligibilityRules.acceptedHomeAreaIds) &&
    isStringArray(eligibilityRules.acceptedLandIds) &&
    (typeof eligibilityRules.minimumAge === "number" ||
      eligibilityRules.minimumAge === null) &&
    isRecord(votingWindow) &&
    (typeof votingWindow.opensAt === "string" || votingWindow.opensAt === null) &&
    (typeof votingWindow.closesAt === "string" || votingWindow.closesAt === null)
  );
};

export const resolveCivicPollPolicy = (
  policyJson: unknown,
  fallbackInput: PollPolicySource,
): CivicPollPolicy =>
  isCivicPollPolicy(policyJson) ? policyJson : buildCivicPollPolicy(fallbackInput);
