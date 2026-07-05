import { createHash } from "node:crypto";
import { canonicalizeJson } from "./pollPolicyService";
import type { BackendAuditEventDecision } from "../types/db";
import type { JsonValue } from "../types/json";

export const BACKEND_AUDIT_LOG_VERSION =
  "civicos-backend-audit-log-v1" as const;
export const BACKEND_AUDIT_LOG_DOMAIN =
  "org.civicos.backend-audit-log" as const;
export const BACKEND_AUDIT_LOG_HASH_ALGORITHM = "sha256" as const;
export const GENESIS_BACKEND_AUDIT_EVENT_HASH = "0".repeat(64);

const HEX_64_PATTERN = /^[0-9a-f]{64}$/;

export type BackendAuditEventSubject = Readonly<{
  type: string | null;
  id: string | null;
}>;

export type BackendAuditEventPayload = Readonly<{
  version: typeof BACKEND_AUDIT_LOG_VERSION;
  eventType: string;
  decision: BackendAuditEventDecision;
  subject: BackendAuditEventSubject;
  occurredAt: string;
  payload: JsonValue;
}>;

export type HashedBackendAuditEvent = Readonly<{
  previousEventHash: string;
  eventHash: string;
  eventPayload: BackendAuditEventPayload;
  canonicalPayload: string;
}>;

const sha256Hex = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

const normalizeText = (value: string | null | undefined): string | null => {
  const normalized = typeof value === "string" ? value.trim() : "";
  return normalized.length > 0 ? normalized : null;
};

const normalizePreviousHash = (value: string | null | undefined): string => {
  const normalized = normalizeText(value)?.toLowerCase();
  if (!normalized) {
    return GENESIS_BACKEND_AUDIT_EVENT_HASH;
  }

  if (!HEX_64_PATTERN.test(normalized)) {
    throw new Error("previousEventHash must be a 64-character hex string.");
  }

  return normalized;
};

export const buildBackendAuditEventHash = (input: {
  previousEventHash?: string | null;
  eventType: string;
  decision: BackendAuditEventDecision;
  subjectType?: string | null;
  subjectId?: string | null;
  occurredAt: string;
  payload?: JsonValue | null;
}): HashedBackendAuditEvent => {
  const eventType = normalizeText(input.eventType);
  if (!eventType) {
    throw new Error("eventType is required.");
  }

  const occurredAt = normalizeText(input.occurredAt);
  if (!occurredAt) {
    throw new Error("occurredAt is required.");
  }

  const previousEventHash = normalizePreviousHash(input.previousEventHash);
  const eventPayload: BackendAuditEventPayload = Object.freeze({
    version: BACKEND_AUDIT_LOG_VERSION,
    eventType,
    decision: input.decision,
    subject: Object.freeze({
      type: normalizeText(input.subjectType),
      id: normalizeText(input.subjectId),
    }),
    occurredAt,
    payload: input.payload ?? {},
  });
  const canonicalPayload = canonicalizeJson(eventPayload);
  const eventHash = sha256Hex(
    [
      BACKEND_AUDIT_LOG_DOMAIN,
      BACKEND_AUDIT_LOG_VERSION,
      BACKEND_AUDIT_LOG_HASH_ALGORITHM,
      previousEventHash,
      canonicalPayload,
    ].join("|"),
  );

  return Object.freeze({
    previousEventHash,
    eventHash,
    eventPayload,
    canonicalPayload,
  });
};

export const buildBackendAuditEventChain = (
  events: readonly Omit<
    Parameters<typeof buildBackendAuditEventHash>[0],
    "previousEventHash"
  >[],
  initialPreviousEventHash: string = GENESIS_BACKEND_AUDIT_EVENT_HASH,
): Readonly<{
  eventCount: number;
  rootHash: string;
  events: HashedBackendAuditEvent[];
}> => {
  let previousEventHash = normalizePreviousHash(initialPreviousEventHash);
  const hashedEvents = events.map((event) => {
    const hashed = buildBackendAuditEventHash({
      ...event,
      previousEventHash,
    });
    previousEventHash = hashed.eventHash;
    return hashed;
  });

  return Object.freeze({
    eventCount: hashedEvents.length,
    rootHash: previousEventHash,
    events: hashedEvents,
  });
};
