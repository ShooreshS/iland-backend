import { describe, expect, it } from "bun:test";

import { hashOpaqueBearerToken } from "../auth/tokens";
import type {
  HumanVerificationRequestRow,
  HumanVerificationStatus,
} from "../types/db";

process.env.AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS = "true";
process.env.SOLANA_AUDIT_TRANSACTIONS_ENABLED = "false";
const { createHumanVerificationApprovalService } = await import(
  "./humanVerificationApprovalService"
);

const now = new Date("2026-09-04T12:00:00.000Z");

const approvedRequest = (): HumanVerificationRequestRow => ({
  id: "35f0ec72-c728-4cf2-ae41-b7ff386fa62d",
  access_token_hash: hashOpaqueBearerToken("review-token"),
  device_credential_id: "device-1",
  device_public_key_pem: "public-key-1",
  platform: "ios",
  status: "approved",
  document_type: "passport",
  similarity: 0.4,
  comparison_threshold: 0.75,
  comparison_model: "mobilefacenet",
  liveness_passed: true,
  gaze_passed: true,
  app_attestation: {},
  reviewer_verified_identity_id: "reviewer-identity-1",
  reviewer_user_id: "reviewer-user-1",
  user_message: null,
  internal_note: null,
  submitted_at: "2026-09-04T11:00:00.000Z",
  decided_at: "2026-09-04T11:30:00.000Z",
  consumed_at: null,
  consumed_by_user_id: null,
  expires_at: "2026-10-04T12:00:00.000Z",
  created_at: "2026-09-04T10:00:00.000Z",
  updated_at: "2026-09-04T11:30:00.000Z",
});

const createHarness = () => {
  let request = approvedRequest();
  let transitionCalls = 0;
  const service = createHumanVerificationApprovalService({
    repositoryLike: {
      getRequestById: async () => request,
      transitionRequest: async (
        _id: string,
        expected: HumanVerificationStatus,
        next: HumanVerificationStatus,
        values: Record<string, unknown> = {},
      ) => {
        transitionCalls += 1;
        if (request.status !== expected) return null;
        request = {
          ...request,
          status: next,
          consumed_at: (values.consumed_at as string) || request.consumed_at,
        };
        return request;
      },
    } as never,
    now: () => now,
  });
  return {
    service,
    getRequest: () => request,
    getTransitionCalls: () => transitionCalls,
  };
};

describe("humanVerificationApprovalService", () => {
  it("consumes an approved review once when token, credential, and key match", async () => {
    const harness = createHarness();
    const result = await harness.service.consume({
      requestId: approvedRequest().id,
      reviewToken: "review-token",
      credentialId: "device-1",
      publicKeyPem: "public-key-1",
    });

    expect(result).toMatchObject({ success: true, request: { status: "consumed" } });
    expect(harness.getRequest().consumed_at).toBe(now.toISOString());

    const replay = await harness.service.consume({
      requestId: approvedRequest().id,
      reviewToken: "review-token",
      credentialId: "device-1",
      publicKeyPem: "public-key-1",
    });
    expect(replay).toMatchObject({
      success: false,
      errorCode: "HUMAN_REVIEW_NOT_APPROVED",
    });
  });

  it("does not consume approval when the device binding differs", async () => {
    const harness = createHarness();
    const result = await harness.service.consume({
      requestId: approvedRequest().id,
      reviewToken: "review-token",
      credentialId: "another-device",
      publicKeyPem: "public-key-1",
    });

    expect(result).toMatchObject({
      success: false,
      errorCode: "HUMAN_REVIEW_NOT_APPROVED",
    });
    expect(harness.getTransitionCalls()).toBe(0);
  });
});
