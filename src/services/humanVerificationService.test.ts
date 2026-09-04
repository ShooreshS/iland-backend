import { createHash } from "node:crypto";
import { describe, expect, it } from "bun:test";

import { hashOpaqueBearerToken } from "../auth/tokens";
import type {
  HumanVerificationMediaRow,
  HumanVerificationRequestRow,
} from "../types/db";

process.env.AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS = "true";
process.env.SOLANA_AUDIT_TRANSACTIONS_ENABLED = "false";
const { createHumanVerificationService } = await import(
  "./humanVerificationService"
);

const now = new Date("2026-09-04T12:00:00.000Z");
const challenge = {
  id: "123e4567-e89b-12d3-a456-426614174000",
  purpose: "human_verification" as const,
  platform: "ios" as const,
  challenge_hash: hashOpaqueBearerToken("raw-challenge"),
  credential_id_hint: "device-1",
  expires_at: "2026-09-04T12:05:00.000Z",
  consumed_at: null,
  metadata: {},
  created_at: now.toISOString(),
};

const bytes = new Uint8Array([
  0xff, 0xd8,
  0xff, 0xc0, 0x00, 0x11, 0x08, 0x02, 0x80, 0x02, 0x80,
  0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x00, 0x03, 0x11, 0x00,
  0xff, 0xd9,
]);
const digest = createHash("sha256").update(bytes).digest("hex");

const input = {
  challengeId: challenge.id,
  challenge: "raw-challenge",
  platform: "ios" as const,
  credentialId: "device-1",
  publicKeyPem: "public-key",
  signature: "signature",
  appAttestation: {},
  documentType: "passport",
  comparison: { similarity: 0.4, threshold: 0.75, model: "mobilefacenet" },
  livenessPassed: true as const,
  gazePassed: true,
  media: [
    {
      kind: "document_portrait" as const,
      mimeType: "image/jpeg" as const,
      sizeBytes: bytes.byteLength,
      width: 640,
      height: 640,
      sha256: digest,
    },
    {
      kind: "live_face" as const,
      mimeType: "image/jpeg" as const,
      sizeBytes: bytes.byteLength,
      width: 640,
      height: 640,
      sha256: digest,
    },
  ],
};

const createHarness = () => {
  let request: HumanVerificationRequestRow | null = null;
  const media: HumanVerificationMediaRow[] = [];
  const repository = {
    getRequestById: async () => request,
    findActiveByCredentialId: async () => null,
    insertRequest: async (value: Record<string, unknown>) => {
      request = {
        id: String(value.id),
        access_token_hash: String(value.accessTokenHash),
        device_credential_id: String(value.deviceCredentialId),
        device_public_key_pem: String(value.devicePublicKeyPem),
        platform: "ios",
        status: "uploading",
        document_type: String(value.documentType),
        similarity: Number(value.similarity),
        comparison_threshold: Number(value.comparisonThreshold),
        comparison_model: String(value.comparisonModel),
        liveness_passed: true,
        gaze_passed: true,
        app_attestation: {},
        reviewer_verified_identity_id: null,
        reviewer_user_id: null,
        user_message: null,
        internal_note: null,
        submitted_at: null,
        decided_at: null,
        consumed_at: null,
        consumed_by_user_id: null,
        expires_at: String(value.expiresAt),
        created_at: now.toISOString(),
        updated_at: now.toISOString(),
      };
      return request;
    },
    insertMedia: async (value: Record<string, unknown>) => {
      const row: HumanVerificationMediaRow = {
        id: `media-${media.length + 1}`,
        request_id: String(value.requestId),
        kind: value.kind as HumanVerificationMediaRow["kind"],
        storage_bucket: String(value.storageBucket),
        storage_path: String(value.storagePath),
        mime_type: "image/jpeg",
        size_bytes: Number(value.sizeBytes),
        width: Number(value.width),
        height: Number(value.height),
        sha256: String(value.sha256),
        upload_status: "signed",
        completed_at: null,
        deleted_at: null,
        created_at: now.toISOString(),
        updated_at: now.toISOString(),
      };
      media.push(row);
      return row;
    },
    listMedia: async () => media,
    markMediaUploaded: async (id: string) => {
      const row = media.find((item) => item.id === id)!;
      row.upload_status = "uploaded";
      return row;
    },
    transitionRequest: async (
      _id: string,
      expected: string,
      next: HumanVerificationRequestRow["status"],
      values: Record<string, unknown> = {},
    ) => {
      if (!request || request.status !== expected) return null;
      request = {
        ...request,
        status: next,
        submitted_at: (values.submitted_at as string) || request.submitted_at,
      };
      return request;
    },
  };
  const service = createHumanVerificationService({
    repositoryLike: repository as never,
    challengeRepositoryLike: {
      getById: async () => challenge,
      markConsumed: async () => challenge,
    } as never,
    verifyCredentialSignatureFn: (() => ({
      success: true,
      signatureEncoding: "base64-der",
      payload: "payload",
    })) as never,
    verifyRegistrationAttestationFn: (async () => ({
      success: true,
      provider: "ios_app_attest",
      environment: "production",
      attestationKeyId: "attest-1",
      attestationPublicKeyPem: "attestation-public-key",
      appIdentifier: "TEAM.com.shooresh.iland",
      packageName: null,
      signingCertDigest: null,
      lastAssertionNonceHash: null,
      lastCounter: null,
      transitionalCryptoBypassUsed: false,
    })) as never,
    storageBucketFactory: () => ({
      createSignedUploadUrl: async (path: string) => ({
        data: { signedUrl: `https://storage.test/${path}`, token: "token", path },
        error: null,
      }),
      info: async () => ({
        data: { size: bytes.byteLength, contentType: "image/jpeg" },
        error: null,
      }),
      download: async () => ({
        data: new Blob([bytes], { type: "image/jpeg" }),
        error: null,
      }),
      remove: async () => ({ data: null, error: null }),
    }),
    now: () => now,
  });
  return { service, media, getRequest: () => request };
};

describe("humanVerificationService", () => {
  it("rejects 112 by 112 model inputs from the human-review upload path", async () => {
    const { service } = createHarness();
    const result = await service.createRequest({
      ...input,
      media: input.media.map((item) => ({ ...item, width: 112, height: 112 })),
    });
    expect(result).toMatchObject({ success: false, errorCode: "INVALID_MEDIA" });
  });

  it("creates and completes a request with two full-resolution byte-verified crops", async () => {
    const { service, media } = createHarness();
    const created = await service.createRequest(input);
    expect(created.success).toBe(true);
    if (!created.success) throw new Error("request creation failed");
    expect(created.uploads.map((item) => [item.kind, item.width, item.height])).toEqual([
      ["document_portrait", 640, 640],
      ["live_face", 640, 640],
    ]);
    const completed = await service.completeRequest(
      created.request.id,
      created.reviewToken,
    );
    expect(completed).toMatchObject({ success: true, request: { status: "pending" } });
    expect(media.every((item) => item.upload_status === "uploaded")).toBe(true);
  });
});
