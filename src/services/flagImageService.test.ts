import { describe, expect, it } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import type { FlagImageRow } from "../types/db";

const { privateKey: googleOAuthPrivateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

process.env.AUTH_IOS_TEAM_ID = "DJWBN8658Q";
process.env.AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS = "true";
process.env.AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_CLIENT_EMAIL =
  "play-integrity-test@example.iam.gserviceaccount.com";
process.env.AUTH_ANDROID_GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY = googleOAuthPrivateKey
  .export({ format: "pem", type: "pkcs8" })
  .toString();
process.env.AUTH_ANDROID_ALLOWED_SIGNING_CERT_DIGESTS =
  "23e31a67fd079259091c31ab079846a30d07f18e66ae675863b18a0a77e66763";
process.env.SOLANA_AUDIT_TRANSACTIONS_ENABLED = "false";

const { createFlagImageService, readFlagImageDimensions } = await import(
  "./flagImageService"
);

const activeFlag = (overrides: Partial<FlagImageRow> = {}): FlagImageRow => ({
  id: "7a7d1d23-8290-4a90-9a22-1e62282492b5",
  name: "Shared flag",
  creator_user_id: "viewer-1",
  storage_bucket: "flag-images",
  storage_path: "flags/7a/flag.png",
  original_file_name: "flag.png",
  mime_type: "image/png",
  size_bytes: 24,
  width: 100,
  height: 100,
  upload_status: "active",
  completed_at: "2026-08-16T00:00:00.000Z",
  created_at: "2026-08-16T00:00:00.000Z",
  updated_at: "2026-08-16T00:00:00.000Z",
  ...overrides,
});

describe("flagImageService", () => {
  it("reads dimensions from a PNG file header", () => {
    const bytes = Buffer.alloc(24);
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(bytes, 0);
    bytes.writeUInt32BE(320, 16);
    bytes.writeUInt32BE(180, 20);

    expect(readFlagImageDimensions(bytes, "image/png")).toEqual({
      width: 320,
      height: 180,
    });
  });

  it("rejects a final image outside the 10:1 aspect-ratio limit", async () => {
    let storageRequested = false;
    const service = createFlagImageService({
      repositoryLike: {} as any,
      userRepositoryLike: {
        getById: async () => ({ id: "viewer-1" }) as any,
        updateSelectedFlagImageId: async () => null,
      },
      storageBucketFactory: () => {
        storageRequested = true;
        return {} as any;
      },
    });

    const result = await service.createUpload(
      {
        name: "Too wide",
        mimeType: "image/png",
        sizeBytes: 24,
        width: 512,
        height: 20,
      },
      "viewer-1",
    );

    expect(result).toMatchObject({
      success: false,
      errorCode: "VALIDATION_FAILED",
    });
    expect(storageRequested).toBe(false);
  });

  it("does not delete an image selected by a user, including for its creator", async () => {
    let deleted = false;
    let storageRemoved = false;
    const service = createFlagImageService({
      repositoryLike: {
        getById: async () => activeFlag(),
        countSelections: async () => 1,
        deleteById: async () => {
          deleted = true;
          return true;
        },
      } as any,
      userRepositoryLike: {} as any,
      storageBucketFactory: () => ({
        remove: async () => {
          storageRemoved = true;
          return { data: null, error: null };
        },
      }) as any,
    });

    const result = await service.deleteImage(activeFlag().id, "viewer-1");

    expect(result).toMatchObject({
      success: false,
      errorCode: "FLAG_IMAGE_IN_USE",
    });
    expect(deleted).toBe(false);
    expect(storageRemoved).toBe(false);
  });

  it("activates an upload only after its actual file dimensions match", async () => {
    const bytes = Buffer.alloc(24);
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(bytes, 0);
    bytes.writeUInt32BE(100, 16);
    bytes.writeUInt32BE(100, 20);
    const signedRow = activeFlag({ upload_status: "signed", completed_at: null });
    let markedActive = false;

    const service = createFlagImageService({
      repositoryLike: {
        getById: async () => signedRow,
        markActive: async () => {
          markedActive = true;
          return activeFlag();
        },
      } as any,
      userRepositoryLike: {} as any,
      storageBucketFactory: () => ({
        info: async () => ({
          data: { size: bytes.length, contentType: "image/png" },
          error: null,
        }),
        download: async () => ({ data: new Blob([bytes]), error: null }),
        createSignedUrl: async () => ({
          data: { signedUrl: "https://storage.example.test/flag" },
          error: null,
        }),
      }) as any,
    });

    const result = await service.completeUpload(signedRow.id, "viewer-1");

    expect(markedActive).toBe(true);
    expect(result).toMatchObject({
      success: true,
      flagImage: {
        id: signedRow.id,
        imageUrl: "https://storage.example.test/flag",
        width: 100,
        height: 100,
      },
    });
  });
});
