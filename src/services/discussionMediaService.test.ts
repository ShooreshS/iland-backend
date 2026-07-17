import { describe, expect, it } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import type {
  DiscussionMediaUploadRow,
  UserRow,
  VerifiedIdentityRow,
} from "../types/db";

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

const { createDiscussionMediaService, DISCUSSION_MEDIA_BUCKET } = await import(
  "./discussionMediaService"
);

const FIXED_TIME = "2026-07-17T12:00:00.000Z";

const user: UserRow = {
  id: "user-1",
  username: "user1",
  display_name: null,
  public_nickname: "clear-voter",
  onboarding_status: "completed",
  verification_level: "nid_verified",
  has_wallet: true,
  wallet_credential_id: null,
  selected_land_id: null,
  preferred_language: null,
  auth_generation: 1,
  account_status: "active",
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
};

const verifiedIdentity: VerifiedIdentityRow = {
  id: "verified-identity-1",
  user_id: "user-1",
  canonical_identity_key: "canonical-key",
  normalization_version: 1,
  verification_method: "passport_nfc",
  verified_at: FIXED_TIME,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
};

const createUploadRow = (
  overrides: Partial<DiscussionMediaUploadRow> = {},
): DiscussionMediaUploadRow => ({
  id: "upload-1",
  uploader_user_id: "user-1",
  storage_bucket: DISCUSSION_MEDIA_BUCKET,
  storage_path: "discussions/ab/upload-1.jpg",
  original_file_name: "photo.jpg",
  mime_type: "image/jpeg",
  size_bytes: 10_000,
  upload_status: "signed",
  attached_post_id: null,
  signed_at: FIXED_TIME,
  completed_at: null,
  attached_at: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

describe("discussionMediaService", () => {
  it("creates a signed upload for verified users", async () => {
    const uploads: DiscussionMediaUploadRow[] = [];
    const service = createDiscussionMediaService({
      repositoryLike: {
        insertUpload: async (input: any) => {
          const row = createUploadRow({
            id: input.id,
            uploader_user_id: input.uploader_user_id,
            storage_bucket: input.storage_bucket,
            storage_path: input.storage_path,
            original_file_name: input.original_file_name,
            mime_type: input.mime_type,
            size_bytes: input.size_bytes,
            upload_status: input.upload_status,
          });
          uploads.push(row);
          return row;
        },
      } as any,
      userRepositoryLike: { getById: async () => user },
      verifiedIdentityRepositoryLike: { getByUserId: async () => verifiedIdentity },
      storageBucketFactory: () =>
        ({
          createSignedUploadUrl: async (path: string) => ({
            data: {
              signedUrl: `https://storage.example.test/upload/${path}?token=secret`,
              token: "secret",
              path,
            },
            error: null,
          }),
        }) as any,
    });

    const result = await service.createImageUpload(
      {
        fileName: "city.jpg",
        mimeType: "image/jpeg",
        sizeBytes: 10_000,
      },
      "user-1",
    );

    expect(result.success).toBe(true);
    expect(result.upload?.uploadUrl).toContain("token=secret");
    expect(uploads[0]).toMatchObject({
      uploader_user_id: "user-1",
      storage_bucket: DISCUSSION_MEDIA_BUCKET,
      mime_type: "image/jpeg",
      size_bytes: 10_000,
      upload_status: "signed",
    });
  });

  it("completes an upload only when storage metadata matches", async () => {
    let upload = createUploadRow();
    const service = createDiscussionMediaService({
      repositoryLike: {
        getUploadById: async () => upload,
        markUploadCompleted: async () => {
          upload = createUploadRow({
            upload_status: "uploaded",
            completed_at: FIXED_TIME,
          });
          return upload;
        },
      } as any,
      userRepositoryLike: { getById: async () => user },
      verifiedIdentityRepositoryLike: { getByUserId: async () => verifiedIdentity },
      storageBucketFactory: () =>
        ({
          info: async () => ({
            data: {
              size: 10_000,
              contentType: "image/jpeg",
            },
            error: null,
          }),
        }) as any,
    });

    const result = await service.completeImageUpload("upload-1", "user-1");

    expect(result).toMatchObject({
      success: true,
      image: {
        uploadId: "upload-1",
        storageBucket: DISCUSSION_MEDIA_BUCKET,
        storagePath: "discussions/ab/upload-1.jpg",
        mimeType: "image/jpeg",
        sizeBytes: 10_000,
      },
    });
  });
});
