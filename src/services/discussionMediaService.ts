import { randomUUID } from "node:crypto";
import { requireSupabaseAdminClient } from "../db/supabaseClient";
import discussionMediaRepository from "../repositories/discussionMediaRepository";
import userRepository from "../repositories/userRepository";
import verifiedIdentityRepository from "../repositories/verifiedIdentityRepository";
import { GATE0_IMAGE_LIMITS } from "./contentModerationGate0Service";
import type {
  CompleteDiscussionImageUploadResultDto,
  CreateDiscussionImageUploadRequestDto,
  CreateDiscussionImageUploadResultDto,
  DiscussionImageInputDto,
  DiscussionImageUploadErrorCode,
} from "../types/contracts";
import type {
  DiscussionMediaUploadRow,
  UserRow,
  VerifiedIdentityRow,
} from "../types/db";

export const DISCUSSION_MEDIA_BUCKET = "discussion-media" as const;
export const DISCUSSION_MEDIA_SIGNED_UPLOAD_TTL_SECONDS = 2 * 60 * 60;
export const DISCUSSION_MEDIA_MODERATION_URL_TTL_SECONDS = 60;
export const DISCUSSION_MEDIA_DISPLAY_URL_TTL_SECONDS = 10 * 60;

type StorageFileInfo = {
  size?: number | null;
  contentType?: string | null;
  content_type?: string | null;
  metadata?: Record<string, unknown> | null;
};

type StorageBucketLike = {
  createSignedUploadUrl: (
    path: string,
    options?: { upsert: boolean },
  ) => Promise<{
    data: { signedUrl: string; token: string; path: string } | null;
    error: unknown;
  }>;
  createSignedUrl: (
    path: string,
    expiresIn: number,
  ) => Promise<{ data: { signedUrl: string } | null; error: unknown }>;
  info: (
    path: string,
  ) => Promise<{ data: StorageFileInfo | null; error: unknown }>;
};

type DiscussionMediaServiceDependencies = {
  repositoryLike?: typeof discussionMediaRepository;
  userRepositoryLike?: Pick<typeof userRepository, "getById">;
  verifiedIdentityRepositoryLike?: Pick<typeof verifiedIdentityRepository, "getByUserId">;
  storageBucketFactory?: (bucket: string) => StorageBucketLike;
  now?: () => Date;
};

export type ResolvedDiscussionImage = {
  moderationImageUrl: string;
  storedImageUrl: string | null;
  storageBucket: string | null;
  storagePath: string | null;
  uploadId: string | null;
  mimeType: string;
  sizeBytes: number;
  altText: string | null;
};

export type DiscussionImageResolutionResult =
  | { ok: true; image: ResolvedDiscussionImage | null }
  | {
      ok: false;
      errorCode: "VALIDATION_FAILED" | "MODERATION_FAILED";
      message: string;
    };

const MIME_EXTENSION: Record<string, string> = {
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/webp": "webp",
  "image/gif": "gif",
};

const normalizeText = (value: unknown): string | null => {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
};

const normalizeMimeType = (value: unknown): string | null => {
  const normalized = normalizeText(value)?.toLowerCase().split(";")[0]?.trim();
  return normalized || null;
};

const normalizeSizeBytes = (value: unknown): number | null => {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
};

const sanitizeFileName = (value: unknown): string | null => {
  const normalized = normalizeText(value);
  if (!normalized) {
    return null;
  }

  return normalized.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 160) || null;
};

const validateUploadMetadata = (
  mimeType: string | null,
  sizeBytes: number | null,
):
  | { ok: true; mimeType: string; sizeBytes: number }
  | { ok: false; message: string } => {
  if (!mimeType || !sizeBytes) {
    return {
      ok: false,
      message: "Image file type and size are required.",
    };
  }

  if (!GATE0_IMAGE_LIMITS.allowedMimeTypes.includes(mimeType)) {
    return {
      ok: false,
      message: "Image file type is not supported.",
    };
  }

  if (sizeBytes > GATE0_IMAGE_LIMITS.maxImageBytes) {
    return {
      ok: false,
      message: "Image file size must be 5 MB or smaller.",
    };
  }

  return { ok: true, mimeType, sizeBytes };
};

const createUploadPath = (uploadId: string, mimeType: string): string => {
  const extension = MIME_EXTENSION[mimeType] || "bin";
  return `discussions/${uploadId.slice(0, 2)}/${uploadId}.${extension}`;
};

const createFailure = <T extends { success: boolean }>(
  errorCode: DiscussionImageUploadErrorCode,
  message: string,
): T =>
  ({
    success: false,
    errorCode,
    message,
  }) as unknown as T;

const storageErrorMessage = (error: unknown): string => {
  if (error instanceof Error && error.message) {
    return error.message;
  }

  return "Storage is not available right now.";
};

const isOwnedUpload = (
  upload: DiscussionMediaUploadRow | null,
  viewerUserId: string,
): upload is DiscussionMediaUploadRow =>
  Boolean(upload && upload.uploader_user_id === viewerUserId);

const readInfoMimeType = (info: StorageFileInfo | null): string | null =>
  normalizeMimeType(
    info?.contentType ||
      info?.content_type ||
      info?.metadata?.mimetype ||
      info?.metadata?.mimeType,
  );

const readInfoSize = (info: StorageFileInfo | null): number | null =>
  normalizeSizeBytes(info?.size || info?.metadata?.size);

export const createDiscussionMediaService = (
  dependencies: DiscussionMediaServiceDependencies = {},
) => {
  const repo = dependencies.repositoryLike || discussionMediaRepository;
  const userRepo = dependencies.userRepositoryLike || userRepository;
  const verifiedIdentityRepo =
    dependencies.verifiedIdentityRepositoryLike || verifiedIdentityRepository;

  const getStorageBucket = (bucket: string): StorageBucketLike => {
    if (dependencies.storageBucketFactory) {
      return dependencies.storageBucketFactory(bucket);
    }

    return requireSupabaseAdminClient().storage.from(bucket) as StorageBucketLike;
  };

  const requireVerifiedUploader = async (
    viewerUserId: string,
  ): Promise<
    | { ok: true; user: UserRow; verifiedIdentity: VerifiedIdentityRow }
    | {
        ok: false;
        errorCode: DiscussionImageUploadErrorCode;
        message: string;
      }
  > => {
    const [user, verifiedIdentity] = await Promise.all([
      userRepo.getById(viewerUserId),
      verifiedIdentityRepo.getByUserId(viewerUserId),
    ]);

    if (!user) {
      return {
        ok: false,
        errorCode: "USER_NOT_FOUND",
        message: "The current user could not be resolved.",
      };
    }

    if (!verifiedIdentity) {
      return {
        ok: false,
        errorCode: "VERIFIED_IDENTITY_REQUIRED",
        message: "A verified identity is required for discussion image uploads.",
      };
    }

    return { ok: true, user, verifiedIdentity };
  };

  const createSignedReadUrl = async (
    bucket: string,
    path: string,
    expiresInSeconds: number,
  ): Promise<string | null> => {
    const { data, error } = await getStorageBucket(bucket).createSignedUrl(
      path,
      expiresInSeconds,
    );
    if (error || !data?.signedUrl) {
      return null;
    }

    return data.signedUrl;
  };

  return {
    async createImageUpload(
      input: CreateDiscussionImageUploadRequestDto,
      viewerUserId: string,
    ): Promise<CreateDiscussionImageUploadResultDto> {
      const creator = await requireVerifiedUploader(viewerUserId);
      if (!creator.ok) {
        return createFailure<CreateDiscussionImageUploadResultDto>(
          creator.errorCode,
          creator.message,
        );
      }

      const metadata = validateUploadMetadata(
        normalizeMimeType(input.mimeType),
        normalizeSizeBytes(input.sizeBytes),
      );
      if (!metadata.ok) {
        return createFailure<CreateDiscussionImageUploadResultDto>(
          "VALIDATION_FAILED",
          metadata.message,
        );
      }

      const uploadId = randomUUID();
      const storagePath = createUploadPath(uploadId, metadata.mimeType);

      let signedUpload;
      try {
        signedUpload = await getStorageBucket(
          DISCUSSION_MEDIA_BUCKET,
        ).createSignedUploadUrl(storagePath, { upsert: false });
      } catch (error) {
        return createFailure<CreateDiscussionImageUploadResultDto>(
          "STORAGE_FAILED",
          storageErrorMessage(error),
        );
      }

      if (signedUpload.error || !signedUpload.data?.signedUrl) {
        return createFailure<CreateDiscussionImageUploadResultDto>(
          "STORAGE_FAILED",
          storageErrorMessage(signedUpload.error),
        );
      }

      await repo.insertUpload({
        id: uploadId,
        uploader_user_id: creator.user.id,
        storage_bucket: DISCUSSION_MEDIA_BUCKET,
        storage_path: storagePath,
        original_file_name: sanitizeFileName(input.fileName),
        mime_type: metadata.mimeType,
        size_bytes: metadata.sizeBytes,
        upload_status: "signed",
      });

      return {
        success: true,
        upload: {
          id: uploadId,
          uploadUrl: signedUpload.data.signedUrl,
          storageBucket: DISCUSSION_MEDIA_BUCKET,
          storagePath,
          mimeType: metadata.mimeType,
          sizeBytes: metadata.sizeBytes,
          expiresInSeconds: DISCUSSION_MEDIA_SIGNED_UPLOAD_TTL_SECONDS,
          maxSizeBytes: GATE0_IMAGE_LIMITS.maxImageBytes,
          allowedMimeTypes: [...GATE0_IMAGE_LIMITS.allowedMimeTypes],
        },
      };
    },

    async completeImageUpload(
      uploadId: string,
      viewerUserId: string,
    ): Promise<CompleteDiscussionImageUploadResultDto> {
      const creator = await requireVerifiedUploader(viewerUserId);
      if (!creator.ok) {
        return createFailure<CompleteDiscussionImageUploadResultDto>(
          creator.errorCode,
          creator.message,
        );
      }

      const upload = await repo.getUploadById(uploadId);
      if (!isOwnedUpload(upload, creator.user.id)) {
        return createFailure<CompleteDiscussionImageUploadResultDto>(
          "UPLOAD_NOT_FOUND",
          "The image upload could not be found.",
        );
      }

      let infoResult;
      try {
        infoResult = await getStorageBucket(upload.storage_bucket).info(
          upload.storage_path,
        );
      } catch (error) {
        return createFailure<CompleteDiscussionImageUploadResultDto>(
          "UPLOAD_NOT_READY",
          storageErrorMessage(error),
        );
      }

      if (infoResult.error || !infoResult.data) {
        return createFailure<CompleteDiscussionImageUploadResultDto>(
          "UPLOAD_NOT_READY",
          "The image file has not finished uploading.",
        );
      }

      const uploadedMimeType = readInfoMimeType(infoResult.data) || upload.mime_type;
      const uploadedSizeBytes = readInfoSize(infoResult.data) || upload.size_bytes;
      if (
        normalizeMimeType(uploadedMimeType) !== upload.mime_type ||
        uploadedSizeBytes !== upload.size_bytes
      ) {
        return createFailure<CompleteDiscussionImageUploadResultDto>(
          "VALIDATION_FAILED",
          "Uploaded image metadata does not match the requested upload.",
        );
      }

      const completed =
        upload.upload_status === "uploaded" || upload.upload_status === "attached"
          ? upload
          : await repo.markUploadCompleted(upload.id);

      return {
        success: true,
        image: {
          uploadId: completed.id,
          storageBucket: completed.storage_bucket,
          storagePath: completed.storage_path,
          mimeType: completed.mime_type,
          sizeBytes: completed.size_bytes,
        },
      };
    },

    async resolveUploadedImageForModeration(
      input: DiscussionImageInputDto,
      viewerUserId: string,
    ): Promise<DiscussionImageResolutionResult> {
      const uploadId = normalizeText(input.uploadId);
      const storageBucket = normalizeText(input.storageBucket);
      const storagePath = normalizeText(input.storagePath);

      if (!uploadId || !storageBucket || !storagePath) {
        return {
          ok: false,
          errorCode: "VALIDATION_FAILED",
          message: "Uploaded image reference is incomplete.",
        };
      }

      const upload = await repo.getUploadById(uploadId);
      if (
        !isOwnedUpload(upload, viewerUserId) ||
        upload.storage_bucket !== storageBucket ||
        upload.storage_path !== storagePath
      ) {
        return {
          ok: false,
          errorCode: "VALIDATION_FAILED",
          message: "Uploaded image reference is invalid.",
        };
      }

      if (upload.upload_status !== "uploaded") {
        return {
          ok: false,
          errorCode: "VALIDATION_FAILED",
          message: "Uploaded image has not been finalized.",
        };
      }

      const signedReadUrl = await createSignedReadUrl(
        upload.storage_bucket,
        upload.storage_path,
        DISCUSSION_MEDIA_MODERATION_URL_TTL_SECONDS,
      );
      if (!signedReadUrl) {
        return {
          ok: false,
          errorCode: "MODERATION_FAILED",
          message: "We could not prepare the uploaded image for moderation.",
        };
      }

      return {
        ok: true,
        image: {
          moderationImageUrl: signedReadUrl,
          storedImageUrl: null,
          storageBucket: upload.storage_bucket,
          storagePath: upload.storage_path,
          uploadId: upload.id,
          mimeType: upload.mime_type,
          sizeBytes: upload.size_bytes,
          altText: normalizeText(input.altText),
        },
      };
    },

    async createDisplayImageUrl(
      storageBucket: string | null,
      storagePath: string | null,
    ): Promise<string | null> {
      const bucket = normalizeText(storageBucket);
      const path = normalizeText(storagePath);
      if (!bucket || !path) {
        return null;
      }

      return createSignedReadUrl(
        bucket,
        path,
        DISCUSSION_MEDIA_DISPLAY_URL_TTL_SECONDS,
      );
    },

    async attachUploadToPost(
      uploadId: string | null,
      viewerUserId: string,
      postId: string,
    ): Promise<void> {
      const normalizedUploadId = normalizeText(uploadId);
      if (!normalizedUploadId) {
        return;
      }

      const upload = await repo.getUploadById(normalizedUploadId);
      if (!isOwnedUpload(upload, viewerUserId) || upload.upload_status !== "uploaded") {
        return;
      }

      await repo.attachUploadToPost(upload.id, postId);
    },
  };
};

export const discussionMediaService = createDiscussionMediaService();

export default discussionMediaService;
