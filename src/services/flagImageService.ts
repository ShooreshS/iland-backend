import { randomUUID } from "node:crypto";
import { Buffer } from "node:buffer";
import { requireSupabaseAdminClient } from "../db/supabaseClient";
import flagImageRepository from "../repositories/flagImageRepository";
import userRepository from "../repositories/userRepository";
import type {
  CompleteFlagImageUploadResultDto,
  CreateFlagImageUploadResultDto,
  DeleteFlagImageResultDto,
  FlagImageDto,
  FlagImageErrorCode,
} from "../types/contracts";
import type { FlagImageRow } from "../types/db";

export const FLAG_IMAGE_BUCKET = "flag-images" as const;
export const FLAG_IMAGE_MAX_BYTES = 5 * 1024 * 1024;
export const FLAG_IMAGE_SIGNED_UPLOAD_TTL_SECONDS = 2 * 60 * 60;
export const FLAG_IMAGE_DISPLAY_URL_TTL_SECONDS = 60 * 60;
export const FLAG_IMAGE_MIN_DIMENSION = 20;
export const FLAG_IMAGE_MAX_DIMENSION = 512;
export const FLAG_IMAGE_MAX_ASPECT_RATIO = 10;

const ALLOWED_MIME_TYPES = new Set(["image/jpeg", "image/png", "image/webp"]);
const MIME_EXTENSION: Record<string, string> = {
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/webp": "webp",
};

type StorageFileInfo = {
  size?: number | string | null;
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
  info: (path: string) => Promise<{ data: StorageFileInfo | null; error: unknown }>;
  download: (path: string) => Promise<{ data: Blob | null; error: unknown }>;
  remove: (paths: string[]) => Promise<{ data: unknown; error: unknown }>;
};

type FlagImageServiceDependencies = {
  repositoryLike?: typeof flagImageRepository;
  userRepositoryLike?: Pick<
    typeof userRepository,
    "getById" | "updateSelectedFlagImageId"
  >;
  storageBucketFactory?: (bucket: string) => StorageBucketLike;
};

export type CreateFlagImageUploadInput = {
  name: string;
  fileName?: string | null;
  mimeType: string;
  sizeBytes: number;
  width: number;
  height: number;
};

const normalizeText = (value: unknown): string | null => {
  if (typeof value !== "string") {
    return null;
  }
  const normalized = value.trim();
  return normalized.length > 0 ? normalized : null;
};

const normalizeMimeType = (value: unknown): string | null =>
  normalizeText(value)?.toLowerCase().split(";")[0]?.trim() || null;

const normalizePositiveInteger = (value: unknown): number | null => {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
};

const sanitizeFileName = (value: unknown): string | null => {
  const normalized = normalizeText(value);
  return normalized?.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 160) || null;
};

const createFailure = <T extends { success: boolean }>(
  errorCode: FlagImageErrorCode,
  message: string,
): T => ({ success: false, errorCode, message }) as unknown as T;

const validateDimensions = (
  width: number | null,
  height: number | null,
): { ok: true; width: number; height: number } | { ok: false; message: string } => {
  if (!width || !height) {
    return { ok: false, message: "Flag image dimensions are required." };
  }
  if (
    width < FLAG_IMAGE_MIN_DIMENSION ||
    height < FLAG_IMAGE_MIN_DIMENSION ||
    width > FLAG_IMAGE_MAX_DIMENSION ||
    height > FLAG_IMAGE_MAX_DIMENSION
  ) {
    return {
      ok: false,
      message: "Flag images must fit between 20×20 and 512×512 pixels.",
    };
  }
  const ratio = width / height;
  if (ratio > FLAG_IMAGE_MAX_ASPECT_RATIO || ratio < 1 / FLAG_IMAGE_MAX_ASPECT_RATIO) {
    return {
      ok: false,
      message: "Flag image aspect ratio must be between 10:1 and 1:10.",
    };
  }
  return { ok: true, width, height };
};

const parsePngDimensions = (bytes: Buffer) => {
  if (
    bytes.length >= 24 &&
    bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))
  ) {
    return { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) };
  }
  return null;
};

const JPEG_SOF_MARKERS = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);

const parseJpegDimensions = (bytes: Buffer) => {
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) {
    return null;
  }

  let offset = 2;
  while (offset + 8 < bytes.length) {
    if (bytes[offset] !== 0xff) {
      offset += 1;
      continue;
    }
    while (offset < bytes.length && bytes[offset] === 0xff) {
      offset += 1;
    }
    const marker = bytes[offset];
    offset += 1;
    if (marker === 0xd9 || marker === 0xda || offset + 2 > bytes.length) {
      break;
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      continue;
    }
    const segmentLength = bytes.readUInt16BE(offset);
    if (segmentLength < 2 || offset + segmentLength > bytes.length) {
      break;
    }
    if (JPEG_SOF_MARKERS.has(marker) && segmentLength >= 7) {
      return {
        width: bytes.readUInt16BE(offset + 5),
        height: bytes.readUInt16BE(offset + 3),
      };
    }
    offset += segmentLength;
  }
  return null;
};

const readUInt24LE = (bytes: Buffer, offset: number): number =>
  bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16);

const parseWebpDimensions = (bytes: Buffer) => {
  if (
    bytes.length < 30 ||
    bytes.toString("ascii", 0, 4) !== "RIFF" ||
    bytes.toString("ascii", 8, 12) !== "WEBP"
  ) {
    return null;
  }

  const chunk = bytes.toString("ascii", 12, 16);
  if (chunk === "VP8X") {
    return {
      width: readUInt24LE(bytes, 24) + 1,
      height: readUInt24LE(bytes, 27) + 1,
    };
  }
  if (chunk === "VP8L" && bytes.length >= 25 && bytes[20] === 0x2f) {
    return {
      width: 1 + bytes[21] + ((bytes[22] & 0x3f) << 8),
      height: 1 + ((bytes[22] & 0xc0) >> 6) + (bytes[23] << 2) + ((bytes[24] & 0x0f) << 10),
    };
  }
  if (
    chunk === "VP8 " &&
    bytes.length >= 30 &&
    bytes[23] === 0x9d &&
    bytes[24] === 0x01 &&
    bytes[25] === 0x2a
  ) {
    return {
      width: bytes.readUInt16LE(26) & 0x3fff,
      height: bytes.readUInt16LE(28) & 0x3fff,
    };
  }
  return null;
};

export const readFlagImageDimensions = (
  bytes: Uint8Array,
  mimeType: string,
): { width: number; height: number } | null => {
  const buffer = Buffer.from(bytes);
  if (mimeType === "image/png") return parsePngDimensions(buffer);
  if (mimeType === "image/jpeg") return parseJpegDimensions(buffer);
  if (mimeType === "image/webp") return parseWebpDimensions(buffer);
  return null;
};

const storageErrorMessage = (error: unknown): string =>
  error instanceof Error && error.message
    ? error.message
    : "Flag image storage is not available right now.";

export const createFlagImageService = (
  dependencies: FlagImageServiceDependencies = {},
) => {
  const repository = dependencies.repositoryLike || flagImageRepository;
  const users = dependencies.userRepositoryLike || userRepository;
  const getStorageBucket = (bucket: string): StorageBucketLike =>
    dependencies.storageBucketFactory
      ? dependencies.storageBucketFactory(bucket)
      : (requireSupabaseAdminClient().storage.from(bucket) as StorageBucketLike);

  const mapRowToDto = async (
    row: FlagImageRow,
    viewerUserId?: string | null,
  ): Promise<FlagImageDto | null> => {
    const { data, error } = await getStorageBucket(row.storage_bucket).createSignedUrl(
      row.storage_path,
      FLAG_IMAGE_DISPLAY_URL_TTL_SECONDS,
    );
    if (error || !data?.signedUrl) {
      return null;
    }
    return {
      id: row.id,
      name: row.name,
      viewerIsCreator: Boolean(viewerUserId && row.creator_user_id === viewerUserId),
      imageUrl: data.signedUrl,
      mimeType: row.mime_type,
      sizeBytes: row.size_bytes,
      width: row.width,
      height: row.height,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  };

  return {
    async listActive(viewerUserId?: string | null): Promise<FlagImageDto[]> {
      const rows = await repository.listActive();
      const mapped = await Promise.all(rows.map((row) => mapRowToDto(row, viewerUserId)));
      return mapped.filter((value): value is FlagImageDto => Boolean(value));
    },

    async getActiveById(
      flagImageId: string | null | undefined,
      viewerUserId?: string | null,
    ): Promise<FlagImageDto | null> {
      const normalizedId = normalizeText(flagImageId);
      if (!normalizedId) return null;
      const row = await repository.getById(normalizedId);
      if (!row || row.upload_status !== "active") return null;
      return mapRowToDto(row, viewerUserId);
    },

    async createUpload(
      input: CreateFlagImageUploadInput,
      viewerUserId: string,
    ): Promise<CreateFlagImageUploadResultDto> {
      const user = await users.getById(viewerUserId);
      if (!user) {
        return createFailure("USER_NOT_FOUND", "The current user could not be resolved.");
      }

      const name = normalizeText(input.name);
      const mimeType = normalizeMimeType(input.mimeType);
      const sizeBytes = normalizePositiveInteger(input.sizeBytes);
      const dimensions = validateDimensions(
        normalizePositiveInteger(input.width),
        normalizePositiveInteger(input.height),
      );
      if (!name || name.length > 80) {
        return createFailure("VALIDATION_FAILED", "A flag name of up to 80 characters is required.");
      }
      if (!mimeType || !ALLOWED_MIME_TYPES.has(mimeType)) {
        return createFailure("VALIDATION_FAILED", "Flag image file type is not supported.");
      }
      if (!sizeBytes || sizeBytes > FLAG_IMAGE_MAX_BYTES) {
        return createFailure("VALIDATION_FAILED", "Flag images must be 5 MB or smaller.");
      }
      if (!dimensions.ok) {
        return createFailure("VALIDATION_FAILED", dimensions.message);
      }

      const id = randomUUID();
      const storagePath = `flags/${id.slice(0, 2)}/${id}.${MIME_EXTENSION[mimeType]}`;
      let signedUpload;
      try {
        signedUpload = await getStorageBucket(FLAG_IMAGE_BUCKET).createSignedUploadUrl(
          storagePath,
          { upsert: false },
        );
      } catch (error) {
        return createFailure("STORAGE_FAILED", storageErrorMessage(error));
      }
      if (signedUpload.error || !signedUpload.data?.signedUrl) {
        return createFailure("STORAGE_FAILED", storageErrorMessage(signedUpload.error));
      }

      await repository.insert({
        id,
        name,
        creator_user_id: user.id,
        storage_bucket: FLAG_IMAGE_BUCKET,
        storage_path: storagePath,
        original_file_name: sanitizeFileName(input.fileName),
        mime_type: mimeType,
        size_bytes: sizeBytes,
        width: dimensions.width,
        height: dimensions.height,
        upload_status: "signed",
      });

      return {
        success: true,
        upload: {
          id,
          uploadUrl: signedUpload.data.signedUrl,
          storageBucket: FLAG_IMAGE_BUCKET,
          storagePath,
          mimeType,
          sizeBytes,
          width: dimensions.width,
          height: dimensions.height,
          expiresInSeconds: FLAG_IMAGE_SIGNED_UPLOAD_TTL_SECONDS,
          maxSizeBytes: FLAG_IMAGE_MAX_BYTES,
        },
      };
    },

    async completeUpload(
      flagImageId: string,
      viewerUserId: string,
    ): Promise<CompleteFlagImageUploadResultDto> {
      const row = await repository.getById(flagImageId);
      if (!row || row.creator_user_id !== viewerUserId) {
        return createFailure("FLAG_IMAGE_NOT_FOUND", "The flag image upload could not be found.");
      }
      if (row.upload_status === "active") {
        const existing = await mapRowToDto(row, viewerUserId);
        return existing
          ? { success: true, flagImage: existing }
          : createFailure("STORAGE_FAILED", "The flag image could not be displayed.");
      }

      const bucket = getStorageBucket(row.storage_bucket);
      const [infoResult, downloadResult] = await Promise.all([
        bucket.info(row.storage_path),
        bucket.download(row.storage_path),
      ]);
      if (infoResult.error || !infoResult.data || downloadResult.error || !downloadResult.data) {
        return createFailure("UPLOAD_NOT_READY", "The flag image has not finished uploading.");
      }

      const uploadedSize = normalizePositiveInteger(
        infoResult.data.size || infoResult.data.metadata?.size,
      );
      const uploadedMime = normalizeMimeType(
        infoResult.data.contentType ||
          infoResult.data.content_type ||
          infoResult.data.metadata?.mimetype ||
          infoResult.data.metadata?.mimeType,
      );
      if ((uploadedSize && uploadedSize !== row.size_bytes) || (uploadedMime && uploadedMime !== row.mime_type)) {
        return createFailure("VALIDATION_FAILED", "Uploaded flag image metadata does not match the request.");
      }

      const bytes = new Uint8Array(await downloadResult.data.arrayBuffer());
      if (bytes.byteLength !== row.size_bytes) {
        return createFailure("VALIDATION_FAILED", "Uploaded flag image size does not match the request.");
      }
      const actualDimensions = readFlagImageDimensions(bytes, row.mime_type);
      const checkedDimensions = validateDimensions(
        actualDimensions?.width || null,
        actualDimensions?.height || null,
      );
      if (
        !checkedDimensions.ok ||
        checkedDimensions.width !== row.width ||
        checkedDimensions.height !== row.height
      ) {
        return createFailure("VALIDATION_FAILED", "Uploaded flag image dimensions are invalid.");
      }

      const completed = await repository.markActive(row.id);
      const flagImage = await mapRowToDto(completed, viewerUserId);
      return flagImage
        ? { success: true, flagImage }
        : createFailure("STORAGE_FAILED", "The flag image could not be displayed.");
    },

    async deleteImage(
      flagImageId: string,
      viewerUserId: string,
    ): Promise<DeleteFlagImageResultDto> {
      const row = await repository.getById(flagImageId);
      if (!row || row.upload_status !== "active") {
        return createFailure("FLAG_IMAGE_NOT_FOUND", "The flag image could not be found.");
      }
      if (row.creator_user_id !== viewerUserId) {
        return createFailure("NOT_FLAG_IMAGE_CREATOR", "Only the flag creator can delete it.");
      }
      if ((await repository.countSelections(row.id)) > 0) {
        return createFailure(
          "FLAG_IMAGE_IN_USE",
          "This flag cannot be deleted because at least one user has selected it.",
        );
      }

      try {
        const deleted = await repository.deleteById(row.id);
        if (!deleted) {
          return createFailure("FLAG_IMAGE_NOT_FOUND", "The flag image could not be found.");
        }
      } catch (error) {
        const code = typeof error === "object" && error && "code" in error
          ? String((error as { code?: unknown }).code || "")
          : "";
        if (code === "23503") {
          return createFailure(
            "FLAG_IMAGE_IN_USE",
            "This flag cannot be deleted because at least one user has selected it.",
          );
        }
        throw error;
      }

      // The database row is deleted first so the foreign-key restriction is
      // the final authority. A failed storage cleanup can only leave an orphan,
      // never delete an image that another user selected.
      try {
        await getStorageBucket(row.storage_bucket).remove([row.storage_path]);
      } catch {
        // The deleted database row can no longer mint a read URL. Storage
        // orphan cleanup can safely be retried out of band.
      }
      return { success: true, deletedFlagImageId: row.id };
    },
  };
};

export const flagImageService = createFlagImageService();

export default flagImageService;
