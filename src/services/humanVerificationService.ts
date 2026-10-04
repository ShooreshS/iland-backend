import {
  createHash,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";

import appAttestationVerifier from "../auth/appAttestation";
import verifyCredentialSignature from "../auth/credentialSignature";
import {
  createOpaqueBearerToken,
  hashOpaqueBearerToken,
} from "../auth/tokens";
import env from "../config/env";
import { requireSupabaseAdminClient } from "../db/supabaseClient";
import authChallengeRepository from "../repositories/authChallengeRepository";
import humanVerificationRepository from "../repositories/humanVerificationRepository";
import type {
  HumanVerificationMediaKind,
  HumanVerificationMediaRow,
  HumanVerificationRequestRow,
} from "../types/db";
import authService from "./authService";
import { decryptPushToken, encryptPushToken, hashPushToken } from "./pushTokenCrypto";
import { sendApnsPush, sendFcmPush } from "./pushProviders";
import type { AdminContext } from "./adminModerationService";

export const HUMAN_VERIFICATION_MEDIA_BUCKET = "verification-review-media" as const;
export const HUMAN_VERIFICATION_REQUEST_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const HUMAN_VERIFICATION_UPLOAD_TTL_SECONDS = 2 * 60 * 60;
export const HUMAN_VERIFICATION_MAX_IMAGE_BYTES = 10 * 1024 * 1024;
export const HUMAN_VERIFICATION_MIN_IMAGE_EDGE = 113;
export const HUMAN_VERIFICATION_DECIDED_MEDIA_RETENTION_MS =
  7 * 24 * 60 * 60 * 1000;

type MediaInput = {
  kind: HumanVerificationMediaKind;
  mimeType: "image/jpeg";
  sizeBytes: number;
  width: number;
  height: number;
  sha256: string;
};

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
  info: (
    path: string,
  ) => Promise<{ data: StorageFileInfo | null; error: unknown }>;
  download: (
    path: string,
  ) => Promise<{ data: Blob | null; error: unknown }>;
  remove: (paths: string[]) => Promise<{ data: unknown; error: unknown }>;
};

type Dependencies = {
  repositoryLike?: typeof humanVerificationRepository;
  challengeRepositoryLike?: typeof authChallengeRepository;
  authServiceLike?: Pick<typeof authService, "issueChallenge">;
  storageBucketFactory?: (bucket: string) => StorageBucketLike;
  verifyCredentialSignatureFn?: typeof verifyCredentialSignature;
  verifyRegistrationAttestationFn?: typeof appAttestationVerifier.verifyRegistrationAttestation;
  now?: () => Date;
};

const normalizeLimit = (value?: number | null): number =>
  Math.min(Math.max(Number.isFinite(Number(value)) ? Number(value) : 50, 1), 100);

const isExpired = (request: HumanVerificationRequestRow, now: Date): boolean =>
  new Date(request.expires_at).getTime() <= now.getTime();

const safeAttestationRecord = (input: {
  provider: string;
  environment: string;
  attestationKeyId: string | null;
  attestationPublicKeyPem: string | null;
  appIdentifier: string | null;
  packageName: string | null;
  signingCertDigest: string | null;
  transitionalCryptoBypassUsed: boolean;
}) => ({
  provider: input.provider,
  environment: input.environment,
  attestationKeyId: input.attestationKeyId,
  attestationPublicKeyPem: input.attestationPublicKeyPem,
  appIdentifier: input.appIdentifier,
  packageName: input.packageName,
  signingCertDigest: input.signingCertDigest,
  transitionalCryptoBypassUsed: input.transitionalCryptoBypassUsed,
});

const requestDto = (request: HumanVerificationRequestRow) => ({
  id: request.id,
  status: request.status,
  documentType: request.document_type,
  similarity: request.similarity,
  threshold: request.comparison_threshold,
  model: request.comparison_model,
  livenessPassed: request.liveness_passed,
  gazePassed: request.gaze_passed,
  submittedAt: request.submitted_at,
  decidedAt: request.decided_at,
  expiresAt: request.expires_at,
  userMessage: request.user_message,
  createdAt: request.created_at,
  updatedAt: request.updated_at,
});

const mediaDto = (media: HumanVerificationMediaRow) => ({
  id: media.id,
  kind: media.kind,
  mimeType: media.mime_type,
  sizeBytes: media.size_bytes,
  width: media.width,
  height: media.height,
  uploadStatus: media.upload_status,
});

const tokenMatches = (request: HumanVerificationRequestRow, token: string): boolean => {
  const actual = Buffer.from(request.access_token_hash, "utf8");
  const expected = Buffer.from(hashOpaqueBearerToken(token), "utf8");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
};

const sha256 = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

const readJpegDimensions = (
  bytes: Uint8Array,
): { width: number; height: number } | null => {
  if (bytes.length < 11 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return null;
  const startOfFrameMarkers = new Set([
    0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7,
    0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf,
  ]);
  let offset = 2;
  while (offset + 8 < bytes.length) {
    while (offset < bytes.length && bytes[offset] === 0xff) offset += 1;
    if (offset >= bytes.length) break;
    const marker = bytes[offset];
    offset += 1;
    if (marker === 0xd8 || marker === 0xd9 || (marker >= 0xd0 && marker <= 0xd7)) {
      continue;
    }
    if (offset + 1 >= bytes.length) break;
    const length = (bytes[offset] << 8) | bytes[offset + 1];
    if (length < 2 || offset + length > bytes.length) break;
    if (startOfFrameMarkers.has(marker) && length >= 7) {
      return {
        height: (bytes[offset + 3] << 8) | bytes[offset + 4],
        width: (bytes[offset + 5] << 8) | bytes[offset + 6],
      };
    }
    offset += length;
  }
  return null;
};

const normalizeStorageMime = (info: StorageFileInfo | null): string | null => {
  const candidate =
    info?.contentType ||
    info?.content_type ||
    info?.metadata?.mimetype ||
    info?.metadata?.mimeType;
  return typeof candidate === "string"
    ? candidate.toLowerCase().split(";")[0]?.trim() || null
    : null;
};

const storageSize = (info: StorageFileInfo | null): number | null => {
  const value = Number(info?.size || info?.metadata?.size);
  return Number.isInteger(value) && value > 0 ? value : null;
};

const createStoragePath = (
  requestId: string,
  kind: HumanVerificationMediaKind,
): string => `reviews/${requestId.slice(0, 2)}/${requestId}/${kind}.jpg`;

const decisionCopy = (status: "approved" | "rejected", locale: string | null) => {
  const language = (locale || "en").toLowerCase().split(/[-_]/u)[0];
  const copy: Record<string, { approved: string; rejected: string }> = {
    en: {
      approved: "Your identity review was approved. Open Review user data to continue.",
      rejected: "Your identity review was rejected. Open Review user data for details.",
    },
    sv: {
      approved: "Din identitetsgranskning godkändes. Öppna Granska användardata för att fortsätta.",
      rejected: "Din identitetsgranskning avslogs. Öppna Granska användardata för mer information.",
    },
  };
  const selected = copy[language] || copy.en;
  return { title: "CivicOS", body: selected[status] };
};

export const createHumanVerificationService = (dependencies: Dependencies = {}) => {
  const repo = dependencies.repositoryLike || humanVerificationRepository;
  const challengeRepo = dependencies.challengeRepositoryLike || authChallengeRepository;
  const auth = dependencies.authServiceLike || authService;
  const verifySignature =
    dependencies.verifyCredentialSignatureFn || verifyCredentialSignature;
  const verifyAttestation =
    dependencies.verifyRegistrationAttestationFn ||
    appAttestationVerifier.verifyRegistrationAttestation;
  const now = dependencies.now || (() => new Date());

  const storageBucket = (
    name: string = HUMAN_VERIFICATION_MEDIA_BUCKET,
  ): StorageBucketLike =>
    dependencies.storageBucketFactory
      ? dependencies.storageBucketFactory(name)
      : (requireSupabaseAdminClient().storage.from(name) as StorageBucketLike);

  const requireReview = async (requestId: string, token: string) => {
    const request = await repo.getRequestById(requestId);
    if (!request || !tokenMatches(request, token)) {
      return null;
    }
    if (
      isExpired(request, now()) &&
      (request.status === "uploading" || request.status === "pending" || request.status === "approved")
    ) {
      return (
        (await repo.transitionRequest(request.id, request.status, "expired")) ||
        ({ ...request, status: "expired" } as HumanVerificationRequestRow)
      );
    }
    return request;
  };

  const sendDecisionPush = async (
    request: HumanVerificationRequestRow,
    status: "approved" | "rejected",
  ): Promise<void> => {
    const installation = await repo.getPushInstallation(request.id);
    if (!installation || installation.status !== "active") return;
    if (!env.notifications.tokenEncryptionKey) {
      await repo.recordPushDelivery(request.id, {
        status: "failed",
        error: "Push-token encryption is not configured.",
      });
      return;
    }

    try {
      const token = decryptPushToken(
        installation.token_ciphertext,
        env.notifications.tokenEncryptionKey,
      );
      const result = installation.provider === "apns"
        ? await sendApnsPush({
            token,
            environment: installation.provider_environment,
            ...decisionCopy(status, installation.locale),
            notificationId: request.id,
            eventType: `verification.review_${status}`,
            targetUrl: "com.shooresh.iland://settings/review-user-data",
          })
        : await sendFcmPush({
            token,
            environment: installation.provider_environment,
            ...decisionCopy(status, installation.locale),
            notificationId: request.id,
            eventType: `verification.review_${status}`,
            targetUrl: "com.shooresh.iland://settings/review-user-data",
          });
      await repo.recordPushDelivery(request.id, {
        status:
          result.outcome === "sent"
            ? "sent"
            : result.outcome === "invalid_token"
              ? "invalid"
              : "failed",
        error: result.errorMessage || result.errorCode || null,
      });
    } catch (error) {
      await repo.recordPushDelivery(request.id, {
        status: "failed",
        error: error instanceof Error ? error.message : "Push delivery failed.",
      });
    }
  };

  return {
    issueChallenge(input: {
      platform: "ios" | "android";
      credentialIdHint?: string | null;
    }) {
      return auth.issueChallenge({
        purpose: "human_verification",
        platform: input.platform,
        credentialIdHint: input.credentialIdHint ?? null,
      });
    },

    async createRequest(input: {
      challengeId: string;
      challenge: string;
      platform: "ios" | "android";
      credentialId: string;
      publicKeyPem: string;
      signature: string;
      appAttestation: Record<string, unknown>;
      documentType: string;
      comparison: { similarity: number; threshold: number; model?: string | null };
      livenessPassed: boolean;
      gazePassed?: boolean | null;
      media: MediaInput[];
    }) {
      const challenge = await challengeRepo.getById(input.challengeId);
      if (
        !challenge ||
        challenge.purpose !== "human_verification" ||
        challenge.platform !== input.platform ||
        challenge.consumed_at ||
        new Date(challenge.expires_at).getTime() <= now().getTime() ||
        challenge.challenge_hash !== hashOpaqueBearerToken(input.challenge) ||
        (challenge.credential_id_hint &&
          challenge.credential_id_hint !== input.credentialId)
      ) {
        return {
          success: false as const,
          errorCode: "INVALID_CHALLENGE",
          message: "The human-verification challenge is invalid or expired.",
        };
      }

      const signature = verifySignature({
        publicKeyPem: input.publicKeyPem,
        challengeId: input.challengeId,
        challenge: input.challenge,
        purpose: "human_verification",
        platform: input.platform,
        signature: input.signature,
      });
      if (!signature.success) return signature;

      const attestation = await verifyAttestation({
        platform: input.platform,
        appAttestation: input.appAttestation,
        challenge: input.challenge,
      });
      if (!attestation.success) return attestation;

      if (!input.livenessPassed || input.comparison.similarity >= input.comparison.threshold) {
        return {
          success: false as const,
          errorCode: "NOT_ELIGIBLE",
          message: "Human review is available only after passed liveness and a low face score.",
        };
      }

      const kinds = input.media.map((item) => item.kind).sort();
      if (
        kinds.length !== 2 ||
        kinds[0] !== "document_portrait" ||
        kinds[1] !== "live_face" ||
        input.media.some(
          (item) =>
            item.mimeType !== "image/jpeg" ||
            !Number.isInteger(item.sizeBytes) ||
            item.sizeBytes <= 0 ||
            item.sizeBytes > HUMAN_VERIFICATION_MAX_IMAGE_BYTES ||
            !Number.isInteger(item.width) ||
            !Number.isInteger(item.height) ||
            item.width < HUMAN_VERIFICATION_MIN_IMAGE_EDGE ||
            item.height < HUMAN_VERIFICATION_MIN_IMAGE_EDGE ||
            !/^[0-9a-f]{64}$/u.test(item.sha256),
        )
      ) {
        return {
          success: false as const,
          errorCode: "INVALID_MEDIA",
          message: "Two full-size normalized JPEG face crops are required.",
        };
      }

      const active = await repo.findActiveByCredentialId(input.credentialId);
      if (active && !isExpired(active, now())) {
        return {
          success: false as const,
          errorCode: "ACTIVE_REQUEST_EXISTS",
          message: "This device already has an active human-verification request.",
        };
      }
      if (active && isExpired(active, now())) {
        await repo.transitionRequest(active.id, active.status, "expired");
      }

      const requestId = randomUUID();
      const accessToken = createOpaqueBearerToken();
      const uploads = [] as Array<{
        input: MediaInput;
        path: string;
        signedUrl: string;
      }>;
      for (const media of input.media) {
        const path = createStoragePath(requestId, media.kind);
        const signed = await storageBucket().createSignedUploadUrl(path, {
          upsert: false,
        });
        if (signed.error || !signed.data?.signedUrl) {
          return {
            success: false as const,
            errorCode: "STORAGE_FAILED",
            message: "A secure face-image upload could not be prepared.",
          };
        }
        uploads.push({ input: media, path, signedUrl: signed.data.signedUrl });
      }

      const request = await repo.insertRequest({
        id: requestId,
        accessTokenHash: accessToken.tokenHash,
        deviceCredentialId: input.credentialId,
        devicePublicKeyPem: input.publicKeyPem,
        platform: input.platform,
        documentType: input.documentType,
        similarity: input.comparison.similarity,
        comparisonThreshold: input.comparison.threshold,
        comparisonModel: input.comparison.model ?? null,
        livenessPassed: input.livenessPassed,
        gazePassed: input.gazePassed ?? null,
        appAttestation: safeAttestationRecord(attestation),
        expiresAt: new Date(now().getTime() + HUMAN_VERIFICATION_REQUEST_TTL_MS).toISOString(),
      });

      const mediaRows = [] as HumanVerificationMediaRow[];
      for (const upload of uploads) {
        mediaRows.push(
          await repo.insertMedia({
            requestId,
            kind: upload.input.kind,
            storageBucket: HUMAN_VERIFICATION_MEDIA_BUCKET,
            storagePath: upload.path,
            mimeType: upload.input.mimeType,
            sizeBytes: upload.input.sizeBytes,
            width: upload.input.width,
            height: upload.input.height,
            sha256: upload.input.sha256,
          }),
        );
      }
      await challengeRepo.markConsumed(input.challengeId);

      return {
        success: true as const,
        request: requestDto(request),
        reviewToken: accessToken.token,
        uploads: mediaRows.map((row) => ({
          ...mediaDto(row),
          uploadUrl: uploads.find((item) => item.input.kind === row.kind)?.signedUrl,
          expiresInSeconds: HUMAN_VERIFICATION_UPLOAD_TTL_SECONDS,
        })),
      };
    },

    async completeRequest(requestId: string, token: string) {
      const request = await requireReview(requestId, token);
      if (!request) {
        return { success: false as const, errorCode: "NOT_FOUND" };
      }
      if (request.status !== "uploading") {
        return request.status === "pending"
          ? { success: true as const, request: requestDto(request) }
          : { success: false as const, errorCode: "NOT_UPLOADABLE" };
      }

      const mediaRows = await repo.listMedia(request.id);
      if (mediaRows.length !== 2) {
        return { success: false as const, errorCode: "MEDIA_NOT_READY" };
      }
      for (const media of mediaRows) {
        const bucket = storageBucket(media.storage_bucket);
        const [infoResult, downloadResult] = await Promise.all([
          bucket.info(media.storage_path),
          bucket.download(media.storage_path),
        ]);
        if (infoResult.error || !infoResult.data || downloadResult.error || !downloadResult.data) {
          return { success: false as const, errorCode: "MEDIA_NOT_READY" };
        }
        const bytes = new Uint8Array(await downloadResult.data.arrayBuffer());
        const actualMime = normalizeStorageMime(infoResult.data) || media.mime_type;
        const actualSize = storageSize(infoResult.data) || bytes.byteLength;
        const dimensions = readJpegDimensions(bytes);
        if (
          actualMime !== media.mime_type ||
          actualSize !== media.size_bytes ||
          bytes.byteLength !== media.size_bytes ||
          sha256(bytes) !== media.sha256 ||
          !dimensions ||
          dimensions.width !== media.width ||
          dimensions.height !== media.height ||
          dimensions.width < HUMAN_VERIFICATION_MIN_IMAGE_EDGE ||
          dimensions.height < HUMAN_VERIFICATION_MIN_IMAGE_EDGE
        ) {
          return {
            success: false as const,
            errorCode: "MEDIA_MISMATCH",
            message: "Uploaded face-image bytes do not match the signed request.",
          };
        }
        if (media.upload_status !== "uploaded") {
          await repo.markMediaUploaded(media.id);
        }
      }

      const submitted = await repo.transitionRequest(request.id, "uploading", "pending", {
        submitted_at: now().toISOString(),
      });
      return submitted
        ? { success: true as const, request: requestDto(submitted) }
        : { success: false as const, errorCode: "CONFLICT" };
    },

    async refreshUploadUrls(requestId: string, token: string) {
      const request = await requireReview(requestId, token);
      if (!request) return { success: false as const, errorCode: "NOT_FOUND" };
      if (request.status !== "uploading") {
        return { success: false as const, errorCode: "NOT_UPLOADABLE" };
      }
      const media = await repo.listMedia(request.id);
      if (media.length !== 2) {
        return { success: false as const, errorCode: "MEDIA_NOT_READY" };
      }
      const uploads = [];
      for (const item of media) {
        const signed = await storageBucket(item.storage_bucket).createSignedUploadUrl(
          item.storage_path,
          { upsert: true },
        );
        if (signed.error || !signed.data?.signedUrl) {
          return { success: false as const, errorCode: "STORAGE_FAILED" };
        }
        uploads.push({
          ...mediaDto(item),
          uploadUrl: signed.data.signedUrl,
          expiresInSeconds: HUMAN_VERIFICATION_UPLOAD_TTL_SECONDS,
        });
      }
      return { success: true as const, uploads };
    },

    async getRequest(requestId: string, token: string) {
      const request = await requireReview(requestId, token);
      return request
        ? {
            success: true as const,
            request: requestDto(request),
            media: (await repo.listMedia(request.id)).map(mediaDto),
          }
        : { success: false as const, errorCode: "NOT_FOUND" };
    },

    async cancelRequest(requestId: string, token: string) {
      const request = await requireReview(requestId, token);
      if (!request) return { success: false as const, errorCode: "NOT_FOUND" };
      if (request.status !== "uploading" && request.status !== "pending") {
        return { success: false as const, errorCode: "NOT_CANCELLABLE" };
      }
      const cancelled = await repo.transitionRequest(
        request.id,
        request.status,
        "cancelled",
      );
      if (!cancelled) return { success: false as const, errorCode: "CONFLICT" };
      const media = await repo.listMedia(request.id);
      await Promise.all(
        media.map((item) =>
          storageBucket(item.storage_bucket).remove([item.storage_path]).catch(() => ({
            data: null,
            error: null,
          })),
        ),
      );
      return { success: true as const, request: requestDto(cancelled) };
    },

    async registerPushInstallation(requestId: string, token: string, input: {
      platform: "ios" | "android";
      provider: "apns" | "fcm";
      providerEnvironment: "sandbox" | "production";
      token: string;
      locale?: string | null;
    }) {
      const request = await requireReview(requestId, token);
      if (!request) return { success: false as const, errorCode: "NOT_FOUND" };
      if (!env.notifications.tokenEncryptionKey) {
        return { success: false as const, errorCode: "PUSH_NOT_CONFIGURED" };
      }
      if (request.platform !== input.platform) {
        return { success: false as const, errorCode: "PLATFORM_MISMATCH" };
      }
      await repo.upsertPushInstallation({
        requestId,
        platform: input.platform,
        provider: input.provider,
        providerEnvironment: input.providerEnvironment,
        tokenCiphertext: encryptPushToken(input.token, env.notifications.tokenEncryptionKey),
        tokenHash: hashPushToken(input.token),
        locale: input.locale ?? null,
      });
      return { success: true as const };
    },

    async listAdminQueue(limit?: number | null) {
      const rows = await repo.listPending(normalizeLimit(limit));
      const current = now();
      const active = [];
      for (const row of rows) {
        if (isExpired(row, current)) {
          await repo.transitionRequest(row.id, "pending", "expired");
        } else {
          active.push(row);
        }
      }
      return active.map(requestDto);
    },

    async getAdminDetail(requestId: string) {
      const request = await repo.getRequestById(requestId);
      if (!request) return null;
      return {
        request: requestDto(request),
        media: (await repo.listMedia(request.id)).map(mediaDto),
        actions: await repo.listReviewActions(request.id),
      };
    },

    async getAdminMedia(requestId: string, kind: HumanVerificationMediaKind) {
      const request = await repo.getRequestById(requestId);
      if (!request) return null;
      const media = (await repo.listMedia(request.id)).find(
        (candidate) => candidate.kind === kind && candidate.upload_status === "uploaded",
      );
      if (!media) return null;
      const download = await storageBucket(media.storage_bucket).download(media.storage_path);
      if (download.error || !download.data) return null;
      return {
        bytes: new Uint8Array(await download.data.arrayBuffer()),
        mimeType: media.mime_type,
      };
    },

    async applyAdminDecision(input: {
      admin: AdminContext;
      requestId: string;
      action: "approve" | "reject";
      internalNote?: string | null;
      userMessage?: string | null;
    }) {
      if (input.admin.reviewer.role === "viewer") {
        return { success: false as const, errorCode: "FORBIDDEN" };
      }
      if (input.action === "reject" && !input.userMessage?.trim()) {
        return { success: false as const, errorCode: "USER_MESSAGE_REQUIRED" };
      }
      const request = await repo.getRequestById(input.requestId);
      if (!request) return { success: false as const, errorCode: "NOT_FOUND" };
      if (isExpired(request, now())) {
        if (request.status === "pending") {
          await repo.transitionRequest(request.id, "pending", "expired");
        }
        return { success: false as const, errorCode: "NOT_REVIEWABLE" };
      }
      if (request.status !== "pending") {
        return { success: false as const, errorCode: "NOT_REVIEWABLE" };
      }
      const nextStatus = input.action === "approve" ? "approved" : "rejected";
      const decided = await repo.transitionRequest(request.id, "pending", nextStatus, {
        reviewer_verified_identity_id: input.admin.verifiedIdentity.id,
        reviewer_user_id: input.admin.user.id,
        user_message: input.userMessage?.trim() || null,
        internal_note: input.internalNote?.trim() || null,
        decided_at: now().toISOString(),
      });
      if (!decided) return { success: false as const, errorCode: "NOT_REVIEWABLE" };
      const action = await repo.insertReviewAction({
        requestId: request.id,
        reviewerVerifiedIdentityId: input.admin.verifiedIdentity.id,
        reviewerUserId: input.admin.user.id,
        action: input.action,
        previousStatus: "pending",
        newStatus: nextStatus,
        internalNote: input.internalNote?.trim() || null,
        userMessage: input.userMessage?.trim() || null,
      });
      await sendDecisionPush(decided, nextStatus).catch((error) => {
        console.error("[humanVerification] decision push failed", {
          requestId: decided.id,
          message: error instanceof Error ? error.message : "Unknown push failure",
        });
      });
      return { success: true as const, request: requestDto(decided), action };
    },

    async cleanupExpiredAndRetainedMedia() {
      const current = now();
      const overdue = await repo.listOverdueActive(current.toISOString(), 100);
      for (const request of overdue) {
        await repo.transitionRequest(request.id, request.status, "expired");
      }
      const cutoff = new Date(
        current.getTime() - HUMAN_VERIFICATION_DECIDED_MEDIA_RETENTION_MS,
      ).toISOString();
      const candidates = await repo.listMediaCleanupCandidates(cutoff, 100);
      let deleted = 0;
      for (const request of candidates) {
        const media = await repo.listMedia(request.id);
        for (const item of media) {
          if (item.upload_status === "deleted") continue;
          const result = await storageBucket(item.storage_bucket).remove([
            item.storage_path,
          ]);
          if (!result.error) {
            await repo.markMediaDeleted(item.id);
            deleted += 1;
          }
        }
      }
      return { expired: overdue.length, deleted };
    },
  };
};

export const humanVerificationService = createHumanVerificationService();
export default humanVerificationService;
