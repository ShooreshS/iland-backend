import env from "../config/env";
import userRepository from "../repositories/userRepository";
import verifiedIdentityRepository from "../repositories/verifiedIdentityRepository";
import type {
  BindVerifiedIdentityErrorCode,
  BindVerifiedIdentityRequestDto,
  BindVerifiedIdentityResultDto,
  BindVerifiedIdentityStatus,
  VerifiedIdentityBindingDto,
} from "../types/contracts";
import type { UserRow, VerifiedIdentityRow } from "../types/db";
import {
  deriveCanonicalIdentityKey,
  isSupportedNormalizationVersion,
  isValidNidnh,
  normalizeNidnh,
} from "./verifiedIdentityDerivationService";

const DEFAULT_VERIFICATION_METHOD = "passport_nfc";
const ONBOARDING_STATUS_UPGRADE_SET = new Set([
  "not_started",
  "passport_started",
  "passport_completed",
]);

export type BindVerifiedIdentityForViewerInput = {
  viewerUserId: string;
  nidnh: string;
  normalizationVersion: number;
  verificationMethod?: BindVerifiedIdentityRequestDto["verificationMethod"];
};

type VerifiedIdentityBindDependencies = {
  pepper: string;
  now: () => string;
  userRepo: Pick<
    typeof userRepository,
    "getById" | "updateVerificationState"
  >;
  verifiedIdentityRepo: Pick<
    typeof verifiedIdentityRepository,
    "getByUserId" | "getByCanonicalIdentityKey" | "insert"
  >;
};

const isUniqueViolation = (error: unknown): boolean => {
  if (!error || typeof error !== "object") {
    return false;
  }

  return (error as { code?: unknown }).code === "23505";
};

const toBindingDto = (row: VerifiedIdentityRow): VerifiedIdentityBindingDto => ({
  id: row.id,
  userId: row.user_id,
  normalizationVersion: row.normalization_version,
  verificationMethod: row.verification_method,
  verifiedAt: row.verified_at,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

const buildFailure = (
  errorCode: BindVerifiedIdentityErrorCode,
  message: string,
): BindVerifiedIdentityResultDto => ({
  success: false,
  errorCode,
  message,
});

const buildSuccess = (
  row: VerifiedIdentityRow,
  status: BindVerifiedIdentityStatus,
): BindVerifiedIdentityResultDto => ({
  success: true,
  status,
  authoritativeUserId: row.user_id,
  verifiedIdentity: toBindingDto(row),
});

const resolveVerificationMethod = (
  value: unknown,
): BindVerifiedIdentityRequestDto["verificationMethod"] | null => {
  if (value === undefined || value === null) {
    return DEFAULT_VERIFICATION_METHOD;
  }

  return value === "passport_nfc" ? value : null;
};

const normalizeViewerUserId = (value: unknown): string | null => {
  if (typeof value !== "string") {
    return null;
  }

  const normalized = value.trim();
  return normalized.length > 0 ? normalized : null;
};

const buildUserVerificationPatch = (
  user: UserRow,
): { verificationLevel?: string; onboardingStatus?: string } | null => {
  const verificationLevel =
    user.verification_level === "anonymous" ||
    user.verification_level === "passport_verified"
      ? "nid_verified"
      : user.verification_level;

  const onboardingStatus = ONBOARDING_STATUS_UPGRADE_SET.has(user.onboarding_status)
    ? "identity_pending"
    : user.onboarding_status;

  const patch: { verificationLevel?: string; onboardingStatus?: string } = {};
  if (verificationLevel !== user.verification_level) {
    patch.verificationLevel = verificationLevel;
  }

  if (onboardingStatus !== user.onboarding_status) {
    patch.onboardingStatus = onboardingStatus;
  }

  return Object.keys(patch).length > 0 ? patch : null;
};

const maybeUpgradeUserVerificationState = async (
  user: UserRow,
  deps: VerifiedIdentityBindDependencies,
): Promise<void> => {
  const patch = buildUserVerificationPatch(user);
  if (!patch) {
    return;
  }

  await deps.userRepo.updateVerificationState(user.id, patch);
};

const tryResolveAfterUniqueViolation = async (
  viewerUserId: string,
  canonicalIdentityKey: string,
  deps: VerifiedIdentityBindDependencies,
): Promise<BindVerifiedIdentityResultDto | null> => {
  const [byCanonical, byUser] = await Promise.all([
    deps.verifiedIdentityRepo.getByCanonicalIdentityKey(canonicalIdentityKey),
    deps.verifiedIdentityRepo.getByUserId(viewerUserId),
  ]);

  if (byCanonical) {
    if (byCanonical.user_id !== viewerUserId) {
      const authoritativeUser = await deps.userRepo.getById(byCanonical.user_id);
      if (authoritativeUser) {
        await maybeUpgradeUserVerificationState(authoritativeUser, deps);
      }

      return buildSuccess(byCanonical, "recovered_existing_user");
    }

    return buildSuccess(byCanonical, "bound_existing_same_user");
  }

  if (byUser) {
    if (byUser.canonical_identity_key !== canonicalIdentityKey) {
      return buildFailure(
        "IDENTITY_ALREADY_BOUND",
        "This user is already linked to a different verified identity.",
      );
    }

    return buildSuccess(byUser, "bound_existing_same_user");
  }

  return null;
};

export const createVerifiedIdentityBindService = (
  overrides: Partial<VerifiedIdentityBindDependencies> = {},
) => {
  const deps: VerifiedIdentityBindDependencies = {
    pepper: overrides.pepper ?? env.verifiedIdentity.pepper,
    now: overrides.now ?? (() => new Date().toISOString()),
    userRepo: overrides.userRepo ?? userRepository,
    verifiedIdentityRepo:
      overrides.verifiedIdentityRepo ?? verifiedIdentityRepository,
  };

  return {
    async bindVerifiedIdentityForViewer(
      input: BindVerifiedIdentityForViewerInput,
    ): Promise<BindVerifiedIdentityResultDto> {
      const viewerUserId = normalizeViewerUserId(input.viewerUserId);
      if (!viewerUserId) {
        return buildFailure("INVALID_INPUT", "A viewer user id is required.");
      }

      if (!isSupportedNormalizationVersion(input.normalizationVersion)) {
        return buildFailure(
          "INVALID_INPUT",
          "Unsupported identity normalization version.",
        );
      }

      const normalizedNidnh = normalizeNidnh(input.nidnh);
      if (!normalizedNidnh || !isValidNidnh(normalizedNidnh)) {
        return buildFailure(
          "INVALID_INPUT",
          "Invalid nidnh. Expected a SHA-512 hex digest.",
        );
      }

      const verificationMethod = resolveVerificationMethod(input.verificationMethod);
      if (!verificationMethod) {
        return buildFailure(
          "INVALID_INPUT",
          "Unsupported verification method for verified identity binding.",
        );
      }

      const viewer = await deps.userRepo.getById(viewerUserId);
      if (!viewer) {
        return buildFailure("USER_NOT_FOUND", "The current user could not be resolved.");
      }

      const canonicalIdentityKey = deriveCanonicalIdentityKey({
        nidnh: normalizedNidnh,
        pepper: deps.pepper,
      });

      const existingByCanonical =
        await deps.verifiedIdentityRepo.getByCanonicalIdentityKey(canonicalIdentityKey);

      if (existingByCanonical) {
        if (existingByCanonical.user_id !== viewerUserId) {
          const authoritativeUser = await deps.userRepo.getById(
            existingByCanonical.user_id,
          );
          if (authoritativeUser) {
            await maybeUpgradeUserVerificationState(authoritativeUser, deps);
          }

          return buildSuccess(existingByCanonical, "recovered_existing_user");
        }

        await maybeUpgradeUserVerificationState(viewer, deps);
        return buildSuccess(existingByCanonical, "bound_existing_same_user");
      }

      const existingByUser = await deps.verifiedIdentityRepo.getByUserId(viewerUserId);
      if (existingByUser) {
        if (existingByUser.canonical_identity_key !== canonicalIdentityKey) {
          return buildFailure(
            "IDENTITY_ALREADY_BOUND",
            "This user is already linked to a different verified identity.",
          );
        }

        await maybeUpgradeUserVerificationState(viewer, deps);
        return buildSuccess(existingByUser, "bound_existing_same_user");
      }

      const verifiedAt = deps.now();

      try {
        const inserted = await deps.verifiedIdentityRepo.insert({
          user_id: viewerUserId,
          canonical_identity_key: canonicalIdentityKey,
          normalization_version: input.normalizationVersion,
          verification_method: verificationMethod,
          verified_at: verifiedAt,
        });

        await maybeUpgradeUserVerificationState(viewer, deps);
        return buildSuccess(inserted, "bound_new");
      } catch (error) {
        if (!isUniqueViolation(error)) {
          throw error;
        }

        const resolved = await tryResolveAfterUniqueViolation(
          viewerUserId,
          canonicalIdentityKey,
          deps,
        );
        if (resolved) {
          return resolved;
        }

        throw error;
      }
    },
  };
};

export const verifiedIdentityBindService = createVerifiedIdentityBindService();

export default verifiedIdentityBindService;
