import { createHmac, randomUUID } from "node:crypto";
import env from "../config/env";
import identityProfileRepository from "../repositories/identityProfileRepository";
import landRepository from "../repositories/landRepository";
import pollRepository from "../repositories/pollRepository";
import userRepository from "../repositories/userRepository";
import walletCredentialRepository from "../repositories/walletCredentialRepository";
import type {
  BackendCredentialStatus,
  CurrentViewerProfileDto,
  GeoAreaOptionDto,
  IssueWalletCredentialRequestDto,
  IssueWalletCredentialResultDto,
  IssuedWalletCredentialDto,
  LandDto,
  PollCreationCountryOptionDto,
  PollCreationReferenceDataDto,
  UpdateViewerHomeLocationRequestDto,
  UpdateViewerHomeLocationResultDto,
  ViewerWalletStateDto,
  WalletCredentialDto,
  WalletStatus,
  ViewerLandSelectionResultDto,
  ViewerLandStateDto,
} from "../types/contracts";
import type {
  IdentityProfileRow,
  LandRow,
  UserRow,
  WalletCredentialRow,
} from "../types/db";

type UpdateSelectedLandInput = {
  landId: string | null;
};

type UpdateSelectedLandFlagInput = {
  landId?: string | null;
  flagType?: string | null;
  flagAsset?: string | null;
  flagEmoji?: string | null;
};

type CreateLandInput = {
  name: string;
  description?: string | null;
  flagType?: string | null;
  flagAsset?: string | null;
  flagEmoji?: string | null;
  selectAfterCreate?: boolean;
};

type IssueWalletCredentialInput = IssueWalletCredentialRequestDto;
type UpdateHomeLocationInput = UpdateViewerHomeLocationRequestDto;

const ALLOWED_HOME_LOCATION_SOURCES = new Set([
  "user_selected",
  "derived_from_document",
  "admin_set",
  "mock",
]);

const DEFAULT_HOME_COUNTRY_CODE = "ZZ";

const normalizeText = (value: unknown): string | null => {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
};

const normalizeCountryCode = (value: unknown): string | null => {
  const normalized = normalizeText(value);
  return normalized ? normalized.toUpperCase() : null;
};

const normalizeCoordinate = (
  value: unknown,
  bounds: { min: number; max: number },
): number | null => {
  if (!Number.isFinite(value)) {
    return null;
  }

  const numericValue = Number(value);
  if (numericValue < bounds.min || numericValue > bounds.max) {
    return null;
  }

  return numericValue;
};

const deriveHomeAreaIdFromCoordinates = (
  latitude: number,
  longitude: number,
): string => {
  const latBucket = Math.round(latitude * 10);
  const lngBucket = Math.round(longitude * 10);
  const latPrefix = latBucket >= 0 ? "n" : "s";
  const lngPrefix = lngBucket >= 0 ? "e" : "w";

  return `grid_${latPrefix}${Math.abs(latBucket)}_${lngPrefix}${Math.abs(lngBucket)}`;
};

const resolveHomeCountryCode = (
  identityProfile: IdentityProfileRow,
  requestedCountryCode: unknown,
): string =>
  normalizeCountryCode(requestedCountryCode) ||
  normalizeCountryCode(identityProfile.home_country_code) ||
  normalizeCountryCode(identityProfile.document_country_code) ||
  normalizeCountryCode(identityProfile.issuing_country_code) ||
  DEFAULT_HOME_COUNTRY_CODE;

const resolveHomeAreaId = (
  requestedAreaId: unknown,
  latitude: number,
  longitude: number,
): string => normalizeText(requestedAreaId) || deriveHomeAreaIdFromCoordinates(latitude, longitude);

const normalizeHomeLocationSource = (value: unknown): string => {
  const normalized = normalizeText(value);
  if (!normalized) {
    return "user_selected";
  }

  return ALLOWED_HOME_LOCATION_SOURCES.has(normalized)
    ? normalized
    : "user_selected";
};

const slugify = (value: string): string =>
  value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");

const mapLandRowToDto = (row: LandRow): LandDto => ({
  id: row.id,
  name: row.name,
  slug: row.slug,
  type: row.type,
  flagType: row.flag_type,
  flagAsset: row.flag_asset,
  flagEmoji: row.flag_emoji,
  founderUserId: row.founder_user_id,
  description: row.description,
  isActive: row.is_active,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

const createFallbackLandFromSelectedId = (
  landId: string,
  referenceUser: UserRow,
): LandDto => ({
  id: landId,
  name: landId,
  slug: slugify(landId) || landId,
  type: "user_defined",
  flagType: "user_defined",
  flagAsset: null,
  flagEmoji: null,
  founderUserId: null,
  description: null,
  isActive: true,
  createdAt: referenceUser.created_at,
  updatedAt: referenceUser.updated_at,
});

const mapAreaOption = (
  areaId: string,
  countryCode: string | null,
): GeoAreaOptionDto => ({
  id: areaId,
  level: "city",
  countryCode: countryCode || "ZZ",
  centerLatitude: 0,
  centerLongitude: 0,
  parentAreaId: null,
  label: null,
  isActive: true,
});

const mapIdentityProfileToDto = (row: IdentityProfileRow | null) => {
  if (!row) {
    return null;
  }

  const homeCountryCode = normalizeCountryCode(row.home_country_code);
  const homeAreaId = normalizeText(row.home_area_id);

  return {
    id: row.id,
    userId: row.user_id,
    passportScanCompleted: row.passport_scan_completed,
    passportNfcCompleted: row.passport_nfc_completed,
    nationalIdScanCompleted: row.national_id_scan_completed,
    faceScanCompleted: row.face_scan_completed,
    faceBoundToIdentity: row.face_bound_to_identity,
    documentCountryCode: normalizeCountryCode(row.document_country_code),
    issuingCountryCode: normalizeCountryCode(row.issuing_country_code),
    homeLocation:
      homeCountryCode && homeAreaId
        ? {
            countryCode: homeCountryCode,
            areaId: homeAreaId,
            approxLatitude: row.home_approx_latitude,
            approxLongitude: row.home_approx_longitude,
            source: row.home_location_source,
            updatedAt: row.home_location_updated_at || row.updated_at,
          }
        : null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
};

const normalizeBackendCredentialStatus = (
  value: unknown,
): BackendCredentialStatus => {
  if (value === "issued" || value === "revoked") {
    return value;
  }

  return "not_issued";
};

const mapWalletCredentialToDto = (
  row: WalletCredentialRow | null,
): WalletCredentialDto | null => {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    userId: row.user_id,
    walletPublicId: row.wallet_public_id,
    holderId: row.holder_id,
    backendCredentialStatus: normalizeBackendCredentialStatus(row.issuance_status),
    issuedAt: row.issued_at,
    revokedAt: row.revoked_at,
  };
};

const buildViewerWalletState = (
  user: UserRow,
  walletCredential: WalletCredentialDto | null,
): ViewerWalletStateDto => {
  const walletExists = user.has_wallet || Boolean(walletCredential);
  const backendCredentialStatus: BackendCredentialStatus =
    walletCredential?.backendCredentialStatus || "not_issued";

  const status: WalletStatus =
    !walletExists
      ? "not_created"
      : backendCredentialStatus === "issued" || backendCredentialStatus === "revoked"
        ? "issued"
        : "local_only";

  return {
    exists: walletExists,
    status,
    backendCredentialStatus,
    credentialId: walletCredential?.id || user.wallet_credential_id || null,
    walletPublicId: walletCredential?.walletPublicId || null,
    issuedAt: walletCredential?.issuedAt || null,
    revokedAt: walletCredential?.revokedAt || null,
  };
};

const mapUserToDto = (user: UserRow) => ({
  id: user.id,
  ...(user.username ? { username: user.username } : null),
  ...(user.display_name ? { displayName: user.display_name } : null),
  onboardingStatus: user.onboarding_status,
  verificationLevel: user.verification_level,
  hasWallet: user.has_wallet,
  walletCredentialId: user.wallet_credential_id,
  selectedLandId: user.selected_land_id,
  ...(user.preferred_language ? { preferredLanguage: user.preferred_language } : null),
  createdAt: user.created_at,
  updatedAt: user.updated_at,
});

const resolveSelectedLand = async (user: UserRow): Promise<LandDto | null> => {
  const selectedLandId = normalizeText(user.selected_land_id);
  if (!selectedLandId) {
    return null;
  }

  const selectedLand = await landRepository.getById(selectedLandId);
  if (selectedLand) {
    return mapLandRowToDto(selectedLand);
  }

  return createFallbackLandFromSelectedId(selectedLandId, user);
};

const buildCurrentViewerProfile = async (
  user: UserRow,
): Promise<CurrentViewerProfileDto> => {
  const [identityProfileRow, selectedLand, walletCredentialRow] = await Promise.all([
    identityProfileRepository.getByUserId(user.id),
    resolveSelectedLand(user),
    walletCredentialRepository.getByUserId(user.id),
  ]);

  const identityProfile = mapIdentityProfileToDto(identityProfileRow);
  const walletCredential = mapWalletCredentialToDto(walletCredentialRow);

  const homeArea =
    identityProfile?.homeLocation?.areaId && identityProfile?.homeLocation?.countryCode
      ? mapAreaOption(
          identityProfile.homeLocation.areaId,
          identityProfile.homeLocation.countryCode,
        )
      : null;

  return {
    user: mapUserToDto(user),
    identityProfile,
    homeArea,
    wallet: buildViewerWalletState(user, walletCredential),
    walletCredential,
    selectedLand,
    primaryCitizenship: null,
  };
};

const buildViewerLandState = async (user: UserRow): Promise<ViewerLandStateDto> => {
  const [activeLands, selectedLand] = await Promise.all([
    landRepository.listActive(),
    resolveSelectedLand(user),
  ]);

  const mappedLands = activeLands.map(mapLandRowToDto);
  if (selectedLand && !mappedLands.some((land) => land.id === selectedLand.id)) {
    mappedLands.unshift(selectedLand);
  }

  return {
    selectedLandId: normalizeText(user.selected_land_id),
    selectedLand,
    lands: mappedLands,
  };
};

const createLandSelectionFailure = (
  errorCode: ViewerLandSelectionResultDto["errorCode"],
  message: string,
): ViewerLandSelectionResultDto => ({
  success: false,
  errorCode,
  message,
});

const buildPollCreationReferenceData = async (): Promise<PollCreationReferenceDataDto> => {
  const [landRows, identityRows, polls] = await Promise.all([
    landRepository.listActive(),
    identityProfileRepository.listReferenceRows(),
    pollRepository.listAll(),
  ]);

  const countrySet = new Set<string>();
  const areaCountryMap = new Map<string, string | null>();

  for (const profile of identityRows) {
    const profileCountries = [
      profile.home_country_code,
      profile.document_country_code,
      profile.issuing_country_code,
    ];

    profileCountries.forEach((countryCode) => {
      const normalized = normalizeCountryCode(countryCode);
      if (normalized) {
        countrySet.add(normalized);
      }
    });

    const areaId = normalizeText(profile.home_area_id);
    if (areaId) {
      const areaCountry = normalizeCountryCode(profile.home_country_code);
      if (!areaCountryMap.has(areaId)) {
        areaCountryMap.set(areaId, areaCountry);
      }
    }
  }

  for (const poll of polls) {
    const jurisdictionCountryCode = normalizeCountryCode(poll.jurisdiction_country_code);
    if (jurisdictionCountryCode) {
      countrySet.add(jurisdictionCountryCode);
    }

    (poll.allowed_document_country_codes || []).forEach((countryCode) => {
      const normalized = normalizeCountryCode(countryCode);
      if (normalized) {
        countrySet.add(normalized);
      }
    });

    (poll.jurisdiction_area_ids || []).forEach((areaId) => {
      const normalizedAreaId = normalizeText(areaId);
      if (normalizedAreaId && !areaCountryMap.has(normalizedAreaId)) {
        areaCountryMap.set(normalizedAreaId, jurisdictionCountryCode);
      }
    });

    (poll.allowed_home_area_ids || []).forEach((areaId) => {
      const normalizedAreaId = normalizeText(areaId);
      if (normalizedAreaId && !areaCountryMap.has(normalizedAreaId)) {
        areaCountryMap.set(normalizedAreaId, jurisdictionCountryCode);
      }
    });
  }

  const areaOptions = [...areaCountryMap.entries()]
    .sort(([leftAreaId], [rightAreaId]) => leftAreaId.localeCompare(rightAreaId))
    .map(([areaId, countryCode]) => mapAreaOption(areaId, countryCode));

  const countryOptions: PollCreationCountryOptionDto[] = [...countrySet]
    .sort((left, right) => left.localeCompare(right))
    .map((countryCode) => ({
      value: countryCode,
      label: countryCode,
    }));

  return {
    lands: landRows.map(mapLandRowToDto),
    areaOptions,
    countryOptions,
  };
};

const resolveUniqueLandSlug = async (requestedName: string): Promise<string> => {
  const baseSlug = slugify(requestedName) || `land-${Date.now().toString(36)}`;
  let candidateSlug = baseSlug;
  let suffix = 2;

  // Keep retrying until we find a free slug.
  // This is deterministic and easy to remove once a DB upsert path is needed.
  while (await landRepository.getBySlug(candidateSlug)) {
    candidateSlug = `${baseSlug}-${suffix}`;
    suffix += 1;
  }

  return candidateSlug;
};

const mapSelectionSuccess = async (
  user: UserRow,
  land: LandDto | null = null,
): Promise<ViewerLandSelectionResultDto> => ({
  success: true,
  profile: await buildCurrentViewerProfile(user),
  state: await buildViewerLandState(user),
  ...(land ? { land } : null),
});

const buildWalletCredentialProofValue = (
  unsignedCredential: Omit<IssuedWalletCredentialDto, "proof">,
): string =>
  createHmac("sha256", env.wallet.issuerSigningSecret)
    .update(JSON.stringify(unsignedCredential))
    .digest("hex");

const buildIssuedWalletCredential = (params: {
  user: UserRow;
  request: IssueWalletCredentialInput;
  issuedAt: string;
}): IssuedWalletCredentialDto => {
  const unsignedCredential: Omit<IssuedWalletCredentialDto, "proof"> = {
    id: `urn:iland:credential:${randomUUID()}`,
    issuer: env.wallet.issuerId,
    type: "IlandIdentityCredential",
    version: "0.0.86",
    subjectId: `did:iland:user:${params.user.id}`,
    holderId: params.request.holderId,
    walletPublicId: params.request.walletPublicId,
    walletPublicKey: params.request.walletPublicKey,
    verifiedIdentity: params.user.verification_level !== "anonymous",
    status: "issued",
    issuedAt: params.issuedAt,
  };

  return {
    ...unsignedCredential,
    proof: {
      type: "hmac_sha256",
      value: buildWalletCredentialProofValue(unsignedCredential),
    },
  };
};

const createWalletIssuanceFailure = (params: {
  user: UserRow;
  walletCredential: WalletCredentialDto | null;
  errorCode: "INVALID_INPUT" | "IDENTITY_PROFILE_REQUIRED" | "CREDENTIAL_REVOKED";
  message: string;
}): IssueWalletCredentialResultDto => ({
  success: false,
  wallet: buildViewerWalletState(params.user, params.walletCredential),
  walletCredential: params.walletCredential,
  errorCode: params.errorCode,
  message: params.message,
});

export const viewerProfileService = {
  async getCurrentViewerProfile(viewerUserId: string): Promise<CurrentViewerProfileDto | null> {
    const user = await userRepository.getById(viewerUserId);
    if (!user) {
      return null;
    }

    return buildCurrentViewerProfile(user);
  },

  async updateHomeLocation(
    viewerUserId: string,
    input: UpdateHomeLocationInput,
  ): Promise<UpdateViewerHomeLocationResultDto> {
    const approxLatitude = normalizeCoordinate(input.approxLatitude, {
      min: -90,
      max: 90,
    });
    const approxLongitude = normalizeCoordinate(input.approxLongitude, {
      min: -180,
      max: 180,
    });

    if (approxLatitude === null || approxLongitude === null) {
      return {
        success: false,
        errorCode: "INVALID_COORDINATES",
        message: "A valid approximate latitude and longitude are required.",
      };
    }

    const user = await userRepository.getById(viewerUserId);
    if (!user) {
      return {
        success: false,
        errorCode: "USER_NOT_FOUND",
        message: "The current user could not be resolved.",
      };
    }

    const identityProfile = await identityProfileRepository.getByUserId(user.id);
    if (!identityProfile) {
      return {
        success: false,
        errorCode: "IDENTITY_PROFILE_NOT_FOUND",
        message: "An identity profile is required before updating home location.",
      };
    }

    const nextHomeCountryCode = resolveHomeCountryCode(
      identityProfile,
      input.countryCode,
    );
    const nextHomeAreaId = resolveHomeAreaId(
      input.areaId,
      approxLatitude,
      approxLongitude,
    );
    const nextHomeLocationSource = normalizeHomeLocationSource(input.source);
    const now = new Date().toISOString();

    const updatedProfile = await identityProfileRepository.updateHomeLocationByUserId(
      user.id,
      {
        home_country_code: nextHomeCountryCode,
        home_area_id: nextHomeAreaId,
        home_approx_latitude: approxLatitude,
        home_approx_longitude: approxLongitude,
        home_location_source: nextHomeLocationSource,
        home_location_updated_at: now,
      },
    );

    if (!updatedProfile) {
      return {
        success: false,
        errorCode: "IDENTITY_PROFILE_NOT_FOUND",
        message: "The identity profile could not be updated.",
      };
    }

    return {
      success: true,
      profile: await buildCurrentViewerProfile(user),
    };
  },

  async issueWalletCredential(
    viewerUserId: string,
    input: IssueWalletCredentialInput,
  ): Promise<IssueWalletCredentialResultDto> {
    const user = await userRepository.getById(viewerUserId);
    if (!user) {
      return {
        success: false,
        wallet: {
          exists: false,
          status: "not_created",
          backendCredentialStatus: "not_issued",
          credentialId: null,
          walletPublicId: null,
          issuedAt: null,
          revokedAt: null,
        },
        walletCredential: null,
        errorCode: "USER_NOT_FOUND",
        message: "The current user could not be resolved.",
      };
    }

    const walletPublicId = normalizeText(input.walletPublicId);
    const holderId = normalizeText(input.holderId);
    const walletPublicKey = normalizeText(input.walletPublicKey);

    if (!walletPublicId || !holderId || !walletPublicKey) {
      return createWalletIssuanceFailure({
        user,
        walletCredential: mapWalletCredentialToDto(
          await walletCredentialRepository.getByUserId(user.id),
        ),
        errorCode: "INVALID_INPUT",
        message:
          "Wallet issuance requires walletPublicId, holderId, and walletPublicKey.",
      });
    }

    const registeredCredentialRow = await walletCredentialRepository.upsertPublicMaterial({
      user_id: user.id,
      wallet_public_id: walletPublicId,
      holder_id: holderId,
      wallet_public_key: walletPublicKey,
    });

    const linkedUser =
      (await userRepository.updateWalletCredentialLink(user.id, {
        hasWallet: true,
        walletCredentialId: registeredCredentialRow.id,
      })) || {
        ...user,
        has_wallet: true,
        wallet_credential_id: registeredCredentialRow.id,
      };

    const registeredWalletCredential =
      mapWalletCredentialToDto(registeredCredentialRow);

    if (registeredCredentialRow.issuance_status === "revoked") {
      return createWalletIssuanceFailure({
        user: linkedUser,
        walletCredential: registeredWalletCredential,
        errorCode: "CREDENTIAL_REVOKED",
        message: "Credential issuance is blocked because this wallet credential is revoked.",
      });
    }

    const identityProfile = await identityProfileRepository.getByUserId(user.id);
    if (!identityProfile) {
      return createWalletIssuanceFailure({
        user: linkedUser,
        walletCredential: registeredWalletCredential,
        errorCode: "IDENTITY_PROFILE_REQUIRED",
        message: "An identity profile is required before wallet credential issuance.",
      });
    }

    const issuedAt = new Date().toISOString();
    const issuedCredential = buildIssuedWalletCredential({
      user: linkedUser,
      request: {
        walletPublicId,
        holderId,
        walletPublicKey,
      },
      issuedAt,
    });

    const issuedCredentialRow = await walletCredentialRepository.updateByUserId(user.id, {
      issuance_status: "issued",
      issued_at: issuedAt,
      revoked_at: null,
      revocation_reason: null,
      credential_payload: issuedCredential as unknown as Record<string, unknown>,
    });

    const resolvedIssuedRow = issuedCredentialRow || registeredCredentialRow;
    const finalWalletCredential = mapWalletCredentialToDto(resolvedIssuedRow);
    if (!finalWalletCredential) {
      return createWalletIssuanceFailure({
        user: linkedUser,
        walletCredential: registeredWalletCredential,
        errorCode: "INVALID_INPUT",
        message: "Wallet credential issuance produced an invalid credential state.",
      });
    }

    const finalUser =
      (await userRepository.updateWalletCredentialLink(user.id, {
        hasWallet: true,
        walletCredentialId: resolvedIssuedRow.id,
      })) || linkedUser;

    return {
      success: true,
      wallet: buildViewerWalletState(finalUser, finalWalletCredential),
      walletCredential: finalWalletCredential,
      issuedCredential,
    };
  },

  async getViewerLandState(viewerUserId: string): Promise<ViewerLandSelectionResultDto> {
    const user = await userRepository.getById(viewerUserId);
    if (!user) {
      return createLandSelectionFailure(
        "USER_NOT_FOUND",
        "The current user could not be resolved.",
      );
    }

    return {
      success: true,
      state: await buildViewerLandState(user),
    };
  },

  async updateSelectedLand(
    viewerUserId: string,
    input: UpdateSelectedLandInput,
  ): Promise<ViewerLandSelectionResultDto> {
    const user = await userRepository.getById(viewerUserId);
    if (!user) {
      return createLandSelectionFailure(
        "USER_NOT_FOUND",
        "The current user could not be resolved.",
      );
    }

    const normalizedLandId = normalizeText(input.landId);
    if (normalizedLandId) {
      const land = await landRepository.getById(normalizedLandId);
      if (!land || !land.is_active) {
        return createLandSelectionFailure(
          "LAND_NOT_FOUND",
          "The selected land does not exist.",
        );
      }
    }

    const updatedUser = await userRepository.updateSelectedLandId(
      user.id,
      normalizedLandId,
    );

    if (!updatedUser) {
      return createLandSelectionFailure(
        "USER_NOT_FOUND",
        "The current user could not be resolved.",
      );
    }

    const selectedLand = normalizedLandId
      ? await resolveSelectedLand(updatedUser)
      : null;

    return mapSelectionSuccess(updatedUser, selectedLand);
  },

  async updateSelectedLandFlag(
    viewerUserId: string,
    input: UpdateSelectedLandFlagInput,
  ): Promise<ViewerLandSelectionResultDto> {
    const user = await userRepository.getById(viewerUserId);
    if (!user) {
      return createLandSelectionFailure(
        "USER_NOT_FOUND",
        "The current user could not be resolved.",
      );
    }

    const selectedLandId = normalizeText(user.selected_land_id);
    const requestedLandId = normalizeText(input.landId) || selectedLandId;

    if (!requestedLandId || requestedLandId !== selectedLandId) {
      return createLandSelectionFailure(
        "INVALID_INPUT",
        "A currently selected land is required before updating the flag.",
      );
    }

    const existingLand = await landRepository.getById(requestedLandId);
    if (!existingLand || !existingLand.is_active) {
      return createLandSelectionFailure(
        "LAND_NOT_FOUND",
        "The selected land does not exist.",
      );
    }

    const nextFlagType = normalizeText(input.flagType);
    const nextFlagAsset = normalizeText(input.flagAsset);
    const nextFlagEmoji = normalizeText(input.flagEmoji);

    if (!nextFlagType && nextFlagAsset === null && nextFlagEmoji === null) {
      return createLandSelectionFailure(
        "INVALID_INPUT",
        "A flag value is required.",
      );
    }

    const updatedLand = await landRepository.updateById(existingLand.id, {
      ...(nextFlagType ? { flag_type: nextFlagType } : null),
      ...(input.flagAsset !== undefined ? { flag_asset: nextFlagAsset } : null),
      ...(input.flagEmoji !== undefined ? { flag_emoji: nextFlagEmoji } : null),
    });

    const resolvedUpdatedLand = updatedLand
      ? mapLandRowToDto(updatedLand)
      : mapLandRowToDto(existingLand);

    return mapSelectionSuccess(user, resolvedUpdatedLand);
  },

  async createLand(
    viewerUserId: string,
    input: CreateLandInput,
  ): Promise<ViewerLandSelectionResultDto> {
    const user = await userRepository.getById(viewerUserId);
    if (!user) {
      return createLandSelectionFailure(
        "USER_NOT_FOUND",
        "The current user could not be resolved.",
      );
    }

    const normalizedName = normalizeText(input.name);
    if (!normalizedName) {
      return createLandSelectionFailure(
        "INVALID_INPUT",
        "A land name is required.",
      );
    }

    const uniqueSlug = await resolveUniqueLandSlug(normalizedName);
    const landId = `land_${crypto.randomUUID()}`;
    const createdLand = await landRepository.insert({
      id: landId,
      name: normalizedName,
      slug: uniqueSlug,
      type: "user_defined",
      flag_type: normalizeText(input.flagType) || "user_defined",
      flag_asset: normalizeText(input.flagAsset),
      flag_emoji: normalizeText(input.flagEmoji),
      founder_user_id: user.id,
      description: normalizeText(input.description),
      is_active: true,
    });

    const shouldSelectAfterCreate = input.selectAfterCreate !== false;
    const maybeUpdatedUser = shouldSelectAfterCreate
      ? await userRepository.updateSelectedLandId(user.id, createdLand.id)
      : user;

    if (!maybeUpdatedUser) {
      return createLandSelectionFailure(
        "USER_NOT_FOUND",
        "The current user could not be resolved.",
      );
    }

    return mapSelectionSuccess(maybeUpdatedUser, mapLandRowToDto(createdLand));
  },

  async getLands(): Promise<LandDto[]> {
    const lands = await landRepository.listActive();
    return lands.map(mapLandRowToDto);
  },

  async getPollCreationReferenceData(): Promise<PollCreationReferenceDataDto> {
    return buildPollCreationReferenceData();
  },
};

export default viewerProfileService;
