import identityProfileRepository from "../repositories/identityProfileRepository";
import landRepository from "../repositories/landRepository";
import pollRepository from "../repositories/pollRepository";
import userRepository from "../repositories/userRepository";
import type {
  CurrentViewerProfileDto,
  GeoAreaOptionDto,
  LandDto,
  PollCreationCountryOptionDto,
  PollCreationReferenceDataDto,
  ViewerLandSelectionResultDto,
  ViewerLandStateDto,
} from "../types/contracts";
import type { IdentityProfileRow, LandRow, UserRow } from "../types/db";

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
  const [identityProfileRow, selectedLand] = await Promise.all([
    identityProfileRepository.getByUserId(user.id),
    resolveSelectedLand(user),
  ]);

  const identityProfile = mapIdentityProfileToDto(identityProfileRow);

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
    walletCredential: null,
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

export const viewerProfileService = {
  async getCurrentViewerProfile(viewerUserId: string): Promise<CurrentViewerProfileDto | null> {
    const user = await userRepository.getById(viewerUserId);
    if (!user) {
      return null;
    }

    return buildCurrentViewerProfile(user);
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
