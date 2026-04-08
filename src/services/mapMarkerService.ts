import identityProfileRepository from "../repositories/identityProfileRepository";
import pollRepository from "../repositories/pollRepository";
import voteRepository from "../repositories/voteRepository";
import { MAP_ALL_POLLS_SCOPE_ID } from "../types/contracts";
import type {
  GetPollVoteMapMarkersRequestDto,
  MapAreaLevel,
  VoteMapMarkerDto,
} from "../types/contracts";

type SeedGroup = {
  originAreaId: string;
  currentAreaId: string;
  totalVotes: number;
  countsByOptionId: Record<string, number>;
  updatedAt: string;
  mergeDepth: number;
};

type AggregationBucket = {
  areaId: string;
  totalVotes: number;
  countsByOptionId: Record<string, number>;
  updatedAt: string;
  mergedFromAreaIds: Set<string>;
  maxMergeDepth: number;
};

type AreaNode = {
  id: string;
  level: MapAreaLevel;
  countryCode: string;
  parentAreaId: string | null;
  latitude: number;
  longitude: number;
  coordinateSource: "fallback" | "profile";
  label: string | null;
};

type OptionMetadata = {
  label: string;
  color: string | null;
};

const DEFAULT_COUNTRY_CODE = "ZZ";
const DEFAULT_HOME_AREA_ID = "unknown";
const PRIVACY_THRESHOLD_K = 3;
const PRIVACY_MERGE_STRATEGY = "hierarchical_parent_k" as const;
const MAP_PROFILE_LOOKUP_CHUNK_SIZE = 500;
const MAP_VOTE_BATCH_SIZE = 5000;

type ResolvedCoordinates = {
  latitude: number;
  longitude: number;
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

const clamp = (value: number, min: number, max: number): number =>
  Math.max(min, Math.min(max, value));

const hashStringToUint32 = (value: string): number => {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
};

const deterministicCoordinate = (
  key: string,
  min: number,
  max: number,
  salt: string,
): number => {
  const hash = hashStringToUint32(`${salt}:${key}`);
  const ratio = hash / 0xffffffff;
  return min + ratio * (max - min);
};

const resolveCoordinate = (
  value: unknown,
  min: number,
  max: number,
): number | null => {
  if (!Number.isFinite(value)) {
    return null;
  }

  return clamp(Number(value), min, max);
};

const resolveProfileCoordinates = (profile: {
  home_approx_latitude: number | null;
  home_approx_longitude: number | null;
} | null): ResolvedCoordinates | null => {
  if (!profile) {
    return null;
  }

  const latitude = resolveCoordinate(profile.home_approx_latitude, -85, 85);
  const longitude = resolveCoordinate(profile.home_approx_longitude, -180, 180);
  if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
    return null;
  }

  return {
    latitude,
    longitude,
  };
};

const createCountryArea = (
  countryCode: string,
  coordinates: ResolvedCoordinates | null,
): AreaNode => {
  const id = `country:${countryCode}`;
  const latitude = coordinates?.latitude ?? clamp(deterministicCoordinate(id, -60, 75, "lat"), -85, 85);
  const longitude =
    coordinates?.longitude ?? clamp(deterministicCoordinate(id, -175, 175, "lng"), -180, 180);

  return {
    id,
    level: "country",
    countryCode,
    parentAreaId: null,
    latitude,
    longitude,
    coordinateSource: coordinates ? "profile" : "fallback",
    label: countryCode,
  };
};

const createCityArea = (
  countryCode: string,
  homeAreaId: string,
  coordinates: ResolvedCoordinates | null,
): AreaNode => {
  const id = `city:${countryCode}:${homeAreaId}`;
  const latitude = coordinates?.latitude ?? clamp(deterministicCoordinate(id, -60, 75, "lat"), -85, 85);
  const longitude =
    coordinates?.longitude ?? clamp(deterministicCoordinate(id, -175, 175, "lng"), -180, 180);

  return {
    id,
    level: "city",
    countryCode,
    parentAreaId: `country:${countryCode}`,
    latitude,
    longitude,
    coordinateSource: coordinates ? "profile" : "fallback",
    label: homeAreaId,
  };
};

const updateAreaCoordinatesFromProfile = (
  area: AreaNode,
  coordinates: ResolvedCoordinates | null,
): void => {
  if (!coordinates) {
    return;
  }

  if (area.coordinateSource === "fallback") {
    area.latitude = coordinates.latitude;
    area.longitude = coordinates.longitude;
    area.coordinateSource = "profile";
  }
};

const ensureAreaHierarchy = (
  countryCode: string,
  homeAreaId: string,
  coordinates: ResolvedCoordinates | null,
  areaLevel: MapAreaLevel,
  areasById: Map<string, AreaNode>,
): string => {
  const countryAreaId = `country:${countryCode}`;
  const existingCountryArea = areasById.get(countryAreaId);
  if (existingCountryArea) {
    updateAreaCoordinatesFromProfile(existingCountryArea, coordinates);
  } else {
    areasById.set(countryAreaId, createCountryArea(countryCode, coordinates));
  }

  if (areaLevel === "country") {
    return countryAreaId;
  }

  const cityAreaId = `city:${countryCode}:${homeAreaId}`;
  const existingCityArea = areasById.get(cityAreaId);
  if (existingCityArea) {
    updateAreaCoordinatesFromProfile(existingCityArea, coordinates);
  } else {
    areasById.set(cityAreaId, createCityArea(countryCode, homeAreaId, coordinates));
  }

  return cityAreaId;
};

const mergeCounts = (
  target: Record<string, number>,
  source: Record<string, number>,
): void => {
  Object.entries(source).forEach(([optionId, count]) => {
    target[optionId] = (target[optionId] || 0) + count;
  });
};

const upsertSeedGroup = (
  seedGroupsByAreaId: Map<string, SeedGroup>,
  areaId: string,
  countsByOptionId: Record<string, number>,
  updatedAt: string,
): void => {
  const existing = seedGroupsByAreaId.get(areaId);
  if (existing) {
    existing.totalVotes += 1;
    mergeCounts(existing.countsByOptionId, countsByOptionId);
    if (updatedAt > existing.updatedAt) {
      existing.updatedAt = updatedAt;
    }
    return;
  }

  seedGroupsByAreaId.set(areaId, {
    originAreaId: areaId,
    currentAreaId: areaId,
    totalVotes: 1,
    countsByOptionId: { ...countsByOptionId },
    updatedAt,
    mergeDepth: 0,
  });
};

const getAreaTotalsByCurrentAreaId = (groups: SeedGroup[]): Map<string, number> => {
  const totals = new Map<string, number>();

  for (const group of groups) {
    totals.set(
      group.currentAreaId,
      (totals.get(group.currentAreaId) || 0) + group.totalVotes,
    );
  }

  return totals;
};

const applyHierarchicalPrivacyFilter = (
  seedGroups: SeedGroup[],
  areaById: Map<string, AreaNode>,
): SeedGroup[] => {
  if (seedGroups.length === 0 || PRIVACY_THRESHOLD_K <= 1) {
    return seedGroups;
  }

  const groups = seedGroups.map((group) => ({
    ...group,
    countsByOptionId: { ...group.countsByOptionId },
  }));

  const maxIterations = Math.max(areaById.size, 1);

  for (let iteration = 0; iteration < maxIterations; iteration += 1) {
    const totalsByAreaId = getAreaTotalsByCurrentAreaId(groups);
    let changed = false;

    for (const group of groups) {
      const currentAreaTotal = totalsByAreaId.get(group.currentAreaId) || 0;
      if (currentAreaTotal >= PRIVACY_THRESHOLD_K) {
        continue;
      }

      const currentArea = areaById.get(group.currentAreaId);
      const parentAreaId = currentArea?.parentAreaId || null;
      if (!parentAreaId) {
        continue;
      }

      if (!areaById.has(parentAreaId)) {
        continue;
      }

      group.currentAreaId = parentAreaId;
      group.mergeDepth += 1;
      changed = true;
    }

    if (!changed) {
      break;
    }
  }

  const finalTotalsByAreaId = getAreaTotalsByCurrentAreaId(groups);

  return groups.filter(
    (group) => (finalTotalsByAreaId.get(group.currentAreaId) || 0) >= PRIVACY_THRESHOLD_K,
  );
};

const aggregatePrivacyFilteredGroups = (
  groups: SeedGroup[],
): Map<string, AggregationBucket> => {
  const buckets = new Map<string, AggregationBucket>();

  for (const group of groups) {
    const existing = buckets.get(group.currentAreaId);
    if (existing) {
      existing.totalVotes += group.totalVotes;
      mergeCounts(existing.countsByOptionId, group.countsByOptionId);
      if (group.updatedAt > existing.updatedAt) {
        existing.updatedAt = group.updatedAt;
      }
      existing.mergedFromAreaIds.add(group.originAreaId);
      if (group.mergeDepth > existing.maxMergeDepth) {
        existing.maxMergeDepth = group.mergeDepth;
      }
      continue;
    }

    buckets.set(group.currentAreaId, {
      areaId: group.currentAreaId,
      totalVotes: group.totalVotes,
      countsByOptionId: { ...group.countsByOptionId },
      updatedAt: group.updatedAt,
      mergedFromAreaIds: new Set([group.originAreaId]),
      maxMergeDepth: group.mergeDepth,
    });
  }

  return buckets;
};

const areaMatchesParentFilter = (
  area: AreaNode,
  parentAreaId: string,
  areaById: Map<string, AreaNode>,
): boolean => {
  if (area.id === parentAreaId) {
    return true;
  }

  let currentParentId = area.parentAreaId;
  while (currentParentId) {
    if (currentParentId === parentAreaId) {
      return true;
    }

    currentParentId = areaById.get(currentParentId)?.parentAreaId || null;
  }

  return false;
};

const buildOptionMetadataById = (
  options: Awaited<ReturnType<typeof pollRepository.getOptionsByPollIds>>,
): Map<string, OptionMetadata> =>
  new Map(
    options.map((option) => [
      option.id,
      {
        label: option.label,
        color: option.color ?? null,
      },
    ]),
  );

const buildOptionBreakdown = (
  bucket: AggregationBucket,
  scopedPollOptions: Awaited<ReturnType<typeof pollRepository.getOptionsByPollId>> | null,
  optionMetadataById: Map<string, OptionMetadata>,
): VoteMapMarkerDto["optionBreakdown"] => {
  if (scopedPollOptions && scopedPollOptions.length > 0) {
    const pollOptionOrderById = new Map(
      scopedPollOptions.map((option) => [option.id, option.display_order]),
    );

    return scopedPollOptions
      .map((option) => {
        const count = bucket.countsByOptionId[option.id] || 0;
        return {
          optionId: option.id,
          label: option.label,
          count,
          color: option.color ?? null,
          percentageWithinArea: bucket.totalVotes > 0 ? count / bucket.totalVotes : 0,
        };
      })
      .sort((left, right) => {
        if (right.count !== left.count) {
          return right.count - left.count;
        }

        const leftOrder =
          pollOptionOrderById.get(left.optionId) ?? Number.MAX_SAFE_INTEGER;
        const rightOrder =
          pollOptionOrderById.get(right.optionId) ?? Number.MAX_SAFE_INTEGER;
        if (leftOrder !== rightOrder) {
          return leftOrder - rightOrder;
        }

        return left.optionId.localeCompare(right.optionId);
      });
  }

  return Object.entries(bucket.countsByOptionId)
    .map(([optionId, count]) => {
      const metadata = optionMetadataById.get(optionId);
      return {
        optionId,
        label: metadata?.label || optionId,
        count,
        color: metadata?.color ?? null,
        percentageWithinArea: bucket.totalVotes > 0 ? count / bucket.totalVotes : 0,
      };
    })
    .sort((left, right) => {
      if (right.count !== left.count) {
        return right.count - left.count;
      }

      if (left.label !== right.label) {
        return left.label.localeCompare(right.label);
      }

      return left.optionId.localeCompare(right.optionId);
    });
};

const buildMarkers = (
  markerScopeId: string,
  buckets: Map<string, AggregationBucket>,
  areaById: Map<string, AreaNode>,
  scopedPollOptions: Awaited<ReturnType<typeof pollRepository.getOptionsByPollId>> | null,
  optionMetadataById: Map<string, OptionMetadata>,
): VoteMapMarkerDto[] =>
  Array.from(buckets.values())
    .map((bucket) => {
      const area = areaById.get(bucket.areaId);
      if (!area) {
        return null;
      }

      const optionBreakdown = buildOptionBreakdown(
        bucket,
        scopedPollOptions,
        optionMetadataById,
      );
      const leading = optionBreakdown.find((entry) => entry.count > 0) || null;
      const mergedFromAreaIds = Array.from(bucket.mergedFromAreaIds).sort();

      return {
        id: `marker_${markerScopeId}_${area.id}`,
        pollId: markerScopeId,
        areaId: area.id,
        areaLevel: area.level,
        parentAreaId: area.parentAreaId,
        latitude: area.latitude,
        longitude: area.longitude,
        totalVotes: bucket.totalVotes,
        optionBreakdown,
        leadingOptionId: leading?.optionId || null,
        leadingOptionLabel: leading?.label || null,
        leadingOptionColor: leading?.color || null,
        leadingOptionCount: leading?.count ?? null,
        leadingOptionPercentage:
          leading && bucket.totalVotes > 0 ? leading.count / bucket.totalVotes : null,
        mergedAreaCount: mergedFromAreaIds.length,
        privacy: {
          thresholdK: PRIVACY_THRESHOLD_K,
          mergeStrategy: PRIVACY_MERGE_STRATEGY,
          mergedFromAreaIds,
          mergedAreaCount: mergedFromAreaIds.length,
          maxMergeDepth: bucket.maxMergeDepth,
        },
        updatedAt: bucket.updatedAt,
      } satisfies VoteMapMarkerDto;
    })
    .filter((marker): marker is VoteMapMarkerDto => Boolean(marker))
    .sort((left, right) => {
      if (right.totalVotes !== left.totalVotes) {
        return right.totalVotes - left.totalVotes;
      }

      if (right.mergedAreaCount !== left.mergedAreaCount) {
        return right.mergedAreaCount - left.mergedAreaCount;
      }

      return left.areaId.localeCompare(right.areaId);
    });

const normalizeAreaLevel = (value: unknown): MapAreaLevel =>
  value === "country" ? "country" : "city";

const applyMapFilters = (
  markers: VoteMapMarkerDto[],
  input: GetPollVoteMapMarkersRequestDto,
  areasById: Map<string, AreaNode>,
): VoteMapMarkerDto[] => {
  const normalizedCountryFilter = normalizeCountryCode(input.countryCode);
  let filteredMarkers = markers;

  if (normalizedCountryFilter) {
    filteredMarkers = filteredMarkers.filter((marker) => {
      const area = areasById.get(marker.areaId);
      return area?.countryCode === normalizedCountryFilter;
    });
  }

  const normalizedParentAreaId = normalizeText(input.parentAreaId);
  if (normalizedParentAreaId) {
    filteredMarkers = filteredMarkers.filter((marker) => {
      const area = areasById.get(marker.areaId);
      if (!area) {
        return false;
      }

      return areaMatchesParentFilter(area, normalizedParentAreaId, areasById);
    });
  }

  return filteredMarkers;
};

const listMapSeedProfilesByUserIds = async (
  userIds: string[],
): Promise<Awaited<ReturnType<typeof identityProfileRepository.listMapSeedByUserIds>>> => {
  if (userIds.length === 0) {
    return [];
  }

  const profiles: Awaited<
    ReturnType<typeof identityProfileRepository.listMapSeedByUserIds>
  > = [];

  for (
    let offset = 0;
    offset < userIds.length;
    offset += MAP_PROFILE_LOOKUP_CHUNK_SIZE
  ) {
    const userIdsChunk = userIds.slice(offset, offset + MAP_PROFILE_LOOKUP_CHUNK_SIZE);
    if (userIdsChunk.length === 0) {
      continue;
    }

    const chunkProfiles =
      await identityProfileRepository.listMapSeedByUserIds(userIdsChunk);
    profiles.push(...chunkProfiles);
  }

  return profiles;
};

const buildMapMarkersFromVotes = async (params: {
  markerScopeId: string;
  areaLevel: MapAreaLevel;
  input: GetPollVoteMapMarkersRequestDto;
  validVotes: Awaited<ReturnType<typeof voteRepository.getValidByPollId>>;
  scopedPollOptions: Awaited<ReturnType<typeof pollRepository.getOptionsByPollId>> | null;
  optionMetadataById: Map<string, OptionMetadata>;
}): Promise<VoteMapMarkerDto[]> => {
  const { markerScopeId, areaLevel, input, validVotes, scopedPollOptions, optionMetadataById } =
    params;

  if (validVotes.length === 0) {
    return [];
  }

  const userIds = Array.from(new Set(validVotes.map((vote) => vote.user_id)));
  const mapSeedProfiles = await listMapSeedProfilesByUserIds(userIds);
  const profileByUserId = new Map(
    mapSeedProfiles.map((profile) => [profile.user_id, profile]),
  );

  const areasById = new Map<string, AreaNode>();
  const seedGroupsByAreaId = new Map<string, SeedGroup>();

  for (const vote of validVotes) {
    const profile = profileByUserId.get(vote.user_id);
    const countryCode =
      normalizeCountryCode(profile?.home_country_code) || DEFAULT_COUNTRY_CODE;
    const homeAreaId = normalizeText(profile?.home_area_id) || DEFAULT_HOME_AREA_ID;
    const coordinates = resolveProfileCoordinates(profile || null);

    const startAreaId = ensureAreaHierarchy(
      countryCode,
      homeAreaId,
      coordinates,
      areaLevel,
      areasById,
    );

    upsertSeedGroup(
      seedGroupsByAreaId,
      startAreaId,
      { [vote.option_id]: 1 },
      vote.submitted_at,
    );
  }

  const privacyFilteredGroups = applyHierarchicalPrivacyFilter(
    Array.from(seedGroupsByAreaId.values()).sort((left, right) =>
      left.originAreaId.localeCompare(right.originAreaId),
    ),
    areasById,
  );

  if (privacyFilteredGroups.length === 0) {
    return [];
  }

  const buckets = aggregatePrivacyFilteredGroups(privacyFilteredGroups);
  const markers = buildMarkers(
    markerScopeId,
    buckets,
    areasById,
    scopedPollOptions,
    optionMetadataById,
  );

  return applyMapFilters(markers, input, areasById);
};

const buildPollMarkersFromAllVotes = async (params: {
  markerScopeId: string;
  pollId: string;
  areaLevel: MapAreaLevel;
  input: GetPollVoteMapMarkersRequestDto;
  scopedPollOptions: Awaited<ReturnType<typeof pollRepository.getOptionsByPollId>> | null;
  optionMetadataById: Map<string, OptionMetadata>;
}): Promise<VoteMapMarkerDto[]> => {
  const { markerScopeId, pollId, areaLevel, input, scopedPollOptions, optionMetadataById } =
    params;

  const totalValidVotes = await voteRepository.countValidByPollId(pollId);
  if (totalValidVotes <= 0) {
    return [];
  }

  const areasById = new Map<string, AreaNode>();
  const seedGroupsByAreaId = new Map<string, SeedGroup>();

  for (
    let offset = 0;
    offset < totalValidVotes;
    offset += MAP_VOTE_BATCH_SIZE
  ) {
    const voteBatch = await voteRepository.getValidByPollIdPage(
      pollId,
      offset,
      offset + MAP_VOTE_BATCH_SIZE - 1,
    );
    if (voteBatch.length === 0) {
      break;
    }

    const userIds = Array.from(new Set(voteBatch.map((vote) => vote.user_id)));
    const mapSeedProfiles = await listMapSeedProfilesByUserIds(userIds);
    const profileByUserId = new Map(
      mapSeedProfiles.map((profile) => [profile.user_id, profile]),
    );

    for (const vote of voteBatch) {
      const profile = profileByUserId.get(vote.user_id);
      const countryCode =
        normalizeCountryCode(profile?.home_country_code) || DEFAULT_COUNTRY_CODE;
      const homeAreaId = normalizeText(profile?.home_area_id) || DEFAULT_HOME_AREA_ID;
      const coordinates = resolveProfileCoordinates(profile || null);

      const startAreaId = ensureAreaHierarchy(
        countryCode,
        homeAreaId,
        coordinates,
        areaLevel,
        areasById,
      );

      upsertSeedGroup(
        seedGroupsByAreaId,
        startAreaId,
        { [vote.option_id]: 1 },
        vote.submitted_at,
      );
    }
  }

  if (seedGroupsByAreaId.size === 0) {
    return [];
  }

  const privacyFilteredGroups = applyHierarchicalPrivacyFilter(
    Array.from(seedGroupsByAreaId.values()).sort((left, right) =>
      left.originAreaId.localeCompare(right.originAreaId),
    ),
    areasById,
  );
  if (privacyFilteredGroups.length === 0) {
    return [];
  }

  const buckets = aggregatePrivacyFilteredGroups(privacyFilteredGroups);
  const markers = buildMarkers(
    markerScopeId,
    buckets,
    areasById,
    scopedPollOptions,
    optionMetadataById,
  );

  return applyMapFilters(markers, input, areasById);
};

export const mapMarkerService = {
  async getPollVoteMarkers(
    input: GetPollVoteMapMarkersRequestDto,
  ): Promise<VoteMapMarkerDto[]> {
    const pollId = normalizeText(input.pollId);
    if (!pollId) {
      return [];
    }

    const areaLevel = normalizeAreaLevel(input.areaLevel);

    if (pollId === MAP_ALL_POLLS_SCOPE_ID) {
      const polls = await pollRepository.listAll();
      if (polls.length === 0) {
        return [];
      }

      const pollIds = polls.map((poll) => poll.id);
      const [allOptions, validVotes] = await Promise.all([
        pollRepository.getOptionsByPollIds(pollIds),
        voteRepository.getValidByPollIds(pollIds),
      ]);

      if (allOptions.length === 0 || validVotes.length === 0) {
        return [];
      }

      return buildMapMarkersFromVotes({
        markerScopeId: MAP_ALL_POLLS_SCOPE_ID,
        areaLevel,
        input,
        validVotes,
        scopedPollOptions: null,
        optionMetadataById: buildOptionMetadataById(allOptions),
      });
    }

    const poll = await pollRepository.getById(pollId);
    if (!poll) {
      return [];
    }

    const pollOptions = await pollRepository.getOptionsByPollId(pollId);
    if (pollOptions.length === 0) {
      return [];
    }

    return buildPollMarkersFromAllVotes({
      markerScopeId: pollId,
      pollId,
      areaLevel,
      input,
      scopedPollOptions: pollOptions,
      optionMetadataById: buildOptionMetadataById(pollOptions),
    });
  },
};

export default mapMarkerService;
