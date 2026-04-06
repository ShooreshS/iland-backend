import { z } from "zod";
import requireViewer from "../auth/requireViewer";
import { json } from "../middleware/json";
import mapMarkerService from "../services/mapMarkerService";
import type { GetPollVoteMapMarkersResponseDto } from "../types/contracts";
import type { RouteDefinition } from "../types/http";

const mapMarkersQuerySchema = z.object({
  pollId: z.string().trim().min(1),
  areaLevel: z.enum(["city", "country"]).optional(),
  parentAreaId: z.string().trim().min(1).optional(),
  countryCode: z.string().trim().min(1).optional(),
  includeEmptyAreas: z.enum(["true", "false", "1", "0"]).optional(),
});

const parseIncludeEmptyAreas = (
  value: "true" | "false" | "1" | "0" | undefined,
): boolean => value === "true" || value === "1";

type MapMarkersRouteDependencies = {
  requireViewerFn?: typeof requireViewer;
  mapMarkerServiceLike?: Pick<typeof mapMarkerService, "getPollVoteMarkers">;
};

export const createGetMapMarkersRoute = (
  dependencies: MapMarkersRouteDependencies = {},
): RouteDefinition => {
  const requireViewerFn = dependencies.requireViewerFn || requireViewer;
  const mapMarkerServiceLike =
    dependencies.mapMarkerServiceLike || mapMarkerService;

  return {
    method: "GET",
    path: "/map/markers",
    handler: async ({ request, url }) => {
      const viewerResult = await requireViewerFn(request);
      if (!viewerResult.ok) {
        return viewerResult.response;
      }

      const parsedQuery = mapMarkersQuerySchema.safeParse({
        pollId: url.searchParams.get("pollId") || undefined,
        areaLevel: url.searchParams.get("areaLevel") || undefined,
        parentAreaId: url.searchParams.get("parentAreaId") || undefined,
        countryCode: url.searchParams.get("countryCode") || undefined,
        includeEmptyAreas: url.searchParams.get("includeEmptyAreas") || undefined,
      });

      if (!parsedQuery.success) {
        return json(
          {
            error: "invalid_request",
            message:
              "Map markers request is invalid. pollId is required (use all_polls for all-polls aggregate mode).",
          },
          400,
        );
      }

      const markers: GetPollVoteMapMarkersResponseDto =
        await mapMarkerServiceLike.getPollVoteMarkers({
          pollId: parsedQuery.data.pollId,
          areaLevel: parsedQuery.data.areaLevel,
          parentAreaId: parsedQuery.data.parentAreaId,
          countryCode: parsedQuery.data.countryCode,
          includeEmptyAreas: parseIncludeEmptyAreas(parsedQuery.data.includeEmptyAreas),
        });

      return json(markers);
    },
  };
};

const getMapMarkersRoute = createGetMapMarkersRoute();

export const mapRoutes: RouteDefinition[] = [getMapMarkersRoute];

export default mapRoutes;
