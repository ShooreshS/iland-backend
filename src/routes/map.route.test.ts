import { describe, expect, it } from "bun:test";
import { json } from "../middleware/json";
import { createGetMapMarkersRoute } from "./map";
import type { VoteMapMarkerDto } from "../types/contracts";
import type { UserRow } from "../types/db";

const viewerUser: UserRow = {
  id: "viewer-user-1",
  username: null,
  display_name: null,
  onboarding_status: "not_started",
  verification_level: "anonymous",
  has_wallet: false,
  wallet_credential_id: null,
  selected_land_id: null,
  preferred_language: null,
  created_at: "2026-04-06T00:00:00.000Z",
  updated_at: "2026-04-06T00:00:00.000Z",
};

const sampleMarker: VoteMapMarkerDto = {
  id: "marker_all_polls_city:IR:tehran",
  pollId: "all_polls",
  areaId: "city:IR:tehran",
  areaLevel: "city",
  parentAreaId: "country:IR",
  latitude: 35.6892,
  longitude: 51.389,
  totalVotes: 12,
  optionBreakdown: [
    {
      optionId: "option-1",
      label: "Option 1",
      count: 12,
      color: null,
      percentageWithinArea: 1,
    },
  ],
  leadingOptionId: "option-1",
  leadingOptionLabel: "Option 1",
  leadingOptionColor: null,
  leadingOptionCount: 12,
  leadingOptionPercentage: 1,
  mergedAreaCount: 1,
  privacy: {
    thresholdK: 3,
    mergeStrategy: "hierarchical_parent_k",
    mergedFromAreaIds: ["city:IR:tehran"],
    mergedAreaCount: 1,
    maxMergeDepth: 0,
  },
  updatedAt: "2026-04-06T12:00:00.000Z",
};

const invokeRoute = async (
  route: ReturnType<typeof createGetMapMarkersRoute>,
  query = "pollId=all_polls",
): Promise<Response> => {
  const request = new Request(`http://127.0.0.1:3001/map/markers?${query}`, {
    method: "GET",
  });

  return route.handler({
    request,
    url: new URL(request.url),
    params: {},
  });
};

describe("GET /map/markers route", () => {
  it("routes all-polls marker requests via pollId=all_polls", async () => {
    let receivedInput: unknown = null;

    const route = createGetMapMarkersRoute({
      requireViewerFn: async () => ({
        ok: true,
        viewer: {
          userId: viewerUser.id,
          user: viewerUser,
        },
      }),
      mapMarkerServiceLike: {
        getPollVoteMarkers: async (input) => {
          receivedInput = input;
          return [sampleMarker];
        },
      },
    });

    const response = await invokeRoute(
      route,
      "pollId=all_polls&areaLevel=country&includeEmptyAreas=true",
    );

    expect(response.status).toBe(200);
    expect(receivedInput).toEqual({
      pollId: "all_polls",
      areaLevel: "country",
      parentAreaId: undefined,
      countryCode: undefined,
      includeEmptyAreas: true,
    });

    const body = (await response.json()) as VoteMapMarkerDto[];
    expect(body).toEqual([sampleMarker]);
  });

  it("rejects invalid requests when pollId is missing", async () => {
    let called = false;

    const route = createGetMapMarkersRoute({
      requireViewerFn: async () => ({
        ok: true,
        viewer: {
          userId: viewerUser.id,
          user: viewerUser,
        },
      }),
      mapMarkerServiceLike: {
        getPollVoteMarkers: async () => {
          called = true;
          return [];
        },
      },
    });

    const response = await invokeRoute(route, "areaLevel=city");

    expect(response.status).toBe(400);
    expect(called).toBe(false);
  });

  it("returns requireViewer failure unchanged", async () => {
    const route = createGetMapMarkersRoute({
      requireViewerFn: async () => ({
        ok: false,
        response: json(
          {
            error: "viewer_not_resolved",
            message: "Missing required dev viewer header.",
          },
          401,
        ),
      }),
      mapMarkerServiceLike: {
        getPollVoteMarkers: async () => [sampleMarker],
      },
    });

    const response = await invokeRoute(route, "pollId=all_polls");

    expect(response.status).toBe(401);
    const body = await response.json();
    expect(body.error).toBe("viewer_not_resolved");
  });
});
