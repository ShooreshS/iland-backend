import { json } from "../middleware/json";
import viewerProfileService from "../services/viewerProfileService";
import type { RouteDefinition } from "../types/http";

const getPollCreationReferenceRoute: RouteDefinition = {
  method: "GET",
  path: "/reference/poll-creation",
  handler: async () => {
    const referenceData = await viewerProfileService.getPollCreationReferenceData();
    return json(referenceData);
  },
};

const getLandsRoute: RouteDefinition = {
  method: "GET",
  path: "/lands",
  handler: async () => {
    const lands = await viewerProfileService.getLands();
    return json(lands);
  },
};

export const referenceRoutes: RouteDefinition[] = [
  getPollCreationReferenceRoute,
  getLandsRoute,
];

export default referenceRoutes;
