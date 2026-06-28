import { json } from "../middleware/json";
import defaultOidcDiscoveryService from "../services/oidcDiscoveryService";
import type { RouteDefinition } from "../types/http";

const PUBLIC_METADATA_CACHE_HEADERS = {
  "cache-control": "public, max-age=300",
};

type OidcDiscoveryServiceLike = Pick<
  typeof defaultOidcDiscoveryService,
  "getOpenIdConfiguration" | "getJwks"
>;

export type IdpRouteDependencies = {
  oidcDiscoveryServiceLike?: OidcDiscoveryServiceLike;
};

export const createIdpRoutes = (
  dependencies: IdpRouteDependencies = {},
): RouteDefinition[] => {
  const oidcDiscoveryService =
    dependencies.oidcDiscoveryServiceLike ?? defaultOidcDiscoveryService;

  const openIdConfigurationRoute: RouteDefinition = {
    method: "GET",
    path: "/idp/.well-known/openid-configuration",
    handler: () =>
      json(oidcDiscoveryService.getOpenIdConfiguration(), 200, {
        ...PUBLIC_METADATA_CACHE_HEADERS,
      }),
  };

  const jwksRoute: RouteDefinition = {
    method: "GET",
    path: "/idp/jwks",
    handler: async () =>
      json(await oidcDiscoveryService.getJwks(), 200, {
        ...PUBLIC_METADATA_CACHE_HEADERS,
      }),
  };

  return [openIdConfigurationRoute, jwksRoute];
};

export const idpRoutes = createIdpRoutes();

export default idpRoutes;
