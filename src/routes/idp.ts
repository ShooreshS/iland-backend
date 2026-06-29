import { json } from "../middleware/json";
import { hashOpaqueBearerToken } from "../auth/tokens";
import defaultRequireViewer from "../auth/requireViewer";
import defaultAuthSessionRepository from "../repositories/authSessionRepository";
import defaultOidcDiscoveryService from "../services/oidcDiscoveryService";
import defaultOidcProviderService from "../services/oidcProviderService";
import type { RouteDefinition } from "../types/http";

const PUBLIC_METADATA_CACHE_HEADERS = {
  "cache-control": "public, max-age=300",
};

type OidcDiscoveryServiceLike = Pick<
  typeof defaultOidcDiscoveryService,
  "getOpenIdConfiguration" | "getJwks"
>;

type OidcProviderServiceLike = Pick<
  typeof defaultOidcProviderService,
  "validateAuthorizationRequest" | "approveAuthorizationRequest" | "exchangeAuthorizationCode"
>;

export type IdpRouteDependencies = {
  oidcDiscoveryServiceLike?: OidcDiscoveryServiceLike;
  oidcProviderServiceLike?: OidcProviderServiceLike;
  requireViewerFn?: typeof defaultRequireViewer;
  authSessionRepositoryLike?: Pick<
    typeof defaultAuthSessionRepository,
    "getByAccessTokenHash"
  >;
};

const NO_STORE_HEADERS = {
  "cache-control": "no-store",
  pragma: "no-cache",
};

const redirect = (location: string, status = 302): Response =>
  new Response(null, {
    status,
    headers: {
      location,
      ...NO_STORE_HEADERS,
    },
  });

const appendAuthorizeError = (input: {
  redirectUri: string;
  error: string;
  errorDescription?: string;
  state?: string | null;
}): string => {
  const redirectUrl = new URL(input.redirectUri);
  redirectUrl.searchParams.set("error", input.error);
  if (input.errorDescription) {
    redirectUrl.searchParams.set("error_description", input.errorDescription);
  }
  if (input.state) {
    redirectUrl.searchParams.set("state", input.state);
  }
  return redirectUrl.toString();
};

const parseBearerToken = (request: Request): string | null => {
  const authorizationHeader = request.headers.get("authorization")?.trim() || "";
  const match = /^Bearer\s+(.+)$/iu.exec(authorizationHeader);
  return match?.[1] ?? null;
};

const parseFormBody = async (request: Request): Promise<URLSearchParams | null> => {
  try {
    return new URLSearchParams(await request.text());
  } catch {
    return null;
  }
};

export const createIdpRoutes = (
  dependencies: IdpRouteDependencies = {},
): RouteDefinition[] => {
  const oidcDiscoveryService =
    dependencies.oidcDiscoveryServiceLike ?? defaultOidcDiscoveryService;
  const oidcProviderService =
    dependencies.oidcProviderServiceLike ?? defaultOidcProviderService;
  const requireViewer = dependencies.requireViewerFn ?? defaultRequireViewer;
  const authSessionRepository =
    dependencies.authSessionRepositoryLike ?? defaultAuthSessionRepository;

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

  const authorizeRoute: RouteDefinition = {
    method: "GET",
    path: "/idp/authorize",
    handler: async ({ request, url }) => {
      const validation = await oidcProviderService.validateAuthorizationRequest(
        url.searchParams,
      );

      if (!validation.success) {
        if (validation.redirectUri) {
          return redirect(
            appendAuthorizeError({
              redirectUri: validation.redirectUri,
              error: validation.error,
              errorDescription: validation.message,
              state: validation.state,
            }),
          );
        }

        return json(
          {
            error: validation.error,
            error_description: validation.message,
          },
          400,
          NO_STORE_HEADERS,
        );
      }

      const viewerResult = await requireViewer(request);
      if (!viewerResult.ok) {
        // Intention:
        // The first provider slice is code-capable but does not yet render a
        // hosted login/consent UI. A valid authorize request without an active
        // first-party CivicOS bearer session therefore returns the standard
        // OAuth error to the RP redirect URI instead of minting a code.
        return redirect(
          appendAuthorizeError({
            redirectUri: validation.request.redirectUri,
            error: "login_required",
            errorDescription:
              "A CivicOS first-party bearer session is required to approve this authorization request.",
            state: validation.request.state,
          }),
        );
      }

      const rawAccessToken = parseBearerToken(request);
      const authSession = rawAccessToken
        ? await authSessionRepository.getByAccessTokenHash(
            hashOpaqueBearerToken(rawAccessToken),
          )
        : null;

      const result = await oidcProviderService.approveAuthorizationRequest({
        request: validation.request,
        viewer: viewerResult.viewer,
        authSessionId:
          authSession?.user_id === viewerResult.viewer.userId ? authSession.id : null,
      });

      return redirect(result.redirectTo);
    },
  };

  const tokenRoute: RouteDefinition = {
    method: "POST",
    path: "/idp/token",
    handler: async ({ request }) => {
      const form = await parseFormBody(request);
      if (!form) {
        return json(
          {
            error: "invalid_request",
            error_description: "Token request body must be form encoded.",
          },
          400,
          NO_STORE_HEADERS,
        );
      }

      const result = await oidcProviderService.exchangeAuthorizationCode({
        form,
        authorizationHeader: request.headers.get("authorization"),
      });

      if (!result.success) {
        return json(
          {
            error: result.error,
            error_description: result.error_description,
          },
          result.status,
          {
            ...NO_STORE_HEADERS,
            ...(result.error === "invalid_client"
              ? { "www-authenticate": 'Basic realm="CivicOS OIDC"' }
              : {}),
          },
        );
      }

      return json(result.body, 200, NO_STORE_HEADERS);
    },
  };

  return [openIdConfigurationRoute, jwksRoute, authorizeRoute, tokenRoute];
};

export const idpRoutes = createIdpRoutes();

export default idpRoutes;
