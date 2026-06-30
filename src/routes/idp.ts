import { createRequire } from "node:module";

import { json } from "../middleware/json";
import { hashOpaqueBearerToken } from "../auth/tokens";
import defaultRequireViewer from "../auth/requireViewer";
import defaultAuthSessionRepository from "../repositories/authSessionRepository";
import defaultOidcDiscoveryService from "../services/oidcDiscoveryService";
import defaultOidcProviderService from "../services/oidcProviderService";
import type { RouteDefinition } from "../types/http";

const require = createRequire(import.meta.url);
const qrCode = require("qrcode") as {
  toString: (
    value: string,
    options: {
      type: "svg";
      errorCorrectionLevel: "L" | "M" | "Q" | "H";
      margin: number;
      width: number;
    },
  ) => Promise<string>;
};

const PUBLIC_METADATA_CACHE_HEADERS = {
  "cache-control": "public, max-age=300",
};

type OidcDiscoveryServiceLike = Pick<
  typeof defaultOidcDiscoveryService,
  "getOpenIdConfiguration" | "getJwks"
>;

type OidcProviderServiceLike = Pick<
  typeof defaultOidcProviderService,
  | "validateAuthorizationRequest"
  | "approveAuthorizationRequest"
  | "createAuthorizationQrTransaction"
  | "getAuthorizationQrTransactionStatus"
  | "previewAuthorizationQrTransaction"
  | "approveAuthorizationQrTransaction"
  | "denyAuthorizationQrTransaction"
  | "exchangeAuthorizationCode"
  | "getUserInfo"
  | "revokeToken"
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

const bearerChallenge = (input?: {
  error?: string;
  errorDescription?: string;
}): string => {
  const parts = ['Bearer realm="CivicOS OIDC"'];
  if (input?.error) {
    parts.push(`error="${input.error.replace(/"/gu, '\\"')}"`);
  }
  if (input?.errorDescription) {
    parts.push(
      `error_description="${input.errorDescription.replace(/"/gu, '\\"')}"`,
    );
  }
  return parts.join(", ");
};

const parseFormBody = async (request: Request): Promise<URLSearchParams | null> => {
  try {
    return new URLSearchParams(await request.text());
  } catch {
    return null;
  }
};

const parseJsonBody = async (request: Request): Promise<Record<string, unknown> | null> => {
  try {
    const parsed = JSON.parse(await request.text());
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed
      : null;
  } catch {
    return null;
  }
};

const toNonEmptyString = (value: unknown): string | null =>
  typeof value === "string" && value.trim().length > 0 ? value.trim() : null;

const escapeHtml = (value: string): string =>
  value
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;")
    .replace(/'/gu, "&#39;");

const createQrSvgDataUrl = async (value: string): Promise<string> => {
  const svg = await qrCode.toString(value, {
    type: "svg",
    errorCorrectionLevel: "M",
    margin: 1,
    width: 280,
  });

  return `data:image/svg+xml;base64,${Buffer.from(svg, "utf8").toString("base64")}`;
};

const renderAuthorizeQrPage = async (input: {
  clientName: string;
  scopes: string[];
  expiresAt: string;
  qrPayload: Record<string, unknown>;
  statusUrl: string;
}): Promise<Response> => {
  const qrPayloadText = JSON.stringify(input.qrPayload);
  const qrSvgDataUrl = await createQrSvgDataUrl(qrPayloadText);
  const escapedClientName = escapeHtml(input.clientName);
  const escapedScopes = escapeHtml(input.scopes.join(" "));
  const escapedExpiresAt = escapeHtml(input.expiresAt);
  const statusUrlJson = JSON.stringify(input.statusUrl);

  return new Response(
    `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>CivicOS authorization</title>
    <style>
      :root { color-scheme: light dark; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
      body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f4f6fb; color: #101828; }
      main { width: min(92vw, 440px); padding: 28px; border-radius: 24px; background: #fff; box-shadow: 0 24px 80px rgba(16, 24, 40, 0.14); text-align: center; }
      h1 { margin: 0 0 8px; font-size: 26px; }
      p { line-height: 1.45; }
      .qr { width: 280px; height: 280px; margin: 20px auto; border-radius: 18px; background: #fff; padding: 12px; border: 1px solid #e4e7ec; }
      .status { margin-top: 18px; color: #475467; }
      .meta { margin-top: 18px; padding-top: 18px; border-top: 1px solid #eaecf0; font-size: 13px; color: #667085; text-align: left; }
      code { overflow-wrap: anywhere; }
      @media (prefers-color-scheme: dark) {
        body { background: #101828; color: #f9fafb; }
        main { background: #1d2939; box-shadow: none; }
        .status, .meta { color: #d0d5dd; }
      }
    </style>
  </head>
  <body>
    <main>
      <h1>Approve with CivicOS</h1>
      <p><strong>${escapedClientName}</strong> is requesting CivicOS login.</p>
      <img class="qr" src="${qrSvgDataUrl}" alt="CivicOS authorization QR code" />
      <p>Open CivicOS, go to Profile, tap the QR scanner icon, and scan this code.</p>
      <p id="status" class="status" aria-live="polite">Waiting for approval…</p>
      <div class="meta">
        <div>Scopes: <code>${escapedScopes}</code></div>
        <div>Expires: <code>${escapedExpiresAt}</code></div>
      </div>
    </main>
    <script>
      const statusElement = document.getElementById("status");
      const statusUrl = ${statusUrlJson};
      let stopped = false;
      async function poll() {
        if (stopped) return;
        try {
          const response = await fetch(statusUrl, { headers: { accept: "application/json" } });
          const result = await response.json().catch(() => null);
          if (response.status === 410 || result?.status === "expired") {
            stopped = true;
            statusElement.textContent = "This authorization code expired. Start login again.";
            return;
          }
          if (!response.ok) {
            throw new Error("status " + response.status);
          }
          if (result?.status === "approved" && result?.redirectTo) {
            stopped = true;
            statusElement.textContent = "Approved. Returning to the website…";
            window.location.assign(result.redirectTo);
            return;
          }
          if (result?.status === "denied" && result?.redirectTo) {
            stopped = true;
            statusElement.textContent = "Request denied. Returning to the website…";
            window.location.assign(result.redirectTo);
            return;
          }
          statusElement.textContent = "Waiting for CivicOS approval…";
        } catch (error) {
          statusElement.textContent = "Could not check approval yet. Retrying…";
        }
        window.setTimeout(poll, 1500);
      }
      poll();
    </script>
  </body>
</html>`,
    {
      status: 200,
      headers: {
        "content-type": "text/html; charset=utf-8",
        ...NO_STORE_HEADERS,
      },
    },
  );
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
        // Hosted authorize UI:
        // Browser requests from relying parties do not carry the app bearer
        // token. We therefore render a short-lived QR challenge. The CivicOS app
        // scans it and approves through /idp/authorize/approve with the current
        // first-party session, then this page polls and redirects the browser
        // back to the RP with a normal authorization code.
        const qrTransaction =
          oidcProviderService.createAuthorizationQrTransaction(validation.request);
        const statusUrl = new URL("/idp/authorize/status", url.origin);
        statusUrl.searchParams.set("requestId", qrTransaction.requestId);
        statusUrl.searchParams.set("pollSecret", qrTransaction.pollSecret);

        return renderAuthorizeQrPage({
          clientName: validation.request.client.client_name,
          scopes: validation.request.scopes,
          expiresAt: qrTransaction.expiresAt,
          qrPayload: qrTransaction.qrPayload,
          statusUrl: statusUrl.toString(),
        });
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

  const authorizeStatusRoute: RouteDefinition = {
    method: "GET",
    path: "/idp/authorize/status",
    handler: ({ url }) => {
      const requestId = url.searchParams.get("requestId")?.trim() || "";
      const pollSecret = url.searchParams.get("pollSecret")?.trim() || "";

      if (!requestId || !pollSecret) {
        return json(
          {
            status: "not_found",
            error: "requestId and pollSecret are required.",
          },
          400,
          NO_STORE_HEADERS,
        );
      }

      const status = oidcProviderService.getAuthorizationQrTransactionStatus({
        requestId,
        pollSecret,
      });

      if (status.status === "not_found") {
        return json(status, 404, NO_STORE_HEADERS);
      }

      if (status.status === "expired") {
        return json(status, 410, NO_STORE_HEADERS);
      }

      return json(status, 200, NO_STORE_HEADERS);
    },
  };

  const authorizeApproveRoute: RouteDefinition = {
    method: "POST",
    path: "/idp/authorize/approve",
    handler: async ({ request }) => {
      const viewerResult = await requireViewer(request);
      if (!viewerResult.ok) {
        return json(
          {
            ok: false,
            error: "unauthorized",
            message: "Sign in to CivicOS before approving this login request.",
          },
          401,
          NO_STORE_HEADERS,
        );
      }

      const body = await parseJsonBody(request);
      const requestId = toNonEmptyString(body?.requestId);
      const secret = toNonEmptyString(body?.secret);
      const approvedClaims =
        body?.approvedClaims &&
        typeof body.approvedClaims === "object" &&
        !Array.isArray(body.approvedClaims)
          ? (body.approvedClaims as Record<string, unknown>)
          : null;

      if (!requestId || !secret) {
        return json(
          {
            ok: false,
            error: "invalid_request",
            message: "requestId and secret are required.",
          },
          400,
          NO_STORE_HEADERS,
        );
      }

      const rawAccessToken = parseBearerToken(request);
      const authSession = rawAccessToken
        ? await authSessionRepository.getByAccessTokenHash(
            hashOpaqueBearerToken(rawAccessToken),
          )
        : null;

      const result = await oidcProviderService.approveAuthorizationQrTransaction({
        requestId,
        secret,
        viewer: viewerResult.viewer,
        authSessionId:
          authSession?.user_id === viewerResult.viewer.userId ? authSession.id : null,
        approvedClaims,
      });

      if (!result.success) {
        return json(
          {
            ok: false,
            error: result.error,
          },
          result.status,
          NO_STORE_HEADERS,
        );
      }

      return json({ ok: true }, 200, NO_STORE_HEADERS);
    },
  };

  const authorizePreviewRoute: RouteDefinition = {
    method: "POST",
    path: "/idp/authorize/preview",
    handler: async ({ request }) => {
      const viewerResult = await requireViewer(request);
      if (!viewerResult.ok) {
        return json(
          {
            ok: false,
            error: "unauthorized",
            message: "Sign in to CivicOS before reviewing this login request.",
          },
          401,
          NO_STORE_HEADERS,
        );
      }

      const body = await parseJsonBody(request);
      const requestId = toNonEmptyString(body?.requestId);
      const secret = toNonEmptyString(body?.secret);

      if (!requestId || !secret) {
        return json(
          {
            ok: false,
            error: "invalid_request",
            message: "requestId and secret are required.",
          },
          400,
          NO_STORE_HEADERS,
        );
      }

      const result = await oidcProviderService.previewAuthorizationQrTransaction({
        requestId,
        secret,
        viewer: viewerResult.viewer,
      });

      if (!result.success) {
        return json(
          {
            ok: false,
            error: result.error,
          },
          result.status,
          NO_STORE_HEADERS,
        );
      }

      return json({ ok: true, ...result.body }, 200, NO_STORE_HEADERS);
    },
  };

  const authorizeDenyRoute: RouteDefinition = {
    method: "POST",
    path: "/idp/authorize/deny",
    handler: async ({ request }) => {
      const viewerResult = await requireViewer(request);
      if (!viewerResult.ok) {
        return json(
          {
            ok: false,
            error: "unauthorized",
            message: "Sign in to CivicOS before denying this login request.",
          },
          401,
          NO_STORE_HEADERS,
        );
      }

      const body = await parseJsonBody(request);
      const requestId = toNonEmptyString(body?.requestId);
      const secret = toNonEmptyString(body?.secret);

      if (!requestId || !secret) {
        return json(
          {
            ok: false,
            error: "invalid_request",
            message: "requestId and secret are required.",
          },
          400,
          NO_STORE_HEADERS,
        );
      }

      const result = oidcProviderService.denyAuthorizationQrTransaction({
        requestId,
        secret,
      });

      if (!result.success) {
        return json(
          {
            ok: false,
            error: result.error,
          },
          result.status,
          NO_STORE_HEADERS,
        );
      }

      return json({ ok: true }, 200, NO_STORE_HEADERS);
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

  const userInfoHandler = async (request: Request): Promise<Response> => {
    const accessToken = parseBearerToken(request);
    if (!accessToken) {
      return json(
        {
          error: "invalid_token",
          error_description: "Bearer access token is required.",
        },
        401,
        {
          ...NO_STORE_HEADERS,
          "www-authenticate": bearerChallenge({
            error: "invalid_token",
            errorDescription: "Bearer access token is required.",
          }),
        },
      );
    }

    const result = await oidcProviderService.getUserInfo({ accessToken });
    if (!result.success) {
      return json(
        {
          error: result.error,
          error_description: result.error_description,
        },
        result.status,
        {
          ...NO_STORE_HEADERS,
          ...(result.error === "invalid_token"
            ? {
                "www-authenticate": bearerChallenge({
                  error: result.error,
                  errorDescription: result.error_description,
                }),
              }
            : {}),
        },
      );
    }

    return json(result.body, 200, NO_STORE_HEADERS);
  };

  const userInfoGetRoute: RouteDefinition = {
    method: "GET",
    path: "/idp/userinfo",
    handler: async ({ request }) => userInfoHandler(request),
  };

  const userInfoPostRoute: RouteDefinition = {
    method: "POST",
    path: "/idp/userinfo",
    handler: async ({ request }) => userInfoHandler(request),
  };

  const revokeRoute: RouteDefinition = {
    method: "POST",
    path: "/idp/revoke",
    handler: async ({ request }) => {
      const form = await parseFormBody(request);
      if (!form) {
        return json(
          {
            error: "invalid_request",
            error_description: "Revocation request body must be form encoded.",
          },
          400,
          NO_STORE_HEADERS,
        );
      }

      const result = await oidcProviderService.revokeToken({
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

      return json({ ok: true }, 200, NO_STORE_HEADERS);
    },
  };

  return [
    openIdConfigurationRoute,
    jwksRoute,
    authorizeRoute,
    authorizeStatusRoute,
    authorizePreviewRoute,
    authorizeApproveRoute,
    authorizeDenyRoute,
    tokenRoute,
    userInfoGetRoute,
    userInfoPostRoute,
    revokeRoute,
  ];
};

export const idpRoutes = createIdpRoutes();

export default idpRoutes;
