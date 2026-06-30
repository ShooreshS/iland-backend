import { createHash } from "node:crypto";
import { createRequire } from "node:module";

import { json } from "../middleware/json";
import { hashOpaqueBearerToken } from "../auth/tokens";
import defaultRequireViewer from "../auth/requireViewer";
import defaultAuthSessionRepository from "../repositories/authSessionRepository";
import defaultOidcAuditEventRepository, {
  type NewOidcAuditEventRow,
} from "../repositories/oidcAuditEventRepository";
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
  oidcAuditEventRepositoryLike?: Pick<
    typeof defaultOidcAuditEventRepository,
    "insert"
  > | null;
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

const OIDC_RATE_LIMITS = {
  authorize: { limit: 80, windowMs: 60_000 },
  authorizeApprove: { limit: 30, windowMs: 60_000 },
  token: { limit: 40, windowMs: 60_000 },
} as const;

type OidcRateLimitName = keyof typeof OIDC_RATE_LIMITS;

type RateLimitBucket = {
  count: number;
  resetAtMs: number;
};

const rateLimitBuckets = new Map<string, RateLimitBucket>();
let lastRateLimitPruneMs = 0;

const hashAuditValue = (value: string | null): string | null => {
  const normalized = value?.trim();
  if (!normalized) {
    return null;
  }

  return createHash("sha256")
    .update(`civicos:oidc-audit:v1:${normalized}`, "utf8")
    .digest("hex");
};

const getClientAddress = (request: Request): string =>
  request.headers.get("cf-connecting-ip")?.split(",")[0]?.trim() ||
  request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
  "unknown";

const getAuditHashes = (request: Request) => ({
  ip_hash: hashAuditValue(getClientAddress(request)),
  user_agent_hash: hashAuditValue(request.headers.get("user-agent")),
});

const consumeRateLimit = (input: {
  request: Request;
  name: OidcRateLimitName;
  subject?: string | null;
}):
  | { allowed: true }
  | {
      allowed: false;
      retryAfterSeconds: number;
      limit: number;
      resetAtMs: number;
    } => {
  const policy = OIDC_RATE_LIMITS[input.name];
  const subject = input.subject?.trim() || "unknown";
  const key = `${input.name}:${getClientAddress(input.request)}:${subject}`;
  const nowMs = Date.now();

  if (nowMs - lastRateLimitPruneMs > 60_000) {
    lastRateLimitPruneMs = nowMs;
    for (const [bucketKey, bucket] of rateLimitBuckets.entries()) {
      if (bucket.resetAtMs <= nowMs) {
        rateLimitBuckets.delete(bucketKey);
      }
    }
  }

  const existing = rateLimitBuckets.get(key);

  if (!existing || existing.resetAtMs <= nowMs) {
    rateLimitBuckets.set(key, {
      count: 1,
      resetAtMs: nowMs + policy.windowMs,
    });
    return { allowed: true };
  }

  if (existing.count >= policy.limit) {
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil((existing.resetAtMs - nowMs) / 1000)),
      limit: policy.limit,
      resetAtMs: existing.resetAtMs,
    };
  }

  existing.count += 1;
  return { allowed: true };
};

const rateLimitResponse = (decision: Exclude<ReturnType<typeof consumeRateLimit>, { allowed: true }>) =>
  json(
    {
      error: "rate_limited",
      error_description: "Too many requests. Try again later.",
    },
    429,
    {
      ...NO_STORE_HEADERS,
      "retry-after": String(decision.retryAfterSeconds),
      "x-ratelimit-limit": String(decision.limit),
      "x-ratelimit-reset": new Date(decision.resetAtMs).toISOString(),
    },
  );

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
  const appLinkUrl = new URL("com.shooresh.iland://oidc/authorize");
  appLinkUrl.searchParams.set("payload", qrPayloadText);
  const escapedClientName = escapeHtml(input.clientName);
  const escapedScopes = escapeHtml(input.scopes.join(" "));
  const escapedExpiresAt = escapeHtml(input.expiresAt);
  const escapedAppLinkUrl = escapeHtml(appLinkUrl.toString());
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
      .app-link { display: inline-flex; align-items: center; justify-content: center; min-height: 48px; margin: 6px auto 10px; padding: 0 18px; border-radius: 999px; background: #155eef; color: #fff; text-decoration: none; font-weight: 700; }
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
      <p>Scan this code from CivicOS on another device, or continue on this device.</p>
      <a class="app-link" href="${escapedAppLinkUrl}" target="_top" rel="noopener">Open CivicOS app</a>
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
            if (window.parent && window.parent !== window) {
              window.parent.postMessage({
                type: "civicos.oidc.authorize.redirect",
                redirectTo: result.redirectTo
              }, "*");
            }
            window.location.assign(result.redirectTo);
            return;
          }
          if (result?.status === "denied" && result?.redirectTo) {
            stopped = true;
            statusElement.textContent = "Request denied. Returning to the website…";
            if (window.parent && window.parent !== window) {
              window.parent.postMessage({
                type: "civicos.oidc.authorize.redirect",
                redirectTo: result.redirectTo
              }, "*");
            }
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
  const oidcAuditEventRepository =
    dependencies.oidcAuditEventRepositoryLike === undefined
      ? defaultOidcAuditEventRepository
      : dependencies.oidcAuditEventRepositoryLike;

  const writeAuditEvent = async (
    request: Request,
    input: Omit<
      NewOidcAuditEventRow,
      "ip_hash" | "user_agent_hash" | "occurred_at"
    >,
  ): Promise<void> => {
    if (!oidcAuditEventRepository) {
      return;
    }

    try {
      await oidcAuditEventRepository.insert({
        ...input,
        ...getAuditHashes(request),
      });
    } catch (error) {
      // Audit is required for security visibility, but it must not make the IdP
      // unavailable. The request outcome remains authoritative; failed audit
      // persistence is surfaced to server logs for operational follow-up.
      console.warn("[idp] oidc audit insert failed", {
        eventType: input.event_type,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  };

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
      const requestedClientId = url.searchParams.get("client_id")?.trim() || null;
      const authorizeLimit = consumeRateLimit({
        request,
        name: "authorize",
        subject: requestedClientId,
      });
      if (!authorizeLimit.allowed) {
        await writeAuditEvent(request, {
          event_type: "oidc_authorize_rate_limited",
          metadata: {
            clientId: requestedClientId,
            path: "/idp/authorize",
          },
        });
        return rateLimitResponse(authorizeLimit);
      }

      const validation = await oidcProviderService.validateAuthorizationRequest(
        url.searchParams,
      );

      if (!validation.success) {
        await writeAuditEvent(request, {
          event_type: "oidc_authorize_failed",
          metadata: {
            clientId: requestedClientId,
            error: validation.error,
            hasRedirectUri: Boolean(validation.redirectUri),
          },
        });

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
        const issuer = oidcDiscoveryService.getOpenIdConfiguration().issuer;
        // Railway may pass the upstream request URL to Bun as http:// even when
        // the public browser URL is https://. Build browser-visible IdP URLs
        // from the configured issuer so the QR page never performs mixed-content
        // polling from an HTTPS iframe.
        const statusUrl = new URL(
          "authorize/status",
          issuer.endsWith("/") ? issuer : `${issuer}/`,
        );
        statusUrl.searchParams.set("requestId", qrTransaction.requestId);
        statusUrl.searchParams.set("pollSecret", qrTransaction.pollSecret);

        await writeAuditEvent(request, {
          client_id: validation.request.client.id,
          event_type: "oidc_authorize_qr_created",
          metadata: {
            clientId: validation.request.client.client_id,
            requestId: qrTransaction.requestId,
            scopes: validation.request.scopes,
          },
        });

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

      await writeAuditEvent(request, {
        user_id: viewerResult.viewer.userId,
        client_id: validation.request.client.id,
        auth_session_id:
          authSession?.user_id === viewerResult.viewer.userId ? authSession.id : null,
        event_type: "oidc_authorize_direct_approved",
        metadata: {
          clientId: validation.request.client.client_id,
          scopes: validation.request.scopes,
        },
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
      const body = await parseJsonBody(request);
      const requestId = toNonEmptyString(body?.requestId);
      const secret = toNonEmptyString(body?.secret);
      const approvedClaims =
        body?.approvedClaims &&
        typeof body.approvedClaims === "object" &&
        !Array.isArray(body.approvedClaims)
          ? (body.approvedClaims as Record<string, unknown>)
          : null;

      const approveLimit = consumeRateLimit({
        request,
        name: "authorizeApprove",
        subject: requestId,
      });
      if (!approveLimit.allowed) {
        await writeAuditEvent(request, {
          event_type: "oidc_authorize_approve_rate_limited",
          metadata: {
            requestId,
            path: "/idp/authorize/approve",
          },
        });
        return rateLimitResponse(approveLimit);
      }

      const viewerResult = await requireViewer(request);
      if (!viewerResult.ok) {
        await writeAuditEvent(request, {
          event_type: "oidc_authorize_approve_unauthorized",
          metadata: {
            requestId,
          },
        });
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

      if (!requestId || !secret) {
        await writeAuditEvent(request, {
          user_id: viewerResult.viewer.userId,
          event_type: "oidc_authorize_approve_failed",
          metadata: {
            error: "invalid_request",
            hasRequestId: Boolean(requestId),
            hasSecret: Boolean(secret),
          },
        });
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
        await writeAuditEvent(request, {
          user_id: viewerResult.viewer.userId,
          auth_session_id:
            authSession?.user_id === viewerResult.viewer.userId ? authSession.id : null,
          event_type: "oidc_authorize_approve_failed",
          metadata: {
            requestId,
            error: result.error,
            status: result.status,
          },
        });
        return json(
          {
            ok: false,
            error: result.error,
          },
          result.status,
          NO_STORE_HEADERS,
        );
      }

      await writeAuditEvent(request, {
        user_id: viewerResult.viewer.userId,
        auth_session_id:
          authSession?.user_id === viewerResult.viewer.userId ? authSession.id : null,
        event_type: "oidc_authorize_approve_succeeded",
        metadata: {
          requestId,
          approvedClaimKeys: Object.entries(approvedClaims ?? {})
            .filter(([, value]) => value === true)
            .map(([key]) => key),
        },
      });

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
        await writeAuditEvent(request, {
          event_type: "oidc_token_failed",
          metadata: {
            error: "invalid_request",
            reason: "body_not_form_encoded",
          },
        });
        return json(
          {
            error: "invalid_request",
            error_description: "Token request body must be form encoded.",
          },
          400,
          NO_STORE_HEADERS,
        );
      }

      const tokenClientId = form.get("client_id")?.trim() || "basic-auth";
      const tokenLimit = consumeRateLimit({
        request,
        name: "token",
        subject: tokenClientId,
      });
      if (!tokenLimit.allowed) {
        await writeAuditEvent(request, {
          event_type: "oidc_token_rate_limited",
          metadata: {
            clientId: tokenClientId,
            grantType: form.get("grant_type") || null,
          },
        });
        return rateLimitResponse(tokenLimit);
      }

      const result = await oidcProviderService.exchangeAuthorizationCode({
        form,
        authorizationHeader: request.headers.get("authorization"),
      });

      if (!result.success) {
        await writeAuditEvent(request, {
          event_type: "oidc_token_failed",
          metadata: {
            clientId: tokenClientId,
            grantType: form.get("grant_type") || null,
            error: result.error,
            status: result.status,
          },
        });
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

      await writeAuditEvent(request, {
        user_id: result.audit.userId,
        client_id: result.audit.clientDbId,
        auth_session_id: result.audit.authSessionId,
        authorization_request_id: result.audit.authorizationRequestId,
        grant_id: result.audit.grantId,
        event_type: "oidc_token_succeeded",
        metadata: {
          clientId: result.audit.clientId,
          grantType: form.get("grant_type") || null,
          scopes: result.audit.scopes,
          issuedRefreshToken: result.audit.issuedRefreshToken,
        },
      });

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
        await writeAuditEvent(request, {
          event_type: "oidc_revoke_failed",
          metadata: {
            error: "invalid_request",
            reason: "body_not_form_encoded",
          },
        });
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
        await writeAuditEvent(request, {
          event_type: "oidc_revoke_failed",
          metadata: {
            clientId: form.get("client_id")?.trim() || "basic-auth",
            tokenTypeHint: form.get("token_type_hint")?.trim() || null,
            error: result.error,
            status: result.status,
          },
        });
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

      await writeAuditEvent(request, {
        event_type: "oidc_revoke_succeeded",
        metadata: {
          clientId: form.get("client_id")?.trim() || "basic-auth",
          tokenTypeHint: form.get("token_type_hint")?.trim() || null,
        },
      });

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
