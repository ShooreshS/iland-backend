import env from "./config/env";
import { withErrorHandling } from "./middleware/errorHandler";
import { json } from "./middleware/json";
import { withRequestLogging } from "./middleware/requestLogger";
import { resolveRoute } from "./routes";
import { createPollMapRefreshWorker } from "./services/pollMapRefreshWorker";
import type { RouteHandler } from "./types/http";

const baseHandler: RouteHandler = async (context) => {
  const resolvedRoute = resolveRoute(context.request.method, context.url.pathname);

  if (!resolvedRoute) {
    return json(
      {
        error: "not_found",
        message: "Route not found.",
      },
      404,
    );
  }

  return resolvedRoute.route.handler({
    ...context,
    params: resolvedRoute.params,
  });
};

const fetchHandler = withErrorHandling(withRequestLogging(baseHandler));

const pollMapRefreshWorker = createPollMapRefreshWorker({
  intervalMs: env.pollMapRefreshWorker.intervalMs,
  pendingVoteThreshold: env.pollMapRefreshWorker.pendingVoteThreshold,
  maxQueueAgeMs: env.pollMapRefreshWorker.maxDelayMs,
  maxPollsPerCycle: env.pollMapRefreshWorker.maxPollsPerCycle,
  failureRetryCooldownMs: env.pollMapRefreshWorker.failureCooldownMs,
});

if (env.pollMapRefreshWorker.enabled) {
  pollMapRefreshWorker.start();
} else {
  console.info("[pollMapRefreshWorker] disabled");
}

const server = Bun.serve({
  hostname: env.host,
  port: env.port,
  fetch: (request) =>
    fetchHandler({
      request,
      url: new URL(request.url),
      params: {},
    }),
});

console.info(`[server] listening on http://${server.hostname}:${server.port}`);
