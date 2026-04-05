import env from "./config/env";
import { withErrorHandling } from "./middleware/errorHandler";
import { json } from "./middleware/json";
import { withRequestLogging } from "./middleware/requestLogger";
import { resolveRoute } from "./routes";
import type { RouteHandler } from "./types/http";

const baseHandler: RouteHandler = async (context) => {
  const route = resolveRoute(context.request.method, context.url.pathname);

  if (!route) {
    return json(
      {
        error: "not_found",
        message: "Route not found.",
      },
      404,
    );
  }

  return route.handler(context);
};

const fetchHandler = withErrorHandling(withRequestLogging(baseHandler));

const server = Bun.serve({
  hostname: env.host,
  port: env.port,
  fetch: (request) =>
    fetchHandler({
      request,
      url: new URL(request.url),
    }),
});

console.info(`[server] listening on http://${server.hostname}:${server.port}`);
