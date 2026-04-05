import type { RouteHandler } from "../types/http";

export const withRequestLogging = (handler: RouteHandler): RouteHandler => {
  return async (context) => {
    const startedAt = performance.now();
    const response = await handler(context);
    const elapsedMs = Math.round((performance.now() - startedAt) * 100) / 100;

    console.info("[http]", {
      method: context.request.method,
      path: context.url.pathname,
      status: response.status,
      elapsedMs,
    });

    return response;
  };
};
