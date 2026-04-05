import { healthRoutes } from "./health";
import { pollRoutes } from "./polls";
import type { ResolvedRoute, RouteDefinition } from "../types/http";

export const routes: RouteDefinition[] = [...healthRoutes, ...pollRoutes];

const normalizePath = (path: string): string =>
  path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;

const splitPath = (path: string): string[] =>
  normalizePath(path)
    .split("/")
    .filter(Boolean);

const matchRoutePath = (
  routePath: string,
  requestPath: string,
): Record<string, string> | null => {
  const routeSegments = splitPath(routePath);
  const requestSegments = splitPath(requestPath);

  if (routeSegments.length !== requestSegments.length) {
    return null;
  }

  const params: Record<string, string> = {};

  for (let index = 0; index < routeSegments.length; index += 1) {
    const routeSegment = routeSegments[index];
    const requestSegment = requestSegments[index];

    if (routeSegment.startsWith(":")) {
      const paramName = routeSegment.slice(1);
      if (!paramName) {
        return null;
      }

      params[paramName] = decodeURIComponent(requestSegment);
      continue;
    }

    if (routeSegment !== requestSegment) {
      return null;
    }
  }

  return params;
};

export const resolveRoute = (method: string, path: string): ResolvedRoute | null => {
  const normalizedMethod = method.toUpperCase();

  for (const route of routes) {
    if (route.method.toUpperCase() !== normalizedMethod) {
      continue;
    }

    const params = matchRoutePath(route.path, path);
    if (params) {
      return {
        route,
        params,
      };
    }
  }

  return null;
};
