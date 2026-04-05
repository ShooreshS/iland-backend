import { healthRoutes } from "./health";
import type { RouteDefinition } from "../types/http";

export const routes: RouteDefinition[] = [...healthRoutes];

export const resolveRoute = (method: string, path: string): RouteDefinition | null => {
  const normalizedPath =
    path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;

  return (
    routes.find(
      (route) =>
        route.method.toUpperCase() === method.toUpperCase() &&
        route.path === normalizedPath,
    ) || null
  );
};
