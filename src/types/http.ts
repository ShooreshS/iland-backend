export type RouteContext = {
  request: Request;
  url: URL;
  params: Record<string, string>;
};

export type RouteHandler = (context: RouteContext) => Promise<Response> | Response;

export type RouteDefinition = {
  method: string;
  path: string;
  handler: RouteHandler;
};

export type ResolvedRoute = {
  route: RouteDefinition;
  params: Record<string, string>;
};
