export type RouteContext = {
  request: Request;
  url: URL;
};

export type RouteHandler = (context: RouteContext) => Promise<Response> | Response;

export type RouteDefinition = {
  method: string;
  path: string;
  handler: RouteHandler;
};
