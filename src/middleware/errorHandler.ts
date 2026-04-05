import type { RouteHandler } from "../types/http";
import { json } from "./json";

export const withErrorHandling = (handler: RouteHandler): RouteHandler => {
  return async (context) => {
    try {
      return await handler(context);
    } catch (error) {
      console.error("[server] unhandled error", {
        message: error instanceof Error ? error.message : String(error),
      });

      return json(
        {
          error: "internal_server_error",
          message: "Unexpected server error.",
        },
        500,
      );
    }
  };
};
