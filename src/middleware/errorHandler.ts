import type { RouteHandler } from "../types/http";
import { json } from "./json";

const toErrorMessage = (error: unknown): string => {
  if (error instanceof Error) {
    return error.message;
  }

  if (
    error &&
    typeof error === "object" &&
    "message" in error &&
    typeof (error as { message?: unknown }).message === "string"
  ) {
    return (error as { message: string }).message;
  }

  return String(error);
};

export const withErrorHandling = (handler: RouteHandler): RouteHandler => {
  return async (context) => {
    try {
      return await handler(context);
    } catch (error) {
      console.error(
        "[server] unhandled error",
        error instanceof Error
          ? {
              name: error.name,
              message: error.message,
              stack: error.stack,
            }
          : {
              message: toErrorMessage(error),
              rawError: error,
            },
      );

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
