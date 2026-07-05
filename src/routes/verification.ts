import { z } from "zod";
import { json } from "../middleware/json";
import verificationProofService from "../services/verificationProofService";
import type { VerificationProofRequestDto } from "../types/contracts";
import type { RouteDefinition } from "../types/http";

const hex64Schema = z
  .string()
  .trim()
  .regex(/^[0-9a-f]{64}$/i)
  .transform((value) => value.toLowerCase());

const verificationProofRequestSchema = z
  .object({
    credentialSchemaHash: hex64Schema,
    proof: z.unknown(),
    publicInputs: z
      .object({
        credentialCommitment: hex64Schema,
        verificationMethodVersion: z.string().trim().min(1),
      })
      .strict(),
  })
  .strict();

type VerificationRouteDependencies = {
  verificationProofServiceLike?: Pick<
    typeof verificationProofService,
    "verifyProof"
  >;
};

export const createPostVerificationProofRoute = (
  dependencies: VerificationRouteDependencies = {},
): RouteDefinition => {
  const proofService =
    dependencies.verificationProofServiceLike || verificationProofService;

  return {
    method: "POST",
    path: "/verification/proof",
    handler: async ({ request }) => {
      let requestBody: unknown;
      try {
        requestBody = await request.json();
      } catch {
        return json(
          {
            error: "invalid_request",
            message: "Request body must be valid JSON.",
          },
          400,
        );
      }

      const parsedBody = verificationProofRequestSchema.safeParse(requestBody);
      if (!parsedBody.success) {
        return json(
          {
            error: "invalid_request",
            message: "Verification proof request body is invalid.",
          },
          400,
        );
      }

      const result = proofService.verifyProof(
        parsedBody.data as VerificationProofRequestDto,
      );

      return json(result, result.verified ? 200 : 400);
    },
  };
};

export const verificationRoutes: RouteDefinition[] = [
  createPostVerificationProofRoute(),
];
