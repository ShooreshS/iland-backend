import { z } from "zod";
import requireViewer from "../auth/requireViewer";
import { json } from "../middleware/json";
import credentialIssuanceService from "../services/credentialIssuanceService";
import proofSystemPolicyService from "../services/proofSystemPolicyService";
import verificationProofService from "../services/verificationProofService";
import zkpSecurityPolicyService from "../services/zkpSecurityPolicyService";
import type {
  CredentialIssuanceRequestDto,
  CredentialIssuanceResultDto,
  VerificationProofRequestDto,
} from "../types/contracts";
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

const credentialIssuanceRequestSchema = z
  .object({
    credentialSchemaHash: hex64Schema,
    credentialCommitment: hex64Schema.nullable().optional(),
  })
  .strict();

const credentialIssuanceErrorStatusMap: Record<
  NonNullable<Extract<CredentialIssuanceResultDto, { success: false }>["errorCode"]>,
  number
> = {
  INVALID_INPUT: 400,
  VERIFIED_IDENTITY_REQUIRED: 409,
  IDENTITY_PROFILE_REQUIRED: 409,
  CREDENTIAL_CONFLICT: 409,
};

type VerificationRouteDependencies = {
  requireViewerFn?: typeof requireViewer;
  credentialIssuanceServiceLike?: Pick<
    typeof credentialIssuanceService,
    "issueCredentialForViewer"
  >;
  verificationProofServiceLike?: Pick<
    typeof verificationProofService,
    "verifyProof"
  >;
  proofSystemPolicyServiceLike?: Pick<
    typeof proofSystemPolicyService,
    "getPolicy"
  >;
  zkpSecurityPolicyServiceLike?: Pick<
    typeof zkpSecurityPolicyService,
    "getPolicy"
  >;
};

export const createPostVerificationCredentialRoute = (
  dependencies: VerificationRouteDependencies = {},
): RouteDefinition => {
  const requireViewerFn = dependencies.requireViewerFn || requireViewer;
  const issuanceService =
    dependencies.credentialIssuanceServiceLike || credentialIssuanceService;

  return {
    method: "POST",
    path: "/verification/credential",
    handler: async ({ request }) => {
      const viewerResult = await requireViewerFn(request);
      if (!viewerResult.ok) {
        return viewerResult.response;
      }

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

      const parsedBody = credentialIssuanceRequestSchema.safeParse(requestBody);
      if (!parsedBody.success) {
        return json(
          {
            error: "invalid_request",
            message: "Credential issuance request body is invalid.",
          },
          400,
        );
      }

      const result = await issuanceService.issueCredentialForViewer({
        viewerUserId: viewerResult.viewer.userId,
        ...(parsedBody.data as CredentialIssuanceRequestDto),
      });

      if (result.success) {
        return json(result, result.status === "issued" ? 201 : 200);
      }

      return json(
        result,
        credentialIssuanceErrorStatusMap[result.errorCode || "INVALID_INPUT"],
      );
    },
  };
};

export const createGetVerificationProofSystemRoute = (
  dependencies: VerificationRouteDependencies = {},
): RouteDefinition => {
  const policyService =
    dependencies.proofSystemPolicyServiceLike || proofSystemPolicyService;

  return {
    method: "GET",
    path: "/verification/proof-system",
    handler: () => json(policyService.getPolicy()),
  };
};

export const createGetVerificationSecurityPolicyRoute = (
  dependencies: VerificationRouteDependencies = {},
): RouteDefinition => {
  const policyService =
    dependencies.zkpSecurityPolicyServiceLike || zkpSecurityPolicyService;

  return {
    method: "GET",
    path: "/verification/security-policy",
    handler: () => json(policyService.getPolicy()),
  };
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
  createGetVerificationProofSystemRoute(),
  createGetVerificationSecurityPolicyRoute(),
  createPostVerificationCredentialRoute(),
  createPostVerificationProofRoute(),
];
