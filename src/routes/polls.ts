import { z } from "zod";
import requireViewer from "../auth/requireViewer";
import { json } from "../middleware/json";
import pollDraftService from "../services/pollDraftService";
import pollPublicAuditService from "../services/pollPublicAuditService";
import pollVotingService from "../services/pollVotingService";
import type {
  CreatePollRequestDto,
  PollManagementErrorCode,
  UpdateDraftPollRequestDto,
  VoteSubmissionFailureDto,
  VoteSubmissionRequestDto,
} from "../types/contracts";
import type { RouteDefinition } from "../types/http";

const hex64Schema = z
  .string()
  .trim()
  .regex(/^[0-9a-f]{64}$/i)
  .transform((value) => value.toLowerCase());

const votePrivacyModeSchema = z.enum([
  "legacy_identity_linked",
  "zk_preprover_audit",
  "zk_secret_ballot_v1",
]);

const pollEncryptionKeyIdSchema = z
  .string()
  .trim()
  .min(1)
  .nullable()
  .optional();

const voteProofPublicInputsSchema = z
  .object({
    pollId: z.string().trim().min(1),
    pollPolicyHash: hex64Schema,
    credentialSchemaHash: hex64Schema,
    nullifier: hex64Schema,
    verificationMethodVersion: z.string().trim().min(1),
    proofSystemVersion: z.string().trim().min(1),
  })
  .strict();

const voteProofEnvelopeSchema = z
  .object({
    version: z.string().trim().min(1),
    proofSystemVersion: z.string().trim().min(1),
    status: z.string().trim().min(1),
    reason: z.string().trim().min(1).nullable().optional(),
    publicInputs: voteProofPublicInputsSchema,
    publicInputsHash: hex64Schema.nullable().optional(),
  })
  .strict()
  .transform((value) => ({
    ...value,
    reason: value.reason ?? null,
    publicInputsHash: value.publicInputsHash ?? null,
  }));

const votePrivacySchema = z
  .object({
    version: z.string().trim().min(1),
    hashSuite: z.string().trim().min(1),
    nullifier: hex64Schema,
    proof: voteProofEnvelopeSchema,
  })
  .strict();

const phase10ProofSchema = z.union([
  voteProofEnvelopeSchema,
  z.string().trim().min(1),
]);

const voteRequestSchema = z
  .object({
    pollId: z.string().trim().min(1).optional(),
    optionId: z.string().trim().min(1),
    pollPolicyHash: hex64Schema.optional(),
    nullifier: hex64Schema.optional(),
    voteCommitment: hex64Schema.nullable().optional(),
    encryptedVote: z.unknown().optional(),
    proof: phase10ProofSchema.optional(),
    publicInputs: voteProofPublicInputsSchema.optional(),
    feeMode: z.enum(["civicos-sponsored", "user-paid"]).nullable().optional(),
    privacy: votePrivacySchema.nullable().optional(),
  })
  .strict();

const auditInclusionQuerySchema = z.object({
  tree: z.enum(["vote_commitment", "nullifier"]),
  leafHash: hex64Schema,
});

const optionInputSchema = z.union([
  z.string(),
  z.object({
    id: z.string().optional(),
    label: z.string(),
    description: z.string().nullable().optional(),
    color: z.string().nullable().optional(),
  }),
]);

const createPollRequestSchema = z.object({
  title: z.string(),
  description: z.string().nullable().optional(),
  options: z.array(optionInputSchema),
  jurisdictionType: z
    .enum(["global", "real_country", "real_area", "land"])
    .optional(),
  jurisdictionCountryCode: z.string().nullable().optional(),
  jurisdictionAreaIds: z.array(z.string()).optional(),
  jurisdictionLandIds: z.array(z.string()).optional(),
  status: z
    .enum(["draft", "scheduled", "active", "closed", "archived"])
    .optional(),
  eligibilityRule: z
    .object({
      requiresVerifiedIdentity: z.boolean().optional(),
      allowedDocumentCountryCodes: z.array(z.string()).optional(),
      allowedHomeAreaIds: z.array(z.string()).optional(),
      allowedLandIds: z.array(z.string()).optional(),
      minimumAge: z.number().nullable().optional(),
    })
    .nullable()
    .optional(),
  votePrivacyMode: votePrivacyModeSchema.optional(),
  pollEncryptionKeyId: pollEncryptionKeyIdSchema,
});

const updateDraftRequestSchema = createPollRequestSchema.extend({
  pollId: z.string().optional(),
  status: z.enum(["draft", "active"]).optional(),
});

const voteErrorStatusMap: Partial<Record<VoteSubmissionFailureDto["errorCode"], number>> = {
  USER_NOT_FOUND: 401,
  IDENTITY_PROFILE_NOT_FOUND: 403,
  HOME_LOCATION_MISSING: 403,
  POLL_NOT_FOUND: 404,
  POLL_NOT_ACTIVE: 409,
  OPTION_NOT_FOUND: 400,
  OPTION_NOT_IN_POLL: 400,
  ALREADY_VOTED: 409,
  ELIGIBILITY_FAILED: 403,
  PROOF_REQUIRED: 403,
  PROOF_INVALID: 400,
  UNKNOWN_ERROR: 500,
};

const draftErrorStatusMap: Partial<Record<PollManagementErrorCode, number>> = {
  USER_NOT_FOUND: 401,
  POLL_NOT_OWNED: 403,
  VALIDATION_FAILED: 400,
  POLL_NOT_FOUND: 404,
  POLL_NOT_EDITABLE: 409,
  POLL_ALREADY_HAS_VOTES: 409,
};

const auditPublishErrorStatusMap: Record<string, number> = {
  POLL_NOT_FOUND: 404,
  POLL_NOT_OWNED: 403,
  NO_ACCEPTED_AUDIT_VOTES: 409,
  TRANSACTIONS_DISABLED: 409,
  PUBLICATION_FAILED: 502,
};

const getPollsRoute: RouteDefinition = {
  method: "GET",
  path: "/polls",
  handler: async ({ request }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const summaries = await pollVotingService.getPollSummaries(viewerResult.viewer.userId);
    return json(summaries);
  },
};

const createDraftPollRoute: RouteDefinition = {
  method: "POST",
  path: "/polls/drafts",
  handler: async ({ request }) => {
    const viewerResult = await requireViewer(request);
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

    const parsedBody = createPollRequestSchema.safeParse(requestBody);
    if (!parsedBody.success) {
      return json(
        {
          error: "invalid_request",
          message: "Poll draft request body is invalid.",
        },
        400,
      );
    }

    const result = await pollDraftService.createPoll(
      parsedBody.data as CreatePollRequestDto,
      viewerResult.viewer.userId,
    );

    if (result.success) {
      return json(result, 201);
    }

    return json(result, draftErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400);
  },
};

const canEditDraftPollRoute: RouteDefinition = {
  method: "GET",
  path: "/polls/drafts/:id/can-edit",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const pollId = params.id?.trim() || "";
    if (!pollId) {
      return json(
        {
          error: "invalid_poll_id",
          message: "A poll id is required.",
        },
        400,
      );
    }

    const result = await pollDraftService.canEditPoll(pollId, viewerResult.viewer.userId);
    return json(result, result.editable ? 200 : draftErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400);
  },
};

const getDraftPollRoute: RouteDefinition = {
  method: "GET",
  path: "/polls/drafts/:id",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const pollId = params.id?.trim() || "";
    if (!pollId) {
      return json(
        {
          error: "invalid_poll_id",
          message: "A poll id is required.",
        },
        400,
      );
    }

    const result = await pollDraftService.getDraftPollForEditing(
      pollId,
      viewerResult.viewer.userId,
    );

    if (result.success) {
      return json(result);
    }

    return json(result, draftErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400);
  },
};

const updateDraftPollRoute: RouteDefinition = {
  method: "PATCH",
  path: "/polls/drafts/:id",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const pollId = params.id?.trim() || "";
    if (!pollId) {
      return json(
        {
          error: "invalid_poll_id",
          message: "A poll id is required.",
        },
        400,
      );
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

    const parsedBody = updateDraftRequestSchema.safeParse(requestBody);
    if (!parsedBody.success) {
      return json(
        {
          error: "invalid_request",
          message: "Draft update request body is invalid.",
        },
        400,
      );
    }

    const result = await pollDraftService.updateDraftPoll(
      {
        ...(parsedBody.data as UpdateDraftPollRequestDto),
        pollId,
      },
      viewerResult.viewer.userId,
    );

    if (result.success) {
      return json(result);
    }

    return json(result, draftErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400);
  },
};

const publishDraftPollRoute: RouteDefinition = {
  method: "POST",
  path: "/polls/drafts/:id/publish",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const pollId = params.id?.trim() || "";
    if (!pollId) {
      return json(
        {
          error: "invalid_poll_id",
          message: "A poll id is required.",
        },
        400,
      );
    }

    const result = await pollDraftService.publishDraftPoll(
      pollId,
      viewerResult.viewer.userId,
    );

    if (result.success) {
      return json(result);
    }

    return json(result, draftErrorStatusMap[result.errorCode || "VALIDATION_FAILED"] || 400);
  },
};

const getPollDetailsRoute: RouteDefinition = {
  method: "GET",
  path: "/polls/:id",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const pollId = params.id?.trim() || "";
    if (!pollId) {
      return json(
        {
          error: "invalid_poll_id",
          message: "A poll id is required.",
        },
        400,
      );
    }

    const details = await pollVotingService.getPollDetails(pollId, viewerResult.viewer.userId);
    if (!details) {
      return json(
        {
          error: "poll_not_found",
          message: "The requested poll does not exist.",
        },
        404,
      );
    }

    return json(details);
  },
};

type PollAuditRouteDependencies = {
  pollPublicAuditServiceLike?: Partial<Pick<
    typeof pollPublicAuditService,
    | "getPublicPollAudit"
    | "getPublicPollAuditInclusionProof"
    | "getPublicVoteReceipt"
  >>;
};

export const createGetPollAuditRoute = (
  dependencies: PollAuditRouteDependencies = {},
): RouteDefinition => {
  const getPublicPollAudit =
    dependencies.pollPublicAuditServiceLike?.getPublicPollAudit?.bind(
      dependencies.pollPublicAuditServiceLike,
    ) || pollPublicAuditService.getPublicPollAudit.bind(pollPublicAuditService);

  return {
    method: "GET",
    path: "/polls/:id/audit",
    handler: async ({ params }) => {
      const pollId = params.id?.trim() || "";
      if (!pollId) {
        return json(
          {
            error: "invalid_poll_id",
            message: "A poll id is required.",
          },
          400,
        );
      }

      const audit = await getPublicPollAudit(pollId);
      if (!audit) {
        return json(
          {
            error: "poll_not_found",
            message: "The requested poll does not exist.",
          },
          404,
        );
      }

      return json(audit);
    },
  };
};

export const createGetPollAuditInclusionRoute = (
  dependencies: PollAuditRouteDependencies = {},
): RouteDefinition => {
  const getPublicPollAuditInclusionProof =
    dependencies.pollPublicAuditServiceLike?.getPublicPollAuditInclusionProof?.bind(
      dependencies.pollPublicAuditServiceLike,
    ) ||
    pollPublicAuditService.getPublicPollAuditInclusionProof.bind(
      pollPublicAuditService,
    );

  return {
    method: "GET",
    path: "/polls/:id/audit/inclusion",
    handler: async ({ params, url }) => {
      const pollId = params.id?.trim() || "";
      if (!pollId) {
        return json(
          {
            error: "invalid_poll_id",
            message: "A poll id is required.",
          },
          400,
        );
      }

      const parsedQuery = auditInclusionQuerySchema.safeParse({
        tree: url.searchParams.get("tree") || undefined,
        leafHash: url.searchParams.get("leafHash") || undefined,
      });

      if (!parsedQuery.success) {
        return json(
          {
            error: "invalid_request",
            message: "Audit inclusion request is invalid.",
          },
          400,
        );
      }

      const result = await getPublicPollAuditInclusionProof({
        pollId,
        tree: parsedQuery.data.tree,
        leafHash: parsedQuery.data.leafHash,
      });

      if (result.success) {
        return json(result);
      }

      return json(result, 404);
    },
  };
};

export const createGetPollReceiptRoute = (
  dependencies: PollAuditRouteDependencies = {},
): RouteDefinition => {
  const getPublicVoteReceipt =
    dependencies.pollPublicAuditServiceLike?.getPublicVoteReceipt?.bind(
      dependencies.pollPublicAuditServiceLike,
    ) || pollPublicAuditService.getPublicVoteReceipt.bind(pollPublicAuditService);

  return {
    method: "GET",
    path: "/polls/:id/receipt/:voteCommitment",
    handler: async ({ params }) => {
      const pollId = params.id?.trim() || "";
      const voteCommitment = params.voteCommitment?.trim() || "";
      if (!pollId) {
        return json(
          {
            error: "invalid_poll_id",
            message: "A poll id is required.",
          },
          400,
        );
      }

      const parsedVoteCommitment = hex64Schema.safeParse(voteCommitment);
      if (!parsedVoteCommitment.success) {
        return json(
          {
            error: "invalid_request",
            message: "Vote commitment must be a 32-byte hex string.",
          },
          400,
        );
      }

      const receipt = await getPublicVoteReceipt({
        pollId,
        voteCommitment: parsedVoteCommitment.data,
      });
      if (!receipt) {
        return json(
          {
            error: "poll_not_found",
            message: "The requested poll does not exist.",
          },
          404,
        );
      }

      return json(receipt, receipt.included ? 200 : 404);
    },
  };
};

const publishPollAuditRoute: RouteDefinition = {
  method: "POST",
  path: "/polls/:id/audit/publish",
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const pollId = params.id?.trim() || "";
    if (!pollId) {
      return json(
        {
          error: "invalid_poll_id",
          message: "A poll id is required.",
        },
        400,
      );
    }

    const result = await pollPublicAuditService.publishPollAudit({
      pollId,
      viewerUserId: viewerResult.viewer.userId,
    });

    if (result.success) {
      return json(result);
    }

    return json(
      result,
      auditPublishErrorStatusMap[result.errorCode] || 500,
    );
  },
};

const buildVotePrivacyFromRequest = (
  requestBody: z.infer<typeof voteRequestSchema>,
): VoteSubmissionRequestDto["privacy"] => {
  if (requestBody.privacy !== undefined) {
    return requestBody.privacy ?? null;
  }

  if (!requestBody.proof || typeof requestBody.proof === "string") {
    return null;
  }

  return {
    version: "civicos-vote-privacy-v1",
    hashSuite: "sha256-sha512-preposeidon-v1",
    nullifier: requestBody.nullifier || requestBody.proof.publicInputs.nullifier,
    proof: requestBody.proof,
  };
};

const publicInputsMatch = (
  left: z.infer<typeof voteProofPublicInputsSchema>,
  right: z.infer<typeof voteProofPublicInputsSchema>,
): boolean =>
  left.pollId === right.pollId &&
  left.pollPolicyHash === right.pollPolicyHash &&
  left.credentialSchemaHash === right.credentialSchemaHash &&
  left.nullifier === right.nullifier &&
  left.verificationMethodVersion === right.verificationMethodVersion &&
  left.proofSystemVersion === right.proofSystemVersion;

const createSubmitVoteRoute = (path: string): RouteDefinition => ({
  method: "POST",
  path,
  handler: async ({ request, params }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const pollId = params.id?.trim() || "";
    if (!pollId) {
      return json(
        {
          error: "invalid_poll_id",
          message: "A poll id is required.",
        },
        400,
      );
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

    const parsedBody = voteRequestSchema.safeParse(requestBody);
    if (!parsedBody.success) {
      return json(
        {
          error: "invalid_request",
          message: "Vote request body is invalid.",
        },
        400,
      );
    }

    if (parsedBody.data.pollId && parsedBody.data.pollId !== pollId) {
      return json(
        {
          error: "invalid_request",
          message: "Body pollId must match the route poll id.",
        },
        400,
      );
    }

    const privacy = buildVotePrivacyFromRequest(parsedBody.data);
    if (
      parsedBody.data.nullifier &&
      privacy?.nullifier &&
      parsedBody.data.nullifier !== privacy.nullifier
    ) {
      return json(
        {
          error: "invalid_request",
          message: "Body nullifier must match the submitted proof envelope.",
        },
        400,
      );
    }

    if (
      parsedBody.data.pollPolicyHash &&
      privacy?.proof.publicInputs.pollPolicyHash &&
      parsedBody.data.pollPolicyHash !== privacy.proof.publicInputs.pollPolicyHash
    ) {
      return json(
        {
          error: "invalid_request",
          message: "Body pollPolicyHash must match the submitted proof envelope.",
        },
        400,
      );
    }

    if (
      parsedBody.data.publicInputs &&
      privacy?.proof.publicInputs &&
      !publicInputsMatch(parsedBody.data.publicInputs, privacy.proof.publicInputs)
    ) {
      return json(
        {
          error: "invalid_request",
          message: "Body publicInputs must match the submitted proof envelope.",
        },
        400,
      );
    }

    const result = await pollVotingService.submitVote({
      pollId,
      optionId: parsedBody.data.optionId,
      privacy,
      expectedVoteCommitment: parsedBody.data.voteCommitment ?? null,
      viewer: viewerResult.viewer.user,
    });

    if (result.success) {
      return json(result);
    }

    return json(result, voteErrorStatusMap[result.errorCode] || 400);
  },
});

const getPollAuditRoute = createGetPollAuditRoute();
const getPollAuditInclusionRoute = createGetPollAuditInclusionRoute();
const getPollReceiptRoute = createGetPollReceiptRoute();
const submitVoteRoute = createSubmitVoteRoute("/polls/:id/votes");
const submitVotePhase10Route = createSubmitVoteRoute("/polls/:id/vote");

export const pollRoutes: RouteDefinition[] = [
  getPollsRoute,
  createDraftPollRoute,
  canEditDraftPollRoute,
  getDraftPollRoute,
  updateDraftPollRoute,
  publishDraftPollRoute,
  getPollAuditRoute,
  getPollAuditInclusionRoute,
  getPollReceiptRoute,
  publishPollAuditRoute,
  getPollDetailsRoute,
  submitVoteRoute,
  submitVotePhase10Route,
];
