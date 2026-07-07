import { z } from "zod";
import requireViewer from "../auth/requireViewer";
import { json } from "../middleware/json";
import pollDraftService from "../services/pollDraftService";
import pollPublicAuditService from "../services/pollPublicAuditService";
import pollVotingService from "../services/pollVotingService";
import type { Groth16TallyProofEnvelopeDto } from "../services/groth16TallyProofVerifierService";
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

const productionVoteProofPublicInputsSchema = z
  .object({
    version: z.string().trim().min(1),
    pollId: z.string().trim().min(1),
    pollPolicyHash: hex64Schema,
    credentialSchemaHash: hex64Schema,
    optionSetHash: hex64Schema,
    credentialRoot: hex64Schema,
    nullifier: hex64Schema,
    voteCommitment: hex64Schema,
    encryptedVoteHash: hex64Schema,
    encryptedVoteCommitment: hex64Schema,
    verificationMethodVersion: z.string().trim().min(1),
    proofSystemVersion: z.string().trim().min(1),
    hashSuite: z.string().trim().min(1),
    circuitId: z.string().trim().min(1),
    verifierKeyHash: hex64Schema,
    publicInputSchemaVersion: z.string().trim().min(1),
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

const productionVoteProofEnvelopeSchema = z
  .object({
    version: z.string().trim().min(1),
    protocol: z.literal("groth16"),
    proofSystemVersion: z.string().trim().min(1),
    status: z.string().trim().min(1),
    hashSuite: z.string().trim().min(1),
    circuitId: z.string().trim().min(1),
    verifierKeyHash: hex64Schema,
    publicInputSchemaVersion: z.string().trim().min(1),
    proof: z.record(z.unknown()),
    publicInputs: productionVoteProofPublicInputsSchema,
    publicInputsHash: hex64Schema,
  })
  .strict();

const tallyProofPublicInputsSchema = z
  .object({
    version: z.string().trim().min(1),
    pollId: z.string().trim().min(1),
    pollPolicyHash: hex64Schema,
    credentialSchemaHash: hex64Schema,
    optionSetHash: hex64Schema,
    nullifierRoot: hex64Schema,
    voteCommitmentRoot: hex64Schema,
    encryptedVoteRoot: hex64Schema,
    acceptedVoteCount: z.number().int().nonnegative(),
    optionResults: z.array(
      z
        .object({
          optionId: z.string().trim().min(1),
          count: z.number().int().nonnegative(),
        })
        .strict(),
    ),
    optionCountsHash: hex64Schema,
    proofSystemVersion: z.string().trim().min(1),
    hashSuite: z.string().trim().min(1),
    circuitId: z.string().trim().min(1),
    verifierKeyHash: hex64Schema,
    publicInputSchemaVersion: z.string().trim().min(1),
  })
  .strict();

const tallyProofEnvelopeSchema = z
  .object({
    version: z.string().trim().min(1),
    protocol: z.literal("groth16"),
    proofSystemVersion: z.string().trim().min(1),
    status: z.string().trim().min(1),
    hashSuite: z.string().trim().min(1),
    circuitId: z.string().trim().min(1),
    verifierKeyHash: hex64Schema,
    publicInputSchemaVersion: z.string().trim().min(1),
    proof: z.record(z.unknown()),
    publicInputs: tallyProofPublicInputsSchema,
    publicInputsHash: hex64Schema,
  })
  .strict();

const preproverVotePrivacySchema = z
  .object({
    version: z.string().trim().min(1),
    hashSuite: z.string().trim().min(1),
    nullifier: hex64Schema,
    proof: voteProofEnvelopeSchema,
  })
  .strict();

const productionVotePrivacySchema = z
  .object({
    version: z.string().trim().min(1),
    votePrivacyMode: z.literal("zk_secret_ballot_v1"),
    hashSuite: z.string().trim().min(1),
    nullifier: hex64Schema,
    voteCommitment: hex64Schema,
    encryptedVoteHash: hex64Schema,
    encryptedVoteCommitment: hex64Schema,
    proof: productionVoteProofEnvelopeSchema,
  })
  .strict();

const votePrivacySchema = z.union([
  preproverVotePrivacySchema,
  productionVotePrivacySchema,
]);

const encryptedVoteSchema = z
  .object({
    version: z.literal("civicos-encrypted-vote-v1"),
    pollEncryptionKeyId: z.string().trim().min(1),
    ciphertext: z.string().trim().min(1),
    nonce: z.string().trim().min(1),
    algorithm: z.string().trim().min(1),
    optionSetHash: hex64Schema,
  })
  .strict();

const phase10ProofSchema = z.union([
  voteProofEnvelopeSchema,
  productionVoteProofEnvelopeSchema,
  z.string().trim().min(1),
]);

const voteRequestPublicInputsSchema = z.union([
  voteProofPublicInputsSchema,
  productionVoteProofPublicInputsSchema,
]);

const voteRequestSchema = z
  .object({
    pollId: z.string().trim().min(1).optional(),
    optionId: z.string().trim().min(1),
    pollPolicyHash: hex64Schema.optional(),
    nullifier: hex64Schema.optional(),
    voteCommitment: hex64Schema.nullable().optional(),
    encryptedVote: encryptedVoteSchema.optional(),
    proof: phase10ProofSchema.optional(),
    publicInputs: voteRequestPublicInputsSchema.optional(),
    feeMode: z.enum(["civicos-sponsored", "user-paid"]).nullable().optional(),
    privacy: votePrivacySchema.nullable().optional(),
  })
  .strict();

const tallyProofRequestSchema = z
  .object({
    proof: tallyProofEnvelopeSchema,
  })
  .strict();

const auditInclusionQuerySchema = z.object({
  tree: z.enum(["vote_commitment", "nullifier", "encrypted_vote"]),
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

const tallyProofErrorStatusMap: Record<string, number> = {
  POLL_NOT_FOUND: 404,
  POLL_NOT_OWNED: 403,
  POLL_NOT_PRODUCTION_ZKP: 409,
  NO_ACCEPTED_AUDIT_VOTES: 409,
  TALLY_PROOF_INVALID: 400,
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

const submitTallyProofRoute: RouteDefinition = {
  method: "POST",
  path: "/polls/:id/tally-proof",
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

    const parsedBody = tallyProofRequestSchema.safeParse(requestBody);
    if (!parsedBody.success) {
      return json(
        {
          error: "invalid_request",
          message: "Tally proof request body is invalid.",
        },
        400,
      );
    }

    const result = await pollPublicAuditService.submitTallyProof({
      pollId,
      viewerUserId: viewerResult.viewer.userId,
      proof: parsedBody.data.proof as Groth16TallyProofEnvelopeDto,
    });

    if (result.success) {
      return json(result);
    }

    return json(result, tallyProofErrorStatusMap[result.errorCode] || 400);
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

  if ("protocol" in requestBody.proof && requestBody.proof.protocol === "groth16") {
    const productionProof = requestBody.proof as z.infer<
      typeof productionVoteProofEnvelopeSchema
    >;
    return {
      version: "civicos-vote-privacy-v1",
      votePrivacyMode: "zk_secret_ballot_v1",
      hashSuite: productionProof.hashSuite,
      nullifier: requestBody.nullifier || productionProof.publicInputs.nullifier,
      voteCommitment: productionProof.publicInputs.voteCommitment,
      encryptedVoteHash: productionProof.publicInputs.encryptedVoteHash,
      encryptedVoteCommitment:
        productionProof.publicInputs.encryptedVoteCommitment,
      proof: productionProof,
    } as VoteSubmissionRequestDto["privacy"];
  }

  const preproverProof = requestBody.proof as z.infer<
    typeof voteProofEnvelopeSchema
  >;
  return {
    version: "civicos-vote-privacy-v1",
    hashSuite: "sha256-sha512-preposeidon-v1",
    nullifier: requestBody.nullifier || preproverProof.publicInputs.nullifier,
    proof: preproverProof,
  };
};

const publicInputsMatch = (
  left: z.infer<typeof voteRequestPublicInputsSchema>,
  right: z.infer<typeof voteRequestPublicInputsSchema>,
): boolean => {
  const baseMatches =
    left.pollId === right.pollId &&
    left.pollPolicyHash === right.pollPolicyHash &&
    left.credentialSchemaHash === right.credentialSchemaHash &&
    left.nullifier === right.nullifier &&
    left.verificationMethodVersion === right.verificationMethodVersion &&
    left.proofSystemVersion === right.proofSystemVersion;

  if (!baseMatches) {
    return false;
  }

  const leftProduction = "publicInputSchemaVersion" in left;
  const rightProduction = "publicInputSchemaVersion" in right;
  if (leftProduction !== rightProduction) {
    return false;
  }

  if (!leftProduction || !rightProduction) {
    return true;
  }

  return (
    left.version === right.version &&
    left.optionSetHash === right.optionSetHash &&
    left.credentialRoot === right.credentialRoot &&
    left.voteCommitment === right.voteCommitment &&
    left.encryptedVoteHash === right.encryptedVoteHash &&
    left.encryptedVoteCommitment === right.encryptedVoteCommitment &&
    left.hashSuite === right.hashSuite &&
    left.circuitId === right.circuitId &&
    left.verifierKeyHash === right.verifierKeyHash &&
    left.publicInputSchemaVersion === right.publicInputSchemaVersion
  );
};

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
      encryptedVote: parsedBody.data.encryptedVote,
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
  submitTallyProofRoute,
  getPollDetailsRoute,
  submitVoteRoute,
  submitVotePhase10Route,
];
