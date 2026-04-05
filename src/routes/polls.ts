import { z } from "zod";
import requireViewer from "../auth/requireViewer";
import { json } from "../middleware/json";
import pollDraftService from "../services/pollDraftService";
import pollVotingService from "../services/pollVotingService";
import type {
  CreatePollRequestDto,
  PollManagementErrorCode,
  UpdateDraftPollRequestDto,
  VoteSubmissionFailureDto,
} from "../types/contracts";
import type { RouteDefinition } from "../types/http";

const voteRequestSchema = z.object({
  optionId: z.string().trim().min(1),
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

const submitVoteRoute: RouteDefinition = {
  method: "POST",
  path: "/polls/:id/votes",
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
          message: "Request body must include a non-empty optionId.",
        },
        400,
      );
    }

    const result = await pollVotingService.submitVote({
      pollId,
      optionId: parsedBody.data.optionId,
      viewer: viewerResult.viewer.user,
    });

    if (result.success) {
      return json(result);
    }

    return json(result, voteErrorStatusMap[result.errorCode] || 400);
  },
};

export const pollRoutes: RouteDefinition[] = [
  getPollsRoute,
  createDraftPollRoute,
  canEditDraftPollRoute,
  getDraftPollRoute,
  updateDraftPollRoute,
  publishDraftPollRoute,
  getPollDetailsRoute,
  submitVoteRoute,
];
