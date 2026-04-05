import { z } from "zod";
import requireViewer from "../auth/requireViewer";
import { json } from "../middleware/json";
import viewerProfileService from "../services/viewerProfileService";
import type {
  IssueWalletCredentialResultDto,
  UpdateViewerHomeLocationResultDto,
  ViewerLandSelectionResultDto,
} from "../types/contracts";
import type { RouteDefinition } from "../types/http";

const selectedLandUpdateSchema = z
  .object({
    landId: z.string().trim().min(1).nullable().optional(),
    selectedLandId: z.string().trim().min(1).nullable().optional(),
  })
  .strict();

const selectedLandFlagUpdateSchema = z
  .object({
    landId: z.string().trim().min(1).nullable().optional(),
    flagType: z.string().trim().min(1).nullable().optional(),
    flagAsset: z.string().trim().min(1).nullable().optional(),
    flagEmoji: z.string().trim().min(1).nullable().optional(),
  })
  .strict();

const createLandSchema = z
  .object({
    name: z.string().trim().min(1),
    description: z.string().trim().min(1).nullable().optional(),
    flagType: z.string().trim().min(1).nullable().optional(),
    flagAsset: z.string().trim().min(1).nullable().optional(),
    flagEmoji: z.string().trim().min(1).nullable().optional(),
    selectAfterCreate: z.boolean().optional(),
  })
  .strict();

const issueWalletCredentialSchema = z
  .object({
    walletPublicId: z.string().trim().min(1),
    holderId: z.string().trim().min(1),
    walletPublicKey: z.string().trim().min(1),
  })
  .strict();

const updateHomeLocationSchema = z
  .object({
    approxLatitude: z.number().finite(),
    approxLongitude: z.number().finite(),
    source: z
      .enum(["user_selected", "derived_from_document", "admin_set", "mock"])
      .optional(),
    countryCode: z.string().trim().min(1).nullable().optional(),
    areaId: z.string().trim().min(1).nullable().optional(),
  })
  .strict();

const selectionErrorStatusMap: Record<NonNullable<ViewerLandSelectionResultDto["errorCode"]>, number> = {
  USER_NOT_FOUND: 401,
  LAND_NOT_FOUND: 404,
  INVALID_INPUT: 400,
};

const walletIssueErrorStatusMap: Record<
  NonNullable<Extract<IssueWalletCredentialResultDto, { success: false }>["errorCode"]>,
  number
> = {
  USER_NOT_FOUND: 401,
  INVALID_INPUT: 400,
  IDENTITY_PROFILE_REQUIRED: 409,
  CREDENTIAL_REVOKED: 409,
};

const homeLocationErrorStatusMap: Record<
  NonNullable<UpdateViewerHomeLocationResultDto["errorCode"]>,
  number
> = {
  USER_NOT_FOUND: 401,
  IDENTITY_PROFILE_NOT_FOUND: 409,
  INVALID_COORDINATES: 400,
  INVALID_INPUT: 400,
};

const getCurrentViewerProfileRoute: RouteDefinition = {
  method: "GET",
  path: "/me/profile",
  handler: async ({ request }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const profile = await viewerProfileService.getCurrentViewerProfile(
      viewerResult.viewer.userId,
    );

    if (!profile) {
      return json(
        {
          error: "viewer_not_found",
          message: "The current viewer profile could not be resolved.",
        },
        404,
      );
    }

    return json(profile);
  },
};

const updateViewerHomeLocationRoute: RouteDefinition = {
  method: "PATCH",
  path: "/me/profile/home-location",
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

    const parsedBody = updateHomeLocationSchema.safeParse(requestBody);
    if (!parsedBody.success) {
      return json(
        {
          error: "invalid_request",
          message: "Home location update request body is invalid.",
        },
        400,
      );
    }

    const result = await viewerProfileService.updateHomeLocation(
      viewerResult.viewer.userId,
      parsedBody.data,
    );

    if (result.success) {
      return json(result);
    }

    return json(
      result,
      homeLocationErrorStatusMap[result.errorCode || "INVALID_INPUT"],
    );
  },
};

const getViewerLandStateRoute: RouteDefinition = {
  method: "GET",
  path: "/me/land",
  handler: async ({ request }) => {
    const viewerResult = await requireViewer(request);
    if (!viewerResult.ok) {
      return viewerResult.response;
    }

    const result = await viewerProfileService.getViewerLandState(
      viewerResult.viewer.userId,
    );

    if (result.success) {
      return json(result);
    }

    return json(result, selectionErrorStatusMap[result.errorCode || "INVALID_INPUT"]);
  },
};

const updateViewerLandRoute: RouteDefinition = {
  method: "PATCH",
  path: "/me/land",
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

    const parsedBody = selectedLandUpdateSchema.safeParse(requestBody);
    if (!parsedBody.success) {
      return json(
        {
          error: "invalid_request",
          message: "Land selection request body is invalid.",
        },
        400,
      );
    }

    const normalizedLandId =
      parsedBody.data.landId !== undefined
        ? parsedBody.data.landId
        : parsedBody.data.selectedLandId !== undefined
          ? parsedBody.data.selectedLandId
          : null;

    const result = await viewerProfileService.updateSelectedLand(
      viewerResult.viewer.userId,
      {
        landId: normalizedLandId,
      },
    );

    if (result.success) {
      return json(result);
    }

    return json(result, selectionErrorStatusMap[result.errorCode || "INVALID_INPUT"]);
  },
};

const updateViewerLandFlagRoute: RouteDefinition = {
  method: "PATCH",
  path: "/me/land/flag",
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

    const parsedBody = selectedLandFlagUpdateSchema.safeParse(requestBody);
    if (!parsedBody.success) {
      return json(
        {
          error: "invalid_request",
          message: "Land flag update request body is invalid.",
        },
        400,
      );
    }

    const result = await viewerProfileService.updateSelectedLandFlag(
      viewerResult.viewer.userId,
      parsedBody.data,
    );

    if (result.success) {
      return json(result);
    }

    return json(result, selectionErrorStatusMap[result.errorCode || "INVALID_INPUT"]);
  },
};

const createViewerLandRoute: RouteDefinition = {
  method: "POST",
  path: "/me/lands",
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

    const parsedBody = createLandSchema.safeParse(requestBody);
    if (!parsedBody.success) {
      return json(
        {
          error: "invalid_request",
          message: "Land creation request body is invalid.",
        },
        400,
      );
    }

    const result = await viewerProfileService.createLand(
      viewerResult.viewer.userId,
      parsedBody.data,
    );

    if (result.success) {
      return json(result, 201);
    }

    return json(result, selectionErrorStatusMap[result.errorCode || "INVALID_INPUT"]);
  },
};

const issueViewerWalletCredentialRoute: RouteDefinition = {
  method: "POST",
  path: "/me/wallet/issue",
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

    const parsedBody = issueWalletCredentialSchema.safeParse(requestBody);
    if (!parsedBody.success) {
      return json(
        {
          error: "invalid_request",
          message: "Wallet issuance request body is invalid.",
        },
        400,
      );
    }

    const result = await viewerProfileService.issueWalletCredential(
      viewerResult.viewer.userId,
      parsedBody.data,
    );

    if (result.success) {
      return json(result);
    }

    return json(result, walletIssueErrorStatusMap[result.errorCode || "INVALID_INPUT"]);
  },
};

export const meRoutes: RouteDefinition[] = [
  getCurrentViewerProfileRoute,
  updateViewerHomeLocationRoute,
  getViewerLandStateRoute,
  updateViewerLandRoute,
  updateViewerLandFlagRoute,
  createViewerLandRoute,
  issueViewerWalletCredentialRoute,
];

export default meRoutes;
