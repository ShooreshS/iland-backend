import { describe, expect, it } from "bun:test";
import { json } from "../middleware/json";
import { createVerifyIdentityRoute } from "./me";
import type { BindVerifiedIdentityResultDto } from "../types/contracts";
import type { UserRow } from "../types/db";

const viewerUser: UserRow = {
  id: "viewer-user-1",
  username: null,
  display_name: null,
  onboarding_status: "not_started",
  verification_level: "anonymous",
  has_wallet: false,
  wallet_credential_id: null,
  selected_land_id: null,
  preferred_language: null,
  created_at: "2026-04-06T00:00:00.000Z",
  updated_at: "2026-04-06T00:00:00.000Z",
};

const invokeRoute = async (
  route: ReturnType<typeof createVerifyIdentityRoute>,
  requestBody: unknown,
): Promise<Response> => {
  const request = new Request("http://127.0.0.1:3001/me/verify-identity", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(requestBody),
  });

  return route.handler({
    request,
    url: new URL(request.url),
    params: {},
  });
};

const buildSuccessResult = (
  userId = viewerUser.id,
  status: "bound_new" | "bound_existing_same_user" | "recovered_existing_user" =
    "bound_new",
): BindVerifiedIdentityResultDto => ({
  success: true,
  status,
  authoritativeUserId: userId,
  verifiedIdentity: {
    id: "verified-identity-1",
    userId,
    normalizationVersion: 1,
    verificationMethod: "passport_nfc",
    verifiedAt: "2026-04-06T12:00:00.000Z",
    createdAt: "2026-04-06T12:00:00.000Z",
    updatedAt: "2026-04-06T12:00:00.000Z",
  },
});

describe("POST /me/verify-identity route", () => {
  it("returns success for first bind", async () => {
    let receivedInput: unknown = null;
    const route = createVerifyIdentityRoute({
      requireViewerFn: async () => ({
        ok: true,
        viewer: {
          userId: viewerUser.id,
          user: viewerUser,
        },
      }),
      bindService: {
        bindVerifiedIdentityForViewer: async (input) => {
          receivedInput = input;
          return buildSuccessResult();
        },
      },
    });

    const response = await invokeRoute(route, {
      nidnh: "a".repeat(128),
      normalizationVersion: 1,
    });

    expect(response.status).toBe(200);
    expect(receivedInput).toEqual({
      viewerUserId: viewerUser.id,
      nidnh: "a".repeat(128),
      normalizationVersion: 1,
      verificationMethod: undefined,
    });

    const body = (await response.json()) as BindVerifiedIdentityResultDto;
    expect(body).toEqual(buildSuccessResult());
  });

  it("returns idempotent success for same-user rebind", async () => {
    const route = createVerifyIdentityRoute({
      requireViewerFn: async () => ({
        ok: true,
        viewer: {
          userId: viewerUser.id,
          user: viewerUser,
        },
      }),
      bindService: {
        bindVerifiedIdentityForViewer: async () => buildSuccessResult(),
      },
    });

    const response = await invokeRoute(route, {
      nidnh: "b".repeat(128),
      normalizationVersion: 1,
      verificationMethod: "passport_nfc",
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as BindVerifiedIdentityResultDto;
    expect(body.success).toBe(true);
  });

  it("returns recovery success when canonical identity is already linked to another user", async () => {
    const route = createVerifyIdentityRoute({
      requireViewerFn: async () => ({
        ok: true,
        viewer: {
          userId: viewerUser.id,
          user: viewerUser,
        },
      }),
      bindService: {
        bindVerifiedIdentityForViewer: async () =>
          buildSuccessResult("canonical-user-1", "recovered_existing_user"),
      },
    });

    const response = await invokeRoute(route, {
      nidnh: "c".repeat(128),
      normalizationVersion: 1,
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as BindVerifiedIdentityResultDto;
    expect(body.success).toBe(true);
    if (body.success) {
      expect(body.status).toBe("recovered_existing_user");
      expect(body.authoritativeUserId).toBe("canonical-user-1");
    }
  });

  it("returns handled IDENTITY_ALREADY_BOUND failure for conflicting user-linked identity", async () => {
    const route = createVerifyIdentityRoute({
      requireViewerFn: async () => ({
        ok: true,
        viewer: {
          userId: viewerUser.id,
          user: viewerUser,
        },
      }),
      bindService: {
        bindVerifiedIdentityForViewer: async () => ({
          success: false,
          errorCode: "IDENTITY_ALREADY_BOUND",
          message: "This user is already linked to a different verified identity.",
        }),
      },
    });

    const response = await invokeRoute(route, {
      nidnh: "c".repeat(128),
      normalizationVersion: 1,
    });

    expect(response.status).toBe(409);
    const body = (await response.json()) as BindVerifiedIdentityResultDto;
    expect(body.success).toBe(false);
    if (!body.success) {
      expect(body.errorCode).toBe("IDENTITY_ALREADY_BOUND");
    }
  });

  it("rejects invalid payload before calling the bind service", async () => {
    let called = false;
    const route = createVerifyIdentityRoute({
      requireViewerFn: async () => ({
        ok: true,
        viewer: {
          userId: viewerUser.id,
          user: viewerUser,
        },
      }),
      bindService: {
        bindVerifiedIdentityForViewer: async () => {
          called = true;
          return buildSuccessResult();
        },
      },
    });

    const response = await invokeRoute(route, {
      nidnh: "not-a-valid-hash",
    });

    expect(response.status).toBe(400);
    expect(called).toBe(false);
  });

  it("does not accept raw-NIDN-style fields in request payload", async () => {
    let called = false;
    const route = createVerifyIdentityRoute({
      requireViewerFn: async () => ({
        ok: true,
        viewer: {
          userId: viewerUser.id,
          user: viewerUser,
        },
      }),
      bindService: {
        bindVerifiedIdentityForViewer: async () => {
          called = true;
          return buildSuccessResult();
        },
      },
    });

    const response = await invokeRoute(route, {
      nidnh: "d".repeat(128),
      normalizationVersion: 1,
      nationalIdNumber: "1234567890",
    });

    expect(response.status).toBe(400);
    expect(called).toBe(false);
  });

  it("returns requireViewer failure response unchanged", async () => {
    const route = createVerifyIdentityRoute({
      requireViewerFn: async () => ({
        ok: false,
        response: json(
          {
            error: "viewer_not_resolved",
            message: "Missing required dev viewer header.",
          },
          401,
        ),
      }),
      bindService: {
        bindVerifiedIdentityForViewer: async () => buildSuccessResult(),
      },
    });

    const response = await invokeRoute(route, {
      nidnh: "f".repeat(128),
      normalizationVersion: 1,
    });

    expect(response.status).toBe(401);
    const body = await response.json();
    expect(body.error).toBe("viewer_not_resolved");
  });
});
