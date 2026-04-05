import { describe, expect, it } from "bun:test";
import { createVerifiedIdentityBindService } from "./verifiedIdentityBindService";
import type { NewVerifiedIdentityRow, UserRow, VerifiedIdentityRow } from "../types/db";

const VALID_NIDNH = "b".repeat(128);
const FIXED_NOW = "2026-04-06T12:00:00.000Z";

const createUser = (id: string): UserRow => ({
  id,
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
});

const createInMemoryDependencies = (seedUsers: UserRow[]) => {
  const users = new Map(seedUsers.map((user) => [user.id, user]));
  const verifiedByCanonical = new Map<string, VerifiedIdentityRow>();
  const verifiedByUser = new Map<string, VerifiedIdentityRow>();
  let sequence = 0;

  return {
    userRepo: {
      async getById(userId: string): Promise<UserRow | null> {
        return users.get(userId) || null;
      },
      async updateVerificationState(
        userId: string,
        params: { verificationLevel?: string; onboardingStatus?: string },
      ): Promise<UserRow | null> {
        const current = users.get(userId);
        if (!current) {
          return null;
        }

        const next: UserRow = {
          ...current,
          verification_level: params.verificationLevel || current.verification_level,
          onboarding_status: params.onboardingStatus || current.onboarding_status,
          updated_at: FIXED_NOW,
        };
        users.set(userId, next);
        return next;
      },
    },
    verifiedIdentityRepo: {
      async getByUserId(userId: string): Promise<VerifiedIdentityRow | null> {
        return verifiedByUser.get(userId) || null;
      },
      async getByCanonicalIdentityKey(
        canonicalIdentityKey: string,
      ): Promise<VerifiedIdentityRow | null> {
        return verifiedByCanonical.get(canonicalIdentityKey) || null;
      },
      async insert(input: NewVerifiedIdentityRow): Promise<VerifiedIdentityRow> {
        if (
          verifiedByCanonical.has(input.canonical_identity_key) ||
          verifiedByUser.has(input.user_id)
        ) {
          const duplicateError = Object.assign(new Error("duplicate key"), {
            code: "23505",
          });
          throw duplicateError;
        }

        sequence += 1;
        const row: VerifiedIdentityRow = {
          id: `verified-identity-${sequence}`,
          user_id: input.user_id,
          canonical_identity_key: input.canonical_identity_key,
          normalization_version: input.normalization_version,
          verification_method: input.verification_method,
          verified_at: input.verified_at,
          created_at: FIXED_NOW,
          updated_at: FIXED_NOW,
        };

        verifiedByCanonical.set(row.canonical_identity_key, row);
        verifiedByUser.set(row.user_id, row);
        return row;
      },
    },
    getUser(userId: string): UserRow | null {
      return users.get(userId) || null;
    },
    getVerifiedIdentityCount(): number {
      return verifiedByCanonical.size;
    },
  };
};

describe("verifiedIdentityBindService", () => {
  it("binds a verified identity on first request", async () => {
    const deps = createInMemoryDependencies([createUser("user-1")]);
    const service = createVerifiedIdentityBindService({
      pepper: "test-pepper",
      now: () => FIXED_NOW,
      userRepo: deps.userRepo,
      verifiedIdentityRepo: deps.verifiedIdentityRepo,
    });

    const result = await service.bindVerifiedIdentityForViewer({
      viewerUserId: "user-1",
      nidnh: VALID_NIDNH,
      normalizationVersion: 1,
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.verifiedIdentity.userId).toBe("user-1");
      expect(result.verifiedIdentity.verificationMethod).toBe("passport_nfc");
      expect(result.verifiedIdentity.normalizationVersion).toBe(1);
    }

    const updatedUser = deps.getUser("user-1");
    expect(updatedUser?.verification_level).toBe("nid_verified");
    expect(updatedUser?.onboarding_status).toBe("identity_pending");
  });

  it("returns idempotent success when the same user binds the same identity again", async () => {
    const deps = createInMemoryDependencies([createUser("user-1")]);
    const service = createVerifiedIdentityBindService({
      pepper: "test-pepper",
      now: () => FIXED_NOW,
      userRepo: deps.userRepo,
      verifiedIdentityRepo: deps.verifiedIdentityRepo,
    });

    const first = await service.bindVerifiedIdentityForViewer({
      viewerUserId: "user-1",
      nidnh: VALID_NIDNH,
      normalizationVersion: 1,
    });
    const second = await service.bindVerifiedIdentityForViewer({
      viewerUserId: "user-1",
      nidnh: VALID_NIDNH,
      normalizationVersion: 1,
    });

    expect(first.success).toBe(true);
    expect(second.success).toBe(true);

    if (first.success && second.success) {
      expect(second.verifiedIdentity.id).toBe(first.verifiedIdentity.id);
    }

    expect(deps.getVerifiedIdentityCount()).toBe(1);
  });

  it("returns IDENTITY_ALREADY_BOUND when another user tries to bind the same identity", async () => {
    const deps = createInMemoryDependencies([
      createUser("user-1"),
      createUser("user-2"),
    ]);
    const service = createVerifiedIdentityBindService({
      pepper: "test-pepper",
      now: () => FIXED_NOW,
      userRepo: deps.userRepo,
      verifiedIdentityRepo: deps.verifiedIdentityRepo,
    });

    const first = await service.bindVerifiedIdentityForViewer({
      viewerUserId: "user-1",
      nidnh: VALID_NIDNH,
      normalizationVersion: 1,
    });
    const second = await service.bindVerifiedIdentityForViewer({
      viewerUserId: "user-2",
      nidnh: VALID_NIDNH,
      normalizationVersion: 1,
    });

    expect(first.success).toBe(true);
    expect(second.success).toBe(false);
    if (!second.success) {
      expect(second.errorCode).toBe("IDENTITY_ALREADY_BOUND");
    }
  });
});

