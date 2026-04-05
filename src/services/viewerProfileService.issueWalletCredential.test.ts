import { describe, expect, it } from "bun:test";
import identityProfileRepository from "../repositories/identityProfileRepository";
import userRepository from "../repositories/userRepository";
import verifiedIdentityRepository from "../repositories/verifiedIdentityRepository";
import walletCredentialRepository from "../repositories/walletCredentialRepository";
import { viewerProfileService } from "./viewerProfileService";
import type {
  IdentityProfileRow,
  UserRow,
  VerifiedIdentityRow,
  WalletCredentialRow,
} from "../types/db";

const FIXED_TIME = "2026-04-06T12:00:00.000Z";

const VALID_ISSUANCE_INPUT = {
  walletPublicId: "wallet-public-1",
  holderId: "holder-1",
  walletPublicKey: "public-key-1",
};

const createUser = (overrides: Partial<UserRow> = {}): UserRow => ({
  id: "user-1",
  username: null,
  display_name: null,
  onboarding_status: "identity_pending",
  verification_level: "nid_verified",
  has_wallet: false,
  wallet_credential_id: null,
  selected_land_id: null,
  preferred_language: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createIdentityProfile = (
  overrides: Partial<IdentityProfileRow> = {},
): IdentityProfileRow => ({
  id: "identity-profile-1",
  user_id: "user-1",
  passport_scan_completed: true,
  passport_nfc_completed: true,
  national_id_scan_completed: false,
  face_scan_completed: false,
  face_bound_to_identity: false,
  document_country_code: "IR",
  issuing_country_code: "IR",
  home_country_code: "IR",
  home_area_id: "grid_n10_e10",
  home_approx_latitude: 10,
  home_approx_longitude: 10,
  home_location_source: "user_selected",
  home_location_updated_at: FIXED_TIME,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createVerifiedIdentity = (
  overrides: Partial<VerifiedIdentityRow> = {},
): VerifiedIdentityRow => ({
  id: "verified-identity-1",
  user_id: "user-1",
  canonical_identity_key: "canonical-key-1",
  normalization_version: 1,
  verification_method: "passport_nfc",
  verified_at: FIXED_TIME,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const createWalletCredential = (
  overrides: Partial<WalletCredentialRow> = {},
): WalletCredentialRow => ({
  id: "wallet-credential-1",
  user_id: "user-1",
  wallet_public_id: VALID_ISSUANCE_INPUT.walletPublicId,
  holder_id: VALID_ISSUANCE_INPUT.holderId,
  wallet_public_key: VALID_ISSUANCE_INPUT.walletPublicKey,
  issuance_status: "not_issued",
  issued_at: null,
  revoked_at: null,
  revocation_reason: null,
  credential_payload: null,
  created_at: FIXED_TIME,
  updated_at: FIXED_TIME,
  ...overrides,
});

const patchMethod = <T extends object, K extends keyof T>(
  target: T,
  key: K,
  implementation: T[K],
): (() => void) => {
  const original = target[key];
  target[key] = implementation;

  return () => {
    target[key] = original;
  };
};

describe("viewerProfileService.issueWalletCredential", () => {
  it("rejects issuance when verified identity is not linked", async () => {
    const user = createUser();
    let upsertCalled = 0;
    let updateCalled = 0;

    const restoreFns = [
      patchMethod(userRepository, "getById", async () => user),
      patchMethod(verifiedIdentityRepository, "getByUserId", async () => null),
      patchMethod(walletCredentialRepository, "getByUserId", async () => null),
      patchMethod(walletCredentialRepository, "upsertPublicMaterial", async () => {
        upsertCalled += 1;
        return createWalletCredential();
      }),
      patchMethod(walletCredentialRepository, "updateByUserId", async () => {
        updateCalled += 1;
        return createWalletCredential({
          issuance_status: "issued",
          issued_at: FIXED_TIME,
        });
      }),
    ];

    try {
      const result = await viewerProfileService.issueWalletCredential(
        user.id,
        VALID_ISSUANCE_INPUT,
      );

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errorCode).toBe("VERIFIED_IDENTITY_REQUIRED");
      }
      expect(upsertCalled).toBe(0);
      expect(updateCalled).toBe(0);
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("issues credential when verified identity is linked", async () => {
    const user = createUser({
      has_wallet: true,
      wallet_credential_id: "wallet-credential-1",
    });
    const linkedUser = createUser({
      has_wallet: true,
      wallet_credential_id: "wallet-credential-1",
      updated_at: "2026-04-06T12:00:01.000Z",
    });

    const registeredCredential = createWalletCredential();
    const issuedCredentialRow = createWalletCredential({
      issuance_status: "issued",
      issued_at: FIXED_TIME,
      credential_payload: {
        id: "urn:iland:credential:test",
      },
    });

    const restoreFns = [
      patchMethod(userRepository, "getById", async () => user),
      patchMethod(verifiedIdentityRepository, "getByUserId", async () =>
        createVerifiedIdentity(),
      ),
      patchMethod(identityProfileRepository, "getByUserId", async () =>
        createIdentityProfile(),
      ),
      patchMethod(walletCredentialRepository, "getByUserId", async () => null),
      patchMethod(
        walletCredentialRepository,
        "upsertPublicMaterial",
        async () => registeredCredential,
      ),
      patchMethod(
        walletCredentialRepository,
        "updateByUserId",
        async () => issuedCredentialRow,
      ),
      patchMethod(userRepository, "updateWalletCredentialLink", async () => linkedUser),
    ];

    try {
      const result = await viewerProfileService.issueWalletCredential(
        user.id,
        VALID_ISSUANCE_INPUT,
      );

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.wallet.backendCredentialStatus).toBe("issued");
        expect(result.wallet.status).toBe("issued");
        expect(result.issuedCredential.verifiedIdentity).toBe(true);
        expect(
          Object.prototype.hasOwnProperty.call(result.issuedCredential, "privateKey"),
        ).toBe(false);
      }
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });

  it("keeps existing IDENTITY_PROFILE_REQUIRED behavior when linked identity exists but profile is missing", async () => {
    const user = createUser();

    const restoreFns = [
      patchMethod(userRepository, "getById", async () => user),
      patchMethod(verifiedIdentityRepository, "getByUserId", async () =>
        createVerifiedIdentity(),
      ),
      patchMethod(identityProfileRepository, "getByUserId", async () => null),
      patchMethod(walletCredentialRepository, "getByUserId", async () => null),
      patchMethod(
        walletCredentialRepository,
        "upsertPublicMaterial",
        async () => createWalletCredential(),
      ),
      patchMethod(userRepository, "updateWalletCredentialLink", async () =>
        createUser({
          has_wallet: true,
          wallet_credential_id: "wallet-credential-1",
        }),
      ),
    ];

    try {
      const result = await viewerProfileService.issueWalletCredential(
        user.id,
        VALID_ISSUANCE_INPUT,
      );

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errorCode).toBe("IDENTITY_PROFILE_REQUIRED");
      }
    } finally {
      restoreFns.reverse().forEach((restore) => restore());
    }
  });
});
