import env from "../config/env";
import identityProfileRepository from "../repositories/identityProfileRepository";
import userRepository from "../repositories/userRepository";
import verifiedIdentityRepository from "../repositories/verifiedIdentityRepository";
import { deriveCanonicalIdentityKey } from "./verifiedIdentityDerivationService";
import type { UserRow } from "../types/db";

const createIdentityProfile = async (userId: string) =>
  identityProfileRepository.insert({
    user_id: userId,
    passport_scan_completed: false,
    passport_nfc_completed: false,
    national_id_scan_completed: false,
    face_scan_completed: false,
    face_bound_to_identity: false,
    passport_verified_at: null,
    national_id_verified_at: null,
    face_verified_at: null,
    document_country_code: null,
    issuing_country_code: null,
    home_country_code: null,
    home_area_id: null,
    home_approx_latitude: null,
    home_approx_longitude: null,
    home_location_source: "user_selected",
    home_location_updated_at: null,
  });

const createVerifiedUser = async (
  params: {
    canonicalIdentityKey: string;
    normalizationVersion: number;
    verificationMethod: "passport_nfc";
  },
): Promise<UserRow> => {
  const user = await userRepository.insert({
    username: null,
    display_name: null,
    onboarding_status: "identity_pending",
    verification_level: "nid_verified",
    has_wallet: false,
    wallet_credential_id: null,
    selected_land_id: null,
    preferred_language: null,
    auth_generation: 1,
    account_status: "active",
  });

  await createIdentityProfile(user.id);
  await verifiedIdentityRepository.insert({
    user_id: user.id,
    canonical_identity_key: params.canonicalIdentityKey,
    normalization_version: params.normalizationVersion,
    verification_method: params.verificationMethod,
    verified_at: new Date().toISOString(),
  });

  return user;
};

export const authAccountBindingService = {
  async resolveOrCreateUserByVerifiedIdentity(input: {
    nidnh: string;
    normalizationVersion: number;
    verificationMethod: "passport_nfc";
  }): Promise<UserRow> {
    const canonicalIdentityKey = deriveCanonicalIdentityKey({
      nidnh: input.nidnh,
      pepper: env.verifiedIdentity.pepper,
    });

    return this.resolveOrCreateUserByCanonicalIdentityKey({
      canonicalIdentityKey,
      normalizationVersion: input.normalizationVersion,
      verificationMethod: input.verificationMethod,
    });
  },

  async resolveOrCreateUserByCanonicalIdentityKey(
    input: {
      canonicalIdentityKey: string;
      normalizationVersion: number;
      verificationMethod: "passport_nfc";
    },
  ): Promise<UserRow> {
    const existingVerifiedIdentity =
      await verifiedIdentityRepository.getByCanonicalIdentityKey(
        input.canonicalIdentityKey,
      );

    if (existingVerifiedIdentity) {
      const existingUser = await userRepository.getById(
        existingVerifiedIdentity.user_id,
      );

      if (!existingUser) {
        throw new Error(
          "Verified identity exists but the authoritative user record is missing.",
        );
      }

      return existingUser;
    }

    // Enforced identity policy:
    // backend identity is anchored by canonical_identity_key, not by device. If
    // no verified user exists yet for the canonical key, registration creates
    // the authoritative backend user and identity profile once.
    return createVerifiedUser(input);
  },
};

export default authAccountBindingService;
