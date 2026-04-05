import identityProfileRepository from "../repositories/identityProfileRepository";
import userRepository from "../repositories/userRepository";
import type { ProvisionalUserBootstrapDto } from "../types/contracts";

const createProvisionalUser = async () =>
  userRepository.insert({
    username: null,
    display_name: null,
    onboarding_status: "not_started",
    verification_level: "anonymous",
    has_wallet: false,
    wallet_credential_id: null,
    selected_land_id: null,
    preferred_language: null,
  });

const createIdentityProfile = async (userId: string) =>
  identityProfileRepository.insert({
    user_id: userId,
    passport_scan_completed: false,
    passport_nfc_completed: false,
    national_id_scan_completed: false,
    face_scan_completed: false,
    face_bound_to_identity: false,
    document_country_code: null,
    issuing_country_code: null,
    home_country_code: null,
    home_area_id: null,
    home_approx_latitude: null,
    home_approx_longitude: null,
    home_location_source: "user_selected",
    home_location_updated_at: null,
  });

const mapBootstrapDto = (
  user: Awaited<ReturnType<typeof createProvisionalUser>>,
  identityProfile: Awaited<ReturnType<typeof createIdentityProfile>>,
): ProvisionalUserBootstrapDto => ({
  user: {
    id: user.id,
    onboardingStatus: user.onboarding_status,
    verificationLevel: user.verification_level,
    hasWallet: user.has_wallet,
    selectedLandId: user.selected_land_id,
    isProvisional: user.verification_level === "anonymous",
    createdAt: user.created_at,
    updatedAt: user.updated_at,
  },
  identityProfile: {
    id: identityProfile.id,
    userId: identityProfile.user_id,
    hasHomeLocation: Boolean(
      identityProfile.home_country_code && identityProfile.home_area_id,
    ),
    createdAt: identityProfile.created_at,
    updatedAt: identityProfile.updated_at,
  },
});

export const userBootstrapService = {
  async bootstrapProvisionalUser(): Promise<ProvisionalUserBootstrapDto> {
    const user = await createProvisionalUser();
    const identityProfile = await createIdentityProfile(user.id);

    return mapBootstrapDto(user, identityProfile);
  },
};

export default userBootstrapService;
