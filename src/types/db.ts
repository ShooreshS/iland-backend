import type { PollJurisdictionType, PollStatus } from "./contracts";

export type UserRow = {
  id: string;
  username: string | null;
  display_name: string | null;
  onboarding_status: string;
  verification_level: string;
  has_wallet: boolean;
  wallet_credential_id: string | null;
  selected_land_id: string | null;
  preferred_language: string | null;
  created_at: string;
  updated_at: string;
};

export type NewUserRow = {
  username: string | null;
  display_name: string | null;
  onboarding_status: string;
  verification_level: string;
  has_wallet: boolean;
  wallet_credential_id: string | null;
  selected_land_id: string | null;
  preferred_language: string | null;
};

export type IdentityProfileRow = {
  id: string;
  user_id: string;
  passport_scan_completed: boolean;
  passport_nfc_completed: boolean;
  national_id_scan_completed: boolean;
  face_scan_completed: boolean;
  face_bound_to_identity: boolean;
  document_country_code: string | null;
  issuing_country_code: string | null;
  home_country_code: string | null;
  home_area_id: string | null;
  home_approx_latitude: number | null;
  home_approx_longitude: number | null;
  home_location_source: string;
  home_location_updated_at: string | null;
  created_at: string;
  updated_at: string;
};

export type NewIdentityProfileRow = {
  user_id: string;
  passport_scan_completed: boolean;
  passport_nfc_completed: boolean;
  national_id_scan_completed: boolean;
  face_scan_completed: boolean;
  face_bound_to_identity: boolean;
  document_country_code: string | null;
  issuing_country_code: string | null;
  home_country_code: string | null;
  home_area_id: string | null;
  home_approx_latitude: number | null;
  home_approx_longitude: number | null;
  home_location_source: string;
  home_location_updated_at: string | null;
};

export type IdentityProfileReferenceRow = {
  home_area_id: string | null;
  home_country_code: string | null;
  document_country_code: string | null;
  issuing_country_code: string | null;
};

export type IdentityProfileMapSeedRow = {
  user_id: string;
  home_area_id: string | null;
  home_country_code: string | null;
  home_approx_latitude: number | null;
  home_approx_longitude: number | null;
};

export type VerifiedIdentityRow = {
  id: string;
  user_id: string;
  canonical_identity_key: string;
  normalization_version: number;
  verification_method: string;
  verified_at: string;
  created_at: string;
  updated_at: string;
};

export type NewVerifiedIdentityRow = {
  user_id: string;
  canonical_identity_key: string;
  normalization_version: number;
  verification_method: string;
  verified_at: string;
};

export type WalletCredentialStatus = "not_issued" | "issued" | "revoked";

export type WalletCredentialRow = {
  id: string;
  user_id: string;
  wallet_public_id: string;
  holder_id: string;
  wallet_public_key: string;
  issuance_status: WalletCredentialStatus;
  issued_at: string | null;
  revoked_at: string | null;
  revocation_reason: string | null;
  credential_payload: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
};

export type NewWalletCredentialRegistrationRow = {
  user_id: string;
  wallet_public_id: string;
  holder_id: string;
  wallet_public_key: string;
};

export type PollRow = {
  id: string;
  slug: string;
  created_by_user_id: string | null;
  title: string;
  description: string | null;
  status: PollStatus;
  jurisdiction_type: PollJurisdictionType;
  jurisdiction_country_code: string | null;
  jurisdiction_area_ids: string[] | null;
  jurisdiction_land_ids: string[] | null;
  requires_verified_identity: boolean;
  allowed_document_country_codes: string[] | null;
  allowed_home_area_ids: string[] | null;
  allowed_land_ids: string[] | null;
  minimum_age: number | null;
  starts_at: string | null;
  ends_at: string | null;
  created_at: string;
  updated_at: string;
};

export type PollOptionRow = {
  id: string;
  poll_id: string;
  label: string;
  description: string | null;
  color: string | null;
  display_order: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
};

export type NewPollRow = {
  slug: string;
  created_by_user_id: string;
  title: string;
  description: string | null;
  status: PollStatus;
  jurisdiction_type: PollJurisdictionType;
  jurisdiction_country_code: string | null;
  jurisdiction_area_ids: string[];
  jurisdiction_land_ids: string[];
  requires_verified_identity: boolean;
  allowed_document_country_codes: string[];
  allowed_home_area_ids: string[];
  allowed_land_ids: string[];
  minimum_age: number | null;
  starts_at: string | null;
  ends_at: string | null;
};

export type NewPollOptionRow = {
  id?: string;
  poll_id: string;
  label: string;
  description: string | null;
  color: string | null;
  display_order: number;
  is_active: boolean;
  created_at?: string;
};

export type LandRow = {
  id: string;
  name: string;
  slug: string;
  type: string;
  flag_type: string;
  flag_asset: string | null;
  flag_emoji: string | null;
  founder_user_id: string | null;
  description: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
};

export type NewLandRow = {
  id?: string;
  name: string;
  slug: string;
  type?: string;
  flag_type?: string;
  flag_asset?: string | null;
  flag_emoji?: string | null;
  founder_user_id?: string | null;
  description?: string | null;
  is_active?: boolean;
};

export type VoteRow = {
  id: string;
  poll_id: string;
  option_id: string;
  user_id: string;
  verified_identity_id: string | null;
  vote_latitude_l0: number | null;
  vote_longitude_l0: number | null;
  vote_location_snapshot_at: string | null;
  vote_location_snapshot_version: number;
  submitted_at: string;
  is_valid: boolean;
  invalid_reason: string | null;
  created_at: string;
  updated_at: string;
};

export type NewVoteRow = {
  poll_id: string;
  option_id: string;
  user_id: string;
  verified_identity_id?: string | null;
  vote_latitude_l0?: number | null;
  vote_longitude_l0?: number | null;
  vote_location_snapshot_at?: string | null;
  vote_location_snapshot_version?: number;
  submitted_at: string;
  is_valid?: boolean;
  invalid_reason?: string | null;
};

export type PollMapMarkerCacheMarkerJson = Record<string, unknown>;

export type PollMapMarkerCacheRow = {
  poll_id: string;
  markers_level1_json: PollMapMarkerCacheMarkerJson[];
  schema_version: number;
  marker_count: number;
  total_votes: number;
  last_vote_submitted_at: string | null;
  refreshed_at: string;
  created_at: string;
  updated_at: string;
};

export type NewPollMapMarkerCacheRow = {
  poll_id: string;
  markers_level1_json?: PollMapMarkerCacheMarkerJson[];
  schema_version?: number;
  marker_count?: number;
  total_votes?: number;
  last_vote_submitted_at?: string | null;
  refreshed_at?: string;
};

export type UpdatePollMapMarkerCacheRow = Partial<
  Omit<
    PollMapMarkerCacheRow,
    "poll_id" | "created_at" | "updated_at"
  >
>;

export type PollMapRefreshQueueRow = {
  poll_id: string;
  pending_vote_events: number;
  first_enqueued_at: string;
  last_enqueued_at: string;
  last_processed_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
};

export type NewPollMapRefreshQueueRow = {
  poll_id: string;
  pending_vote_events?: number;
  first_enqueued_at?: string;
  last_enqueued_at?: string;
  last_processed_at?: string | null;
  last_error?: string | null;
};

export type UpdatePollMapRefreshQueueRow = Partial<
  Omit<
    PollMapRefreshQueueRow,
    "poll_id" | "created_at" | "updated_at"
  >
>;
