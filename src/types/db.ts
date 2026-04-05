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

export type VoteRow = {
  id: string;
  poll_id: string;
  option_id: string;
  user_id: string;
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
  submitted_at: string;
  is_valid?: boolean;
  invalid_reason?: string | null;
};
