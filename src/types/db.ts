import type {
  PollJurisdictionType,
  PollStatus,
  PollVotePrivacyMode,
} from "./contracts";
import type { JsonValue } from "./json";

export type UserRow = {
  id: string;
  username: string | null;
  display_name: string | null;
  public_nickname: string | null;
  onboarding_status: string;
  verification_level: string;
  has_wallet: boolean;
  wallet_credential_id: string | null;
  selected_land_id: string | null;
  preferred_language: string | null;
  auth_generation: number;
  account_status: "active" | "disabled" | "banned";
  created_at: string;
  updated_at: string;
};

export type NewUserRow = {
  username: string | null;
  display_name: string | null;
  public_nickname?: string | null;
  onboarding_status: string;
  verification_level: string;
  has_wallet: boolean;
  wallet_credential_id: string | null;
  selected_land_id: string | null;
  preferred_language: string | null;
  auth_generation?: number;
  account_status?: "active" | "disabled" | "banned";
};

export type AuthCredentialPlatform = "ios" | "android";
export type AuthCredentialAlgorithm = "p256";
export type AuthCredentialStatus = "active" | "revoked" | "superseded";

export type AuthCredentialRow = {
  id: string;
  user_id: string;
  platform: AuthCredentialPlatform;
  algorithm: AuthCredentialAlgorithm;
  credential_id: string;
  public_key_pem: string;
  status: AuthCredentialStatus;
  device_label: string | null;
  last_authenticated_at: string | null;
  superseded_by_auth_credential_id: string | null;
  revoked_at: string | null;
  revocation_reason: string | null;
  created_at: string;
  updated_at: string;
};

export type NewAuthCredentialRow = {
  user_id: string;
  platform: AuthCredentialPlatform;
  algorithm: AuthCredentialAlgorithm;
  credential_id: string;
  public_key_pem: string;
  device_label?: string | null;
};

export type AppAttestationProvider =
  | "ios_app_attest"
  | "android_play_integrity";
export type AppAttestationEnvironment = "development" | "production";
export type AppAttestationCredentialStatus =
  | "pending"
  | "verified"
  | "revoked"
  | "superseded";

export type AppAttestationCredentialRow = {
  id: string;
  user_id: string;
  auth_credential_id: string;
  platform: AuthCredentialPlatform;
  attestation_provider: AppAttestationProvider;
  environment: AppAttestationEnvironment;
  attestation_key_id: string | null;
  public_key_pem: string | null;
  app_identifier: string | null;
  package_name: string | null;
  signing_cert_digest: string | null;
  status: AppAttestationCredentialStatus;
  last_counter: number | null;
  last_asserted_at: string | null;
  last_assertion_nonce_hash: string | null;
  revoked_at: string | null;
  revocation_reason: string | null;
  created_at: string;
  updated_at: string;
};

export type NewAppAttestationCredentialRow = {
  user_id: string;
  auth_credential_id: string;
  platform: AuthCredentialPlatform;
  attestation_provider: AppAttestationProvider;
  environment: AppAttestationEnvironment;
  attestation_key_id?: string | null;
  public_key_pem?: string | null;
  app_identifier?: string | null;
  package_name?: string | null;
  signing_cert_digest?: string | null;
  status?: AppAttestationCredentialStatus;
};

export type AuthSessionStatus = "active" | "revoked" | "expired" | "superseded";

export type AuthSessionRow = {
  id: string;
  user_id: string;
  auth_credential_id: string;
  status: AuthSessionStatus;
  auth_generation: number;
  current_access_token_hash: string | null;
  attestation_verified_at: string;
  last_seen_at: string;
  expires_at: string;
  revoked_at: string | null;
  revocation_reason: string | null;
  created_at: string;
  updated_at: string;
};

export type NewAuthSessionRow = {
  user_id: string;
  auth_credential_id: string;
  status?: AuthSessionStatus;
  auth_generation: number;
  current_access_token_hash: string;
  attestation_verified_at: string;
  last_seen_at?: string;
  expires_at: string;
};

export type RefreshTokenFamilyStatus =
  | "active"
  | "revoked"
  | "reused"
  | "expired";

export type RefreshTokenFamilyRow = {
  id: string;
  session_id: string;
  user_id: string;
  status: RefreshTokenFamilyStatus;
  current_token_hash: string;
  previous_token_hash: string | null;
  rotation_counter: number;
  last_rotated_at: string;
  last_used_at: string | null;
  expires_at: string;
  revoked_at: string | null;
  revocation_reason: string | null;
  created_at: string;
  updated_at: string;
};

export type NewRefreshTokenFamilyRow = {
  session_id: string;
  user_id: string;
  status?: RefreshTokenFamilyStatus;
  current_token_hash: string;
  previous_token_hash?: string | null;
  rotation_counter?: number;
  last_rotated_at?: string;
  expires_at: string;
};

export type AuthAuditEventRow = {
  id: string;
  user_id: string | null;
  auth_credential_id: string | null;
  session_id: string | null;
  event_type: string;
  platform: AuthCredentialPlatform | null;
  metadata: Record<string, unknown>;
  occurred_at: string;
};

export type NewAuthAuditEventRow = {
  user_id?: string | null;
  auth_credential_id?: string | null;
  session_id?: string | null;
  event_type: string;
  platform?: AuthCredentialPlatform | null;
  metadata?: Record<string, unknown>;
  occurred_at?: string;
};

export type AuthChallengePurpose = "register" | "login" | "recover";

export type AuthChallengeRow = {
  id: string;
  purpose: AuthChallengePurpose;
  platform: AuthCredentialPlatform;
  challenge_hash: string;
  credential_id_hint: string | null;
  expires_at: string;
  consumed_at: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
};

export type NewAuthChallengeRow = {
  purpose: AuthChallengePurpose;
  platform: AuthCredentialPlatform;
  challenge_hash: string;
  credential_id_hint?: string | null;
  expires_at: string;
  metadata?: Record<string, unknown>;
};

export type IdentityProfileRow = {
  id: string;
  user_id: string;
  passport_scan_completed: boolean;
  passport_nfc_completed: boolean;
  national_id_scan_completed: boolean;
  face_scan_completed: boolean;
  face_bound_to_identity: boolean;
  passport_verified_at: string | null;
  national_id_verified_at: string | null;
  face_verified_at: string | null;
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
  passport_verified_at: string | null;
  national_id_verified_at: string | null;
  face_verified_at: string | null;
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

export type CredentialRegistryRow = {
  id: string;
  verified_identity_id: string;
  identity_key_hash: string;
  credential_commitment: string;
  credential_schema_hash: string;
  claims_hash: string;
  credential_issuer_id: string;
  commitment_scheme: string;
  merkle_depth: number;
  leaf_index: number;
  revoked_at: string | null;
  revocation_reason: string | null;
  created_at: string;
  updated_at: string;
};

export type NewCredentialRegistryRow = {
  verified_identity_id: string;
  identity_key_hash: string;
  credential_commitment: string;
  credential_schema_hash: string;
  claims_hash: string;
  credential_issuer_id: string;
  commitment_scheme?: string;
  merkle_depth?: number;
  leaf_index: number;
};

export type CredentialRootRow = {
  id: string;
  root: string;
  previous_root: string | null;
  merkle_depth: number;
  leaf_count: number;
  latest_credential_registry_id: string | null;
  solana_tx_signature: string | null;
  created_at: string;
};

export type NewCredentialRootRow = {
  root: string;
  previous_root?: string | null;
  merkle_depth?: number;
  leaf_count: number;
  latest_credential_registry_id?: string | null;
  solana_tx_signature?: string | null;
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

export type OidcSigningKeyStatus =
  | "active"
  | "retiring"
  | "retired"
  | "revoked";

export type OidcSigningKeyRow = {
  id: string;
  kid: string;
  key_use: "sig";
  algorithm: "RS256";
  status: OidcSigningKeyStatus;
  public_jwk: Record<string, unknown>;
  private_key_ref: string | null;
  not_before: string;
  not_after: string | null;
  activated_at: string | null;
  retired_at: string | null;
  revoked_at: string | null;
  created_at: string;
  updated_at: string;
};

export type OidcClientType = "confidential" | "public";
export type OidcClientApplicationType = "web" | "native";
export type OidcClientStatus = "active" | "disabled" | "deleted";

export type OidcClientRow = {
  id: string;
  client_id: string;
  client_name: string;
  client_type: OidcClientType;
  application_type: OidcClientApplicationType;
  status: OidcClientStatus;
  client_uri: string | null;
  logo_uri: string | null;
  tos_uri: string | null;
  policy_uri: string | null;
  sector_identifier: string;
  allowed_scopes: string[];
  default_scopes: string[];
  require_pkce: boolean;
  pkce_required_method: "S256";
  id_token_signed_response_alg: "RS256";
  access_token_ttl_seconds: number;
  authorization_code_ttl_seconds: number;
  refresh_token_ttl_days: number;
  created_at: string;
  updated_at: string;
};

export type OidcClientSecretStatus = "active" | "revoked" | "expired";

export type OidcClientSecretRow = {
  id: string;
  client_id: string;
  secret_hash: string;
  label: string | null;
  status: OidcClientSecretStatus;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  revocation_reason: string | null;
  created_at: string;
  updated_at: string;
};

export type OidcClientRedirectUriUsage = "redirect" | "post_logout";

export type OidcClientRedirectUriRow = {
  id: string;
  client_id: string;
  usage: OidcClientRedirectUriUsage;
  redirect_uri: string;
  created_at: string;
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
  poll_policy_json?: JsonValue | null;
  poll_policy_hash?: string | null;
  credential_schema_json?: JsonValue | null;
  credential_schema_hash?: string | null;
  vote_privacy_mode?: PollVotePrivacyMode;
  option_set_hash?: string | null;
  poll_encryption_key_id?: string | null;
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
  id?: string;
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
  poll_policy_json?: JsonValue | null;
  poll_policy_hash?: string | null;
  credential_schema_json?: JsonValue | null;
  credential_schema_hash?: string | null;
  vote_privacy_mode?: PollVotePrivacyMode;
  option_set_hash?: string | null;
  poll_encryption_key_id?: string | null;
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

export type PollEncryptionKeyRow = {
  id: string;
  key_id: string;
  poll_id: string | null;
  status: "active" | "revoked";
  algorithm: string;
  key_agreement: string;
  kdf: string;
  cipher: string;
  public_key_jwk: JsonValue;
  public_key_hash: string;
  private_key_jwk: JsonValue;
  custody_model: string;
  created_at: string;
  revoked_at: string | null;
  revocation_reason: string | null;
};

export type NewPollEncryptionKeyRow = {
  key_id: string;
  poll_id?: string | null;
  status?: "active" | "revoked";
  algorithm: string;
  key_agreement: string;
  kdf: string;
  cipher: string;
  public_key_jwk: JsonValue;
  public_key_hash: string;
  private_key_jwk: JsonValue;
  custody_model?: string;
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
  nullifier: string | null;
  vote_commitment: string | null;
  encrypted_vote: JsonValue | null;
  proof_hash: string | null;
  proof_system_version: string | null;
  verification_method_version: string | null;
  proof_verification_status: "preprover_accepted" | "verified" | "rejected" | null;
  proof_public_inputs_json: JsonValue | null;
  proof_envelope_json: JsonValue | null;
  accepted_at: string | null;
  batch_id: string | null;
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
  nullifier?: string | null;
  vote_commitment?: string | null;
  encrypted_vote?: JsonValue | null;
  proof_hash?: string | null;
  proof_system_version?: string | null;
  verification_method_version?: string | null;
  proof_verification_status?: "preprover_accepted" | "verified" | "rejected" | null;
  proof_public_inputs_json?: JsonValue | null;
  proof_envelope_json?: JsonValue | null;
  accepted_at?: string | null;
  batch_id?: string | null;
  vote_latitude_l0?: number | null;
  vote_longitude_l0?: number | null;
  vote_location_snapshot_at?: string | null;
  vote_location_snapshot_version?: number;
  submitted_at: string;
  is_valid?: boolean;
  invalid_reason?: string | null;
};

export type PollRootRow = {
  id: string;
  poll_id: string;
  batch_id: string;
  previous_nullifier_root: string | null;
  nullifier_root: string;
  previous_vote_commitment_root: string | null;
  vote_commitment_root: string;
  previous_encrypted_vote_root: string | null;
  encrypted_vote_root: string;
  accepted_count: number;
  solana_tx_signature: string | null;
  created_at: string;
};

export type NewPollRootRow = {
  poll_id: string;
  batch_id: string;
  previous_nullifier_root?: string | null;
  nullifier_root: string;
  previous_vote_commitment_root?: string | null;
  vote_commitment_root: string;
  previous_encrypted_vote_root?: string | null;
  encrypted_vote_root: string;
  accepted_count: number;
  solana_tx_signature?: string | null;
};

export type PollAuditEventRow = {
  id: string;
  poll_id: string | null;
  event_type: string;
  payload_hash: string;
  payload_json: JsonValue | null;
  solana_tx_signature: string | null;
  created_at: string;
};

export type NewPollAuditEventRow = {
  poll_id?: string | null;
  event_type: string;
  payload_hash: string;
  payload_json?: JsonValue | null;
  solana_tx_signature?: string | null;
};

export type PollZkVoteRow = {
  id: string;
  poll_id: string;
  nullifier: string;
  vote_commitment: string;
  encrypted_vote: JsonValue;
  encrypted_vote_hash: string;
  encrypted_vote_commitment: string;
  proof_hash: string;
  proof_system_version: string;
  verification_method_version: string;
  proof_verification_status: "verified";
  proof_public_inputs_json: JsonValue;
  proof_envelope_hash: string;
  verifier_key_hash: string;
  circuit_id: string;
  accepted_at: string;
  batch_id: string | null;
  created_at: string;
};

export type NewPollZkVoteRow = {
  poll_id: string;
  nullifier: string;
  vote_commitment: string;
  encrypted_vote: JsonValue;
  encrypted_vote_hash: string;
  encrypted_vote_commitment: string;
  proof_hash: string;
  proof_system_version: string;
  verification_method_version: string;
  proof_verification_status?: "verified";
  proof_public_inputs_json: JsonValue;
  proof_envelope_hash: string;
  verifier_key_hash: string;
  circuit_id: string;
  accepted_at?: string;
  batch_id?: string | null;
};

export type PollTallyProofRow = {
  id: string;
  poll_id: string;
  result_hash: string;
  tally_proof_hash: string;
  tally_public_inputs_hash: string;
  tally_verifier_key_hash: string;
  tally_circuit_id: string;
  nullifier_root: string;
  vote_commitment_root: string;
  encrypted_vote_root: string;
  accepted_count: number;
  proof_envelope_json: JsonValue;
  verified_at: string;
  created_at: string;
};

export type NewPollTallyProofRow = {
  poll_id: string;
  result_hash: string;
  tally_proof_hash: string;
  tally_public_inputs_hash: string;
  tally_verifier_key_hash: string;
  tally_circuit_id: string;
  nullifier_root: string;
  vote_commitment_root: string;
  encrypted_vote_root: string;
  accepted_count: number;
  proof_envelope_json: JsonValue;
  verified_at?: string;
};

export type ZkpTallyJobStatus =
  | "pending"
  | "running"
  | "succeeded"
  | "failed"
  | "cancelled";

export type ZkpTallyJobRow = {
  id: string;
  poll_id: string;
  status: ZkpTallyJobStatus;
  priority: number;
  attempts: number;
  max_attempts: number;
  locked_by: string | null;
  locked_at: string | null;
  next_attempt_at: string;
  proof_public_inputs_hash: string | null;
  tally_proof_hash: string | null;
  result_hash: string | null;
  error_code: string | null;
  error_message: string | null;
  created_at: string;
  updated_at: string;
};

export type ZkpTallyWorkerHeartbeatStatus =
  | "starting"
  | "running"
  | "idle"
  | "stopping"
  | "stopped"
  | "error";

export type ZkpTallyWorkerHeartbeatRow = {
  worker_id: string;
  host: string | null;
  status: ZkpTallyWorkerHeartbeatStatus;
  current_job_id: string | null;
  message: string | null;
  first_seen_at: string;
  last_seen_at: string;
};

export type BackendAuditEventDecision =
  | "accepted"
  | "rejected"
  | "recorded"
  | "published"
  | "errored";

export type BackendAuditEventRow = {
  id: string;
  stream_id: string;
  sequence: number;
  previous_event_hash: string;
  event_hash: string;
  event_type: string;
  decision: BackendAuditEventDecision;
  subject_type: string | null;
  subject_id: string | null;
  event_payload_json: JsonValue;
  occurred_at: string;
  anchored_at: string | null;
  anchor_cluster: string | null;
  anchor_tx_signature: string | null;
  created_at: string;
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
