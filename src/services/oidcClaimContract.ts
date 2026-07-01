export const OIDC_SUPPORTED_SCOPES = [
  "openid",
  "profile",
  "offline_access",
] as const;

export const OIDC_PROTOCOL_CLAIMS = [
  "sub",
  "iss",
  "aud",
  "exp",
  "iat",
  "auth_time",
  "nonce",
] as const;

export const OIDC_PROFILE_PROOF_CLAIMS = [
  "nickname",
  "preferred_username",
  "profile_completed",
  "passport_verified",
  "face_verified",
] as const;

export const OIDC_ASSURANCE_CLAIMS = ["amr", "acr"] as const;

export const OIDC_SUPPORTED_CLAIMS = [
  ...OIDC_PROTOCOL_CLAIMS,
  ...OIDC_PROFILE_PROOF_CLAIMS,
  ...OIDC_ASSURANCE_CLAIMS,
] as const;

export type ShareableClaimKey =
  | "nickname"
  | "profile_completed"
  | "passport_verified"
  | "face_verified";

export const OIDC_SHAREABLE_CLAIMS: ReadonlyArray<{
  key: ShareableClaimKey;
  label: string;
  description: string;
  valueType: "string" | "boolean";
}> = [
  {
    key: "nickname",
    label: "Public nickname",
    description: "Share your public CivicOS nickname.",
    valueType: "string",
  },
  {
    key: "profile_completed",
    label: "Profile completion proof",
    description: "Share whether your CivicOS profile is complete.",
    valueType: "boolean",
  },
  {
    key: "passport_verified",
    label: "Passport verification proof",
    description: "Share whether your passport verification is complete.",
    valueType: "boolean",
  },
  {
    key: "face_verified",
    label: "Face verification proof",
    description: "Share whether your face verification is complete.",
    valueType: "boolean",
  },
] as const;

export const OIDC_USERINFO_PROFILE_CLAIMS = [
  "nickname",
  "preferred_username",
  "profile_completed",
  "passport_verified",
  "face_verified",
] as const;

export const OIDC_FORBIDDEN_PUBLIC_CLAIMS = [
  "id",
  "user_id",
  "internal_user_id",
  "nidn",
  "nidnh",
  "passport_number",
  "birth_date",
  "date_of_birth",
  "mrz",
  "barcode",
  "nfc",
  "face_image",
  "face_mesh",
  "auth_credential_id",
  "credential_id",
  "attestation_key_id",
  "attestation_diagnostics",
] as const;
