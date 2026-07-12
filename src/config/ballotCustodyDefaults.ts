export const BALLOT_CUSTODY_POLICY_VERSION =
  "civicos-ballot-custody-policy-v1" as const;

export const OPERATOR_TRUSTED_PRIVATE_BETA_CUSTODY_MODE =
  "operator_trusted_private_beta" as const;
export const THRESHOLD_TRUSTEE_CUSTODY_MODE = "threshold_trustee_v1" as const;

export const OPERATOR_TRUSTED_BACKEND_DB_CUSTODY_MODEL =
  "operator-trusted-backend-db-v1" as const;
export const LEGACY_BACKEND_DB_CUSTODY_MODEL =
  "backend-db-service-role-v1" as const;
export const THRESHOLD_TRUSTEE_CUSTODY_MODEL =
  "threshold-trustee-v1" as const;

export const BALLOT_CUSTODY_MODES = [
  OPERATOR_TRUSTED_PRIVATE_BETA_CUSTODY_MODE,
  THRESHOLD_TRUSTEE_CUSTODY_MODE,
] as const;

export type BallotCustodyMode = (typeof BALLOT_CUSTODY_MODES)[number];
