import { env } from "../config/env";
import {
  BALLOT_CUSTODY_POLICY_VERSION,
  LEGACY_BACKEND_DB_CUSTODY_MODEL,
  OPERATOR_TRUSTED_BACKEND_DB_CUSTODY_MODEL,
  OPERATOR_TRUSTED_PRIVATE_BETA_CUSTODY_MODE,
  THRESHOLD_TRUSTEE_CUSTODY_MODE,
  THRESHOLD_TRUSTEE_CUSTODY_MODEL,
  type BallotCustodyMode,
} from "../config/ballotCustodyDefaults";

export {
  BALLOT_CUSTODY_POLICY_VERSION,
  LEGACY_BACKEND_DB_CUSTODY_MODEL,
  OPERATOR_TRUSTED_BACKEND_DB_CUSTODY_MODEL,
  OPERATOR_TRUSTED_PRIVATE_BETA_CUSTODY_MODE,
  THRESHOLD_TRUSTEE_CUSTODY_MODE,
  THRESHOLD_TRUSTEE_CUSTODY_MODEL,
  type BallotCustodyMode,
};

export type BallotCustodyPolicy = Readonly<{
  version: typeof BALLOT_CUSTODY_POLICY_VERSION;
  mode: BallotCustodyMode;
  releaseMode: "private_beta" | "public_production";
  pollEncryptionKeyCustodyModel:
    | typeof OPERATOR_TRUSTED_BACKEND_DB_CUSTODY_MODEL
    | typeof THRESHOLD_TRUSTEE_CUSTODY_MODEL;
  acceptedPollEncryptionKeyCustodyModels: readonly string[];
  decryptor: "backend_service" | "threshold_trustees";
  operatorTrusted: boolean;
  threshold: boolean;
  backendCanDecryptBallots: boolean;
  backendKeyGenerationSupported: boolean;
  liveProvisionalPerOptionResults: boolean;
  acceptedVoteCountPublicDuringVoting: true;
  publicSecretBallotClaimAllowed: boolean;
  privateKeyMaterialExposedByApi: false;
  privateKeyStorage:
    | "plaintext_database_jwk_private_beta"
    | "threshold_trustee_shares";
  claim: string;
  productionGaps: readonly string[];
}>;

export const normalizeBallotCustodyMode = (
  value: unknown,
): BallotCustodyMode => {
  if (value === THRESHOLD_TRUSTEE_CUSTODY_MODE) {
    return THRESHOLD_TRUSTEE_CUSTODY_MODE;
  }
  return OPERATOR_TRUSTED_PRIVATE_BETA_CUSTODY_MODE;
};

export const buildBallotCustodyPolicy = (
  input: Partial<{
    mode: BallotCustodyMode;
    publicSecretBallotClaimsEnabled: boolean;
    liveProvisionalResultsEnabled: boolean;
  }> = {},
): BallotCustodyPolicy => {
  const mode = normalizeBallotCustodyMode(input.mode);
  const threshold = mode === THRESHOLD_TRUSTEE_CUSTODY_MODE;
  const liveProvisionalPerOptionResults =
    input.liveProvisionalResultsEnabled ?? !threshold;
  const publicSecretBallotClaimAllowed =
    input.publicSecretBallotClaimsEnabled === true && threshold;

  if (threshold) {
    return Object.freeze({
      version: BALLOT_CUSTODY_POLICY_VERSION,
      mode,
      releaseMode: "public_production",
      pollEncryptionKeyCustodyModel: THRESHOLD_TRUSTEE_CUSTODY_MODEL,
      acceptedPollEncryptionKeyCustodyModels: [
        THRESHOLD_TRUSTEE_CUSTODY_MODEL,
      ],
      decryptor: "threshold_trustees",
      operatorTrusted: false,
      threshold: true,
      backendCanDecryptBallots: false,
      backendKeyGenerationSupported: false,
      liveProvisionalPerOptionResults: false,
      acceptedVoteCountPublicDuringVoting: true,
      publicSecretBallotClaimAllowed,
      privateKeyMaterialExposedByApi: false,
      privateKeyStorage: "threshold_trustee_shares",
      claim:
        "Threshold trustee custody is required before CivicOS can claim ballots are secret from the operator.",
      productionGaps: [
        "Threshold key generation and trustee share distribution are not integrated.",
        "Trustee-assisted poll-close decryption/tally ceremony is not integrated.",
        "Live per-option provisional results are disabled under threshold custody.",
      ],
    });
  }

  return Object.freeze({
    version: BALLOT_CUSTODY_POLICY_VERSION,
    mode,
    releaseMode: "private_beta",
    pollEncryptionKeyCustodyModel: OPERATOR_TRUSTED_BACKEND_DB_CUSTODY_MODEL,
    acceptedPollEncryptionKeyCustodyModels: [
      OPERATOR_TRUSTED_BACKEND_DB_CUSTODY_MODEL,
      LEGACY_BACKEND_DB_CUSTODY_MODEL,
    ],
    decryptor: "backend_service",
    operatorTrusted: true,
    threshold: false,
    backendCanDecryptBallots: true,
    backendKeyGenerationSupported: true,
    liveProvisionalPerOptionResults,
    acceptedVoteCountPublicDuringVoting: true,
    publicSecretBallotClaimAllowed: false,
    privateKeyMaterialExposedByApi: false,
    privateKeyStorage: "plaintext_database_jwk_private_beta",
    claim:
      "Private beta custody: CivicOS backend can decrypt ballots for provisional and final tally operations.",
    productionGaps: [
      "Move poll decryption keys to threshold trustees before public secret-ballot claims.",
      "Do not market operator-secret ballots while backend-held keys can decrypt openings.",
    ],
  });
};

export const getBallotCustodyPolicy = (): BallotCustodyPolicy =>
  buildBallotCustodyPolicy({
    mode: env.zkp.ballotCustody.mode,
    publicSecretBallotClaimsEnabled:
      env.zkp.ballotCustody.publicSecretBallotClaimsEnabled,
    liveProvisionalResultsEnabled:
      env.zkp.ballotCustody.liveProvisionalResultsEnabled,
  });

export const isAcceptedPollEncryptionCustodyModel = (
  custodyModel: string,
  policy: BallotCustodyPolicy = getBallotCustodyPolicy(),
): boolean => policy.acceptedPollEncryptionKeyCustodyModels.includes(custodyModel);

export const canBackendDecryptPollEncryptionCustodyModel = (
  custodyModel: string,
  policy: BallotCustodyPolicy = getBallotCustodyPolicy(),
): boolean =>
  policy.backendCanDecryptBallots &&
  isAcceptedPollEncryptionCustodyModel(custodyModel, policy);

export const ballotCustodyPolicyService = {
  getPolicy: getBallotCustodyPolicy,
};

export default ballotCustodyPolicyService;
