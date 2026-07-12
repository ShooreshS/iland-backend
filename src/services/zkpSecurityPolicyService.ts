import { env } from "../config/env";
import {
  BACKEND_AUDIT_LOG_DOMAIN,
  BACKEND_AUDIT_LOG_HASH_ALGORITHM,
  BACKEND_AUDIT_LOG_VERSION,
  GENESIS_BACKEND_AUDIT_EVENT_HASH,
} from "./backendAuditHashChainService";
import { getBallotCustodyPolicy } from "./ballotCustodyPolicyService";
import { getProofSystemPolicy } from "./proofSystemPolicyService";
import { getSolanaAuditFeePolicy } from "./solanaAuditFeePolicyService";

export const ZKP_SECURITY_POLICY_VERSION =
  "civicos-zkp-security-policy-v1" as const;

export const ROOT_PUBLISHER_ACTIONS = [
  "registry-initialization",
  "poll-account-creation",
  "root-batch-commit",
  "final-result-publication",
] as const;

export type ZkpSecurityPolicy = Readonly<{
  version: typeof ZKP_SECURITY_POLICY_VERSION;
  phase: 12;
  backendSigner: Readonly<{
    role: "root_publisher_key";
    rootPublisherPublicKey: string | null;
    feePayerPublicKey: string | null;
    transactionsEnabled: boolean;
    privateKeyMaterialAcceptedByBackend: boolean;
    backendEnvFeePayerSecretConfigured: boolean;
    keypairFilesAllowedInRepository: false;
    custodyModel:
      | "external_kms_hsm_or_multisig_signing_service"
      | "backend_env_test_fee_payer_key";
    requiresSolFunding: true;
    dailyFeeLimitRequired: true;
    separateClusterKeysRequired: true;
    rotationPlanRequired: true;
    signsOnly: typeof ROOT_PUBLISHER_ACTIONS;
  }>;
  registryGovernance: Readonly<{
    registryAuthorityPublicKey: string | null;
    rootPublisherPublicKey: string | null;
    separateRootPublisherRequired: true;
    separationSatisfied: boolean;
    backendControlsRegistryAuthority: false;
  }>;
  programUpgradeAuthority: Readonly<{
    programId: string;
    developerWalletAllowed: false;
    backendControlsUpgradeAuthority: false;
    multisigRequired: true;
    timelockRecommended: true;
    publicUpgradeAnnouncementsRequired: true;
    versionedProgramIdsRequired: true;
  }>;
  ballotCustody: Readonly<{
    version: "civicos-ballot-custody-policy-v1";
    mode: "operator_trusted_private_beta" | "threshold_trustee_v1";
    releaseMode: "private_beta" | "public_production";
    decryptor: "backend_service" | "threshold_trustees";
    operatorTrusted: boolean;
    threshold: boolean;
    backendCanDecryptBallots: boolean;
    liveProvisionalPerOptionResults: boolean;
    acceptedVoteCountPublicDuringVoting: true;
    publicSecretBallotClaimAllowed: boolean;
    privateKeyMaterialExposedByApi: false;
    claim: string;
    productionGaps: readonly string[];
  }>;
  antiSpam: Readonly<{
    proofVerificationBeforeAcceptingVote: true;
    rateLimitsRequired: true;
    deviceSessionAbuseLimitsRequired: true;
    captchaPolicy: "allowed_only_when_privacy_acceptable";
    pollLevelQuotasRequired: true;
    backendFraudDetectionRequired: true;
    currentControls: string[];
    productionGaps: string[];
  }>;
  auditLog: Readonly<{
    version: typeof BACKEND_AUDIT_LOG_VERSION;
    domain: typeof BACKEND_AUDIT_LOG_DOMAIN;
    hashAlgorithm: typeof BACKEND_AUDIT_LOG_HASH_ALGORITHM;
    genesisPreviousHash: string;
    eventHashRule: "sha256(domain|version|hash_algorithm|previous_event_hash|canonical_event_payload)";
    table: "backend_audit_events";
    appendRpc: "append_backend_audit_event";
    anchorTarget: "audit_log_root";
    anchoringMode: "periodic_or_result_publication";
    storesRawIdentityFields: false;
    storesPrivateWitness: false;
  }>;
}>;

export const getZkpSecurityPolicy = (): ZkpSecurityPolicy => {
  const feePolicy = getSolanaAuditFeePolicy();
  const proofSystemPolicy = getProofSystemPolicy();
  const ballotCustody = getBallotCustodyPolicy();
  const backendEnvFeePayerSecretConfigured =
    typeof env.solanaAudit.feePayerSecretKey === "string" &&
    env.solanaAudit.feePayerSecretKey.trim().length > 0;

  return Object.freeze({
    version: ZKP_SECURITY_POLICY_VERSION,
    phase: 12,
    backendSigner: Object.freeze({
      role: "root_publisher_key",
      rootPublisherPublicKey: env.solanaAudit.rootPublisherPublicKey,
      feePayerPublicKey: feePolicy.feePayerPublicKey,
      transactionsEnabled: feePolicy.transactionsEnabled,
      privateKeyMaterialAcceptedByBackend: backendEnvFeePayerSecretConfigured,
      backendEnvFeePayerSecretConfigured,
      keypairFilesAllowedInRepository: false,
      custodyModel: backendEnvFeePayerSecretConfigured
        ? "backend_env_test_fee_payer_key"
        : "external_kms_hsm_or_multisig_signing_service",
      requiresSolFunding: true,
      dailyFeeLimitRequired: true,
      separateClusterKeysRequired: true,
      rotationPlanRequired: true,
      signsOnly: ROOT_PUBLISHER_ACTIONS,
    }),
    registryGovernance: Object.freeze({
      registryAuthorityPublicKey: env.solanaAudit.registryAuthority,
      rootPublisherPublicKey: env.solanaAudit.rootPublisherPublicKey,
      separateRootPublisherRequired: true,
      separationSatisfied: Boolean(
        env.solanaAudit.registryAuthority &&
          env.solanaAudit.rootPublisherPublicKey &&
          env.solanaAudit.registryAuthority !== env.solanaAudit.rootPublisherPublicKey,
      ),
      backendControlsRegistryAuthority: false,
    }),
    programUpgradeAuthority: Object.freeze({
      programId: env.solanaAudit.programId,
      developerWalletAllowed: false,
      backendControlsUpgradeAuthority: false,
      multisigRequired: true,
      timelockRecommended: true,
      publicUpgradeAnnouncementsRequired: true,
      versionedProgramIdsRequired: true,
    }),
    ballotCustody: Object.freeze({
      version: ballotCustody.version,
      mode: ballotCustody.mode,
      releaseMode: ballotCustody.releaseMode,
      decryptor: ballotCustody.decryptor,
      operatorTrusted: ballotCustody.operatorTrusted,
      threshold: ballotCustody.threshold,
      backendCanDecryptBallots: ballotCustody.backendCanDecryptBallots,
      liveProvisionalPerOptionResults:
        ballotCustody.liveProvisionalPerOptionResults,
      acceptedVoteCountPublicDuringVoting:
        ballotCustody.acceptedVoteCountPublicDuringVoting,
      publicSecretBallotClaimAllowed:
        ballotCustody.publicSecretBallotClaimAllowed,
      privateKeyMaterialExposedByApi:
        ballotCustody.privateKeyMaterialExposedByApi,
      claim: ballotCustody.claim,
      productionGaps: ballotCustody.productionGaps,
    }),
    antiSpam: Object.freeze({
      proofVerificationBeforeAcceptingVote: true,
      rateLimitsRequired: true,
      deviceSessionAbuseLimitsRequired: true,
      captchaPolicy: "allowed_only_when_privacy_acceptable",
      pollLevelQuotasRequired: true,
      backendFraudDetectionRequired: true,
      currentControls: [
        "Protected routes resolve authenticated backend sessions.",
        "Production auth requires app-attested sessions unless explicitly disabled outside production.",
        `Verified polls require ${proofSystemPolicy.proofVerificationMode} proof-envelope validation before vote insertion.`,
        "Verified identity and nullifier uniqueness block repeat votes.",
        "OIDC endpoints use hashed rate-limit buckets.",
      ],
      productionGaps: [
        "Route-level rate limits for poll creation and vote submission.",
        "Poll-level sponsored-fee quotas before transaction publication is enabled.",
        "Fraud scoring hooks for abnormal session/device/poll behavior.",
      ],
    }),
    auditLog: Object.freeze({
      version: BACKEND_AUDIT_LOG_VERSION,
      domain: BACKEND_AUDIT_LOG_DOMAIN,
      hashAlgorithm: BACKEND_AUDIT_LOG_HASH_ALGORITHM,
      genesisPreviousHash: GENESIS_BACKEND_AUDIT_EVENT_HASH,
      eventHashRule:
        "sha256(domain|version|hash_algorithm|previous_event_hash|canonical_event_payload)",
      table: "backend_audit_events",
      appendRpc: "append_backend_audit_event",
      anchorTarget: "audit_log_root",
      anchoringMode: "periodic_or_result_publication",
      storesRawIdentityFields: false,
      storesPrivateWitness: false,
    }),
  });
};

export const zkpSecurityPolicyService = {
  getPolicy: getZkpSecurityPolicy,
};

export default zkpSecurityPolicyService;
