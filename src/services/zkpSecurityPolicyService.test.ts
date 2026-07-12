import { describe, expect, it } from "bun:test";

import {
  ROOT_PUBLISHER_ACTIONS,
  getZkpSecurityPolicy,
} from "./zkpSecurityPolicyService";

describe("zkpSecurityPolicyService", () => {
  it("requires external custody for the backend root publisher signer", () => {
    const policy = getZkpSecurityPolicy();

    expect(policy.version).toBe("civicos-zkp-security-policy-v1");
    expect(policy.phase).toBe(12);
    expect(policy.backendSigner).toMatchObject({
      role: "root_publisher_key",
      transactionsEnabled: false,
      keypairFilesAllowedInRepository: false,
      requiresSolFunding: true,
      dailyFeeLimitRequired: true,
      separateClusterKeysRequired: true,
      rotationPlanRequired: true,
    });
    expect(typeof policy.backendSigner.privateKeyMaterialAcceptedByBackend).toBe(
      "boolean",
    );
    expect(typeof policy.backendSigner.backendEnvFeePayerSecretConfigured).toBe(
      "boolean",
    );
    expect([
      "external_kms_hsm_or_multisig_signing_service",
      "backend_env_test_fee_payer_key",
    ]).toContain(policy.backendSigner.custodyModel);
    expect(policy.backendSigner.signsOnly).toBe(ROOT_PUBLISHER_ACTIONS);
  });

  it("tracks registry authority separately from root publisher", () => {
    const policy = getZkpSecurityPolicy();

    expect(policy.registryGovernance).toMatchObject({
      registryAuthorityPublicKey: null,
      separateRootPublisherRequired: true,
      separationSatisfied: false,
      backendControlsRegistryAuthority: false,
    });
    expect(policy.registryGovernance.rootPublisherPublicKey).toBe(
      policy.backendSigner.rootPublisherPublicKey,
    );
  });

  it("keeps program upgrade authority outside a developer wallet and backend", () => {
    const policy = getZkpSecurityPolicy();

    expect(policy.programUpgradeAuthority).toMatchObject({
      developerWalletAllowed: false,
      backendControlsUpgradeAuthority: false,
      multisigRequired: true,
      timelockRecommended: true,
      publicUpgradeAnnouncementsRequired: true,
      versionedProgramIdsRequired: true,
    });
  });

  it("states the ballot custody trust boundary", () => {
    const policy = getZkpSecurityPolicy();

    expect(policy.ballotCustody).toMatchObject({
      version: "civicos-ballot-custody-policy-v1",
      mode: "operator_trusted_private_beta",
      releaseMode: "private_beta",
      decryptor: "backend_service",
      operatorTrusted: true,
      threshold: false,
      backendCanDecryptBallots: true,
      liveProvisionalPerOptionResults: true,
      acceptedVoteCountPublicDuringVoting: true,
      publicSecretBallotClaimAllowed: false,
      privateKeyMaterialExposedByApi: false,
    });
    expect(policy.ballotCustody.productionGaps).toContain(
      "Do not market operator-secret ballots while backend-held keys can decrypt openings.",
    );
  });

  it("records anti-spam requirements and current controls", () => {
    const policy = getZkpSecurityPolicy();

    expect(policy.antiSpam.proofVerificationBeforeAcceptingVote).toBe(true);
    expect(policy.antiSpam.rateLimitsRequired).toBe(true);
    expect(policy.antiSpam.deviceSessionAbuseLimitsRequired).toBe(true);
    expect(policy.antiSpam.pollLevelQuotasRequired).toBe(true);
    expect(policy.antiSpam.backendFraudDetectionRequired).toBe(true);
    expect(policy.antiSpam.currentControls).toContain(
      "Verified identity and nullifier uniqueness block repeat votes.",
    );
    expect(policy.antiSpam.productionGaps).toContain(
      "Route-level rate limits for poll creation and vote submission.",
    );
  });

  it("defines the hash-linked audit log boundary", () => {
    const policy = getZkpSecurityPolicy();

    expect(policy.auditLog).toMatchObject({
      version: "civicos-backend-audit-log-v1",
      hashAlgorithm: "sha256",
      table: "backend_audit_events",
      appendRpc: "append_backend_audit_event",
      anchorTarget: "audit_log_root",
      anchoringMode: "periodic_or_result_publication",
      storesRawIdentityFields: false,
      storesPrivateWitness: false,
    });
    expect(policy.auditLog.genesisPreviousHash).toBe("0".repeat(64));
  });
});
