import { describe, expect, it } from "bun:test";

import {
  buildBallotCustodyPolicy,
  canBackendDecryptPollEncryptionCustodyModel,
  isAcceptedPollEncryptionCustodyModel,
} from "./ballotCustodyPolicyService";

describe("ballotCustodyPolicyService", () => {
  it("defaults to explicit operator-trusted private beta custody", () => {
    const policy = buildBallotCustodyPolicy();

    expect(policy).toMatchObject({
      version: "civicos-ballot-custody-policy-v1",
      mode: "operator_trusted_private_beta",
      releaseMode: "private_beta",
      pollEncryptionKeyCustodyModel: "operator-trusted-backend-db-v1",
      decryptor: "backend_service",
      operatorTrusted: true,
      threshold: false,
      backendCanDecryptBallots: true,
      backendKeyGenerationSupported: true,
      liveProvisionalPerOptionResults: true,
      acceptedVoteCountPublicDuringVoting: true,
      publicSecretBallotClaimAllowed: false,
      privateKeyMaterialExposedByApi: false,
    });
    expect(
      isAcceptedPollEncryptionCustodyModel(
        "backend-db-service-role-v1",
        policy,
      ),
    ).toBe(true);
    expect(
      canBackendDecryptPollEncryptionCustodyModel(
        "operator-trusted-backend-db-v1",
        policy,
      ),
    ).toBe(true);
  });

  it("models threshold custody as non-backend-decryptable until trustees exist", () => {
    const policy = buildBallotCustodyPolicy({
      mode: "threshold_trustee_v1",
      publicSecretBallotClaimsEnabled: true,
      liveProvisionalResultsEnabled: false,
    });

    expect(policy).toMatchObject({
      mode: "threshold_trustee_v1",
      releaseMode: "public_production",
      pollEncryptionKeyCustodyModel: "threshold-trustee-v1",
      decryptor: "threshold_trustees",
      operatorTrusted: false,
      threshold: true,
      backendCanDecryptBallots: false,
      backendKeyGenerationSupported: false,
      liveProvisionalPerOptionResults: false,
      publicSecretBallotClaimAllowed: true,
    });
    expect(
      canBackendDecryptPollEncryptionCustodyModel(
        "threshold-trustee-v1",
        policy,
      ),
    ).toBe(false);
  });
});
