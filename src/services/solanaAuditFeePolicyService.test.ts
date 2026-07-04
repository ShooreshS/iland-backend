import { describe, expect, it } from "bun:test";

import { env } from "../config/env";
import { SOLANA_BASE_FEE_LAMPORTS_PER_SIGNATURE } from "../config/solanaAuditDefaults";
import {
  getSolanaAuditFeePolicy,
  resolveSolanaAuditFeeResponsibility,
  type SolanaAuditFeePolicy,
} from "./solanaAuditFeePolicyService";

const policyWith = (
  overrides: Partial<SolanaAuditFeePolicy>,
): SolanaAuditFeePolicy => ({
  ...getSolanaAuditFeePolicy(),
  ...overrides,
});

describe("Phase 7 Solana fee sponsorship policy", () => {
  it("defaults to CivicOS-sponsored SOL fees with user-paid mode disabled", () => {
    const policy = getSolanaAuditFeePolicy();

    expect(policy.defaultFeeMode).toBe("civicos-sponsored");
    expect(policy.sponsorshipEnabled).toBe(true);
    expect(policy.userPaidFeesEnabled).toBe(false);
    expect(policy.networkFeeCurrency).toBe("SOL");
    expect(policy.baseFeeLamportsPerSignature).toBe(
      SOLANA_BASE_FEE_LAMPORTS_PER_SIGNATURE,
    );
    expect(policy.sholanPaysNetworkFees).toBe(false);
    expect(policy.chargesSholanForBackendProcessing).toBe(false);
    expect(policy.transactionsEnabled).toBe(false);
  });

  it("does not charge Solana fees for normal vote submission", () => {
    expect(resolveSolanaAuditFeeResponsibility({ action: "vote-submission" })).toEqual({
      action: "vote-submission",
      status: "not_required",
      requiresOnChainTransaction: false,
      effectiveFeeMode: null,
      networkFeeCurrency: "SOL",
      baseFeeLamportsPerSignature: SOLANA_BASE_FEE_LAMPORTS_PER_SIGNATURE,
      requiresBackendSigner: false,
      requiresUserWallet: false,
      feePayerPublicKey: null,
      sholanCostBaseUnits: "0",
      message: "Normal vote submission remains off-chain and has no Solana fee.",
    });
  });

  it("uses a backend signer and SOL fee payer for sponsored root commits", () => {
    const result = resolveSolanaAuditFeeResponsibility(
      { action: "root-batch-commit" },
      policyWith({ feePayerPublicKey: "FeePayer1111111111111111111111111111111111" }),
    );

    expect(result.status).toBe("accepted");
    expect(result.effectiveFeeMode).toBe("civicos-sponsored");
    expect(result.requiresOnChainTransaction).toBe(true);
    expect(result.requiresBackendSigner).toBe(true);
    expect(result.requiresUserWallet).toBe(false);
    expect(result.feePayerPublicKey).toBe(
      "FeePayer1111111111111111111111111111111111",
    );
    expect(result.networkFeeCurrency).toBe("SOL");
    expect(result.sholanCostBaseUnits).toBe("0");
  });

  it("keeps user-paid mode disabled by default", () => {
    const result = resolveSolanaAuditFeeResponsibility({
      action: "donation",
      requestedFeeMode: "user-paid",
    });

    expect(result.status).toBe("user_paid_disabled");
    expect(result.requiresUserWallet).toBe(false);
    expect(result.sholanCostBaseUnits).toBe("0");
  });

  it("allows user-paid fees only for optional actions when explicitly enabled", () => {
    const policy = policyWith({ userPaidFeesEnabled: true });

    const donation = resolveSolanaAuditFeeResponsibility(
      { action: "donation", requestedFeeMode: "user-paid" },
      policy,
    );
    const rootCommit = resolveSolanaAuditFeeResponsibility(
      { action: "root-batch-commit", requestedFeeMode: "user-paid" },
      policy,
    );

    expect(donation.status).toBe("accepted");
    expect(donation.requiresUserWallet).toBe(true);
    expect(donation.requiresBackendSigner).toBe(false);
    expect(rootCommit.status).toBe("unsupported_user_paid_action");
  });

  it("exposes Phase 7 fee defaults through env config", () => {
    expect(env.solanaAudit.defaultFeeMode).toBe("civicos-sponsored");
    expect(env.solanaAudit.sponsorshipEnabled).toBe(true);
    expect(env.solanaAudit.userPaidFeesEnabled).toBe(false);
    expect(env.solanaAudit.baseFeeLamportsPerSignature).toBe(
      SOLANA_BASE_FEE_LAMPORTS_PER_SIGNATURE,
    );
    expect(env.solanaAudit.networkFeeCurrency).toBe("SOL");
  });
});
