import { env } from "../config/env";
import {
  DEFAULT_SOLANA_AUDIT_FEE_MODE,
  SOLANA_BASE_FEE_LAMPORTS_PER_SIGNATURE,
  type SolanaAuditFeeMode,
} from "../config/solanaAuditDefaults";

export const SOLANA_AUDIT_ACTIONS = [
  "vote-submission",
  "registry-initialization",
  "poll-account-creation",
  "root-batch-commit",
  "final-result-publication",
  "donation",
  "community-poll-creation",
  "public-proposal-publication",
  "poll-batch-sponsorship",
  "governance-reward-claim",
] as const;

export type SolanaAuditAction = (typeof SOLANA_AUDIT_ACTIONS)[number];

export type SolanaAuditFeeResponsibilityStatus =
  | "not_required"
  | "accepted"
  | "sponsorship_disabled"
  | "user_paid_disabled"
  | "unsupported_user_paid_action";

export type SolanaAuditFeePolicy = Readonly<{
  defaultFeeMode: SolanaAuditFeeMode;
  sponsorshipEnabled: boolean;
  userPaidFeesEnabled: boolean;
  networkFeeCurrency: "SOL";
  baseFeeLamportsPerSignature: typeof SOLANA_BASE_FEE_LAMPORTS_PER_SIGNATURE;
  sholanPaysNetworkFees: false;
  chargesSholanForBackendProcessing: false;
  transactionsEnabled: boolean;
  feePayerPublicKey: string | null;
}>;

export type SolanaAuditFeeResponsibility = Readonly<{
  action: SolanaAuditAction;
  status: SolanaAuditFeeResponsibilityStatus;
  requiresOnChainTransaction: boolean;
  effectiveFeeMode: SolanaAuditFeeMode | null;
  networkFeeCurrency: "SOL";
  baseFeeLamportsPerSignature: typeof SOLANA_BASE_FEE_LAMPORTS_PER_SIGNATURE;
  requiresBackendSigner: boolean;
  requiresUserWallet: boolean;
  feePayerPublicKey: string | null;
  sholanCostBaseUnits: "0";
  message: string;
}>;

const BACKEND_SPONSORED_ACTIONS = new Set<SolanaAuditAction>([
  "registry-initialization",
  "poll-account-creation",
  "root-batch-commit",
  "final-result-publication",
]);

const USER_PAID_ELIGIBLE_ACTIONS = new Set<SolanaAuditAction>([
  "donation",
  "community-poll-creation",
  "public-proposal-publication",
  "poll-batch-sponsorship",
  "governance-reward-claim",
]);

export const getSolanaAuditFeePolicy = (): SolanaAuditFeePolicy =>
  Object.freeze({
    defaultFeeMode: env.solanaAudit.defaultFeeMode,
    sponsorshipEnabled: env.solanaAudit.sponsorshipEnabled,
    userPaidFeesEnabled: env.solanaAudit.userPaidFeesEnabled,
    networkFeeCurrency: "SOL",
    baseFeeLamportsPerSignature: SOLANA_BASE_FEE_LAMPORTS_PER_SIGNATURE,
    sholanPaysNetworkFees: false,
    chargesSholanForBackendProcessing: false,
    transactionsEnabled: env.solanaAudit.transactionsEnabled,
    feePayerPublicKey: env.solanaAudit.feePayerPublicKey,
  });

export const resolveSolanaAuditFeeResponsibility = (
  input: Readonly<{
    action: SolanaAuditAction;
    requestedFeeMode?: SolanaAuditFeeMode | null;
  }>,
  policy: SolanaAuditFeePolicy = getSolanaAuditFeePolicy(),
): SolanaAuditFeeResponsibility => {
  if (input.action === "vote-submission") {
    return Object.freeze({
      action: input.action,
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
  }

  const effectiveFeeMode =
    input.requestedFeeMode ?? policy.defaultFeeMode ?? DEFAULT_SOLANA_AUDIT_FEE_MODE;

  if (effectiveFeeMode === "civicos-sponsored") {
    if (!policy.sponsorshipEnabled) {
      return Object.freeze({
        action: input.action,
        status: "sponsorship_disabled",
        requiresOnChainTransaction: true,
        effectiveFeeMode,
        networkFeeCurrency: "SOL",
        baseFeeLamportsPerSignature: SOLANA_BASE_FEE_LAMPORTS_PER_SIGNATURE,
        requiresBackendSigner: false,
        requiresUserWallet: false,
        feePayerPublicKey: null,
        sholanCostBaseUnits: "0",
        message: "CivicOS-sponsored Solana fees are disabled by configuration.",
      });
    }

    return Object.freeze({
      action: input.action,
      status: "accepted",
      requiresOnChainTransaction: true,
      effectiveFeeMode,
      networkFeeCurrency: "SOL",
      baseFeeLamportsPerSignature: SOLANA_BASE_FEE_LAMPORTS_PER_SIGNATURE,
      requiresBackendSigner: BACKEND_SPONSORED_ACTIONS.has(input.action),
      requiresUserWallet: false,
      feePayerPublicKey: policy.feePayerPublicKey,
      sholanCostBaseUnits: "0",
      message:
        "CivicOS sponsors the Solana transaction fee; the fee payer must hold SOL.",
    });
  }

  if (!policy.userPaidFeesEnabled) {
    return Object.freeze({
      action: input.action,
      status: "user_paid_disabled",
      requiresOnChainTransaction: true,
      effectiveFeeMode,
      networkFeeCurrency: "SOL",
      baseFeeLamportsPerSignature: SOLANA_BASE_FEE_LAMPORTS_PER_SIGNATURE,
      requiresBackendSigner: false,
      requiresUserWallet: false,
      feePayerPublicKey: null,
      sholanCostBaseUnits: "0",
      message: "User-paid Solana fees are not enabled for this environment.",
    });
  }

  if (!USER_PAID_ELIGIBLE_ACTIONS.has(input.action)) {
    return Object.freeze({
      action: input.action,
      status: "unsupported_user_paid_action",
      requiresOnChainTransaction: true,
      effectiveFeeMode,
      networkFeeCurrency: "SOL",
      baseFeeLamportsPerSignature: SOLANA_BASE_FEE_LAMPORTS_PER_SIGNATURE,
      requiresBackendSigner: false,
      requiresUserWallet: false,
      feePayerPublicKey: null,
      sholanCostBaseUnits: "0",
      message: "This audit action is not eligible for user-paid fees.",
    });
  }

  return Object.freeze({
    action: input.action,
    status: "accepted",
    requiresOnChainTransaction: true,
    effectiveFeeMode,
    networkFeeCurrency: "SOL",
    baseFeeLamportsPerSignature: SOLANA_BASE_FEE_LAMPORTS_PER_SIGNATURE,
    requiresBackendSigner: false,
    requiresUserWallet: true,
    feePayerPublicKey: null,
    sholanCostBaseUnits: "0",
    message: "The user's Solana wallet pays the network fee in SOL.",
  });
};
