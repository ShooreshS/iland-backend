import {
  SHOLAN_TOKEN_DEFAULTS,
  type SolanaAuditCluster,
} from "../config/solanaAuditDefaults";

export const SOLANA_NETWORK_FEE_CURRENCY = "SOL" as const;

export type SolanaAuditTokenPolicy = Readonly<{
  cluster: SolanaAuditCluster;
  token: typeof SHOLAN_TOKEN_DEFAULTS;
  registry: Readonly<{
    recordTokenMetadataOnly: boolean;
    requiresTokenProgramWithMint: boolean;
  }>;
  backend: Readonly<{
    needsBackendWalletForTokenMetadataOnly: boolean;
    needsRootPublisherSignerForOnChainAuditPublication: boolean;
    rootPublisherNetworkFeeCurrency: typeof SOLANA_NETWORK_FEE_CURRENCY;
    chargesSholanForBackendProcessing: boolean;
    sholanCanPaySolanaNetworkFeesDirectly: boolean;
  }>;
  futureUses: readonly ("governance" | "rewards" | "staking" | "slashing")[];
}>;

export const SHOLAN_PHASE_6_POLICY: SolanaAuditTokenPolicy = Object.freeze({
  cluster: SHOLAN_TOKEN_DEFAULTS.cluster,
  token: SHOLAN_TOKEN_DEFAULTS,
  registry: Object.freeze({
    recordTokenMetadataOnly: true,
    requiresTokenProgramWithMint: true,
  }),
  backend: Object.freeze({
    needsBackendWalletForTokenMetadataOnly: false,
    needsRootPublisherSignerForOnChainAuditPublication: true,
    rootPublisherNetworkFeeCurrency: SOLANA_NETWORK_FEE_CURRENCY,
    chargesSholanForBackendProcessing: false,
    sholanCanPaySolanaNetworkFeesDirectly: false,
  }),
  futureUses: ["governance", "rewards", "staking", "slashing"] as const,
});

export const buildInitializeRegistryTokenArgs = (
  policy: SolanaAuditTokenPolicy = SHOLAN_PHASE_6_POLICY,
): Readonly<{
  tokenMint: string;
  tokenProgram: string;
}> =>
  Object.freeze({
    tokenMint: policy.token.mint,
    tokenProgram: policy.token.tokenProgram,
  });

export const getBackendWalletRequirementSummary = (
  policy: SolanaAuditTokenPolicy = SHOLAN_PHASE_6_POLICY,
): Readonly<{
  phase6TokenMetadataOnlyRequiresBackendWallet: boolean;
  laterRootPublicationRequiresSigner: boolean;
  networkFeeCurrency: typeof SOLANA_NETWORK_FEE_CURRENCY;
  backendProcessingCostCurrency: null;
}> =>
  Object.freeze({
    phase6TokenMetadataOnlyRequiresBackendWallet:
      policy.backend.needsBackendWalletForTokenMetadataOnly,
    laterRootPublicationRequiresSigner:
      policy.backend.needsRootPublisherSignerForOnChainAuditPublication,
    networkFeeCurrency: policy.backend.rootPublisherNetworkFeeCurrency,
    backendProcessingCostCurrency: null,
  });
