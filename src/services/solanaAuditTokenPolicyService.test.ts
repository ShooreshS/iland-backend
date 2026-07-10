import { describe, expect, it } from "bun:test";

import { env } from "../config/env";
import { TOKEN_2022_PROGRAM_ID } from "../config/solanaAuditDefaults";
import {
  SHOLAN_PHASE_6_POLICY,
  buildInitializeRegistryTokenArgs,
  getBackendWalletRequirementSummary,
} from "./solanaAuditTokenPolicyService";

describe("Phase 6 SHOLAN token policy", () => {
  it("records the existing SHOLAN Token-2022 mint as the audit token", () => {
    expect(SHOLAN_PHASE_6_POLICY.cluster).toBe("mainnet-beta");
    expect(SHOLAN_PHASE_6_POLICY.token.mint).toBe(
      "GJRpZhWZcLGP8ZUKggxDTw7y5N3LGXa2gWqKRSLDWiBq",
    );
    expect(SHOLAN_PHASE_6_POLICY.token.tokenProgram).toBe(TOKEN_2022_PROGRAM_ID);
    expect(SHOLAN_PHASE_6_POLICY.token.symbol).toBe("SHOLAN");
    expect(SHOLAN_PHASE_6_POLICY.token.decimals).toBe(9);
    expect(SHOLAN_PHASE_6_POLICY.token.mintAuthority).toBeNull();
    expect(SHOLAN_PHASE_6_POLICY.token.freezeAuthority).toBeNull();
  });

  it("keeps Phase 6 token integration metadata-only", () => {
    expect(SHOLAN_PHASE_6_POLICY.registry.recordTokenMetadataOnly).toBe(true);
    expect(SHOLAN_PHASE_6_POLICY.backend.chargesSholanForBackendProcessing).toBe(false);
    expect(SHOLAN_PHASE_6_POLICY.backend.sholanCanPaySolanaNetworkFeesDirectly).toBe(
      false,
    );
    expect(SHOLAN_PHASE_6_POLICY.backend.rootPublisherNetworkFeeCurrency).toBe("SOL");
  });

  it("builds the initialize_registry token arguments", () => {
    expect(buildInitializeRegistryTokenArgs()).toEqual({
      tokenMint: "GJRpZhWZcLGP8ZUKggxDTw7y5N3LGXa2gWqKRSLDWiBq",
      tokenProgram: TOKEN_2022_PROGRAM_ID,
    });
  });

  it("documents backend signer requirements separately from SHOLAN token costs", () => {
    expect(getBackendWalletRequirementSummary()).toEqual({
      phase6TokenMetadataOnlyRequiresBackendWallet: false,
      laterRootPublicationRequiresSigner: true,
      networkFeeCurrency: "SOL",
      backendProcessingCostCurrency: null,
    });
  });

  it("exposes matching public Solana audit defaults through env config", () => {
    expect(["localnet", "devnet", "testnet", "mainnet-beta"]).toContain(
      env.solanaAudit.cluster,
    );
    expect(env.solanaAudit.tokenMint).toBe(SHOLAN_PHASE_6_POLICY.token.mint);
    expect(env.solanaAudit.tokenProgram).toBe(
      SHOLAN_PHASE_6_POLICY.token.tokenProgram,
    );
    expect(env.solanaAudit.tokenRequiredForBackendProcessing).toBe(false);
    expect(env.solanaAudit.networkFeeCurrency).toBe("SOL");
    expect(typeof env.solanaAudit.transactionsEnabled).toBe("boolean");
    if (
      env.solanaAudit.cluster === "mainnet-beta" &&
      env.solanaAudit.transactionsEnabled
    ) {
      expect(env.solanaAudit.mainnetConfirmed).toBe(true);
    }
  });
});
