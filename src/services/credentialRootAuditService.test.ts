import { describe, expect, it } from "bun:test";

import type { CredentialRootRow } from "../types/db";
import { createCredentialRootAuditService } from "./credentialRootAuditService";

const rootRow = (overrides: Partial<CredentialRootRow> = {}): CredentialRootRow => ({
  id: overrides.id ?? "root-row-1",
  root: overrides.root ?? "1".repeat(64),
  previous_root: overrides.previous_root ?? null,
  merkle_depth: overrides.merkle_depth ?? 32,
  leaf_count: overrides.leaf_count ?? 1,
  latest_credential_registry_id:
    overrides.latest_credential_registry_id ?? "credential-registry-secret-row",
  solana_tx_signature: overrides.solana_tx_signature ?? null,
  created_at: overrides.created_at ?? "2026-07-13T00:00:00.000Z",
});

describe("credentialRootAuditService", () => {
  it("returns public credential roots without credential registry row ids", async () => {
    const latest = rootRow();
    const service = createCredentialRootAuditService({
      repository: {
        getLatestRoot: async () => latest,
        listAcceptedRoots: async () => [
          latest,
          rootRow({
            id: "root-row-2",
            root: "2".repeat(64),
            previous_root: "1".repeat(64),
            leaf_count: 2,
            solana_tx_signature: "devnet-signature",
          }),
        ],
      },
    });

    const audit = await service.getCredentialRootAudit({ limit: 2 });
    const serialized = JSON.stringify(audit);

    expect(audit).toMatchObject({
      version: "civicos-credential-root-audit-v1",
      commitmentScheme: "civicos-credential-commitment-v1",
      merkleDepth: 32,
      identityMaterialExposed: false,
      latestRoot: {
        root: "1".repeat(64),
        leafCount: 1,
        solanaTxSignature: null,
        explorerUrl: null,
      },
      acceptedRoots: [
        {
          root: "1".repeat(64),
          previousRoot: null,
          leafCount: 1,
          explorerUrl: null,
        },
        {
          root: "2".repeat(64),
          previousRoot: "1".repeat(64),
          leafCount: 2,
          solanaTxSignature: "devnet-signature",
          explorerUrl: expect.stringContaining(
            "https://explorer.solana.com/tx/devnet-signature",
          ),
        },
      ],
      anchoring: {
        mode: "solana-root-chain",
        registryRowIdsExposed: false,
        credentialCommitmentsExposed: false,
      },
    });
    expect(serialized).not.toContain("credential-registry-secret-row");
    expect(serialized).not.toContain("latest_credential_registry_id");
  });
});
