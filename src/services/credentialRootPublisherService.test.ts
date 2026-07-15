import { describe, expect, it } from "bun:test";

import type { CredentialRootRow } from "../types/db";
import { createCredentialRootPublisherService } from "./credentialRootPublisherService";

const rootRow = (
  root: string,
  overrides: Partial<CredentialRootRow> = {},
): CredentialRootRow => ({
  id: `root-${root[0]}`,
  root,
  previous_root: overrides.previous_root ?? null,
  merkle_depth: overrides.merkle_depth ?? 32,
  leaf_count: overrides.leaf_count ?? 1,
  latest_credential_registry_id:
    overrides.latest_credential_registry_id ?? "registry-row-1",
  solana_tx_signature: overrides.solana_tx_signature ?? null,
  created_at: overrides.created_at ?? "2026-07-16T00:00:00.000Z",
});

describe("credentialRootPublisherService", () => {
  it("dry-runs unpublished credential roots without sending transactions", async () => {
    const sentRoots: string[] = [];
    const markedRoots: string[] = [];
    const service = createCredentialRootPublisherService({
      repository: {
        listUnpublishedRoots: async () => [rootRow("1".repeat(64))],
        markRootPublished: async (input) => {
          markedRoots.push(input.root);
          return null;
        },
      },
      solanaPublisher: {
        publishCredentialRoot: async (input) => {
          sentRoots.push(input.credentialRoot.root);
          return {
            cluster: "devnet",
            programId: "program",
            registryAddress: "registry",
            credentialRootAddress: "credential-root",
            signature: "signature",
            feePayerPublicKey: "fee-payer",
            rootPublisherPublicKey: "root-publisher",
            explorerUrl: "https://explorer.solana.com/tx/signature?cluster=devnet",
          };
        },
      },
    });

    const result = await service.publishPendingCredentialRoots({ dryRun: true });

    expect(result).toMatchObject({
      dryRun: true,
      unpublishedCount: 1,
      publishedCount: 0,
      roots: [
        {
          root: "1".repeat(64),
          status: "dry_run",
          solanaTxSignature: null,
          credentialRootAddress: null,
        },
      ],
    });
    expect(sentRoots).toEqual([]);
    expect(markedRoots).toEqual([]);
  });

  it("publishes roots and records Solana signatures after success", async () => {
    const marked: { root: string; signature: string }[] = [];
    const service = createCredentialRootPublisherService({
      repository: {
        listUnpublishedRoots: async () => [
          rootRow("1".repeat(64), { leaf_count: 1 }),
          rootRow("2".repeat(64), {
            previous_root: "1".repeat(64),
            leaf_count: 2,
          }),
        ],
        markRootPublished: async (input) => {
          marked.push({
            root: input.root,
            signature: input.solanaTxSignature,
          });
          return rootRow(input.root, {
            solana_tx_signature: input.solanaTxSignature,
          });
        },
      },
      solanaPublisher: {
        publishCredentialRoot: async (input) => ({
          cluster: "devnet",
          programId: "program",
          registryAddress: "registry",
          credentialRootAddress: `credential-root-${input.credentialRoot.root[0]}`,
          signature: `signature-${input.credentialRoot.root[0]}`,
          feePayerPublicKey: "fee-payer",
          rootPublisherPublicKey: "root-publisher",
          explorerUrl: `https://explorer.solana.com/tx/signature-${input.credentialRoot.root[0]}?cluster=devnet`,
        }),
      },
    });

    const result = await service.publishPendingCredentialRoots({ dryRun: false });

    expect(result.publishedCount).toBe(2);
    expect(result.roots.map((root) => root.solanaTxSignature)).toEqual([
      "signature-1",
      "signature-2",
    ]);
    expect(marked).toEqual([
      { root: "1".repeat(64), signature: "signature-1" },
      { root: "2".repeat(64), signature: "signature-2" },
    ]);
  });
});
