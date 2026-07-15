import credentialRegistryRepository from "../repositories/credentialRegistryRepository";
import type { CredentialRootRow } from "../types/db";
import { CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH } from "./credentialRegistryConstants";
import solanaAuditPublisherService from "./solanaAuditPublisherService";

type CredentialRootPublisherRepositoryPort = Pick<
  typeof credentialRegistryRepository,
  "listUnpublishedRoots" | "markRootPublished"
>;

type CredentialRootSolanaPublisherPort = Pick<
  typeof solanaAuditPublisherService,
  "publishCredentialRoot"
>;

export type CredentialRootPublicationItem = Readonly<{
  root: string;
  previousRoot: string | null;
  merkleDepth: number;
  leafCount: number;
  status: "dry_run" | "published";
  solanaTxSignature: string | null;
  explorerUrl: string | null;
  credentialRootAddress: string | null;
}>;

export type PublishPendingCredentialRootsResult = Readonly<{
  dryRun: boolean;
  requestedLimit: number;
  unpublishedCount: number;
  publishedCount: number;
  roots: readonly CredentialRootPublicationItem[];
}>;

export const createCredentialRootPublisherService = (
  dependencies: Partial<{
    repository: CredentialRootPublisherRepositoryPort;
    solanaPublisher: CredentialRootSolanaPublisherPort;
  }> = {},
) => {
  const repository = dependencies.repository ?? credentialRegistryRepository;
  const solanaPublisher =
    dependencies.solanaPublisher ?? solanaAuditPublisherService;

  return Object.freeze({
    async publishPendingCredentialRoots(input: {
      limit?: number;
      dryRun?: boolean;
      merkleDepth?: number;
    } = {}): Promise<PublishPendingCredentialRootsResult> {
      const limit = Math.min(
        Math.max(Number.isInteger(input.limit) ? Number(input.limit) : 25, 1),
        500,
      );
      const merkleDepth =
        input.merkleDepth ?? CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH;
      const dryRun = input.dryRun !== false;
      const roots = await repository.listUnpublishedRoots({
        merkleDepth,
        limit,
      });

      const results: CredentialRootPublicationItem[] = [];
      for (const root of roots) {
        if (dryRun) {
          results.push(toDryRunItem(root));
          continue;
        }

        const publication = await solanaPublisher.publishCredentialRoot({
          credentialRoot: root,
        });
        await repository.markRootPublished({
          root: root.root,
          solanaTxSignature: publication.signature,
        });
        results.push({
          root: root.root,
          previousRoot: root.previous_root,
          merkleDepth: root.merkle_depth,
          leafCount: root.leaf_count,
          status: "published",
          solanaTxSignature: publication.signature,
          explorerUrl: publication.explorerUrl,
          credentialRootAddress: publication.credentialRootAddress,
        });
      }

      return Object.freeze({
        dryRun,
        requestedLimit: limit,
        unpublishedCount: roots.length,
        publishedCount: dryRun ? 0 : results.length,
        roots: Object.freeze(results),
      });
    },
  });
};

const toDryRunItem = (root: CredentialRootRow): CredentialRootPublicationItem =>
  Object.freeze({
    root: root.root,
    previousRoot: root.previous_root,
    merkleDepth: root.merkle_depth,
    leafCount: root.leaf_count,
    status: "dry_run",
    solanaTxSignature: null,
    explorerUrl: null,
    credentialRootAddress: null,
  });

export const credentialRootPublisherService =
  createCredentialRootPublisherService();

export default credentialRootPublisherService;
