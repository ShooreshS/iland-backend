import env from "../config/env";
import credentialRegistryRepository from "../repositories/credentialRegistryRepository";
import type { CredentialRootRow } from "../types/db";
import {
  CIVIC_CREDENTIAL_REGISTRY_COMMITMENT_SCHEME,
  CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH,
} from "./credentialRegistryConstants";

export const CREDENTIAL_ROOT_AUDIT_VERSION =
  "civicos-credential-root-audit-v1" as const;

const DEFAULT_ROOT_LIMIT = 64;
const MAX_ROOT_LIMIT = 500;

type CredentialRootAuditRepositoryPort = Pick<
  typeof credentialRegistryRepository,
  "getLatestRoot" | "listAcceptedRoots"
>;

export type PublicCredentialRoot = Readonly<{
  root: string;
  previousRoot: string | null;
  merkleDepth: number;
  leafCount: number;
  createdAt: string;
  solanaTxSignature: string | null;
  explorerUrl: string | null;
}>;

export type CredentialRootAudit = Readonly<{
  version: typeof CREDENTIAL_ROOT_AUDIT_VERSION;
  commitmentScheme: typeof CIVIC_CREDENTIAL_REGISTRY_COMMITMENT_SCHEME;
  merkleDepth: typeof CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH;
  identityMaterialExposed: false;
  latestRoot: PublicCredentialRoot | null;
  acceptedRoots: readonly PublicCredentialRoot[];
  anchoring: Readonly<{
    mode: "public-api-root-chain" | "solana-root-chain";
    cluster: string;
    programId: string;
    solanaTxSignatureField: "solanaTxSignature";
    solanaExplorerUrlField: "explorerUrl";
    registryRowIdsExposed: false;
    credentialCommitmentsExposed: false;
  }>;
}>;

const normalizeLimit = (value: unknown): number => {
  const limit =
    value === undefined || value === null || value === ""
      ? DEFAULT_ROOT_LIMIT
      : Number(value);

  if (!Number.isInteger(limit) || limit < 1) {
    return DEFAULT_ROOT_LIMIT;
  }

  return Math.min(limit, MAX_ROOT_LIMIT);
};

const toPublicCredentialRoot = (
  row: CredentialRootRow,
): PublicCredentialRoot =>
  Object.freeze({
    root: row.root,
    previousRoot: row.previous_root,
    merkleDepth: row.merkle_depth,
    leafCount: row.leaf_count,
    createdAt: row.created_at,
    solanaTxSignature: row.solana_tx_signature,
    explorerUrl: buildSolanaExplorerUrl(row.solana_tx_signature),
  });

const buildSolanaExplorerUrl = (signature: string | null): string | null => {
  if (!signature) {
    return null;
  }

  if (env.solanaAudit.cluster === "mainnet-beta") {
    return `https://explorer.solana.com/tx/${signature}`;
  }

  const cluster =
    env.solanaAudit.cluster === "localnet" ? "custom" : env.solanaAudit.cluster;
  return `https://explorer.solana.com/tx/${signature}?cluster=${cluster}`;
};

export const createCredentialRootAuditService = (
  overrides: Partial<{
    repository: CredentialRootAuditRepositoryPort;
  }> = {},
) => {
  const repository = overrides.repository ?? credentialRegistryRepository;

  return {
    async getCredentialRootAudit(input: {
      limit?: unknown;
    } = {}): Promise<CredentialRootAudit> {
      const limit = normalizeLimit(input.limit);
      const [latestRoot, acceptedRoots] = await Promise.all([
        repository.getLatestRoot(CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH),
        repository.listAcceptedRoots({
          merkleDepth: CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH,
          limit,
        }),
      ]);

      const publicAcceptedRoots = Object.freeze(
        acceptedRoots.map(toPublicCredentialRoot),
      );
      const hasSolanaAnchor = publicAcceptedRoots.some(
        (root) => Boolean(root.solanaTxSignature),
      );

      return Object.freeze({
        version: CREDENTIAL_ROOT_AUDIT_VERSION,
        commitmentScheme: CIVIC_CREDENTIAL_REGISTRY_COMMITMENT_SCHEME,
        merkleDepth: CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH,
        identityMaterialExposed: false,
        latestRoot: latestRoot ? toPublicCredentialRoot(latestRoot) : null,
        acceptedRoots: publicAcceptedRoots,
        anchoring: Object.freeze({
          mode: hasSolanaAnchor ? "solana-root-chain" : "public-api-root-chain",
          cluster: env.solanaAudit.cluster,
          programId: env.solanaAudit.programId,
          solanaTxSignatureField: "solanaTxSignature",
          solanaExplorerUrlField: "explorerUrl",
          registryRowIdsExposed: false,
          credentialCommitmentsExposed: false,
        }),
      });
    },
  };
};

export const credentialRootAuditService = createCredentialRootAuditService();

export default credentialRootAuditService;
