import credentialRegistryRepository from "../repositories/credentialRegistryRepository";
import type {
  CredentialRegistryRow,
  CredentialRootRow,
  VerifiedIdentityRow,
} from "../types/db";
import { poseidonHashHex64 } from "./poseidonBn254Service";

export const CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH = 24;
export const CIVIC_CREDENTIAL_REGISTRY_COMMITMENT_SCHEME =
  "civicos-credential-commitment-v1";

const HEX_64_PATTERN = /^[0-9a-f]{64}$/;
const ZERO_FIELD = "0".repeat(64);

type CredentialRegistryRepositoryPort = Pick<
  typeof credentialRegistryRepository,
  | "getByIdentityKeyHash"
  | "getByIdentityKeyHashAndSchema"
  | "getByVerifiedIdentityId"
  | "getByVerifiedIdentityIdAndSchema"
  | "listActiveByLeafIndex"
  | "insertRegistryEntry"
  | "getAcceptedRoot"
  | "getLatestRoot"
  | "insertRoot"
>;

export type CredentialRegistryMerklePath = Readonly<{
  root: string;
  siblings: string[];
  pathIndices: number[];
}>;

export type CredentialRegistryMerkleMaterial = Readonly<{
  root: string;
  leafCount: number;
  pathsByLeafIndex: Map<number, CredentialRegistryMerklePath>;
}>;

export type IssueCredentialRegistryEntryInput = Readonly<{
  verifiedIdentity: Pick<
    VerifiedIdentityRow,
    "id" | "canonical_identity_key"
  >;
  credentialCommitment: string;
  credentialSchemaHash: string;
  claimsHash: string;
  credentialIssuerId: string;
  commitmentScheme?: string;
  merkleDepth?: number;
}>;

export type IssueCredentialRegistryEntryResult = Readonly<{
  status: "issued" | "existing";
  registryEntry: CredentialRegistryRow;
  credentialRoot: CredentialRootRow;
  merklePath: CredentialRegistryMerklePath;
}>;

export const normalizeCredentialRegistryHex64 = (
  fieldName: string,
  value: unknown,
): string => {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (!HEX_64_PATTERN.test(normalized)) {
    throw new Error(`${fieldName} must be a 32-byte lowercase hex value.`);
  }
  return normalized;
};

const normalizeMerkleDepth = (value: unknown): number => {
  const depth =
    value === undefined || value === null
      ? CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH
      : Number(value);
  if (!Number.isInteger(depth) || depth <= 0 || depth > 64) {
    throw new Error("Credential registry Merkle depth must be an integer from 1 to 64.");
  }
  return depth;
};

const normalizeLeafIndex = (value: unknown, depth: number): number => {
  const leafIndex = Number(value);
  if (!Number.isInteger(leafIndex) || leafIndex < 0) {
    throw new Error("Credential registry leaf index must be a non-negative integer.");
  }
  const maxLeafCount = 1n << BigInt(depth);
  if (BigInt(leafIndex) >= maxLeafCount) {
    throw new Error("Credential registry leaf index exceeds the configured Merkle depth.");
  }
  return leafIndex;
};

const isUniqueViolation = (error: unknown): boolean =>
  Boolean(error && typeof error === "object" && (error as { code?: unknown }).code === "23505");

const assertExistingEntryMatchesInput = (
  existing: CredentialRegistryRow,
  input: {
    credentialCommitment: string;
    credentialSchemaHash: string;
    claimsHash: string;
    credentialIssuerId: string;
    commitmentScheme: string;
    merkleDepth: number;
  },
): void => {
  if (existing.revoked_at) {
    throw new Error("Credential registry entry is revoked.");
  }

  if (
    existing.credential_commitment !== input.credentialCommitment ||
    existing.credential_schema_hash !== input.credentialSchemaHash ||
    existing.claims_hash !== input.claimsHash ||
    existing.credential_issuer_id !== input.credentialIssuerId ||
    existing.commitment_scheme !== input.commitmentScheme ||
    existing.merkle_depth !== input.merkleDepth
  ) {
    throw new Error(
      "Verified identity already has a different credential registry entry.",
    );
  }
};

export const deriveCredentialIdentityKeyHash = async (
  canonicalIdentityKey: string,
): Promise<string> =>
  poseidonHashHex64([
    normalizeCredentialRegistryHex64(
      "canonicalIdentityKey",
      canonicalIdentityKey,
    ),
  ]);

const buildZeroHashes = async (depth: number): Promise<string[]> => {
  const zeroHashes = [ZERO_FIELD];
  for (let level = 0; level < depth; level += 1) {
    zeroHashes.push(
      await poseidonHashHex64([zeroHashes[level], zeroHashes[level]]),
    );
  }
  return zeroHashes;
};

const buildSparseMerkleLayers = async (input: {
  leaves: readonly Pick<CredentialRegistryRow, "leaf_index" | "credential_commitment">[];
  depth: number;
  zeroHashes: string[];
}): Promise<Map<bigint, string>[]> => {
  const layers: Map<bigint, string>[] = [];
  let current = new Map<bigint, string>();

  for (const leaf of input.leaves) {
    const leafIndex = normalizeLeafIndex(leaf.leaf_index, input.depth);
    const credentialCommitment = normalizeCredentialRegistryHex64(
      "credentialCommitment",
      leaf.credential_commitment,
    );
    current.set(BigInt(leafIndex), credentialCommitment);
  }

  for (let level = 0; level < input.depth; level += 1) {
    layers.push(new Map(current));
    const next = new Map<bigint, string>();
    const processed = new Set<bigint>();
    const indices = Array.from(current.keys()).sort((left, right) =>
      left < right ? -1 : left > right ? 1 : 0,
    );

    for (const index of indices) {
      if (processed.has(index)) {
        continue;
      }

      const siblingIndex = index ^ 1n;
      const isRight = index % 2n === 1n;
      const ownValue = current.get(index) || input.zeroHashes[level];
      const siblingValue = current.get(siblingIndex) || input.zeroHashes[level];
      const left = isRight ? siblingValue : ownValue;
      const right = isRight ? ownValue : siblingValue;
      const parentIndex = index / 2n;
      next.set(parentIndex, await poseidonHashHex64([left, right]));
      processed.add(index);
      processed.add(siblingIndex);
    }

    current = next;
  }

  layers.push(new Map(current));
  return layers;
};

export const buildCredentialRegistryMerkleMaterial = async (input: {
  leaves: readonly Pick<CredentialRegistryRow, "leaf_index" | "credential_commitment">[];
  depth?: number;
}): Promise<CredentialRegistryMerkleMaterial> => {
  const depth = normalizeMerkleDepth(input.depth);
  const zeroHashes = await buildZeroHashes(depth);
  const layers = await buildSparseMerkleLayers({
    leaves: input.leaves,
    depth,
    zeroHashes,
  });
  const root = layers[depth]?.get(0n) || zeroHashes[depth];
  const pathsByLeafIndex = new Map<number, CredentialRegistryMerklePath>();

  for (const leaf of input.leaves) {
    const leafIndex = normalizeLeafIndex(leaf.leaf_index, depth);
    const siblings: string[] = [];
    const pathIndices: number[] = [];
    let cursor = BigInt(leafIndex);

    for (let level = 0; level < depth; level += 1) {
      const siblingIndex = cursor ^ 1n;
      siblings.push(layers[level]?.get(siblingIndex) || zeroHashes[level]);
      pathIndices.push(cursor % 2n === 1n ? 1 : 0);
      cursor /= 2n;
    }

    pathsByLeafIndex.set(leafIndex, Object.freeze({ root, siblings, pathIndices }));
  }

  return Object.freeze({
    root,
    leafCount: input.leaves.length,
    pathsByLeafIndex,
  });
};

const nextLeafIndex = (rows: readonly CredentialRegistryRow[]): number =>
  rows.reduce((max, row) => Math.max(max, row.leaf_index), -1) + 1;

export const createCredentialRegistryService = (
  overrides: Partial<{
    repository: CredentialRegistryRepositoryPort;
  }> = {},
) => {
  const repository = overrides.repository ?? credentialRegistryRepository;

  const buildResultForEntry = async (
    status: IssueCredentialRegistryEntryResult["status"],
    entry: CredentialRegistryRow,
  ): Promise<IssueCredentialRegistryEntryResult> => {
    const [activeEntries, latestRoot] = await Promise.all([
      repository.listActiveByLeafIndex(entry.merkle_depth),
      repository.getLatestRoot(entry.merkle_depth),
    ]);
    const material = await buildCredentialRegistryMerkleMaterial({
      leaves: activeEntries,
      depth: entry.merkle_depth,
    });
    const merklePath = material.pathsByLeafIndex.get(entry.leaf_index);
    if (!merklePath) {
      throw new Error("Credential registry entry is missing from active Merkle material.");
    }

    let credentialRoot =
      latestRoot && latestRoot.root === material.root
        ? latestRoot
        : await repository.insertRoot({
            root: material.root,
            previous_root: latestRoot?.root ?? null,
            merkle_depth: entry.merkle_depth,
            leaf_count: material.leafCount,
            latest_credential_registry_id: entry.id,
          });

    if (credentialRoot.root !== merklePath.root) {
      credentialRoot = await repository.insertRoot({
        root: merklePath.root,
        previous_root: credentialRoot.root,
        merkle_depth: entry.merkle_depth,
        leaf_count: material.leafCount,
        latest_credential_registry_id: entry.id,
      });
    }

    return Object.freeze({
      status,
      registryEntry: entry,
      credentialRoot,
      merklePath,
    });
  };

  return {
    async deriveIdentityKeyHash(canonicalIdentityKey: string): Promise<string> {
      return deriveCredentialIdentityKeyHash(canonicalIdentityKey);
    },

    async isAcceptedCredentialRoot(root: string): Promise<boolean> {
      const normalizedRoot = normalizeCredentialRegistryHex64("root", root);
      return Boolean(await repository.getAcceptedRoot(normalizedRoot));
    },

    async issueCredentialRegistryEntry(
      input: IssueCredentialRegistryEntryInput,
    ): Promise<IssueCredentialRegistryEntryResult> {
      const merkleDepth = normalizeMerkleDepth(input.merkleDepth);
      const commitmentScheme =
        input.commitmentScheme ?? CIVIC_CREDENTIAL_REGISTRY_COMMITMENT_SCHEME;
      const credentialCommitment = normalizeCredentialRegistryHex64(
        "credentialCommitment",
        input.credentialCommitment,
      );
      const credentialSchemaHash = normalizeCredentialRegistryHex64(
        "credentialSchemaHash",
        input.credentialSchemaHash,
      );
      const claimsHash = normalizeCredentialRegistryHex64(
        "claimsHash",
        input.claimsHash,
      );
      const credentialIssuerId =
        typeof input.credentialIssuerId === "string"
          ? input.credentialIssuerId.trim()
          : "";
      if (!credentialIssuerId) {
        throw new Error("credentialIssuerId is required.");
      }

      const identityKeyHash = await deriveCredentialIdentityKeyHash(
        input.verifiedIdentity.canonical_identity_key,
      );
      const existingByIdentity =
        await repository.getByIdentityKeyHashAndSchema(
          identityKeyHash,
          credentialSchemaHash,
        );
      if (existingByIdentity) {
        assertExistingEntryMatchesInput(existingByIdentity, {
          credentialCommitment,
          credentialSchemaHash,
          claimsHash,
          credentialIssuerId,
          commitmentScheme,
          merkleDepth,
        });
        return buildResultForEntry("existing", existingByIdentity);
      }

      const existingByVerifiedIdentity =
        await repository.getByVerifiedIdentityIdAndSchema(
          input.verifiedIdentity.id,
          credentialSchemaHash,
        );
      if (existingByVerifiedIdentity) {
        assertExistingEntryMatchesInput(existingByVerifiedIdentity, {
          credentialCommitment,
          credentialSchemaHash,
          claimsHash,
          credentialIssuerId,
          commitmentScheme,
          merkleDepth,
        });
        return buildResultForEntry("existing", existingByVerifiedIdentity);
      }

      const activeEntries = await repository.listActiveByLeafIndex(merkleDepth);
      const leafIndex = nextLeafIndex(activeEntries);

      try {
        const inserted = await repository.insertRegistryEntry({
          verified_identity_id: input.verifiedIdentity.id,
          identity_key_hash: identityKeyHash,
          credential_commitment: credentialCommitment,
          credential_schema_hash: credentialSchemaHash,
          claims_hash: claimsHash,
          credential_issuer_id: credentialIssuerId,
          commitment_scheme: commitmentScheme,
          merkle_depth: merkleDepth,
          leaf_index: leafIndex,
        });
        return buildResultForEntry("issued", inserted);
      } catch (error) {
        if (!isUniqueViolation(error)) {
          throw error;
        }

        const existing = await repository.getByIdentityKeyHashAndSchema(
          identityKeyHash,
          credentialSchemaHash,
        );
        if (!existing) {
          throw error;
        }

        assertExistingEntryMatchesInput(existing, {
          credentialCommitment,
          credentialSchemaHash,
          claimsHash,
          credentialIssuerId,
          commitmentScheme,
          merkleDepth,
        });
        return buildResultForEntry("existing", existing);
      }
    },
  };
};

export const credentialRegistryService = createCredentialRegistryService();

export default credentialRegistryService;
