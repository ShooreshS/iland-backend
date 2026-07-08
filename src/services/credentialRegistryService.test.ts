import { describe, expect, it } from "bun:test";

import type {
  CredentialRegistryRow,
  CredentialRootRow,
  NewCredentialRegistryRow,
  NewCredentialRootRow,
  VerifiedIdentityRow,
} from "../types/db";

process.env.NODE_ENV = "test";
process.env.AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS = "true";

const {
  buildCredentialRegistryMerkleMaterial,
  createCredentialRegistryService,
  deriveCredentialIdentityKeyHash,
} = await import("./credentialRegistryService");
const { poseidonHashHex64 } = await import("./poseidonBn254Service");

const FIXED_TIME = "2026-07-08T12:00:00.000Z";

const hex = (char: string): string => char.repeat(64);

const verifiedIdentity: Pick<
  VerifiedIdentityRow,
  "id" | "canonical_identity_key"
> = {
  id: "verified-identity-1",
  canonical_identity_key: hex("a"),
};

const createMockCredentialRegistryRepository = () => {
  const registryRows: CredentialRegistryRow[] = [];
  const rootRows: CredentialRootRow[] = [];

  const repository = {
    registryRows,
    rootRows,

    async getByIdentityKeyHash(
      identityKeyHash: string,
    ): Promise<CredentialRegistryRow | null> {
      return registryRows.find((row) => row.identity_key_hash === identityKeyHash) || null;
    },

    async getByIdentityKeyHashAndSchema(
      identityKeyHash: string,
      credentialSchemaHash: string,
    ): Promise<CredentialRegistryRow | null> {
      return (
        registryRows.find(
          (row) =>
            row.identity_key_hash === identityKeyHash &&
            row.credential_schema_hash === credentialSchemaHash,
        ) || null
      );
    },

    async getByVerifiedIdentityId(
      verifiedIdentityId: string,
    ): Promise<CredentialRegistryRow | null> {
      return (
        registryRows.find(
          (row) => row.verified_identity_id === verifiedIdentityId,
        ) || null
      );
    },

    async getByVerifiedIdentityIdAndSchema(
      verifiedIdentityId: string,
      credentialSchemaHash: string,
    ): Promise<CredentialRegistryRow | null> {
      return (
        registryRows.find(
          (row) =>
            row.verified_identity_id === verifiedIdentityId &&
            row.credential_schema_hash === credentialSchemaHash,
        ) || null
      );
    },

    async listActiveByLeafIndex(
      merkleDepth: number,
    ): Promise<CredentialRegistryRow[]> {
      return registryRows
        .filter(
          (row) => row.merkle_depth === merkleDepth && row.revoked_at === null,
        )
        .sort((left, right) => left.leaf_index - right.leaf_index);
    },

    async insertRegistryEntry(
      input: NewCredentialRegistryRow,
    ): Promise<CredentialRegistryRow> {
      if (
        registryRows.some(
          (row) =>
            (row.identity_key_hash === input.identity_key_hash &&
              row.credential_schema_hash === input.credential_schema_hash) ||
            (row.verified_identity_id === input.verified_identity_id &&
              row.credential_schema_hash === input.credential_schema_hash) ||
            (row.merkle_depth === (input.merkle_depth ?? 24) &&
              row.leaf_index === input.leaf_index),
        )
      ) {
        throw { code: "23505", message: "duplicate key value violates unique constraint" };
      }

      const row: CredentialRegistryRow = {
        id: `credential-registry-${registryRows.length + 1}`,
        verified_identity_id: input.verified_identity_id,
        identity_key_hash: input.identity_key_hash,
        credential_commitment: input.credential_commitment,
        credential_schema_hash: input.credential_schema_hash,
        claims_hash: input.claims_hash,
        credential_issuer_id: input.credential_issuer_id,
        commitment_scheme:
          input.commitment_scheme ?? "civicos-credential-commitment-v1",
        merkle_depth: input.merkle_depth ?? 24,
        leaf_index: input.leaf_index,
        revoked_at: null,
        revocation_reason: null,
        created_at: FIXED_TIME,
        updated_at: FIXED_TIME,
      };
      registryRows.push(row);
      return row;
    },

    async getAcceptedRoot(root: string): Promise<CredentialRootRow | null> {
      return rootRows.find((row) => row.root === root) || null;
    },

    async getLatestRoot(merkleDepth: number): Promise<CredentialRootRow | null> {
      return (
        [...rootRows]
          .filter((row) => row.merkle_depth === merkleDepth)
          .sort((left, right) => right.created_at.localeCompare(left.created_at))[0] ||
        null
      );
    },

    async insertRoot(input: NewCredentialRootRow): Promise<CredentialRootRow> {
      const existing = rootRows.find((row) => row.root === input.root);
      if (existing) {
        return existing;
      }

      const row: CredentialRootRow = {
        id: `credential-root-${rootRows.length + 1}`,
        root: input.root,
        previous_root: input.previous_root ?? null,
        merkle_depth: input.merkle_depth ?? 24,
        leaf_count: input.leaf_count,
        latest_credential_registry_id:
          input.latest_credential_registry_id ?? null,
        solana_tx_signature: input.solana_tx_signature ?? null,
        created_at: `${FIXED_TIME}.${rootRows.length}`,
      };
      rootRows.push(row);
      return row;
    },
  };

  return repository;
};

describe("credentialRegistryService", () => {
  it("derives a stable Poseidon identity key hash", async () => {
    const first = await deriveCredentialIdentityKeyHash(hex("a"));
    const second = await deriveCredentialIdentityKeyHash(hex("a"));

    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(first).toBe(second);
    expect(first).not.toBe(hex("a"));
  });

  it("builds sparse Poseidon Merkle roots and paths without a full tree", async () => {
    const material = await buildCredentialRegistryMerkleMaterial({
      depth: 3,
      leaves: [
        {
          leaf_index: 0,
          credential_commitment: hex("1"),
        },
        {
          leaf_index: 2,
          credential_commitment: hex("2"),
        },
      ],
    });

    const path = material.pathsByLeafIndex.get(2);
    expect(material.root).toMatch(/^[0-9a-f]{64}$/);
    expect(path?.siblings).toHaveLength(3);
    expect(path?.pathIndices).toEqual([0, 1, 0]);

    let cursor = hex("2");
    if (!path) {
      throw new Error("Expected leaf path.");
    }

    for (let level = 0; level < path.siblings.length; level += 1) {
      const sibling = path.siblings[level];
      cursor =
        path.pathIndices[level] === 0
          ? await poseidonHashHex64([cursor, sibling])
          : await poseidonHashHex64([sibling, cursor]);
    }

    expect(cursor).toBe(material.root);
  });

  it("issues one registry entry and root per verified identity schema", async () => {
    const repository = createMockCredentialRegistryRepository();
    const service = createCredentialRegistryService({ repository });
    const input = {
      verifiedIdentity,
      credentialCommitment: hex("1"),
      credentialSchemaHash: hex("2"),
      claimsHash: hex("3"),
      credentialIssuerId: "did:civicos:issuer:v1",
      merkleDepth: 3,
    };

    const issued = await service.issueCredentialRegistryEntry(input);
    const existing = await service.issueCredentialRegistryEntry(input);

    expect(issued.status).toBe("issued");
    expect(existing.status).toBe("existing");
    expect(existing.registryEntry.id).toBe(issued.registryEntry.id);
    expect(repository.registryRows).toHaveLength(1);
    expect(repository.rootRows).toHaveLength(1);
    expect(issued.registryEntry.leaf_index).toBe(0);
    expect(issued.credentialRoot.root).toBe(issued.merklePath.root);
    await expect(
      service.isAcceptedCredentialRoot(issued.credentialRoot.root),
    ).resolves.toBe(true);
  });

  it("rejects a different credential commitment for an existing identity", async () => {
    const repository = createMockCredentialRegistryRepository();
    const service = createCredentialRegistryService({ repository });
    const input = {
      verifiedIdentity,
      credentialCommitment: hex("1"),
      credentialSchemaHash: hex("2"),
      claimsHash: hex("3"),
      credentialIssuerId: "did:civicos:issuer:v1",
      merkleDepth: 3,
    };

    await service.issueCredentialRegistryEntry(input);

    await expect(
      service.issueCredentialRegistryEntry({
        ...input,
        credentialCommitment: hex("4"),
      }),
    ).rejects.toThrow("different credential registry entry");
  });

  it("allows a distinct credential schema for the same verified identity", async () => {
    const repository = createMockCredentialRegistryRepository();
    const service = createCredentialRegistryService({ repository });

    const first = await service.issueCredentialRegistryEntry({
      verifiedIdentity,
      credentialCommitment: hex("1"),
      credentialSchemaHash: hex("2"),
      claimsHash: hex("3"),
      credentialIssuerId: "did:civicos:issuer:v1",
      merkleDepth: 3,
    });
    const second = await service.issueCredentialRegistryEntry({
      verifiedIdentity,
      credentialCommitment: hex("4"),
      credentialSchemaHash: hex("5"),
      claimsHash: hex("6"),
      credentialIssuerId: "did:civicos:issuer:v1",
      merkleDepth: 3,
    });

    expect(first.status).toBe("issued");
    expect(second.status).toBe("issued");
    expect(repository.registryRows).toHaveLength(2);
    expect(repository.registryRows.map((row) => row.leaf_index)).toEqual([0, 1]);
  });
});
