import { requireSupabaseAdminClient } from "../db/supabaseClient";
import {
  CIVIC_CREDENTIAL_REGISTRY_COMMITMENT_SCHEME,
  CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH,
} from "../services/credentialRegistryConstants";
import type {
  CredentialRegistryRow,
  CredentialRootRow,
  NewCredentialRegistryRow,
  NewCredentialRootRow,
} from "../types/db";

const CREDENTIAL_REGISTRY_COLUMNS =
  "id,verified_identity_id,identity_key_hash,credential_commitment,credential_schema_hash,claims_hash,credential_issuer_id,commitment_scheme,merkle_depth,leaf_index,revoked_at,revocation_reason,created_at,updated_at";
const CREDENTIAL_ROOT_COLUMNS =
  "id,root,previous_root,merkle_depth,leaf_count,latest_credential_registry_id,solana_tx_signature,created_at";

type CredentialRegistryRepositoryDependencies = {
  getSupabaseAdminClient?: () => ReturnType<typeof requireSupabaseAdminClient>;
};

export const createCredentialRegistryRepository = (
  dependencies: CredentialRegistryRepositoryDependencies = {},
) => {
  const getSupabaseAdminClient =
    dependencies.getSupabaseAdminClient || requireSupabaseAdminClient;

  return {
    async getByIdentityKeyHash(
      identityKeyHash: string,
    ): Promise<CredentialRegistryRow | null> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("credential_registry")
        .select(CREDENTIAL_REGISTRY_COLUMNS)
        .eq("identity_key_hash", identityKeyHash)
        .maybeSingle<CredentialRegistryRow>();

      if (error) {
        throw error;
      }

      return data || null;
    },

    async getByIdentityKeyHashAndSchema(
      identityKeyHash: string,
      credentialSchemaHash: string,
    ): Promise<CredentialRegistryRow | null> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("credential_registry")
        .select(CREDENTIAL_REGISTRY_COLUMNS)
        .eq("identity_key_hash", identityKeyHash)
        .eq("credential_schema_hash", credentialSchemaHash)
        .maybeSingle<CredentialRegistryRow>();

      if (error) {
        throw error;
      }

      return data || null;
    },

    async getByVerifiedIdentityId(
      verifiedIdentityId: string,
    ): Promise<CredentialRegistryRow | null> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("credential_registry")
        .select(CREDENTIAL_REGISTRY_COLUMNS)
        .eq("verified_identity_id", verifiedIdentityId)
        .maybeSingle<CredentialRegistryRow>();

      if (error) {
        throw error;
      }

      return data || null;
    },

    async getByVerifiedIdentityIdAndSchema(
      verifiedIdentityId: string,
      credentialSchemaHash: string,
    ): Promise<CredentialRegistryRow | null> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("credential_registry")
        .select(CREDENTIAL_REGISTRY_COLUMNS)
        .eq("verified_identity_id", verifiedIdentityId)
        .eq("credential_schema_hash", credentialSchemaHash)
        .maybeSingle<CredentialRegistryRow>();

      if (error) {
        throw error;
      }

      return data || null;
    },

    async listActiveByLeafIndex(
      merkleDepth: number,
    ): Promise<CredentialRegistryRow[]> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("credential_registry")
        .select(CREDENTIAL_REGISTRY_COLUMNS)
        .eq("merkle_depth", merkleDepth)
        .is("revoked_at", null)
        .order("leaf_index", { ascending: true });

      if (error) {
        throw error;
      }

      return (data || []) as CredentialRegistryRow[];
    },

    async insertRegistryEntry(
      input: NewCredentialRegistryRow,
    ): Promise<CredentialRegistryRow> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("credential_registry")
        .insert({
          verified_identity_id: input.verified_identity_id,
          identity_key_hash: input.identity_key_hash,
          credential_commitment: input.credential_commitment,
          credential_schema_hash: input.credential_schema_hash,
          claims_hash: input.claims_hash,
          credential_issuer_id: input.credential_issuer_id,
          commitment_scheme:
            input.commitment_scheme ?? CIVIC_CREDENTIAL_REGISTRY_COMMITMENT_SCHEME,
          merkle_depth:
            input.merkle_depth ?? CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH,
          leaf_index: input.leaf_index,
        })
        .select(CREDENTIAL_REGISTRY_COLUMNS)
        .single<CredentialRegistryRow>();

      if (error) {
        throw error;
      }

      return data;
    },

    async getAcceptedRoot(
      root: string,
      merkleDepth: number = CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH,
    ): Promise<CredentialRootRow | null> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("credential_roots")
        .select(CREDENTIAL_ROOT_COLUMNS)
        .eq("root", root)
        .eq("merkle_depth", merkleDepth)
        .maybeSingle<CredentialRootRow>();

      if (error) {
        throw error;
      }

      return data || null;
    },

    async getLatestRoot(
      merkleDepth: number,
    ): Promise<CredentialRootRow | null> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("credential_roots")
        .select(CREDENTIAL_ROOT_COLUMNS)
        .eq("merkle_depth", merkleDepth)
        .order("created_at", { ascending: false })
        .order("leaf_count", { ascending: false })
        .limit(1)
        .maybeSingle<CredentialRootRow>();

      if (error) {
        throw error;
      }

      return data || null;
    },

    async listAcceptedRoots(input: {
      merkleDepth: number;
      limit: number;
    }): Promise<CredentialRootRow[]> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("credential_roots")
        .select(CREDENTIAL_ROOT_COLUMNS)
        .eq("merkle_depth", input.merkleDepth)
        .order("created_at", { ascending: false })
        .order("leaf_count", { ascending: false })
        .limit(input.limit);

      if (error) {
        throw error;
      }

      return (data || []) as CredentialRootRow[];
    },

    async insertRoot(input: NewCredentialRootRow): Promise<CredentialRootRow> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("credential_roots")
        .insert({
          root: input.root,
          previous_root: input.previous_root ?? null,
          merkle_depth:
            input.merkle_depth ?? CIVIC_CREDENTIAL_REGISTRY_MERKLE_DEPTH,
          leaf_count: input.leaf_count,
          latest_credential_registry_id:
            input.latest_credential_registry_id ?? null,
          solana_tx_signature: input.solana_tx_signature ?? null,
        })
        .select(CREDENTIAL_ROOT_COLUMNS)
        .single<CredentialRootRow>();

      if (error) {
        throw error;
      }

      return data;
    },

    async markRootPublished(input: {
      root: string;
      solanaTxSignature: string;
    }): Promise<CredentialRootRow | null> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("credential_roots")
        .update({ solana_tx_signature: input.solanaTxSignature })
        .eq("root", input.root)
        .select(CREDENTIAL_ROOT_COLUMNS)
        .maybeSingle<CredentialRootRow>();

      if (error) {
        throw error;
      }

      return data || null;
    },
  };
};

export const credentialRegistryRepository =
  createCredentialRegistryRepository();

export default credentialRegistryRepository;
