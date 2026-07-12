import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  NewPollEncryptionKeyRow,
  PollEncryptionKeyRow,
} from "../types/db";

const POLL_ENCRYPTION_KEY_COLUMNS =
  "id,key_id,poll_id,status,algorithm,key_agreement,kdf,cipher,public_key_jwk,public_key_hash,private_key_jwk,custody_model,created_at,revoked_at,revocation_reason";

type PollEncryptionKeyRepositoryDependencies = {
  getSupabaseAdminClient?: () => ReturnType<typeof requireSupabaseAdminClient>;
};

export const createPollEncryptionKeyRepository = (
  dependencies: PollEncryptionKeyRepositoryDependencies = {},
) => {
  const getSupabaseAdminClient =
    dependencies.getSupabaseAdminClient || requireSupabaseAdminClient;

  return {
    async getByKeyId(keyId: string): Promise<PollEncryptionKeyRow | null> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("poll_encryption_keys")
        .select(POLL_ENCRYPTION_KEY_COLUMNS)
        .eq("key_id", keyId)
        .maybeSingle<PollEncryptionKeyRow>();

      if (error) {
        throw error;
      }

      return data || null;
    },

    async getByPollId(pollId: string): Promise<PollEncryptionKeyRow | null> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("poll_encryption_keys")
        .select(POLL_ENCRYPTION_KEY_COLUMNS)
        .eq("poll_id", pollId)
        .maybeSingle<PollEncryptionKeyRow>();

      if (error) {
        throw error;
      }

      return data || null;
    },

    async insert(input: NewPollEncryptionKeyRow): Promise<PollEncryptionKeyRow> {
      const supabase = getSupabaseAdminClient();

      const { data, error } = await supabase
        .from("poll_encryption_keys")
        .insert({
          key_id: input.key_id,
          poll_id: input.poll_id ?? null,
          status: input.status ?? "active",
          algorithm: input.algorithm,
          key_agreement: input.key_agreement,
          kdf: input.kdf,
          cipher: input.cipher,
          public_key_jwk: input.public_key_jwk,
          public_key_hash: input.public_key_hash,
          private_key_jwk: input.private_key_jwk,
          custody_model:
            input.custody_model ?? "operator-trusted-backend-db-v1",
        })
        .select(POLL_ENCRYPTION_KEY_COLUMNS)
        .single<PollEncryptionKeyRow>();

      if (error) {
        throw error;
      }

      return data;
    },
  };
};

export const pollEncryptionKeyRepository =
  createPollEncryptionKeyRepository();

export default pollEncryptionKeyRepository;
