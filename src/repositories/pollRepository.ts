import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  NewPollOptionRow,
  NewPollRow,
  PollOptionRow,
  PollRow,
  PollVotePrivacyMode,
} from "../types/db";

const BASE_POLL_COLUMNS =
  "id,slug,created_by_user_id,title,description,status,jurisdiction_type,jurisdiction_country_code,jurisdiction_area_ids,jurisdiction_land_ids,requires_verified_identity,allowed_document_country_codes,allowed_home_area_ids,allowed_land_ids,minimum_age,starts_at,ends_at,poll_policy_json,poll_policy_hash,credential_schema_json,credential_schema_hash,created_at,updated_at";
const POLL_CONTRACT_COLUMNS =
  "vote_privacy_mode,option_set_hash,poll_encryption_key_id";
const POLL_COLUMNS = `${BASE_POLL_COLUMNS},${POLL_CONTRACT_COLUMNS}`;

const POLL_OPTION_COLUMNS =
  "id,poll_id,label,description,color,display_order,is_active,created_at,updated_at";

const POLL_CONTRACT_COLUMN_NAMES = [
  "vote_privacy_mode",
  "option_set_hash",
  "poll_encryption_key_id",
] as const;

const KNOWN_POLL_VOTE_PRIVACY_MODES = new Set<PollVotePrivacyMode>([
  "legacy_identity_linked",
  "zk_preprover_audit",
  "zk_secret_ballot_v1",
]);

type PartialPollRow = Omit<
  PollRow,
  "vote_privacy_mode" | "option_set_hash" | "poll_encryption_key_id"
> &
  Partial<
    Pick<
      PollRow,
      "vote_privacy_mode" | "option_set_hash" | "poll_encryption_key_id"
    >
  >;

const isMissingPollContractColumnError = (error: unknown): boolean => {
  if (!error || typeof error !== "object") {
    return false;
  }

  const code = (error as { code?: unknown }).code;
  if (typeof code !== "string") {
    return false;
  }

  const normalizedCode = code.trim().toUpperCase();
  if (
    normalizedCode !== "42703" &&
    normalizedCode !== "PGRST204" &&
    normalizedCode !== "PGRST205"
  ) {
    return false;
  }

  const message = (error as { message?: unknown }).message;
  if (typeof message !== "string") {
    return false;
  }

  const normalized = message.toLowerCase();
  return POLL_CONTRACT_COLUMN_NAMES.some((columnName) =>
    normalized.includes(columnName),
  );
};

const resolveVotePrivacyMode = (
  row: PartialPollRow,
): PollVotePrivacyMode => {
  const candidate = row.vote_privacy_mode;
  if (candidate && KNOWN_POLL_VOTE_PRIVACY_MODES.has(candidate)) {
    return candidate;
  }

  return row.poll_policy_hash && row.credential_schema_hash
    ? "zk_preprover_audit"
    : "legacy_identity_linked";
};

const withPollContractDefaults = (row: PartialPollRow): PollRow => ({
  ...row,
  vote_privacy_mode: resolveVotePrivacyMode(row),
  option_set_hash: row.option_set_hash ?? null,
  poll_encryption_key_id: row.poll_encryption_key_id ?? null,
});

const buildPollInsertPayload = (input: NewPollRow) => ({
  ...(input.id ? { id: input.id } : null),
  slug: input.slug,
  created_by_user_id: input.created_by_user_id,
  title: input.title,
  description: input.description,
  status: input.status,
  jurisdiction_type: input.jurisdiction_type,
  jurisdiction_country_code: input.jurisdiction_country_code,
  jurisdiction_area_ids: input.jurisdiction_area_ids,
  jurisdiction_land_ids: input.jurisdiction_land_ids,
  requires_verified_identity: input.requires_verified_identity,
  allowed_document_country_codes: input.allowed_document_country_codes,
  allowed_home_area_ids: input.allowed_home_area_ids,
  allowed_land_ids: input.allowed_land_ids,
  minimum_age: input.minimum_age,
  starts_at: input.starts_at,
  ends_at: input.ends_at,
  poll_policy_json: input.poll_policy_json ?? null,
  poll_policy_hash: input.poll_policy_hash ?? null,
  credential_schema_json: input.credential_schema_json ?? null,
  credential_schema_hash: input.credential_schema_hash ?? null,
});

const buildPollContractPayload = (input: NewPollRow) => ({
  vote_privacy_mode: input.vote_privacy_mode ?? "zk_preprover_audit",
  option_set_hash: input.option_set_hash ?? null,
  poll_encryption_key_id: input.poll_encryption_key_id ?? null,
});

const buildPollUpdatePayload = (input: NewPollRow) => {
  const { id: _id, ...payload } = buildPollInsertPayload(input);
  return payload;
};

export const pollRepository = {
  async listAll(): Promise<PollRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("polls")
      .select(POLL_COLUMNS)
      .order("created_at", { ascending: false });

    if (error && isMissingPollContractColumnError(error)) {
      const fallback = await supabase
        .from("polls")
        .select(BASE_POLL_COLUMNS)
        .order("created_at", { ascending: false });

      if (fallback.error) {
        throw fallback.error;
      }

      return ((fallback.data || []) as PartialPollRow[]).map(
        withPollContractDefaults,
      );
    }

    if (error) {
      throw error;
    }

    return ((data || []) as PartialPollRow[]).map(withPollContractDefaults);
  },

  async getById(pollId: string): Promise<PollRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("polls")
      .select(POLL_COLUMNS)
      .eq("id", pollId)
      .maybeSingle<PollRow>();

    if (error && isMissingPollContractColumnError(error)) {
      const fallback = await supabase
        .from("polls")
        .select(BASE_POLL_COLUMNS)
        .eq("id", pollId)
        .maybeSingle<PartialPollRow>();

      if (fallback.error) {
        throw fallback.error;
      }

      return fallback.data ? withPollContractDefaults(fallback.data) : null;
    }

    if (error) {
      throw error;
    }

    return data ? withPollContractDefaults(data) : null;
  },

  async getOptionsByPollId(pollId: string): Promise<PollOptionRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_options")
      .select(POLL_OPTION_COLUMNS)
      .eq("poll_id", pollId)
      .order("display_order", { ascending: true })
      .order("created_at", { ascending: true });

    if (error) {
      throw error;
    }

    return (data || []) as PollOptionRow[];
  },

  async getOptionsByPollIds(pollIds: string[]): Promise<PollOptionRow[]> {
    if (pollIds.length === 0) {
      return [];
    }

    const supabase = requireSupabaseAdminClient();
    const { data, error } = await supabase
      .from("poll_options")
      .select(POLL_OPTION_COLUMNS)
      .in("poll_id", pollIds);

    if (error) {
      throw error;
    }

    return (data || []) as PollOptionRow[];
  },

  async getOptionById(optionId: string): Promise<PollOptionRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_options")
      .select(POLL_OPTION_COLUMNS)
      .eq("id", optionId)
      .maybeSingle<PollOptionRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async getOptionByIdForPoll(pollId: string, optionId: string): Promise<PollOptionRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("poll_options")
      .select(POLL_OPTION_COLUMNS)
      .eq("poll_id", pollId)
      .eq("id", optionId)
      .maybeSingle<PollOptionRow>();

    if (error) {
      throw error;
    }

    return data || null;
  },

  async insert(input: NewPollRow): Promise<PollRow> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("polls")
      .insert({
        ...buildPollInsertPayload(input),
        ...buildPollContractPayload(input),
      })
      .select(POLL_COLUMNS)
      .single<PollRow>();

    if (error && isMissingPollContractColumnError(error)) {
      const fallback = await supabase
        .from("polls")
        .insert(buildPollInsertPayload(input))
        .select(BASE_POLL_COLUMNS)
        .single<PartialPollRow>();

      if (fallback.error) {
        throw fallback.error;
      }

      return withPollContractDefaults(fallback.data);
    }

    if (error) {
      throw error;
    }

    return withPollContractDefaults(data);
  },

  async updateById(pollId: string, input: NewPollRow): Promise<PollRow | null> {
    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("polls")
      .update({
        ...buildPollUpdatePayload(input),
        ...buildPollContractPayload(input),
      })
      .eq("id", pollId)
      .select(POLL_COLUMNS)
      .maybeSingle<PollRow>();

    if (error && isMissingPollContractColumnError(error)) {
      const fallback = await supabase
        .from("polls")
        .update(buildPollUpdatePayload(input))
        .eq("id", pollId)
        .select(BASE_POLL_COLUMNS)
        .maybeSingle<PartialPollRow>();

      if (fallback.error) {
        throw fallback.error;
      }

      return fallback.data ? withPollContractDefaults(fallback.data) : null;
    }

    if (error) {
      throw error;
    }

    return data ? withPollContractDefaults(data) : null;
  },

  async insertOptions(options: NewPollOptionRow[]): Promise<PollOptionRow[]> {
    if (options.length === 0) {
      return [];
    }

    const supabase = requireSupabaseAdminClient();
    const payload = options.map((option) => ({
      ...(option.id ? { id: option.id } : null),
      poll_id: option.poll_id,
      label: option.label,
      description: option.description,
      color: option.color,
      display_order: option.display_order,
      is_active: option.is_active,
      ...(option.created_at ? { created_at: option.created_at } : null),
    }));

    const { error } = await supabase.from("poll_options").insert(payload);
    if (error) {
      throw error;
    }

    const pollId = options[0].poll_id;
    return this.getOptionsByPollId(pollId);
  },

  async replaceOptions(pollId: string, options: NewPollOptionRow[]): Promise<PollOptionRow[]> {
    const supabase = requireSupabaseAdminClient();

    const { error: deleteError } = await supabase
      .from("poll_options")
      .delete()
      .eq("poll_id", pollId);

    if (deleteError) {
      throw deleteError;
    }

    if (options.length === 0) {
      return [];
    }

    return this.insertOptions(options);
  },
};

export default pollRepository;
