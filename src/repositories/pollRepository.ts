import { requireSupabaseAdminClient } from "../db/supabaseClient";
import type {
  NewPollOptionRow,
  NewPollRow,
  PollOptionRow,
  PollRow,
} from "../types/db";
import type {
  PollResultPublicationMode,
  PollVotePrivacyMode,
} from "../types/contracts";

const BASE_POLL_COLUMNS =
  "id,slug,created_by_user_id,title,description,status,jurisdiction_type,jurisdiction_country_code,jurisdiction_area_ids,jurisdiction_land_ids,requires_verified_identity,allowed_document_country_codes,allowed_home_area_ids,allowed_land_ids,minimum_age,starts_at,ends_at,poll_policy_json,poll_policy_hash,credential_schema_json,credential_schema_hash,created_at,updated_at";
const POLL_CONTRACT_COLUMNS =
  "vote_privacy_mode,result_publication_mode,option_set_hash,poll_encryption_key_id";
const POLL_MODERATION_COLUMNS =
  "moderation_status,moderation_model,moderation_flagged,moderation_categories,moderation_category_scores,moderation_applied_input_types,moderation_raw,moderated_at,moderation_error,moderation_policy_version,gate2_status,gate2_model,gate2_result,human_review_status,human_review_decision,human_reviewed_at";
const POLL_COLUMNS = `${BASE_POLL_COLUMNS},${POLL_CONTRACT_COLUMNS},${POLL_MODERATION_COLUMNS}`;

const POLL_OPTION_COLUMNS =
  "id,poll_id,label,description,color,display_order,is_active,created_at,updated_at";

const POLL_CONTRACT_COLUMN_NAMES = [
  "vote_privacy_mode",
  "result_publication_mode",
  "option_set_hash",
  "poll_encryption_key_id",
] as const;
const POLL_MODERATION_COLUMN_NAMES = [
  "moderation_status",
  "moderation_model",
  "moderation_flagged",
  "moderation_categories",
  "moderation_category_scores",
  "moderation_applied_input_types",
  "moderation_raw",
  "moderated_at",
  "moderation_error",
  "moderation_policy_version",
  "gate2_status",
  "gate2_model",
  "gate2_result",
  "human_review_status",
  "human_review_decision",
  "human_reviewed_at",
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
      | "vote_privacy_mode"
      | "result_publication_mode"
      | "option_set_hash"
      | "poll_encryption_key_id"
    >
  >;

const isMissingOptionalPollColumnError = (error: unknown): boolean => {
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
  return [...POLL_CONTRACT_COLUMN_NAMES, ...POLL_MODERATION_COLUMN_NAMES].some(
    (columnName) => normalized.includes(columnName),
  );
};

const resolveVotePrivacyMode = (
  row: PartialPollRow,
): PollVotePrivacyMode => {
  const candidate = row.vote_privacy_mode;
  if (candidate && KNOWN_POLL_VOTE_PRIVACY_MODES.has(candidate)) {
    return candidate;
  }

  return "zk_secret_ballot_v1";
};

const resolveResultPublicationMode = (
  row: PartialPollRow,
): PollResultPublicationMode =>
  row.result_publication_mode === "creator_managed"
    ? "creator_managed"
    : "auto_on_close";

const withPollContractDefaults = (row: PartialPollRow): PollRow => ({
  ...row,
  vote_privacy_mode: resolveVotePrivacyMode(row),
  result_publication_mode: resolveResultPublicationMode(row),
  option_set_hash: row.option_set_hash ?? null,
  poll_encryption_key_id: row.poll_encryption_key_id ?? null,
  moderation_status:
    row.moderation_status ?? (row.status === "draft" ? "draft" : "published"),
  moderation_model: row.moderation_model ?? null,
  moderation_flagged: row.moderation_flagged ?? null,
  moderation_categories: row.moderation_categories ?? null,
  moderation_category_scores: row.moderation_category_scores ?? null,
  moderation_applied_input_types:
    row.moderation_applied_input_types ?? null,
  moderation_raw: row.moderation_raw ?? null,
  moderated_at: row.moderated_at ?? null,
  moderation_error: row.moderation_error ?? null,
  moderation_policy_version: row.moderation_policy_version ?? null,
  gate2_status: row.gate2_status ?? null,
  gate2_model: row.gate2_model ?? null,
  gate2_result: row.gate2_result ?? null,
  human_review_status: row.human_review_status ?? null,
  human_review_decision: row.human_review_decision ?? null,
  human_reviewed_at: row.human_reviewed_at ?? null,
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
  vote_privacy_mode: input.vote_privacy_mode ?? "zk_secret_ballot_v1",
  result_publication_mode: input.result_publication_mode ?? "auto_on_close",
  option_set_hash: input.option_set_hash ?? null,
  poll_encryption_key_id: input.poll_encryption_key_id ?? null,
});

const buildPollModerationPayload = (input: NewPollRow) => ({
  ...(input.moderation_status !== undefined
    ? { moderation_status: input.moderation_status }
    : null),
  ...(input.moderation_model !== undefined
    ? { moderation_model: input.moderation_model }
    : null),
  ...(input.moderation_flagged !== undefined
    ? { moderation_flagged: input.moderation_flagged }
    : null),
  ...(input.moderation_categories !== undefined
    ? { moderation_categories: input.moderation_categories }
    : null),
  ...(input.moderation_category_scores !== undefined
    ? { moderation_category_scores: input.moderation_category_scores }
    : null),
  ...(input.moderation_applied_input_types !== undefined
    ? { moderation_applied_input_types: input.moderation_applied_input_types }
    : null),
  ...(input.moderation_raw !== undefined
    ? { moderation_raw: input.moderation_raw }
    : null),
  ...(input.moderated_at !== undefined
    ? { moderated_at: input.moderated_at }
    : null),
  ...(input.moderation_error !== undefined
    ? { moderation_error: input.moderation_error }
    : null),
  ...(input.moderation_policy_version !== undefined
    ? { moderation_policy_version: input.moderation_policy_version }
    : null),
  ...(input.gate2_status !== undefined
    ? { gate2_status: input.gate2_status }
    : null),
  ...(input.gate2_model !== undefined ? { gate2_model: input.gate2_model } : null),
  ...(input.gate2_result !== undefined
    ? { gate2_result: input.gate2_result }
    : null),
  ...(input.human_review_status !== undefined
    ? { human_review_status: input.human_review_status }
    : null),
  ...(input.human_review_decision !== undefined
    ? { human_review_decision: input.human_review_decision }
    : null),
  ...(input.human_reviewed_at !== undefined
    ? { human_reviewed_at: input.human_reviewed_at }
    : null),
});

const buildPollUpdatePayload = (input: NewPollRow) => {
  const { id: _id, ...payload } = buildPollInsertPayload(input);
  return payload;
};

const closeExpiredPolls = async (nowIso = new Date().toISOString()): Promise<void> => {
  const supabase = requireSupabaseAdminClient();

  const { error } = await supabase
    .from("polls")
    .update({
      status: "closed",
      updated_at: nowIso,
    })
    .in("status", ["active", "scheduled"])
    .not("ends_at", "is", null)
    .lte("ends_at", nowIso);

  if (error) {
    throw error;
  }
};

const getByIdInternal = async (
  pollId: string,
): Promise<PollRow | null> => {
  const supabase = requireSupabaseAdminClient();

  const { data, error } = await supabase
    .from("polls")
    .select(POLL_COLUMNS)
    .eq("id", pollId)
    .maybeSingle<PollRow>();

  if (error && isMissingOptionalPollColumnError(error)) {
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
};

export const pollRepository = {
  closeExpiredPolls,

  async listAll(): Promise<PollRow[]> {
    await closeExpiredPolls();

    const supabase = requireSupabaseAdminClient();

    const { data, error } = await supabase
      .from("polls")
      .select(POLL_COLUMNS)
      .order("created_at", { ascending: false });

    if (error && isMissingOptionalPollColumnError(error)) {
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
    await closeExpiredPolls();
    return getByIdInternal(pollId);
  },

  async getByIdWithoutStatusRefresh(pollId: string): Promise<PollRow | null> {
    return getByIdInternal(pollId);
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
        ...buildPollModerationPayload(input),
      })
      .select(POLL_COLUMNS)
      .single<PollRow>();

    if (error && isMissingOptionalPollColumnError(error)) {
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
        ...buildPollModerationPayload(input),
      })
      .eq("id", pollId)
      .select(POLL_COLUMNS)
      .maybeSingle<PollRow>();

    if (error && isMissingOptionalPollColumnError(error)) {
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
