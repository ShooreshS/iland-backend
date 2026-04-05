-- DEV ONLY TEMPLATE (0.0.86)
--
-- Purpose:
--   Create ONE sample poll with options and many synthetic votes.
--   Run manually in Supabase SQL Editor.
--
-- Safe usage:
--   1) Edit only the CONFIG section below.
--   2) Keep poll_slug unique for each run.
--   3) Run the whole file.
--
-- This template respects current schema constraints:
--   - single-choice (one vote row per user per poll)
--   - vote option must belong to the poll
--   - unique (poll_id, user_id)

begin;

do $$
declare
  ------------------------------------------------------------------------------
  -- CONFIG: EDIT THESE VALUES BEFORE RUNNING
  ------------------------------------------------------------------------------

  -- Poll owner. Paste an existing user UUID as text.
  -- Leave empty ('') to auto-use latest user, or auto-create one when DB is empty.
  cfg_created_by_user_id_text text := '';
  cfg_auto_create_creator_if_missing boolean := true;

  -- Must be unique across polls.
  cfg_poll_slug text := 'dev-sample-poll-001';

  cfg_poll_title text := 'Sample poll title';
  cfg_poll_description text := 'Sample poll created from supabase/dev/002_sample_poll_template.sql';

  -- Allowed: draft | scheduled | active | closed | archived
  cfg_poll_status text := 'active';

  -- Allowed: global | real_country | real_area | land
  cfg_jurisdiction_type text := 'global';

  -- Scope fields (set to null or empty arrays when not needed)
  cfg_jurisdiction_country_code text := null;            -- e.g. 'SE'
  cfg_jurisdiction_area_ids text[] := array[]::text[];  -- e.g. array['se-stockholm-01']
  cfg_jurisdiction_land_ids text[] := array[]::text[];  -- e.g. array['land_123']

  -- Eligibility fields
  cfg_requires_verified_identity boolean := false;
  cfg_allowed_document_country_codes text[] := array[]::text[];
  cfg_allowed_home_area_ids text[] := array[]::text[];
  cfg_allowed_land_ids text[] := array[]::text[];
  cfg_minimum_age integer := null;

  -- Optional schedule times
  cfg_starts_at timestamptz := now();
  cfg_ends_at timestamptz := null;

  -- Option labels and vote counts. These arrays must have matching lengths.
  -- vote_count controls synthetic votes per option.
  -- Use 0 to create an option with zero synthetic votes.
  cfg_option_labels text[] := array[
    'Option A',
    'Option B',
    'Option C'
  ];
  cfg_option_vote_counts integer[] := array[
    120,
    80,
    30
  ];

  -- Optional per-option description/color arrays.
  -- Use empty array to skip all descriptions/colors.
  cfg_option_descriptions text[] := array[]::text[];
  cfg_option_colors text[] := array[
    '#3B82F6',
    '#EF4444',
    '#10B981'
  ];

  -- Optional creator defaults (used only when auto-creating creator user).
  cfg_creator_username text := 'dev-poll-creator';
  cfg_creator_display_name text := 'Dev Poll Creator';

  -- Synthetic user generation settings.
  -- Prefix is auto-suffixed with timestamp each run to avoid collisions.
  cfg_synthetic_user_prefix text := 'devpoll';
  cfg_synthetic_user_language text := 'en';

  -- Allowed: anonymous | passport_verified | nid_verified | face_verified | fully_verified
  cfg_synthetic_user_verification_level text := 'anonymous';

  -- Optional synthetic user fields
  cfg_synthetic_selected_land_id text := null;

  -- If true, create identity_profiles for synthetic users too.
  -- Recommended true when testing poll-scoped map markers. If home fields are null,
  -- backend map service will fall back to generic privacy-safe unknown area buckets.
  cfg_create_identity_profiles boolean := true;

  -- If true, mark synthetic identity checks as completed in identity_profiles.
  cfg_mark_identity_checks_completed boolean := false;
  cfg_synthetic_document_country_code text := null;
  cfg_synthetic_home_country_code text := null;
  cfg_synthetic_home_area_id text := null;

  ------------------------------------------------------------------------------
  -- INTERNALS (do not edit below this line)
  ------------------------------------------------------------------------------
  resolved_created_by_user_id uuid;
  resolved_user_prefix text;
  new_poll_id uuid;
  option_count integer;
  total_vote_count integer := 0;
  i integer;
  option_id uuid;
begin
  if nullif(trim(coalesce(cfg_poll_slug, '')), '') is null then
    raise exception 'cfg_poll_slug is required and must be unique.';
  end if;

  option_count := coalesce(cardinality(cfg_option_labels), 0);

  if option_count = 0 then
    raise exception 'At least one option label is required in cfg_option_labels.';
  end if;

  if coalesce(cardinality(cfg_option_vote_counts), 0) <> option_count then
    raise exception 'cfg_option_vote_counts must match cfg_option_labels length.';
  end if;

  if coalesce(cardinality(cfg_option_descriptions), 0) not in (0, option_count) then
    raise exception 'cfg_option_descriptions must be empty or match cfg_option_labels length.';
  end if;

  if coalesce(cardinality(cfg_option_colors), 0) not in (0, option_count) then
    raise exception 'cfg_option_colors must be empty or match cfg_option_labels length.';
  end if;

  for i in 1..option_count loop
    if nullif(trim(coalesce(cfg_option_labels[i], '')), '') is null then
      raise exception 'Option label at position % is empty.', i;
    end if;

    if coalesce(cfg_option_vote_counts[i], 0) < 0 then
      raise exception 'Option vote count at position % is negative.', i;
    end if;

    total_vote_count := total_vote_count + coalesce(cfg_option_vote_counts[i], 0);
  end loop;

  if total_vote_count = 0 then
    raise exception 'Total votes must be > 0. Increase cfg_option_vote_counts.';
  end if;

  resolved_created_by_user_id := nullif(trim(coalesce(cfg_created_by_user_id_text, '')), '')::uuid;

  if resolved_created_by_user_id is null then
    select u.id
    into resolved_created_by_user_id
    from public.users u
    order by u.created_at desc
    limit 1;
  end if;

  if resolved_created_by_user_id is null and cfg_auto_create_creator_if_missing then
    insert into public.users (
      username,
      display_name,
      onboarding_status,
      verification_level,
      has_wallet,
      wallet_credential_id,
      selected_land_id,
      preferred_language
    ) values (
      nullif(trim(coalesce(cfg_creator_username, '')), ''),
      nullif(trim(coalesce(cfg_creator_display_name, '')), ''),
      'not_started',
      'anonymous',
      false,
      null,
      null,
      null
    )
    returning id into resolved_created_by_user_id;
  end if;

  if resolved_created_by_user_id is null then
    raise exception 'No users found. Set cfg_created_by_user_id_text or enable cfg_auto_create_creator_if_missing.';
  end if;

  perform 1 from public.users u where u.id = resolved_created_by_user_id;
  if not found then
    raise exception 'cfg_created_by_user_id_text (%) does not exist in public.users.', cfg_created_by_user_id_text;
  end if;

  insert into public.polls (
    slug,
    created_by_user_id,
    title,
    description,
    status,
    jurisdiction_type,
    jurisdiction_country_code,
    jurisdiction_area_ids,
    jurisdiction_land_ids,
    requires_verified_identity,
    allowed_document_country_codes,
    allowed_home_area_ids,
    allowed_land_ids,
    minimum_age,
    starts_at,
    ends_at
  ) values (
    trim(cfg_poll_slug),
    resolved_created_by_user_id,
    cfg_poll_title,
    cfg_poll_description,
    cfg_poll_status,
    cfg_jurisdiction_type,
    nullif(trim(coalesce(cfg_jurisdiction_country_code, '')), ''),
    coalesce(cfg_jurisdiction_area_ids, array[]::text[]),
    coalesce(cfg_jurisdiction_land_ids, array[]::text[]),
    cfg_requires_verified_identity,
    coalesce(cfg_allowed_document_country_codes, array[]::text[]),
    coalesce(cfg_allowed_home_area_ids, array[]::text[]),
    coalesce(cfg_allowed_land_ids, array[]::text[]),
    cfg_minimum_age,
    cfg_starts_at,
    cfg_ends_at
  )
  returning id into new_poll_id;

  create temporary table tmp_option_map (
    option_index integer primary key,
    option_id uuid not null,
    vote_count integer not null
  ) on commit drop;

  for i in 1..option_count loop
    insert into public.poll_options (
      poll_id,
      label,
      description,
      color,
      display_order,
      is_active
    ) values (
      new_poll_id,
      trim(cfg_option_labels[i]),
      case
        when coalesce(cardinality(cfg_option_descriptions), 0) = option_count
          then nullif(trim(coalesce(cfg_option_descriptions[i], '')), '')
        else null
      end,
      case
        when coalesce(cardinality(cfg_option_colors), 0) = option_count
          then nullif(trim(coalesce(cfg_option_colors[i], '')), '')
        else null
      end,
      i,
      true
    )
    returning id into option_id;

    if coalesce(cfg_option_vote_counts[i], 0) > 0 then
      insert into tmp_option_map (option_index, option_id, vote_count)
      values (i, option_id, cfg_option_vote_counts[i]);
    end if;
  end loop;

  if not exists (select 1 from tmp_option_map) then
    raise exception 'At least one option must have vote_count > 0.';
  end if;

  resolved_user_prefix := concat(
    coalesce(nullif(trim(coalesce(cfg_synthetic_user_prefix, '')), ''), trim(cfg_poll_slug)),
    '-',
    to_char(clock_timestamp(), 'YYYYMMDDHH24MISSMS')
  );

  create temporary table tmp_synthetic_user_source (
    seq integer primary key,
    username text not null,
    display_name text not null
  ) on commit drop;

  insert into tmp_synthetic_user_source (seq, username, display_name)
  select
    gs,
    format('%s-voter-%s', resolved_user_prefix, lpad(gs::text, 6, '0')),
    format('Synthetic Voter %s', lpad(gs::text, 6, '0'))
  from generate_series(1, total_vote_count) as gs;

  create temporary table tmp_synthetic_users (
    seq integer primary key,
    user_id uuid not null
  ) on commit drop;

  with inserted_users as (
    insert into public.users (
      username,
      display_name,
      onboarding_status,
      verification_level,
      has_wallet,
      wallet_credential_id,
      selected_land_id,
      preferred_language
    )
    select
      src.username,
      src.display_name,
      'completed',
      cfg_synthetic_user_verification_level,
      false,
      null,
      nullif(trim(coalesce(cfg_synthetic_selected_land_id, '')), ''),
      nullif(trim(coalesce(cfg_synthetic_user_language, '')), '')
    from tmp_synthetic_user_source src
    returning id, username
  )
  insert into tmp_synthetic_users (seq, user_id)
  select src.seq, iu.id
  from tmp_synthetic_user_source src
  join inserted_users iu on iu.username = src.username;

  if cfg_create_identity_profiles then
    insert into public.identity_profiles (
      user_id,
      passport_scan_completed,
      passport_nfc_completed,
      national_id_scan_completed,
      face_scan_completed,
      face_bound_to_identity,
      document_country_code,
      issuing_country_code,
      home_country_code,
      home_area_id,
      home_approx_latitude,
      home_approx_longitude,
      home_location_source,
      home_location_updated_at
    )
    select
      su.user_id,
      cfg_mark_identity_checks_completed,
      cfg_mark_identity_checks_completed,
      cfg_mark_identity_checks_completed,
      cfg_mark_identity_checks_completed,
      cfg_mark_identity_checks_completed,
      nullif(trim(coalesce(cfg_synthetic_document_country_code, '')), ''),
      nullif(trim(coalesce(cfg_synthetic_document_country_code, '')), ''),
      nullif(trim(coalesce(cfg_synthetic_home_country_code, '')), ''),
      nullif(trim(coalesce(cfg_synthetic_home_area_id, '')), ''),
      null,
      null,
      'mock',
      case
        when nullif(trim(coalesce(cfg_synthetic_home_area_id, '')), '') is not null
          then now()
        else null
      end
    from tmp_synthetic_users su
    on conflict (user_id) do nothing;
  end if;

  create temporary table tmp_option_ranges on commit drop as
  select
    om.option_id,
    (sum(om.vote_count) over (order by om.option_index) - om.vote_count + 1) as start_seq,
    sum(om.vote_count) over (order by om.option_index) as end_seq
  from tmp_option_map om
  order by om.option_index;

  insert into public.votes (
    poll_id,
    option_id,
    user_id,
    submitted_at,
    is_valid,
    invalid_reason
  )
  select
    new_poll_id,
    r.option_id,
    su.user_id,
    now() - make_interval(secs => (total_vote_count - su.seq)),
    true,
    null
  from tmp_synthetic_users su
  join tmp_option_ranges r
    on su.seq between r.start_seq and r.end_seq;

  raise notice 'Created poll id: %', new_poll_id;
  raise notice 'Created options: %', (select count(*) from tmp_option_map);
  raise notice 'Synthetic users created: %', (select count(*) from tmp_synthetic_users);
  raise notice 'Votes inserted: %', (select count(*) from public.votes where poll_id = new_poll_id);
  raise notice 'Synthetic user prefix used: %', resolved_user_prefix;
end
$$;

commit;
