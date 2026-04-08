Yes. Based on your Codex report, the safest path is:

create/apply the earlier migration that defines public.set_updated_at()
create/apply the poll map cache migration
reload PostgREST schema
restart backend
verify the cache/queue objects exist
only then investigate whether Codex’s fallback logic should be reverted

Supabase’s current docs confirm you can run SQL from the Dashboard SQL Editor, and reloading PostgREST schema is done by running NOTIFY pgrst, 'reload schema'; in the SQL Editor.

Step 1: Open the right place in Supabase

In the Supabase Dashboard for your active project:

open SQL Editor
create a new query
Step 2: Check whether public.set_updated_at() already exists

Paste and run this first:

select
  n.nspname as schema_name,
  p.proname as function_name
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public'
  and p.proname = 'set_updated_at';

Interpretation:

if you get 1 row, continue to Step 3
if you get 0 rows, continue to Step 2B
Step 2B: Create public.set_updated_at() only if missing

Your Codex report says it is defined in:

supabase/migrations/20260405021000_init_v086_poll_vote.sql

Since we are not assuming the DB has it, run this in SQL Editor:

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

Then continue.

Step 3: Create the missing poll-map objects

Now paste and run this whole block in SQL Editor:

begin;

create table if not exists public.poll_map_marker_cache (
  poll_id uuid primary key references public.polls(id) on delete cascade,
  markers_level1_json jsonb not null default '[]'::jsonb,
  schema_version integer not null default 1,
  marker_count integer not null default 0 check (marker_count >= 0),
  total_votes integer not null default 0 check (total_votes >= 0),
  last_vote_submitted_at timestamptz null,
  refreshed_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint poll_map_marker_cache_markers_is_array
    check (jsonb_typeof(markers_level1_json) = 'array')
);

create index if not exists idx_poll_map_marker_cache_refreshed_at
  on public.poll_map_marker_cache (refreshed_at desc);

drop trigger if exists trg_poll_map_marker_cache_set_updated_at on public.poll_map_marker_cache;
create trigger trg_poll_map_marker_cache_set_updated_at
before update on public.poll_map_marker_cache
for each row execute function public.set_updated_at();

create table if not exists public.poll_map_refresh_queue (
  poll_id uuid primary key references public.polls(id) on delete cascade,
  pending_vote_events integer not null default 0 check (pending_vote_events >= 0),
  first_enqueued_at timestamptz not null default now(),
  last_enqueued_at timestamptz not null default now(),
  last_processed_at timestamptz null,
  last_error text null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_poll_map_refresh_queue_pending
  on public.poll_map_refresh_queue (last_enqueued_at asc)
  where pending_vote_events > 0;

drop trigger if exists trg_poll_map_refresh_queue_set_updated_at on public.poll_map_refresh_queue;
create trigger trg_poll_map_refresh_queue_set_updated_at
before update on public.poll_map_refresh_queue
for each row execute function public.set_updated_at();

alter table public.votes
  add column if not exists vote_latitude_l0 double precision null,
  add column if not exists vote_longitude_l0 double precision null,
  add column if not exists vote_location_snapshot_at timestamptz null,
  add column if not exists vote_location_snapshot_version smallint not null default 1;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'votes_vote_latitude_l0_range_check'
  ) then
    alter table public.votes
      add constraint votes_vote_latitude_l0_range_check
      check (vote_latitude_l0 is null or (vote_latitude_l0 >= -90 and vote_latitude_l0 <= 90));
  end if;

  if not exists (
    select 1 from pg_constraint
    where conname = 'votes_vote_longitude_l0_range_check'
  ) then
    alter table public.votes
      add constraint votes_vote_longitude_l0_range_check
      check (vote_longitude_l0 is null or (vote_longitude_l0 >= -180 and vote_longitude_l0 <= 180));
  end if;

  if not exists (
    select 1 from pg_constraint
    where conname = 'votes_vote_location_snapshot_version_check'
  ) then
    alter table public.votes
      add constraint votes_vote_location_snapshot_version_check
      check (vote_location_snapshot_version >= 1);
  end if;
end $$;

create or replace function public.enqueue_poll_map_refresh(p_poll_id uuid)
returns void
language plpgsql
as $$
begin
  insert into public.poll_map_refresh_queue (
    poll_id,
    pending_vote_events,
    first_enqueued_at,
    last_enqueued_at
  )
  values (
    p_poll_id,
    1,
    now(),
    now()
  )
  on conflict (poll_id)
  do update set
    pending_vote_events = public.poll_map_refresh_queue.pending_vote_events + 1,
    last_enqueued_at = now();
end;
$$;

commit;
Step 4: Reload the API schema cache

Run this in SQL Editor:

NOTIFY pgrst, 'reload schema';

Supabase documents this as the way to refresh PostgREST schema after creating tables, columns, or functions.

Step 5: Verify the objects now exist

Run this:

select to_regclass('public.poll_map_marker_cache') as poll_map_marker_cache;
select to_regclass('public.poll_map_refresh_queue') as poll_map_refresh_queue;

select column_name
from information_schema.columns
where table_schema = 'public'
  and table_name = 'votes'
  and column_name in (
    'vote_latitude_l0',
    'vote_longitude_l0',
    'vote_location_snapshot_at',
    'vote_location_snapshot_version'
  )
order by column_name;

Expected:

both to_regclass(...) calls return table names, not null
the votes query returns all 4 columns
Step 6: Restart the backend

Restart your backend process so it reconnects cleanly and starts the worker again.

Step 7: Verify whether the cache starts filling

Run this in SQL Editor:

select
  poll_id,
  marker_count,
  total_votes,
  refreshed_at,
  jsonb_array_length(markers_level1_json) as markers_json_count
from public.poll_map_marker_cache
order by refreshed_at desc;

If rows appear, the cache path is alive.