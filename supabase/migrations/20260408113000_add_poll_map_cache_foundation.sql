begin;

create table if not exists public.poll_map_marker_cache (
  poll_id uuid primary key
    references public.polls(id)
    on delete cascade,
  markers_level1_json jsonb not null default '[]'::jsonb,
  schema_version integer not null default 1
    check (schema_version > 0),
  marker_count integer not null default 0
    check (marker_count >= 0),
  total_votes integer not null default 0
    check (total_votes >= 0),
  last_vote_submitted_at timestamptz,
  refreshed_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint poll_map_marker_cache_markers_level1_json_array_chk
    check (jsonb_typeof(markers_level1_json) = 'array')
);

create index if not exists idx_poll_map_marker_cache_refreshed_at
  on public.poll_map_marker_cache(refreshed_at desc);

create table if not exists public.poll_map_refresh_queue (
  poll_id uuid primary key
    references public.polls(id)
    on delete cascade,
  pending_vote_events integer not null default 0
    check (pending_vote_events >= 0),
  first_enqueued_at timestamptz not null default now(),
  last_enqueued_at timestamptz not null default now(),
  last_processed_at timestamptz,
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_poll_map_refresh_queue_pending_first
  on public.poll_map_refresh_queue(first_enqueued_at asc)
  where pending_vote_events > 0;

alter table public.votes
  add column if not exists vote_latitude_l0 double precision;

alter table public.votes
  add column if not exists vote_longitude_l0 double precision;

alter table public.votes
  add column if not exists vote_location_snapshot_at timestamptz;

alter table public.votes
  add column if not exists vote_location_snapshot_version smallint not null default 1;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'votes_vote_latitude_l0_range_chk'
  ) then
    alter table public.votes
      add constraint votes_vote_latitude_l0_range_chk
      check (
        vote_latitude_l0 is null
        or (vote_latitude_l0 >= -90 and vote_latitude_l0 <= 90)
      );
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'votes_vote_longitude_l0_range_chk'
  ) then
    alter table public.votes
      add constraint votes_vote_longitude_l0_range_chk
      check (
        vote_longitude_l0 is null
        or (vote_longitude_l0 >= -180 and vote_longitude_l0 <= 180)
      );
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'votes_vote_location_snapshot_version_chk'
  ) then
    alter table public.votes
      add constraint votes_vote_location_snapshot_version_chk
      check (vote_location_snapshot_version > 0);
  end if;
end;
$$;

create or replace function public.enqueue_poll_map_refresh(p_poll_id uuid)
returns public.poll_map_refresh_queue
language plpgsql
as $$
declare
  queued_row public.poll_map_refresh_queue%rowtype;
begin
  if p_poll_id is null then
    raise exception 'p_poll_id is required';
  end if;

  insert into public.poll_map_refresh_queue (
    poll_id,
    pending_vote_events,
    first_enqueued_at,
    last_enqueued_at,
    last_processed_at,
    last_error
  )
  values (
    p_poll_id,
    1,
    now(),
    now(),
    null,
    null
  )
  on conflict (poll_id) do update
    set pending_vote_events = public.poll_map_refresh_queue.pending_vote_events + 1,
        last_enqueued_at = now(),
        last_error = null
  returning * into queued_row;

  return queued_row;
end;
$$;

drop trigger if exists poll_map_marker_cache_set_updated_at on public.poll_map_marker_cache;
create trigger poll_map_marker_cache_set_updated_at
before update on public.poll_map_marker_cache
for each row
execute function public.set_updated_at();

drop trigger if exists poll_map_refresh_queue_set_updated_at on public.poll_map_refresh_queue;
create trigger poll_map_refresh_queue_set_updated_at
before update on public.poll_map_refresh_queue
for each row
execute function public.set_updated_at();

commit;
