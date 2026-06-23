begin;

-- Security hardening:
-- pin function lookup to the intended schema set so callers cannot influence
-- object resolution through a mutable search_path.

create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create or replace function public.enqueue_poll_map_refresh(p_poll_id uuid)
returns public.poll_map_refresh_queue
language plpgsql
set search_path = public, pg_temp
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

commit;
