-- CivicOS ZKP tally worker queue.
--
-- This is a backend-admin queue. RLS is enabled so anon/authenticated clients
-- cannot read job state directly; the backend exposes safe public status.

create table if not exists public.zkp_tally_jobs (
  id uuid primary key default gen_random_uuid(),
  poll_id uuid not null references public.polls(id) on delete cascade,
  status text not null default 'pending' check (
    status in ('pending', 'running', 'succeeded', 'failed', 'cancelled')
  ),
  priority integer not null default 100,
  attempts integer not null default 0,
  max_attempts integer not null default 3,
  locked_by text,
  locked_at timestamptz,
  next_attempt_at timestamptz not null default now(),
  proof_public_inputs_hash text,
  tally_proof_hash text,
  result_hash text,
  error_code text,
  error_message text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (poll_id),
  check (attempts >= 0),
  check (max_attempts >= 1),
  check (proof_public_inputs_hash is null or proof_public_inputs_hash ~ '^[0-9a-f]{64}$'),
  check (tally_proof_hash is null or tally_proof_hash ~ '^[0-9a-f]{64}$'),
  check (result_hash is null or result_hash ~ '^[0-9a-f]{64}$')
);

alter table public.zkp_tally_jobs enable row level security;

create index if not exists idx_zkp_tally_jobs_claimable
  on public.zkp_tally_jobs(status, next_attempt_at, priority, created_at);

create index if not exists idx_zkp_tally_jobs_locked
  on public.zkp_tally_jobs(status, locked_at)
  where status = 'running';

create table if not exists public.zkp_tally_worker_heartbeats (
  worker_id text primary key,
  host text,
  status text not null default 'running' check (
    status in ('starting', 'running', 'idle', 'stopping', 'stopped', 'error')
  ),
  current_job_id uuid references public.zkp_tally_jobs(id) on delete set null,
  message text,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);

alter table public.zkp_tally_worker_heartbeats enable row level security;

create or replace function public.touch_zkp_tally_job_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists trg_touch_zkp_tally_job_updated_at on public.zkp_tally_jobs;
create trigger trg_touch_zkp_tally_job_updated_at
before update on public.zkp_tally_jobs
for each row
execute function public.touch_zkp_tally_job_updated_at();

create or replace function public.enqueue_zkp_tally_job(
  p_poll_id uuid,
  p_priority integer default 100,
  p_max_attempts integer default 3
)
returns public.zkp_tally_jobs
language plpgsql
security definer
set search_path = public
as $$
declare
  v_job public.zkp_tally_jobs;
begin
  insert into public.zkp_tally_jobs (
    poll_id,
    status,
    priority,
    max_attempts,
    next_attempt_at,
    error_code,
    error_message
  )
  values (
    p_poll_id,
    'pending',
    coalesce(p_priority, 100),
    greatest(coalesce(p_max_attempts, 3), 1),
    now(),
    null,
    null
  )
  on conflict (poll_id) do update set
    priority = least(public.zkp_tally_jobs.priority, excluded.priority),
    max_attempts = greatest(public.zkp_tally_jobs.max_attempts, excluded.max_attempts),
    status = case
      when public.zkp_tally_jobs.status in ('failed', 'cancelled') then 'pending'
      else public.zkp_tally_jobs.status
    end,
    locked_by = case
      when public.zkp_tally_jobs.status in ('failed', 'cancelled') then null
      else public.zkp_tally_jobs.locked_by
    end,
    locked_at = case
      when public.zkp_tally_jobs.status in ('failed', 'cancelled') then null
      else public.zkp_tally_jobs.locked_at
    end,
    next_attempt_at = case
      when public.zkp_tally_jobs.status in ('failed', 'cancelled') then now()
      else public.zkp_tally_jobs.next_attempt_at
    end,
    error_code = case
      when public.zkp_tally_jobs.status in ('failed', 'cancelled') then null
      else public.zkp_tally_jobs.error_code
    end,
    error_message = case
      when public.zkp_tally_jobs.status in ('failed', 'cancelled') then null
      else public.zkp_tally_jobs.error_message
    end
  returning * into v_job;

  return v_job;
end;
$$;

create or replace function public.claim_zkp_tally_job(
  p_worker_id text,
  p_lock_timeout_seconds integer default 600
)
returns public.zkp_tally_jobs
language plpgsql
security definer
set search_path = public
as $$
declare
  v_job public.zkp_tally_jobs;
begin
  with candidate as (
    select *
    from public.zkp_tally_jobs
    where
      (
        status = 'pending'
        and next_attempt_at <= now()
        and attempts < max_attempts
      )
      or (
        status = 'running'
        and locked_at < now() - make_interval(secs => greatest(coalesce(p_lock_timeout_seconds, 600), 1))
        and attempts < max_attempts
      )
    order by priority asc, created_at asc
    for update skip locked
    limit 1
  )
  update public.zkp_tally_jobs job
  set
    status = 'running',
    attempts = job.attempts + 1,
    locked_by = p_worker_id,
    locked_at = now(),
    error_code = null,
    error_message = null
  from candidate
  where job.id = candidate.id
  returning job.* into v_job;

  return v_job;
end;
$$;

create or replace function public.complete_zkp_tally_job(
  p_job_id uuid,
  p_worker_id text,
  p_proof_public_inputs_hash text,
  p_tally_proof_hash text,
  p_result_hash text
)
returns public.zkp_tally_jobs
language plpgsql
security definer
set search_path = public
as $$
declare
  v_job public.zkp_tally_jobs;
begin
  update public.zkp_tally_jobs
  set
    status = 'succeeded',
    locked_by = null,
    locked_at = null,
    next_attempt_at = now(),
    proof_public_inputs_hash = lower(p_proof_public_inputs_hash),
    tally_proof_hash = lower(p_tally_proof_hash),
    result_hash = lower(p_result_hash),
    error_code = null,
    error_message = null
  where id = p_job_id
    and status = 'running'
    and locked_by = p_worker_id
  returning * into v_job;

  return v_job;
end;
$$;

create or replace function public.fail_zkp_tally_job(
  p_job_id uuid,
  p_worker_id text,
  p_error_code text,
  p_error_message text,
  p_retry_after_seconds integer default 60,
  p_retryable boolean default true
)
returns public.zkp_tally_jobs
language plpgsql
security definer
set search_path = public
as $$
declare
  v_job public.zkp_tally_jobs;
begin
  update public.zkp_tally_jobs
  set
    status = case
      when not coalesce(p_retryable, true) then 'failed'
      when attempts >= max_attempts then 'failed'
      else 'pending'
    end,
    locked_by = null,
    locked_at = null,
    next_attempt_at = case
      when not coalesce(p_retryable, true) then now()
      when attempts >= max_attempts then now()
      else now() + make_interval(secs => greatest(coalesce(p_retry_after_seconds, 60), 0))
    end,
    error_code = left(coalesce(p_error_code, 'UNKNOWN_ERROR'), 120),
    error_message = left(coalesce(p_error_message, 'Tally worker failed.'), 2000)
  where id = p_job_id
    and status = 'running'
    and locked_by = p_worker_id
  returning * into v_job;

  return v_job;
end;
$$;

create or replace function public.heartbeat_zkp_tally_worker(
  p_worker_id text,
  p_host text default null,
  p_status text default 'running',
  p_current_job_id uuid default null,
  p_message text default null
)
returns public.zkp_tally_worker_heartbeats
language plpgsql
security definer
set search_path = public
as $$
declare
  v_heartbeat public.zkp_tally_worker_heartbeats;
begin
  insert into public.zkp_tally_worker_heartbeats (
    worker_id,
    host,
    status,
    current_job_id,
    message,
    first_seen_at,
    last_seen_at
  )
  values (
    p_worker_id,
    nullif(left(coalesce(p_host, ''), 255), ''),
    coalesce(p_status, 'running'),
    p_current_job_id,
    left(coalesce(p_message, ''), 1000),
    now(),
    now()
  )
  on conflict (worker_id) do update set
    host = excluded.host,
    status = excluded.status,
    current_job_id = excluded.current_job_id,
    message = excluded.message,
    last_seen_at = now()
  returning * into v_heartbeat;

  return v_heartbeat;
end;
$$;

comment on table public.zkp_tally_jobs is
  'Backend-only queue for Groth16 tally proof generation jobs.';

comment on table public.zkp_tally_worker_heartbeats is
  'Backend-only liveness records for dedicated ZKP tally worker services.';
