begin;

create table if not exists public.backend_audit_events (
  id uuid primary key default gen_random_uuid(),
  stream_id text not null default 'global',
  sequence bigint not null check (sequence >= 0),
  previous_event_hash text not null
    check (previous_event_hash ~ '^[0-9a-f]{64}$'),
  event_hash text not null unique
    check (event_hash ~ '^[0-9a-f]{64}$'),
  event_type text not null,
  decision text not null
    check (decision in ('accepted', 'rejected', 'recorded', 'published', 'errored')),
  subject_type text,
  subject_id text,
  event_payload_json jsonb not null,
  occurred_at timestamptz not null,
  anchored_at timestamptz,
  anchor_cluster text,
  anchor_tx_signature text,
  created_at timestamptz not null default now(),
  unique (stream_id, sequence)
);

create index if not exists idx_backend_audit_events_stream_sequence
  on public.backend_audit_events(stream_id, sequence desc);

create index if not exists idx_backend_audit_events_subject
  on public.backend_audit_events(subject_type, subject_id, sequence desc)
  where subject_type is not null and subject_id is not null;

comment on table public.backend_audit_events is
  'Hash-linked backend security/audit decisions. Each event hash commits to the previous event hash and canonical event payload; audit roots can later be anchored on Solana.';

comment on column public.backend_audit_events.previous_event_hash is
  'Previous event hash in this stream, or 64 zeroes for the first event.';

comment on column public.backend_audit_events.event_payload_json is
  'Canonicalized by the backend before hashing. Must not contain raw identity documents, private witnesses, private keys, seed phrases, or raw IP/user-agent values.';

alter table public.backend_audit_events enable row level security;

create or replace function public.append_backend_audit_event(
  p_stream_id text,
  p_previous_event_hash text,
  p_event_hash text,
  p_event_type text,
  p_decision text,
  p_subject_type text default null,
  p_subject_id text default null,
  p_event_payload_json jsonb default '{}'::jsonb,
  p_occurred_at timestamptz default now()
)
returns public.backend_audit_events
language plpgsql
security definer
set search_path = public
as $$
declare
  v_stream_id text := coalesce(nullif(trim(p_stream_id), ''), 'global');
  v_latest public.backend_audit_events%rowtype;
  v_sequence bigint := 0;
  v_inserted public.backend_audit_events%rowtype;
  v_genesis_hash text := repeat('0', 64);
begin
  if p_previous_event_hash is null or p_previous_event_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'previous event hash must be 64 lowercase hex characters';
  end if;

  if p_event_hash is null or p_event_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'event hash must be 64 lowercase hex characters';
  end if;

  if p_event_type is null or length(trim(p_event_type)) = 0 then
    raise exception 'event type is required';
  end if;

  if p_decision not in ('accepted', 'rejected', 'recorded', 'published', 'errored') then
    raise exception 'unsupported backend audit decision: %', p_decision;
  end if;

  perform pg_advisory_xact_lock(hashtext(v_stream_id)::bigint);

  select *
    into v_latest
    from public.backend_audit_events
    where stream_id = v_stream_id
    order by sequence desc
    limit 1
    for update;

  if found then
    if v_latest.event_hash <> p_previous_event_hash then
      raise exception 'previous event hash does not match current stream tail';
    end if;

    v_sequence := v_latest.sequence + 1;
  elsif p_previous_event_hash <> v_genesis_hash then
    raise exception 'first event in a stream must use the genesis previous hash';
  end if;

  insert into public.backend_audit_events (
    stream_id,
    sequence,
    previous_event_hash,
    event_hash,
    event_type,
    decision,
    subject_type,
    subject_id,
    event_payload_json,
    occurred_at
  )
  values (
    v_stream_id,
    v_sequence,
    p_previous_event_hash,
    p_event_hash,
    trim(p_event_type),
    p_decision,
    nullif(trim(p_subject_type), ''),
    nullif(trim(p_subject_id), ''),
    p_event_payload_json,
    p_occurred_at
  )
  returning * into v_inserted;

  return v_inserted;
end;
$$;

revoke all on function public.append_backend_audit_event(
  text,
  text,
  text,
  text,
  text,
  text,
  text,
  jsonb,
  timestamptz
) from public;

grant execute on function public.append_backend_audit_event(
  text,
  text,
  text,
  text,
  text,
  text,
  text,
  jsonb,
  timestamptz
) to service_role;

commit;
