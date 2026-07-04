begin;

alter table public.polls
  add column if not exists poll_policy_json jsonb,
  add column if not exists poll_policy_hash text,
  add column if not exists credential_schema_json jsonb,
  add column if not exists credential_schema_hash text;

create index if not exists idx_polls_poll_policy_hash
  on public.polls(poll_policy_hash);

create index if not exists idx_polls_credential_schema_hash
  on public.polls(credential_schema_hash);

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'polls_poll_policy_hash_hex'
  ) then
    alter table public.polls
      add constraint polls_poll_policy_hash_hex
      check (poll_policy_hash is null or poll_policy_hash ~ '^[0-9a-f]{64}$');
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'polls_credential_schema_hash_hex'
  ) then
    alter table public.polls
      add constraint polls_credential_schema_hash_hex
      check (
        credential_schema_hash is null
        or credential_schema_hash ~ '^[0-9a-f]{64}$'
      );
  end if;
end $$;

comment on column public.polls.poll_policy_json is
  'Canonical CivicOS ZKP poll policy snapshot used to derive poll_policy_hash.';
comment on column public.polls.poll_policy_hash is
  'SHA-256 hash of canonical CivicOS ZKP poll policy JSON.';
comment on column public.polls.credential_schema_json is
  'Canonical CivicOS credential schema snapshot bound to the poll policy.';
comment on column public.polls.credential_schema_hash is
  'SHA-256 hash of canonical CivicOS credential schema JSON.';

commit;
