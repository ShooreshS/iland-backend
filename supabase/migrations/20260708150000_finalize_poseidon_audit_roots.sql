begin;

alter table public.poll_roots
  add column if not exists previous_encrypted_vote_root text,
  add column if not exists encrypted_vote_root text;

update public.poll_roots
set encrypted_vote_root = repeat('0', 64)
where encrypted_vote_root is null;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'poll_roots_previous_encrypted_vote_root_hex'
  ) then
    alter table public.poll_roots
      add constraint poll_roots_previous_encrypted_vote_root_hex
      check (
        previous_encrypted_vote_root is null
        or previous_encrypted_vote_root ~ '^[0-9a-f]{64}$'
      );
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'poll_roots_encrypted_vote_root_hex'
  ) then
    alter table public.poll_roots
      add constraint poll_roots_encrypted_vote_root_hex
      check (encrypted_vote_root ~ '^[0-9a-f]{64}$');
  end if;
end $$;

alter table public.poll_roots
  alter column encrypted_vote_root set not null;

comment on column public.poll_roots.previous_encrypted_vote_root is
  'Previous encrypted-vote Poseidon audit root for batch-chain continuity.';
comment on column public.poll_roots.encrypted_vote_root is
  'Poseidon root of encrypted-vote commitments for the accepted ZKP vote set.';

commit;
