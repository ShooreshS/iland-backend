begin;

alter table public.poll_zk_votes
  add column if not exists encrypted_vote_commitment text;

update public.poll_zk_votes
set encrypted_vote_commitment = encrypted_vote_hash
where encrypted_vote_commitment is null;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'poll_zk_votes_encrypted_vote_commitment_hex'
  ) then
    alter table public.poll_zk_votes
      add constraint poll_zk_votes_encrypted_vote_commitment_hex
      check (encrypted_vote_commitment ~ '^[0-9a-f]{64}$');
  end if;
end $$;

alter table public.poll_zk_votes
  alter column encrypted_vote_commitment set not null;

comment on column public.poll_zk_votes.encrypted_vote_hash is
  'SHA-256 hash of the submitted encrypted vote payload for ciphertext integrity checks.';
comment on column public.poll_zk_votes.encrypted_vote_commitment is
  'Poseidon BN254 commitment to the encrypted vote opening used by vote and tally circuits.';

commit;
