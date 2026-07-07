begin;

alter table public.polls
  add column if not exists vote_privacy_mode text not null default 'legacy_identity_linked',
  add column if not exists option_set_hash text,
  add column if not exists poll_encryption_key_id text;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'polls_vote_privacy_mode_known'
  ) then
    alter table public.polls
      add constraint polls_vote_privacy_mode_known
      check (
        vote_privacy_mode in (
          'legacy_identity_linked',
          'zk_preprover_audit',
          'zk_secret_ballot_v1'
        )
      );
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'polls_option_set_hash_hex'
  ) then
    alter table public.polls
      add constraint polls_option_set_hash_hex
      check (option_set_hash is null or option_set_hash ~ '^[0-9a-f]{64}$');
  end if;
end $$;

create index if not exists idx_polls_vote_privacy_mode
  on public.polls(vote_privacy_mode);

comment on column public.polls.vote_privacy_mode is
  'Vote privacy/storage mode. zk_secret_ballot_v1 routes accepted production ZKP votes to poll_zk_votes, not identity-linked votes.';
comment on column public.polls.option_set_hash is
  'Canonical hash of the poll option set used by production ZKP vote and tally proofs.';
comment on column public.polls.poll_encryption_key_id is
  'Identifier for the public poll encryption key used by encrypted secret-ballot vote payloads.';

create table if not exists public.poll_zk_votes (
  id uuid primary key default gen_random_uuid(),
  poll_id uuid not null references public.polls(id) on delete cascade,
  nullifier text not null,
  vote_commitment text not null,
  encrypted_vote jsonb not null,
  encrypted_vote_hash text not null,
  encrypted_vote_commitment text not null,
  proof_hash text not null,
  proof_system_version text not null,
  verification_method_version text not null,
  proof_verification_status text not null default 'verified',
  proof_public_inputs_json jsonb not null,
  proof_envelope_hash text not null,
  verifier_key_hash text not null,
  circuit_id text not null,
  accepted_at timestamptz not null default now(),
  batch_id text,
  created_at timestamptz not null default now(),
  unique (poll_id, nullifier),
  check (nullifier ~ '^[0-9a-f]{64}$'),
  check (vote_commitment ~ '^[0-9a-f]{64}$'),
  check (encrypted_vote_hash ~ '^[0-9a-f]{64}$'),
  check (encrypted_vote_commitment ~ '^[0-9a-f]{64}$'),
  check (proof_hash ~ '^[0-9a-f]{64}$'),
  check (proof_envelope_hash ~ '^[0-9a-f]{64}$'),
  check (verifier_key_hash ~ '^[0-9a-f]{64}$'),
  check (proof_verification_status = 'verified')
);

create index if not exists idx_poll_zk_votes_poll_accepted
  on public.poll_zk_votes(poll_id, accepted_at, id);

create index if not exists idx_poll_zk_votes_batch_id
  on public.poll_zk_votes(poll_id, batch_id)
  where batch_id is not null;

create index if not exists idx_poll_zk_votes_proof_hash
  on public.poll_zk_votes(proof_hash);

comment on table public.poll_zk_votes is
  'Production ZKP vote ledger for anonymous secret-ballot polls. This table intentionally has no user_id, verified_identity_id, plaintext option_id, or location snapshot.';
comment on column public.poll_zk_votes.encrypted_vote is
  'Encrypted vote payload. The backend stores ciphertext for tally/proof workflows, not a plaintext option id.';
comment on column public.poll_zk_votes.encrypted_vote_hash is
  'SHA-256 hash of the submitted encrypted vote payload for ciphertext integrity checks.';
comment on column public.poll_zk_votes.encrypted_vote_commitment is
  'Poseidon BN254 commitment to the encrypted vote opening used by vote and tally circuits.';
comment on column public.poll_zk_votes.proof_verification_status is
  'Always verified for this table; pre-prover transition rows stay in public.votes.';

create table if not exists public.poll_tally_proofs (
  id uuid primary key default gen_random_uuid(),
  poll_id uuid not null references public.polls(id) on delete cascade,
  result_hash text not null,
  tally_proof_hash text not null,
  tally_public_inputs_hash text not null,
  tally_verifier_key_hash text not null,
  tally_circuit_id text not null,
  nullifier_root text not null,
  vote_commitment_root text not null,
  encrypted_vote_root text not null,
  accepted_count integer not null default 0 check (accepted_count >= 0),
  proof_envelope_json jsonb not null,
  verified_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  unique (poll_id, result_hash),
  check (result_hash ~ '^[0-9a-f]{64}$'),
  check (tally_proof_hash ~ '^[0-9a-f]{64}$'),
  check (tally_public_inputs_hash ~ '^[0-9a-f]{64}$'),
  check (tally_verifier_key_hash ~ '^[0-9a-f]{64}$'),
  check (nullifier_root ~ '^[0-9a-f]{64}$'),
  check (vote_commitment_root ~ '^[0-9a-f]{64}$'),
  check (encrypted_vote_root ~ '^[0-9a-f]{64}$')
);

create index if not exists idx_poll_tally_proofs_poll_created
  on public.poll_tally_proofs(poll_id, created_at);

comment on table public.poll_tally_proofs is
  'Verified public tally proof envelopes and hashes for production ZKP poll results.';

commit;
