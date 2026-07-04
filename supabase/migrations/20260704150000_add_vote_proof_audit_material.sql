begin;

alter table public.votes
  add column if not exists nullifier text,
  add column if not exists vote_commitment text,
  add column if not exists encrypted_vote jsonb,
  add column if not exists proof_hash text,
  add column if not exists proof_system_version text,
  add column if not exists verification_method_version text,
  add column if not exists proof_verification_status text,
  add column if not exists proof_public_inputs_json jsonb,
  add column if not exists proof_envelope_json jsonb,
  add column if not exists accepted_at timestamptz,
  add column if not exists batch_id text;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'votes_nullifier_hex'
  ) then
    alter table public.votes
      add constraint votes_nullifier_hex
      check (nullifier is null or nullifier ~ '^[0-9a-f]{64}$');
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'votes_vote_commitment_hex'
  ) then
    alter table public.votes
      add constraint votes_vote_commitment_hex
      check (vote_commitment is null or vote_commitment ~ '^[0-9a-f]{64}$');
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'votes_proof_hash_hex'
  ) then
    alter table public.votes
      add constraint votes_proof_hash_hex
      check (proof_hash is null or proof_hash ~ '^[0-9a-f]{64}$');
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'votes_proof_verification_status_known'
  ) then
    alter table public.votes
      add constraint votes_proof_verification_status_known
      check (
        proof_verification_status is null
        or proof_verification_status in (
          'preprover_accepted',
          'verified',
          'rejected'
        )
      );
  end if;
end $$;

create unique index if not exists ux_votes_poll_nullifier
  on public.votes(poll_id, nullifier)
  where nullifier is not null;

create index if not exists idx_votes_proof_hash
  on public.votes(proof_hash)
  where proof_hash is not null;

create index if not exists idx_votes_batch_id
  on public.votes(poll_id, batch_id)
  where batch_id is not null;

comment on column public.votes.nullifier is
  'Per-poll ZKP nullifier used for duplicate-proof rejection without storing identity.';
comment on column public.votes.vote_commitment is
  'Hash commitment to the accepted off-chain vote record for later public audit roots.';
comment on column public.votes.encrypted_vote is
  'Reserved encrypted vote payload. CivicOS v1 still stores option_id off-chain until results publication.';
comment on column public.votes.proof_hash is
  'Hash of the submitted vote proof envelope.';
comment on column public.votes.proof_verification_status is
  'preprover_accepted means the Phase 3 envelope passed backend checks but is not a SNARK verification.';

create table if not exists public.poll_roots (
  id uuid primary key default gen_random_uuid(),
  poll_id uuid not null references public.polls(id) on delete cascade,
  batch_id text not null,
  previous_nullifier_root text,
  nullifier_root text not null,
  previous_vote_commitment_root text,
  vote_commitment_root text not null,
  accepted_count integer not null default 0 check (accepted_count >= 0),
  solana_tx_signature text,
  created_at timestamptz not null default now(),
  unique (poll_id, batch_id),
  check (
    previous_nullifier_root is null
    or previous_nullifier_root ~ '^[0-9a-f]{64}$'
  ),
  check (nullifier_root ~ '^[0-9a-f]{64}$'),
  check (
    previous_vote_commitment_root is null
    or previous_vote_commitment_root ~ '^[0-9a-f]{64}$'
  ),
  check (vote_commitment_root ~ '^[0-9a-f]{64}$')
);

create index if not exists idx_poll_roots_poll_created
  on public.poll_roots(poll_id, created_at);

comment on table public.poll_roots is
  'Per-poll proof/nullifier/vote-commitment root history for later Solana anchoring.';

create table if not exists public.poll_audit_events (
  id uuid primary key default gen_random_uuid(),
  poll_id uuid references public.polls(id) on delete cascade,
  event_type text not null,
  payload_hash text not null check (payload_hash ~ '^[0-9a-f]{64}$'),
  payload_json jsonb,
  solana_tx_signature text,
  created_at timestamptz not null default now()
);

create index if not exists idx_poll_audit_events_poll_created
  on public.poll_audit_events(poll_id, created_at);

create index if not exists idx_poll_audit_events_type
  on public.poll_audit_events(event_type);

comment on table public.poll_audit_events is
  'Poll-specific audit log for proof batches, root publication, and result publication.';

commit;
