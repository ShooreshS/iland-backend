begin;

create table if not exists public.credential_registry (
  id uuid primary key default gen_random_uuid(),
  verified_identity_id uuid not null references public.verified_identities(id) on delete restrict,
  identity_key_hash text not null,
  credential_commitment text not null,
  credential_schema_hash text not null,
  claims_hash text not null,
  credential_issuer_id text not null,
  commitment_scheme text not null default 'civicos-credential-commitment-v1',
  merkle_depth integer not null default 24,
  leaf_index bigint not null,
  revoked_at timestamptz,
  revocation_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (verified_identity_id),
  unique (identity_key_hash),
  unique (merkle_depth, leaf_index),
  check (identity_key_hash ~ '^[0-9a-f]{64}$'),
  check (credential_commitment ~ '^[0-9a-f]{64}$'),
  check (credential_schema_hash ~ '^[0-9a-f]{64}$'),
  check (claims_hash ~ '^[0-9a-f]{64}$'),
  check (merkle_depth > 0 and merkle_depth <= 64),
  check (leaf_index >= 0),
  check (
    (revoked_at is null and revocation_reason is null)
    or (revoked_at is not null)
  )
);

create index if not exists idx_credential_registry_active_leaf
  on public.credential_registry(merkle_depth, leaf_index)
  where revoked_at is null;

create index if not exists idx_credential_registry_created_at
  on public.credential_registry(created_at);

comment on table public.credential_registry is
  'Internal CivicOS ZKP credential registry. One row is issued per unique verified identity and later proven through a Poseidon Merkle root.';
comment on column public.credential_registry.verified_identity_id is
  'Internal FK to the canonical verified identity. This is not copied into poll_zk_votes or public audit material.';
comment on column public.credential_registry.identity_key_hash is
  'Poseidon BN254 hash of verified_identities.canonical_identity_key. Unique anti-Sybil anchor for anonymous ZKP voting.';
comment on column public.credential_registry.credential_commitment is
  'Poseidon BN254 credential leaf committed by the vote circuit.';
comment on column public.credential_registry.claims_hash is
  'Poseidon/SHA-domain-separated hash of server-issued eligibility claims for the credential.';
comment on column public.credential_registry.leaf_index is
  'Credential Merkle tree leaf index. Unique within a Merkle depth.';

drop trigger if exists credential_registry_set_updated_at on public.credential_registry;
create trigger credential_registry_set_updated_at
before update on public.credential_registry
for each row
execute function public.set_updated_at();

create table if not exists public.credential_roots (
  id uuid primary key default gen_random_uuid(),
  root text not null,
  previous_root text,
  merkle_depth integer not null default 24,
  leaf_count bigint not null,
  latest_credential_registry_id uuid references public.credential_registry(id) on delete restrict,
  solana_tx_signature text,
  created_at timestamptz not null default now(),
  unique (root),
  unique (merkle_depth, leaf_count, root),
  check (root ~ '^[0-9a-f]{64}$'),
  check (previous_root is null or previous_root ~ '^[0-9a-f]{64}$'),
  check (merkle_depth > 0 and merkle_depth <= 64),
  check (leaf_count >= 0)
);

create index if not exists idx_credential_roots_created_at
  on public.credential_roots(created_at);

create index if not exists idx_credential_roots_depth_leaf_count
  on public.credential_roots(merkle_depth, leaf_count desc, created_at desc);

comment on table public.credential_roots is
  'Append-only history of accepted CivicOS credential Merkle roots for ZKP vote verification.';
comment on column public.credential_roots.root is
  'Poseidon BN254 Merkle root accepted by the backend verifier as a credentialRoot public input.';
comment on column public.credential_roots.previous_root is
  'Previous accepted credential root for audit-chain continuity.';
comment on column public.credential_roots.leaf_count is
  'Number of non-revoked credential registry leaves included in this root.';
comment on column public.credential_roots.solana_tx_signature is
  'Optional Solana transaction signature if/when credential roots are anchored on-chain.';

commit;
