begin;

create table if not exists public.poll_encryption_keys (
  id uuid primary key default gen_random_uuid(),
  key_id text not null unique,
  poll_id uuid references public.polls(id) on delete set null,
  status text not null default 'active',
  algorithm text not null,
  key_agreement text not null,
  kdf text not null,
  cipher text not null,
  public_key_jwk jsonb not null,
  public_key_hash text not null,
  private_key_jwk jsonb not null,
  custody_model text not null default 'backend-db-service-role-v1',
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  revocation_reason text,
  unique (poll_id),
  check (key_id <> ''),
  check (status in ('active', 'revoked')),
  check (algorithm = 'x25519-hkdf-sha256-aes-256-gcm-v1'),
  check (key_agreement = 'x25519'),
  check (kdf = 'hkdf-sha256'),
  check (cipher = 'aes-256-gcm'),
  check (public_key_hash ~ '^[0-9a-f]{64}$'),
  check (
    (status = 'active' and revoked_at is null and revocation_reason is null)
    or (status = 'revoked' and revoked_at is not null)
  )
);

create index if not exists idx_poll_encryption_keys_poll_id
  on public.poll_encryption_keys(poll_id);

create index if not exists idx_poll_encryption_keys_public_key_hash
  on public.poll_encryption_keys(public_key_hash);

comment on table public.poll_encryption_keys is
  'Backend-custodied poll encryption keys for CivicOS production ZKP secret-ballot payloads.';
comment on column public.poll_encryption_keys.key_id is
  'Stable pollEncryptionKeyId referenced by polls and encrypted vote payloads.';
comment on column public.poll_encryption_keys.public_key_jwk is
  'Public X25519 JWK published to clients for encrypting ballot openings.';
comment on column public.poll_encryption_keys.private_key_jwk is
  'Private X25519 JWK kept behind Supabase service-role access for tally-time decryption. This is v1 custody, not final threshold custody.';
comment on column public.poll_encryption_keys.public_key_hash is
  'SHA-256 hash of the canonical public key contract, used by mobile encrypted vote payloads.';
comment on column public.poll_encryption_keys.custody_model is
  'Current custody model. v1 uses backend-db-service-role-v1; mainnet should move to threshold/KMS/HSM signing and decryption custody.';

commit;
