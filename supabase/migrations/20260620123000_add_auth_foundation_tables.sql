begin;

create table if not exists public.auth_credentials (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  platform text not null check (platform in ('ios', 'android')),
  algorithm text not null check (algorithm in ('p256')),
  credential_id text not null unique,
  public_key_pem text not null,
  status text not null default 'active'
    check (status in ('active', 'revoked', 'superseded')),
  device_label text,
  last_authenticated_at timestamptz,
  superseded_by_auth_credential_id uuid references public.auth_credentials(id),
  revoked_at timestamptz,
  revocation_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_auth_credentials_user_id
  on public.auth_credentials(user_id);

create index if not exists idx_auth_credentials_user_status
  on public.auth_credentials(user_id, status);

comment on table public.auth_credentials is
  'Device-bound authentication credentials. A verified real-world identity may attach multiple active device credentials over time, but each request must still resolve to the same backend identity through canonical_identity_key-backed user binding.';

comment on column public.auth_credentials.credential_id is
  'Stable server-side identifier for the device authentication credential. This is not exposed as an RP identity.';

comment on column public.auth_credentials.public_key_pem is
  'P-256 public key enrolled from the device. The private key must remain non-exportable in Secure Enclave or Android Keystore.';

drop trigger if exists auth_credentials_set_updated_at on public.auth_credentials;
create trigger auth_credentials_set_updated_at
before update on public.auth_credentials
for each row
execute function public.set_updated_at();

create table if not exists public.app_attestation_credentials (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  auth_credential_id uuid not null unique references public.auth_credentials(id) on delete cascade,
  platform text not null check (platform in ('ios', 'android')),
  attestation_provider text not null
    check (attestation_provider in ('ios_app_attest', 'android_play_integrity')),
  environment text not null default 'development'
    check (environment in ('development', 'production')),
  attestation_key_id text,
  app_identifier text,
  package_name text,
  signing_cert_digest text,
  status text not null default 'verified'
    check (status in ('pending', 'verified', 'revoked', 'superseded')),
  last_counter bigint,
  last_asserted_at timestamptz,
  last_assertion_nonce_hash text,
  revoked_at timestamptz,
  revocation_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_app_attestation_credentials_user_status
  on public.app_attestation_credentials(user_id, status);

comment on table public.app_attestation_credentials is
  'Verified app-instance attestation state. Production protected routes must only accept sessions that originate from a verified and non-revoked attested app context.';

comment on column public.app_attestation_credentials.last_assertion_nonce_hash is
  'Tracks the most recent verified assertion nonce binding so replay detection can reject reused assertions without persisting raw challenge values.';

drop trigger if exists app_attestation_credentials_set_updated_at on public.app_attestation_credentials;
create trigger app_attestation_credentials_set_updated_at
before update on public.app_attestation_credentials
for each row
execute function public.set_updated_at();

create table if not exists public.auth_sessions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  auth_credential_id uuid not null references public.auth_credentials(id) on delete cascade,
  status text not null default 'active'
    check (status in ('active', 'revoked', 'expired', 'superseded')),
  auth_generation integer not null default 1 check (auth_generation > 0),
  attestation_verified_at timestamptz not null,
  last_seen_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  revocation_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_auth_sessions_user_status
  on public.auth_sessions(user_id, status);

create index if not exists idx_auth_sessions_credential_status
  on public.auth_sessions(auth_credential_id, status);

comment on table public.auth_sessions is
  'First-party app sessions. Viewer resolution must migrate from caller-supplied UUIDs to these server-side sessions before production launch.';

comment on column public.auth_sessions.auth_generation is
  'Session generation snapshot. Recovery or security revocation increments the authoritative generation so older sessions fail immediately.';

drop trigger if exists auth_sessions_set_updated_at on public.auth_sessions;
create trigger auth_sessions_set_updated_at
before update on public.auth_sessions
for each row
execute function public.set_updated_at();

create table if not exists public.refresh_token_families (
  id uuid primary key default gen_random_uuid(),
  session_id uuid not null unique references public.auth_sessions(id) on delete cascade,
  user_id uuid not null references public.users(id) on delete cascade,
  status text not null default 'active'
    check (status in ('active', 'revoked', 'reused', 'expired')),
  current_token_hash text not null unique,
  previous_token_hash text,
  rotation_counter integer not null default 0 check (rotation_counter >= 0),
  last_rotated_at timestamptz not null default now(),
  last_used_at timestamptz,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  revocation_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_refresh_token_families_user_status
  on public.refresh_token_families(user_id, status);

comment on table public.refresh_token_families is
  'Per-session rotating refresh-token families. Reuse on one device/session must revoke that family without destroying unrelated healthy device sessions.';

drop trigger if exists refresh_token_families_set_updated_at on public.refresh_token_families;
create trigger refresh_token_families_set_updated_at
before update on public.refresh_token_families
for each row
execute function public.set_updated_at();

create table if not exists public.auth_audit_events (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.users(id) on delete set null,
  auth_credential_id uuid references public.auth_credentials(id) on delete set null,
  session_id uuid references public.auth_sessions(id) on delete set null,
  event_type text not null,
  platform text,
  metadata jsonb not null default '{}'::jsonb,
  occurred_at timestamptz not null default now()
);

create index if not exists idx_auth_audit_events_user_occurred_at
  on public.auth_audit_events(user_id, occurred_at desc);

create index if not exists idx_auth_audit_events_event_type
  on public.auth_audit_events(event_type);

comment on table public.auth_audit_events is
  'Immutable authentication and recovery audit trail. These events explain why a session or credential was accepted, revoked, superseded, or denied.';

commit;
