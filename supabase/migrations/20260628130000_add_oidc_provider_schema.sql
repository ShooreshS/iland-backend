begin;

create table if not exists public.oidc_clients (
  id uuid primary key default gen_random_uuid(),
  client_id text not null unique,
  client_name text not null,
  client_type text not null default 'confidential'
    check (client_type in ('confidential', 'public')),
  application_type text not null default 'web'
    check (application_type in ('web', 'native')),
  status text not null default 'active'
    check (status in ('active', 'disabled', 'deleted')),
  client_uri text,
  logo_uri text,
  tos_uri text,
  policy_uri text,
  sector_identifier text not null,
  allowed_scopes text[] not null default array['openid']::text[],
  default_scopes text[] not null default array['openid']::text[],
  require_pkce boolean not null default true,
  pkce_required_method text not null default 'S256'
    check (pkce_required_method in ('S256')),
  id_token_signed_response_alg text not null default 'RS256'
    check (id_token_signed_response_alg in ('RS256')),
  access_token_ttl_seconds integer not null default 900
    check (access_token_ttl_seconds between 60 and 3600),
  authorization_code_ttl_seconds integer not null default 300
    check (authorization_code_ttl_seconds between 60 and 600),
  refresh_token_ttl_days integer not null default 30
    check (refresh_token_ttl_days between 1 and 365),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ('openid' = any (allowed_scopes)),
  check (default_scopes <@ allowed_scopes)
);

create index if not exists idx_oidc_clients_status
  on public.oidc_clients(status);

comment on table public.oidc_clients is
  'OIDC relying-party registrations. These rows are backend-administered only; public clients must never be able to self-register directly through Supabase.';

comment on column public.oidc_clients.client_id is
  'Public OAuth/OIDC client identifier exposed to relying parties. This is not a database id and is safe to place in authorize URLs.';

comment on column public.oidc_clients.sector_identifier is
  'Sector identifier used for pairwise subject generation. For the first web client this will normally be the relying-party host such as codeiland.com.';

drop trigger if exists oidc_clients_set_updated_at on public.oidc_clients;
create trigger oidc_clients_set_updated_at
before update on public.oidc_clients
for each row
execute function public.set_updated_at();

create table if not exists public.oidc_client_secrets (
  id uuid primary key default gen_random_uuid(),
  client_id uuid not null references public.oidc_clients(id) on delete cascade,
  secret_hash text not null unique,
  label text,
  status text not null default 'active'
    check (status in ('active', 'revoked', 'expired')),
  last_used_at timestamptz,
  expires_at timestamptz,
  revoked_at timestamptz,
  revocation_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_oidc_client_secrets_client_status
  on public.oidc_client_secrets(client_id, status);

comment on table public.oidc_client_secrets is
  'Rotatable confidential-client secrets. Only hashes are stored; raw client secrets must be shown once at creation time and never persisted.';

comment on column public.oidc_client_secrets.secret_hash is
  'Hash of the RP client secret. The raw secret must never be stored in the database or logs.';

drop trigger if exists oidc_client_secrets_set_updated_at on public.oidc_client_secrets;
create trigger oidc_client_secrets_set_updated_at
before update on public.oidc_client_secrets
for each row
execute function public.set_updated_at();

create table if not exists public.oidc_client_redirect_uris (
  id uuid primary key default gen_random_uuid(),
  client_id uuid not null references public.oidc_clients(id) on delete cascade,
  usage text not null default 'redirect'
    check (usage in ('redirect', 'post_logout')),
  redirect_uri text not null,
  created_at timestamptz not null default now(),
  unique (client_id, usage, redirect_uri),
  check (redirect_uri ~ '^https://')
);

create index if not exists idx_oidc_client_redirect_uris_client_usage
  on public.oidc_client_redirect_uris(client_id, usage);

comment on table public.oidc_client_redirect_uris is
  'Exact allowed redirect and post-logout redirect URIs for each OIDC client. Wildcards are intentionally unsupported.';

comment on column public.oidc_client_redirect_uris.redirect_uri is
  'Exact URI string that must match the authorize or logout request. Use HTTPS only for first release web clients.';

create table if not exists public.oidc_pairwise_subjects (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  sector_identifier text not null,
  subject_identifier text not null unique,
  first_client_id uuid references public.oidc_clients(id) on delete set null,
  created_at timestamptz not null default now(),
  unique (user_id, sector_identifier)
);

create index if not exists idx_oidc_pairwise_subjects_user_id
  on public.oidc_pairwise_subjects(user_id);

comment on table public.oidc_pairwise_subjects is
  'Stable pairwise OIDC subject identifiers. External relying parties receive subject_identifier, never internal users.id.';

comment on column public.oidc_pairwise_subjects.subject_identifier is
  'Opaque subject value used as the OIDC sub claim for one user and sector identifier.';

create table if not exists public.oidc_authorization_requests (
  id uuid primary key default gen_random_uuid(),
  request_id text not null unique,
  client_id uuid not null references public.oidc_clients(id) on delete cascade,
  user_id uuid references public.users(id) on delete cascade,
  auth_session_id uuid references public.auth_sessions(id) on delete set null,
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'denied', 'expired', 'consumed', 'cancelled')),
  response_type text not null default 'code'
    check (response_type in ('code')),
  redirect_uri text not null,
  scopes text[] not null,
  state text,
  nonce text,
  code_challenge text not null,
  code_challenge_method text not null default 'S256'
    check (code_challenge_method in ('S256')),
  prompt text[] not null default array[]::text[],
  max_age_seconds integer check (max_age_seconds is null or max_age_seconds >= 0),
  ui_locales text[] not null default array[]::text[],
  login_hint_hash text,
  consent_required boolean not null default true,
  approved_at timestamptz,
  denied_at timestamptz,
  consumed_at timestamptz,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_oidc_authorization_requests_client_status
  on public.oidc_authorization_requests(client_id, status);

create index if not exists idx_oidc_authorization_requests_user_status
  on public.oidc_authorization_requests(user_id, status);

create index if not exists idx_oidc_authorization_requests_expires_at
  on public.oidc_authorization_requests(expires_at);

comment on table public.oidc_authorization_requests is
  'Short-lived OIDC authorize/consent transactions. They bind client, redirect_uri, PKCE challenge, requested scopes, optional nonce, and the approving first-party session.';

comment on column public.oidc_authorization_requests.state is
  'RP-provided state value that must be echoed back to the redirect URI. It is short-lived but may contain RP metadata, so it must not be logged.';

comment on column public.oidc_authorization_requests.nonce is
  'OIDC nonce to copy into the ID token after successful authorization. It is not a backend secret but must stay scoped to this short-lived transaction.';

drop trigger if exists oidc_authorization_requests_set_updated_at on public.oidc_authorization_requests;
create trigger oidc_authorization_requests_set_updated_at
before update on public.oidc_authorization_requests
for each row
execute function public.set_updated_at();

create table if not exists public.oidc_authorization_codes (
  id uuid primary key default gen_random_uuid(),
  code_hash text not null unique,
  authorization_request_id uuid not null references public.oidc_authorization_requests(id) on delete cascade,
  client_id uuid not null references public.oidc_clients(id) on delete cascade,
  user_id uuid not null references public.users(id) on delete cascade,
  auth_session_id uuid references public.auth_sessions(id) on delete set null,
  pairwise_subject_id uuid not null references public.oidc_pairwise_subjects(id) on delete cascade,
  status text not null default 'active'
    check (status in ('active', 'consumed', 'expired', 'revoked')),
  redirect_uri text not null,
  scopes text[] not null,
  nonce text,
  code_challenge text not null,
  code_challenge_method text not null default 'S256'
    check (code_challenge_method in ('S256')),
  auth_generation integer not null check (auth_generation > 0),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  revoked_at timestamptz,
  revocation_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_oidc_authorization_codes_client_status
  on public.oidc_authorization_codes(client_id, status);

create index if not exists idx_oidc_authorization_codes_user_status
  on public.oidc_authorization_codes(user_id, status);

create index if not exists idx_oidc_authorization_codes_expires_at
  on public.oidc_authorization_codes(expires_at);

comment on table public.oidc_authorization_codes is
  'One-time OAuth authorization codes. Only code hashes are stored; raw authorization codes must never be persisted or logged.';

comment on column public.oidc_authorization_codes.auth_generation is
  'User auth_generation at approval time. Token exchange must reject stale codes after recovery or account security revocation.';

drop trigger if exists oidc_authorization_codes_set_updated_at on public.oidc_authorization_codes;
create trigger oidc_authorization_codes_set_updated_at
before update on public.oidc_authorization_codes
for each row
execute function public.set_updated_at();

create table if not exists public.oidc_grants (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  client_id uuid not null references public.oidc_clients(id) on delete cascade,
  pairwise_subject_id uuid not null references public.oidc_pairwise_subjects(id) on delete cascade,
  status text not null default 'active'
    check (status in ('active', 'revoked', 'expired')),
  scopes text[] not null,
  claims jsonb not null default '{}'::jsonb,
  consented_at timestamptz not null default now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  revocation_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (user_id, client_id)
);

create index if not exists idx_oidc_grants_client_status
  on public.oidc_grants(client_id, status);

create index if not exists idx_oidc_grants_user_status
  on public.oidc_grants(user_id, status);

comment on table public.oidc_grants is
  'User consent grants for OIDC clients. Grants define which scopes/claims a relying party may receive until revoked or expired.';

drop trigger if exists oidc_grants_set_updated_at on public.oidc_grants;
create trigger oidc_grants_set_updated_at
before update on public.oidc_grants
for each row
execute function public.set_updated_at();

create table if not exists public.oidc_refresh_token_families (
  id uuid primary key default gen_random_uuid(),
  grant_id uuid not null references public.oidc_grants(id) on delete cascade,
  auth_session_id uuid references public.auth_sessions(id) on delete set null,
  client_id uuid not null references public.oidc_clients(id) on delete cascade,
  user_id uuid not null references public.users(id) on delete cascade,
  status text not null default 'active'
    check (status in ('active', 'revoked', 'reused', 'expired')),
  current_token_hash text not null unique,
  previous_token_hash text,
  rotation_counter integer not null default 0 check (rotation_counter >= 0),
  auth_generation integer not null check (auth_generation > 0),
  last_rotated_at timestamptz not null default now(),
  last_used_at timestamptz,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  revocation_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_oidc_refresh_token_families_previous_hash
  on public.oidc_refresh_token_families(previous_token_hash)
  where previous_token_hash is not null;

create index if not exists idx_oidc_refresh_token_families_user_status
  on public.oidc_refresh_token_families(user_id, status);

create index if not exists idx_oidc_refresh_token_families_client_status
  on public.oidc_refresh_token_families(client_id, status);

comment on table public.oidc_refresh_token_families is
  'OIDC/offline_access refresh-token families. Only token hashes are stored. Reuse must revoke this family without destroying unrelated first-party sessions.';

drop trigger if exists oidc_refresh_token_families_set_updated_at on public.oidc_refresh_token_families;
create trigger oidc_refresh_token_families_set_updated_at
before update on public.oidc_refresh_token_families
for each row
execute function public.set_updated_at();

create table if not exists public.oidc_signing_keys (
  id uuid primary key default gen_random_uuid(),
  kid text not null unique,
  key_use text not null default 'sig'
    check (key_use in ('sig')),
  algorithm text not null default 'RS256'
    check (algorithm in ('RS256')),
  status text not null default 'active'
    check (status in ('active', 'retiring', 'retired', 'revoked')),
  public_jwk jsonb not null,
  private_key_ref text,
  not_before timestamptz not null default now(),
  not_after timestamptz,
  activated_at timestamptz,
  retired_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_oidc_signing_keys_status
  on public.oidc_signing_keys(status, algorithm);

comment on table public.oidc_signing_keys is
  'OIDC JWKS signing-key metadata. Store public JWKs here; private signing material should live in Railway/Supabase secrets or another key store referenced by private_key_ref.';

comment on column public.oidc_signing_keys.private_key_ref is
  'Reference to private signing material outside this table. Do not store raw private keys here.';

drop trigger if exists oidc_signing_keys_set_updated_at on public.oidc_signing_keys;
create trigger oidc_signing_keys_set_updated_at
before update on public.oidc_signing_keys
for each row
execute function public.set_updated_at();

create table if not exists public.oidc_audit_events (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.users(id) on delete set null,
  client_id uuid references public.oidc_clients(id) on delete set null,
  auth_session_id uuid references public.auth_sessions(id) on delete set null,
  authorization_request_id uuid references public.oidc_authorization_requests(id) on delete set null,
  grant_id uuid references public.oidc_grants(id) on delete set null,
  event_type text not null,
  ip_hash text,
  user_agent_hash text,
  metadata jsonb not null default '{}'::jsonb,
  occurred_at timestamptz not null default now()
);

create index if not exists idx_oidc_audit_events_user_occurred_at
  on public.oidc_audit_events(user_id, occurred_at desc);

create index if not exists idx_oidc_audit_events_client_occurred_at
  on public.oidc_audit_events(client_id, occurred_at desc);

create index if not exists idx_oidc_audit_events_event_type
  on public.oidc_audit_events(event_type);

comment on table public.oidc_audit_events is
  'Immutable OIDC provider audit trail for authorize, consent, code exchange, token refresh, revocation, and error events.';

alter table public.oidc_clients enable row level security;
alter table public.oidc_client_secrets enable row level security;
alter table public.oidc_client_redirect_uris enable row level security;
alter table public.oidc_pairwise_subjects enable row level security;
alter table public.oidc_authorization_requests enable row level security;
alter table public.oidc_authorization_codes enable row level security;
alter table public.oidc_grants enable row level security;
alter table public.oidc_refresh_token_families enable row level security;
alter table public.oidc_signing_keys enable row level security;
alter table public.oidc_audit_events enable row level security;

commit;
