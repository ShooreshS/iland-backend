begin;

create table if not exists public.oidc_access_tokens (
  id uuid primary key default gen_random_uuid(),
  token_hash text not null unique,
  grant_id uuid references public.oidc_grants(id) on delete set null,
  auth_session_id uuid references public.auth_sessions(id) on delete set null,
  client_id uuid not null references public.oidc_clients(id) on delete cascade,
  user_id uuid not null references public.users(id) on delete cascade,
  pairwise_subject_id uuid not null references public.oidc_pairwise_subjects(id) on delete cascade,
  status text not null default 'active'
    check (status in ('active', 'revoked', 'expired')),
  scopes text[] not null,
  claims jsonb not null default '{}'::jsonb,
  auth_generation integer not null check (auth_generation > 0),
  last_used_at timestamptz,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  revocation_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_oidc_access_tokens_user_status
  on public.oidc_access_tokens(user_id, status);

create index if not exists idx_oidc_access_tokens_client_status
  on public.oidc_access_tokens(client_id, status);

create index if not exists idx_oidc_access_tokens_expires_at
  on public.oidc_access_tokens(expires_at);

comment on table public.oidc_access_tokens is
  'Opaque OIDC access tokens for UserInfo/revocation. Only token hashes are stored; raw access tokens must never be persisted or logged.';

comment on column public.oidc_access_tokens.claims is
  'Consent-filtered claim/proof snapshot allowed for this access token. Do not store raw identity evidence here.';

drop trigger if exists oidc_access_tokens_set_updated_at on public.oidc_access_tokens;
create trigger oidc_access_tokens_set_updated_at
before update on public.oidc_access_tokens
for each row
execute function public.set_updated_at();

alter table public.oidc_access_tokens enable row level security;

commit;
