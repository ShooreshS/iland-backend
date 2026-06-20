begin;

create table if not exists public.auth_challenges (
  id uuid primary key default gen_random_uuid(),
  purpose text not null check (purpose in ('register', 'login', 'recover')),
  platform text not null check (platform in ('ios', 'android')),
  challenge_hash text not null unique,
  credential_id_hint text,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_auth_challenges_purpose_platform
  on public.auth_challenges(purpose, platform);

create index if not exists idx_auth_challenges_expires_at
  on public.auth_challenges(expires_at);

comment on table public.auth_challenges is
  'Short-lived registration, login, and recovery challenges. Only a hash of the issued challenge is stored so challenge replay checks do not require persisting the raw secret server-side.';

comment on column public.auth_challenges.credential_id_hint is
  'Optional client-provided credential hint. This narrows lookup during login without acting as a standalone authenticator.';

commit;
