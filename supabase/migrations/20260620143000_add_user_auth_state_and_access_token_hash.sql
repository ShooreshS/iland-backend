begin;

alter table public.users
  add column if not exists auth_generation integer not null default 1
    check (auth_generation > 0),
  add column if not exists account_status text not null default 'active'
    check (account_status in ('active', 'disabled', 'banned'));

comment on column public.users.auth_generation is
  'Monotonic authentication generation. Recovery or security revocation increments this so older sessions fail immediately.';

comment on column public.users.account_status is
  'Account-level auth gate. Disabled or banned users must not log in, refresh, recover, or use protected APIs until support/admin review re-enables them.';

alter table public.auth_sessions
  add column if not exists current_access_token_hash text unique;

comment on column public.auth_sessions.current_access_token_hash is
  'Hash of the currently active first-party bearer token for this session. The raw access token is never stored at rest.';

commit;
