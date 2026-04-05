begin;

create table if not exists public.wallet_credentials (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references public.users(id) on delete cascade,
  wallet_public_id text not null unique,
  holder_id text not null,
  wallet_public_key text not null,
  issuance_status text not null default 'not_issued'
    check (issuance_status in ('not_issued', 'issued', 'revoked')),
  issued_at timestamptz,
  revoked_at timestamptz,
  revocation_reason text,
  credential_payload jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_wallet_credentials_user_id
  on public.wallet_credentials(user_id);

create index if not exists idx_wallet_credentials_issuance_status
  on public.wallet_credentials(issuance_status);

drop trigger if exists wallet_credentials_set_updated_at on public.wallet_credentials;
create trigger wallet_credentials_set_updated_at
before update on public.wallet_credentials
for each row
execute function public.set_updated_at();

commit;
