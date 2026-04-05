begin;

create table if not exists public.verified_identities (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references public.users(id) on delete cascade,
  canonical_identity_key text not null unique,
  normalization_version integer not null check (normalization_version > 0),
  verification_method text not null default 'passport_nfc',
  verified_at timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_verified_identities_verified_at
  on public.verified_identities(verified_at desc);

comment on column public.verified_identities.canonical_identity_key is
  'HMAC-SHA-256(server_pepper, nidnh). Raw NIDN and nidnh are never stored.';

drop trigger if exists verified_identities_set_updated_at on public.verified_identities;
create trigger verified_identities_set_updated_at
before update on public.verified_identities
for each row
execute function public.set_updated_at();

commit;
