begin;

create extension if not exists pgcrypto;

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  username text,
  display_name text,
  onboarding_status text not null default 'not_started'
    check (onboarding_status in (
      'not_started',
      'passport_started',
      'passport_completed',
      'wallet_created',
      'identity_pending',
      'completed'
    )),
  verification_level text not null default 'anonymous'
    check (verification_level in (
      'anonymous',
      'passport_verified',
      'nid_verified',
      'face_verified',
      'fully_verified'
    )),
  has_wallet boolean not null default false,
  wallet_credential_id text,
  selected_land_id text,
  preferred_language text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.identity_profiles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references public.users(id) on delete cascade,
  passport_scan_completed boolean not null default false,
  passport_nfc_completed boolean not null default false,
  national_id_scan_completed boolean not null default false,
  face_scan_completed boolean not null default false,
  face_bound_to_identity boolean not null default false,
  document_country_code text,
  issuing_country_code text,
  home_country_code text,
  home_area_id text,
  home_approx_latitude double precision,
  home_approx_longitude double precision,
  home_location_source text not null default 'user_selected'
    check (home_location_source in (
      'user_selected',
      'derived_from_document',
      'admin_set',
      'mock'
    )),
  home_location_updated_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.polls (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique,
  created_by_user_id uuid references public.users(id) on delete set null,
  title text not null,
  description text,
  status text not null
    check (status in ('draft', 'scheduled', 'active', 'closed', 'archived')),
  jurisdiction_type text not null
    check (jurisdiction_type in ('global', 'real_country', 'real_area', 'land')),
  jurisdiction_country_code text,
  jurisdiction_area_ids text[] not null default '{}',
  jurisdiction_land_ids text[] not null default '{}',
  requires_verified_identity boolean not null default false,
  allowed_document_country_codes text[] not null default '{}',
  allowed_home_area_ids text[] not null default '{}',
  allowed_land_ids text[] not null default '{}',
  minimum_age integer check (minimum_age is null or minimum_age >= 0),
  starts_at timestamptz,
  ends_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (ends_at is null or starts_at is null or ends_at > starts_at)
);

create table if not exists public.poll_options (
  id uuid primary key default gen_random_uuid(),
  poll_id uuid not null references public.polls(id) on delete cascade,
  label text not null,
  description text,
  color text,
  display_order integer not null default 0,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (poll_id, id)
);

create table if not exists public.votes (
  id uuid primary key default gen_random_uuid(),
  poll_id uuid not null references public.polls(id) on delete cascade,
  option_id uuid not null,
  user_id uuid not null references public.users(id) on delete cascade,
  submitted_at timestamptz not null default now(),
  is_valid boolean not null default true,
  invalid_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint votes_single_vote_per_user_per_poll unique (poll_id, user_id),
  constraint votes_option_belongs_to_poll
    foreign key (poll_id, option_id)
    references public.poll_options(poll_id, id)
    on delete restrict
);

create index if not exists idx_identity_profiles_user_id
  on public.identity_profiles(user_id);
create index if not exists idx_polls_status
  on public.polls(status);
create index if not exists idx_poll_options_poll_id_order
  on public.poll_options(poll_id, display_order);
create index if not exists idx_votes_poll_id
  on public.votes(poll_id);
create index if not exists idx_votes_user_id
  on public.votes(user_id);
create index if not exists idx_votes_poll_id_option_id
  on public.votes(poll_id, option_id);

comment on constraint votes_single_vote_per_user_per_poll on public.votes is
  '0.0.86 single-choice: one vote per user per poll.';

drop trigger if exists users_set_updated_at on public.users;
create trigger users_set_updated_at
before update on public.users
for each row
execute function public.set_updated_at();

drop trigger if exists identity_profiles_set_updated_at on public.identity_profiles;
create trigger identity_profiles_set_updated_at
before update on public.identity_profiles
for each row
execute function public.set_updated_at();

drop trigger if exists polls_set_updated_at on public.polls;
create trigger polls_set_updated_at
before update on public.polls
for each row
execute function public.set_updated_at();

drop trigger if exists poll_options_set_updated_at on public.poll_options;
create trigger poll_options_set_updated_at
before update on public.poll_options
for each row
execute function public.set_updated_at();

drop trigger if exists votes_set_updated_at on public.votes;
create trigger votes_set_updated_at
before update on public.votes
for each row
execute function public.set_updated_at();

commit;
