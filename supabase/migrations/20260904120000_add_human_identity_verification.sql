begin;

alter table public.auth_challenges
  drop constraint if exists auth_challenges_purpose_check;
alter table public.auth_challenges
  add constraint auth_challenges_purpose_check
  check (purpose in ('register', 'login', 'recover', 'human_verification'));

create table if not exists public.human_verification_requests (
  id uuid primary key default gen_random_uuid(),
  access_token_hash text not null unique,
  device_credential_id text not null,
  device_public_key_pem text not null,
  platform text not null check (platform in ('ios', 'android')),
  status text not null default 'uploading'
    check (status in (
      'uploading', 'pending', 'approved', 'rejected', 'consumed',
      'expired', 'cancelled'
    )),
  document_type text not null,
  similarity double precision not null check (similarity >= -1 and similarity <= 1),
  comparison_threshold double precision not null
    check (comparison_threshold >= 0 and comparison_threshold <= 1),
  comparison_model text,
  liveness_passed boolean not null,
  gaze_passed boolean,
  app_attestation jsonb not null default '{}'::jsonb,
  reviewer_verified_identity_id uuid
    references public.verified_identities(id) on delete restrict,
  reviewer_user_id uuid references public.users(id) on delete restrict,
  user_message text,
  internal_note text,
  submitted_at timestamptz,
  decided_at timestamptz,
  consumed_at timestamptz,
  consumed_by_user_id uuid references public.users(id) on delete set null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

drop trigger if exists human_verification_requests_set_updated_at
  on public.human_verification_requests;
create trigger human_verification_requests_set_updated_at
before update on public.human_verification_requests
for each row execute function public.set_updated_at();

create index if not exists human_verification_requests_queue_idx
  on public.human_verification_requests (status, submitted_at, created_at);
create index if not exists human_verification_requests_credential_idx
  on public.human_verification_requests (device_credential_id, created_at desc);
create unique index if not exists human_verification_requests_active_credential_idx
  on public.human_verification_requests (device_credential_id)
  where status in ('uploading', 'pending', 'approved');

create table if not exists public.human_verification_media (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null references public.human_verification_requests(id)
    on delete cascade,
  kind text not null check (kind in ('document_portrait', 'live_face')),
  storage_bucket text not null,
  storage_path text not null unique,
  mime_type text not null check (mime_type = 'image/jpeg'),
  size_bytes bigint not null check (size_bytes > 0 and size_bytes <= 10485760),
  width integer not null check (width > 112 and width <= 8192),
  height integer not null check (height > 112 and height <= 8192),
  sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'),
  upload_status text not null default 'signed'
    check (upload_status in ('signed', 'uploaded', 'deleted')),
  completed_at timestamptz,
  deleted_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (request_id, kind)
);

drop trigger if exists human_verification_media_set_updated_at
  on public.human_verification_media;
create trigger human_verification_media_set_updated_at
before update on public.human_verification_media
for each row execute function public.set_updated_at();

create index if not exists human_verification_media_request_idx
  on public.human_verification_media (request_id, kind);

create table if not exists public.human_verification_review_actions (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null references public.human_verification_requests(id)
    on delete cascade,
  reviewer_verified_identity_id uuid not null
    references public.verified_identities(id) on delete restrict,
  reviewer_user_id uuid not null references public.users(id) on delete restrict,
  action text not null check (action in ('approve', 'reject')),
  previous_status text not null,
  new_status text not null,
  internal_note text,
  user_message text,
  created_at timestamptz not null default now()
);

create index if not exists human_verification_review_actions_request_idx
  on public.human_verification_review_actions (request_id, created_at desc);

create table if not exists public.human_verification_push_installations (
  request_id uuid primary key references public.human_verification_requests(id)
    on delete cascade,
  platform text not null check (platform in ('ios', 'android')),
  provider text not null check (provider in ('apns', 'fcm')),
  provider_environment text not null
    check (provider_environment in ('sandbox', 'production')),
  token_ciphertext text not null,
  token_hash text not null,
  locale text,
  status text not null default 'active'
    check (status in ('active', 'sent', 'invalid', 'failed')),
  last_delivery_error text,
  last_registered_at timestamptz not null default now(),
  last_delivery_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (
    (platform = 'ios' and provider = 'apns')
    or (platform = 'android' and provider = 'fcm')
  ),
  check (provider = 'apns' or provider_environment = 'production')
);

drop trigger if exists human_verification_push_installations_set_updated_at
  on public.human_verification_push_installations;
create trigger human_verification_push_installations_set_updated_at
before update on public.human_verification_push_installations
for each row execute function public.set_updated_at();

alter table public.human_verification_requests enable row level security;
alter table public.human_verification_media enable row level security;
alter table public.human_verification_review_actions enable row level security;
alter table public.human_verification_push_installations enable row level security;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'verification-review-media',
  'verification-review-media',
  false,
  10485760,
  array['image/jpeg']::text[]
)
on conflict (id) do update
set
  public = false,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

notify pgrst, 'reload schema';

commit;
