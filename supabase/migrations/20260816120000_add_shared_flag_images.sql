begin;

insert into storage.buckets (
  id,
  name,
  public,
  file_size_limit,
  allowed_mime_types
)
values (
  'flag-images',
  'flag-images',
  false,
  5242880,
  array['image/jpeg', 'image/png', 'image/webp']
)
on conflict (id) do update
set
  public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

create table if not exists public.flag_images (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(trim(name)) between 1 and 80),
  creator_user_id uuid references public.users(id) on delete set null,
  storage_bucket text not null default 'flag-images',
  storage_path text not null unique,
  original_file_name text,
  mime_type text not null check (mime_type in ('image/jpeg', 'image/png', 'image/webp')),
  size_bytes bigint not null check (size_bytes > 0 and size_bytes <= 5242880),
  width integer not null check (width between 20 and 512),
  height integer not null check (height between 20 and 512),
  upload_status text not null default 'signed'
    check (upload_status in ('signed', 'active', 'abandoned')),
  completed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint flag_images_aspect_ratio_check check (
    width::numeric / height::numeric between 0.1 and 10
  )
);

drop trigger if exists flag_images_set_updated_at on public.flag_images;
create trigger flag_images_set_updated_at
before update on public.flag_images
for each row execute function public.set_updated_at();

create index if not exists flag_images_status_created_idx
  on public.flag_images (upload_status, created_at desc);

create index if not exists flag_images_creator_idx
  on public.flag_images (creator_user_id, created_at desc)
  where creator_user_id is not null;

alter table public.users
  add column if not exists selected_flag_image_id uuid;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'users_selected_flag_image_id_fkey'
      and conrelid = 'public.users'::regclass
  ) then
    alter table public.users
      add constraint users_selected_flag_image_id_fkey
      foreign key (selected_flag_image_id)
      references public.flag_images(id)
      on delete restrict;
  end if;
end
$$;

create index if not exists users_selected_flag_image_idx
  on public.users (selected_flag_image_id)
  where selected_flag_image_id is not null;

create or replace function public.clear_disabled_user_flag_selection()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  if new.account_status = 'disabled' then
    new.selected_flag_image_id := null;
  end if;
  return new;
end;
$$;

drop trigger if exists users_clear_disabled_flag_selection on public.users;
create trigger users_clear_disabled_flag_selection
before update of account_status on public.users
for each row execute function public.clear_disabled_user_flag_selection();

-- These tables are accessed through authenticated backend routes with the
-- service role. There are deliberately no direct client policies.
alter table public.flag_images enable row level security;

comment on table public.flag_images is
  'Shared user-created flag images. A selected image is protected from deletion by the users foreign key.';

notify pgrst, 'reload schema';

commit;
