begin;

insert into storage.buckets (
  id,
  name,
  public,
  file_size_limit,
  allowed_mime_types
)
values (
  'discussion-media',
  'discussion-media',
  false,
  20971520,
  array['image/jpeg', 'image/png', 'image/webp', 'image/gif']
)
on conflict (id) do update
set
  public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

create table if not exists public.discussion_media_uploads (
  id uuid primary key default gen_random_uuid(),
  uploader_user_id uuid not null references public.users(id) on delete cascade,
  storage_bucket text not null default 'discussion-media',
  storage_path text not null unique,
  original_file_name text,
  mime_type text not null
    check (mime_type in ('image/jpeg', 'image/png', 'image/webp', 'image/gif')),
  size_bytes bigint not null
    check (size_bytes > 0 and size_bytes <= 20971520),
  upload_status text not null default 'signed'
    check (upload_status in ('signed', 'uploaded', 'attached', 'abandoned')),
  attached_post_id uuid references public.discussion_posts(id) on delete set null,
  signed_at timestamptz not null default now(),
  completed_at timestamptz,
  attached_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

drop trigger if exists discussion_media_uploads_set_updated_at on public.discussion_media_uploads;
create trigger discussion_media_uploads_set_updated_at
before update on public.discussion_media_uploads
for each row execute function public.set_updated_at();

create index if not exists discussion_media_uploads_uploader_status_idx
  on public.discussion_media_uploads (uploader_user_id, upload_status, created_at desc);

create index if not exists discussion_media_uploads_attached_post_idx
  on public.discussion_media_uploads (attached_post_id)
  where attached_post_id is not null;

commit;
