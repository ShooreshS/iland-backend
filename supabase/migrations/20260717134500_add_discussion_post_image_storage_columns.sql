begin;

alter table public.discussion_posts
  add column if not exists image_storage_bucket text,
  add column if not exists image_storage_path text;

do $$
declare
  constraint_record record;
begin
  for constraint_record in
    select conname
    from pg_constraint
    where conrelid = 'public.discussion_posts'::regclass
      and contype = 'c'
      and pg_get_constraintdef(oid) ilike '%caption%'
      and pg_get_constraintdef(oid) ilike '%image_url%'
      and pg_get_constraintdef(oid) not ilike '%image_storage_path%'
  loop
    execute format(
      'alter table public.discussion_posts drop constraint %I',
      constraint_record.conname
    );
  end loop;
end;
$$;

alter table public.discussion_posts
  drop constraint if exists discussion_posts_content_check;

alter table public.discussion_posts
  add constraint discussion_posts_content_check
  check (
    nullif(btrim(coalesce(caption, '')), '') is not null
    or image_url is not null
    or image_storage_path is not null
  );

create unique index if not exists discussion_posts_image_storage_path_idx
  on public.discussion_posts (image_storage_bucket, image_storage_path)
  where image_storage_path is not null;

notify pgrst, 'reload schema';

commit;
