begin;

update storage.buckets
set file_size_limit = 5242880
where id = 'discussion-media';

alter table public.discussion_media_uploads
  drop constraint if exists discussion_media_uploads_size_bytes_check;

alter table public.discussion_media_uploads
  add constraint discussion_media_uploads_size_bytes_check
  check (size_bytes > 0 and size_bytes <= 5242880);

commit;
