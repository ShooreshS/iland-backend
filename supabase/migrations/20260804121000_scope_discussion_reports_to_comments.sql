begin;

alter table public.discussion_post_reports
  add column if not exists comment_id uuid
    references public.discussion_comments(id) on delete cascade;

alter table public.discussion_post_reports
  drop constraint if exists discussion_post_reports_post_id_reporter_user_id_key;

create unique index if not exists discussion_post_reports_post_reporter_unique_idx
  on public.discussion_post_reports (post_id, reporter_user_id)
  where comment_id is null;

create unique index if not exists discussion_post_reports_comment_reporter_unique_idx
  on public.discussion_post_reports (comment_id, reporter_user_id)
  where comment_id is not null;

create index if not exists discussion_post_reports_comment_idx
  on public.discussion_post_reports (comment_id, created_at desc)
  where comment_id is not null;

notify pgrst, 'reload schema';

commit;
