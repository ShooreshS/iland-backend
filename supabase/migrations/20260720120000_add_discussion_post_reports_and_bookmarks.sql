begin;

create extension if not exists pgcrypto;

create table if not exists public.discussion_post_bookmarks (
  post_id uuid not null references public.discussion_posts(id) on delete cascade,
  user_id uuid not null references public.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (post_id, user_id)
);

create index if not exists discussion_post_bookmarks_user_idx
  on public.discussion_post_bookmarks (user_id, created_at desc);

create table if not exists public.discussion_post_reports (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.discussion_posts(id) on delete cascade,
  reporter_user_id uuid not null references public.users(id) on delete cascade,
  category text not null
    check (category in (
      'spam',
      'harassment',
      'hate_or_abuse',
      'misinformation',
      'illegal_or_unsafe',
      'other'
    )),
  comment text,
  status text not null default 'open'
    check (status in ('open', 'reviewed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (post_id, reporter_user_id)
);

drop trigger if exists discussion_post_reports_set_updated_at on public.discussion_post_reports;
create trigger discussion_post_reports_set_updated_at
before update on public.discussion_post_reports
for each row execute function public.set_updated_at();

create index if not exists discussion_post_reports_queue_idx
  on public.discussion_post_reports (status, created_at asc, post_id);

create index if not exists discussion_post_reports_reporter_idx
  on public.discussion_post_reports (reporter_user_id, created_at desc);

create or replace view public.discussion_post_open_report_queue as
select
  post_id,
  count(*)::integer as report_count,
  min(created_at) as first_reported_at,
  max(created_at) as latest_reported_at
from public.discussion_post_reports
where status = 'open'
group by post_id;

notify pgrst, 'reload schema';

commit;
