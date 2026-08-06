begin;

create or replace view public.discussion_post_open_report_queue as
select
  post_id,
  count(*)::integer as report_count,
  min(created_at) as first_reported_at,
  max(created_at) as latest_reported_at
from public.discussion_post_reports
where status = 'open'
  and comment_id is null
group by post_id;

create or replace view public.discussion_comment_open_report_queue as
select
  comment_id,
  post_id,
  count(*)::integer as report_count,
  min(created_at) as first_reported_at,
  max(created_at) as latest_reported_at
from public.discussion_post_reports
where status = 'open'
  and comment_id is not null
group by comment_id, post_id;

notify pgrst, 'reload schema';

commit;
