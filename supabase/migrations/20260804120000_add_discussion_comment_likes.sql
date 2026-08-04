begin;

alter table public.discussion_comments
  add column if not exists like_count integer not null default 0
    check (like_count >= 0);

create table if not exists public.discussion_comment_likes (
  comment_id uuid not null references public.discussion_comments(id) on delete cascade,
  user_id uuid not null references public.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (comment_id, user_id)
);

create index if not exists discussion_comment_likes_user_idx
  on public.discussion_comment_likes (user_id, created_at desc);

create or replace function public.refresh_discussion_comment_like_count()
returns trigger
language plpgsql
as $$
declare
  target_comment_id uuid;
begin
  target_comment_id := coalesce(new.comment_id, old.comment_id);

  update public.discussion_comments
  set
    like_count = (
      select count(*)::integer
      from public.discussion_comment_likes
      where comment_id = target_comment_id
    ),
    updated_at = now()
  where id = target_comment_id;

  return coalesce(new, old);
end;
$$;

drop trigger if exists discussion_comment_likes_refresh_count
  on public.discussion_comment_likes;
create trigger discussion_comment_likes_refresh_count
after insert or delete on public.discussion_comment_likes
for each row execute function public.refresh_discussion_comment_like_count();

notify pgrst, 'reload schema';

commit;
