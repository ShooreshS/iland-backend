begin;

alter table public.discussion_comments
  add column if not exists thread_root_comment_id uuid,
  add column if not exists reply_to_comment_id uuid,
  add column if not exists direct_reply_count integer not null default 0,
  add column if not exists thread_reply_count integer not null default 0,
  add column if not exists feed_score double precision not null default 0;

alter table public.discussion_comments
  drop constraint if exists discussion_comments_thread_root_comment_id_fkey,
  add constraint discussion_comments_thread_root_comment_id_fkey
    foreign key (thread_root_comment_id)
    references public.discussion_comments(id)
    on delete cascade,
  drop constraint if exists discussion_comments_reply_to_comment_id_fkey,
  add constraint discussion_comments_reply_to_comment_id_fkey
    foreign key (reply_to_comment_id)
    references public.discussion_comments(id)
    on delete set null,
  drop constraint if exists discussion_comments_direct_reply_count_check,
  add constraint discussion_comments_direct_reply_count_check
    check (direct_reply_count >= 0),
  drop constraint if exists discussion_comments_thread_reply_count_check,
  add constraint discussion_comments_thread_reply_count_check
    check (thread_reply_count >= 0),
  drop constraint if exists discussion_comments_not_own_thread_root_check,
  add constraint discussion_comments_not_own_thread_root_check
    check (thread_root_comment_id is null or thread_root_comment_id <> id),
  drop constraint if exists discussion_comments_not_own_reply_target_check,
  add constraint discussion_comments_not_own_reply_target_check
    check (reply_to_comment_id is null or reply_to_comment_id <> id);

create or replace function public.validate_discussion_comment_thread_links()
returns trigger
language plpgsql
as $$
declare
  root_post_id uuid;
  root_thread_id uuid;
  target_post_id uuid;
  target_thread_id uuid;
begin
  if new.thread_root_comment_id is null then
    if new.reply_to_comment_id is not null then
      raise exception 'Root comments cannot have a reply target.'
        using errcode = '23514';
    end if;
    return new;
  end if;

  select post_id, thread_root_comment_id
  into root_post_id, root_thread_id
  from public.discussion_comments
  where id = new.thread_root_comment_id;

  if root_post_id is null
    or root_post_id <> new.post_id
    or root_thread_id is not null then
    raise exception 'Comment thread root must be a root comment on the same post.'
      using errcode = '23514';
  end if;

  if new.reply_to_comment_id is null then
    if tg_op = 'INSERT' then
      raise exception 'New replies must identify their direct reply target.'
        using errcode = '23514';
    end if;
    return new;
  end if;

  select post_id, thread_root_comment_id
  into target_post_id, target_thread_id
  from public.discussion_comments
  where id = new.reply_to_comment_id;

  if target_post_id is null
    or target_post_id <> new.post_id
    or coalesce(target_thread_id, new.reply_to_comment_id)
      <> new.thread_root_comment_id then
    raise exception 'Reply target must belong to the selected comment thread.'
      using errcode = '23514';
  end if;

  return new;
end;
$$;

drop trigger if exists discussion_comments_validate_thread_links
  on public.discussion_comments;
create trigger discussion_comments_validate_thread_links
before insert or update of post_id, thread_root_comment_id, reply_to_comment_id
on public.discussion_comments
for each row execute function public.validate_discussion_comment_thread_links();

create or replace function public.set_discussion_comment_feed_score()
returns trigger
language plpgsql
as $$
begin
  new.feed_score =
    extract(epoch from new.created_at)
    + (coalesce(new.like_count, 0) * 3600)
    + (
      case
        when new.thread_root_comment_id is null
          then coalesce(new.thread_reply_count, 0)
        else coalesce(new.direct_reply_count, 0)
      end * 7200
    );
  return new;
end;
$$;

drop trigger if exists discussion_comments_feed_score_trigger
  on public.discussion_comments;
create trigger discussion_comments_feed_score_trigger
before insert or update of created_at, like_count, direct_reply_count, thread_reply_count
on public.discussion_comments
for each row execute function public.set_discussion_comment_feed_score();

create or replace function public.refresh_discussion_comment_reply_metrics(
  target_comment_id uuid
)
returns void
language plpgsql
as $$
begin
  if target_comment_id is null then
    return;
  end if;

  update public.discussion_comments as target
  set
    direct_reply_count = (
      select count(*)::integer
      from public.discussion_comments as reply
      where reply.reply_to_comment_id = target.id
        and reply.moderation_status = 'published'
    ),
    thread_reply_count = case
      when target.thread_root_comment_id is null then (
        select count(*)::integer
        from public.discussion_comments as reply
        where reply.thread_root_comment_id = target.id
          and reply.moderation_status = 'published'
      )
      else 0
    end
  where target.id = target_comment_id;
end;
$$;

create or replace function public.refresh_discussion_comment_reply_metrics_trigger()
returns trigger
language plpgsql
as $$
begin
  if tg_op <> 'INSERT' then
    perform public.refresh_discussion_comment_reply_metrics(old.reply_to_comment_id);
    perform public.refresh_discussion_comment_reply_metrics(old.thread_root_comment_id);
  end if;

  if tg_op <> 'DELETE' then
    if tg_op = 'INSERT'
      or new.reply_to_comment_id is distinct from old.reply_to_comment_id
      or new.moderation_status is distinct from old.moderation_status then
      perform public.refresh_discussion_comment_reply_metrics(new.reply_to_comment_id);
    end if;

    if tg_op = 'INSERT'
      or new.thread_root_comment_id is distinct from old.thread_root_comment_id
      or new.moderation_status is distinct from old.moderation_status then
      perform public.refresh_discussion_comment_reply_metrics(new.thread_root_comment_id);
    end if;
  end if;

  return coalesce(new, old);
end;
$$;

drop trigger if exists discussion_comments_refresh_reply_metrics
  on public.discussion_comments;
create trigger discussion_comments_refresh_reply_metrics
after insert or delete or update of moderation_status, thread_root_comment_id, reply_to_comment_id
on public.discussion_comments
for each row execute function public.refresh_discussion_comment_reply_metrics_trigger();

create index if not exists discussion_comments_thread_roots_feed_idx
  on public.discussion_comments (
    post_id,
    moderation_status,
    feed_score desc,
    created_at desc,
    id desc
  )
  where thread_root_comment_id is null;

create index if not exists discussion_comments_thread_replies_idx
  on public.discussion_comments (
    thread_root_comment_id,
    moderation_status,
    created_at asc,
    id asc
  )
  where thread_root_comment_id is not null;

create index if not exists discussion_comments_reply_target_idx
  on public.discussion_comments (reply_to_comment_id)
  where reply_to_comment_id is not null;

update public.discussion_comments as target
set
  direct_reply_count = (
    select count(*)::integer
    from public.discussion_comments as reply
    where reply.reply_to_comment_id = target.id
      and reply.moderation_status = 'published'
  ),
  thread_reply_count = case
    when target.thread_root_comment_id is null then (
      select count(*)::integer
      from public.discussion_comments as reply
      where reply.thread_root_comment_id = target.id
        and reply.moderation_status = 'published'
    )
    else 0
  end;

create or replace function public.list_discussion_comment_reply_preview(
  p_thread_root_comment_ids uuid[],
  p_per_root_limit integer default 2
)
returns setof public.discussion_comments
language sql
stable
security invoker
set search_path = public
as $$
  select comment_row.*
  from (
    select
      reply.id,
      row_number() over (
        partition by reply.thread_root_comment_id
        order by reply.created_at asc, reply.id asc
      ) as reply_position
    from public.discussion_comments as reply
    where reply.thread_root_comment_id = any(p_thread_root_comment_ids)
      and reply.moderation_status = 'published'
  ) as ranked
  join public.discussion_comments as comment_row
    on comment_row.id = ranked.id
  where ranked.reply_position <= greatest(1, least(p_per_root_limit, 10))
  order by
    comment_row.thread_root_comment_id,
    comment_row.created_at asc,
    comment_row.id asc;
$$;

create or replace function public.list_discussion_comment_orphans(
  p_post_id uuid,
  p_limit integer default 20
)
returns setof public.discussion_comments
language sql
stable
security invoker
set search_path = public
as $$
  select reply.*
  from public.discussion_comments as reply
  join public.discussion_comments as root
    on root.id = reply.thread_root_comment_id
  where reply.post_id = p_post_id
    and reply.moderation_status = 'published'
    and root.moderation_status <> 'published'
  order by reply.feed_score desc, reply.created_at desc, reply.id desc
  limit greatest(1, least(p_limit, 50));
$$;

notify pgrst, 'reload schema';

commit;
