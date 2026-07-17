begin;

create extension if not exists pgcrypto;

create table if not exists public.discussion_posts (
  id uuid primary key default gen_random_uuid(),
  author_user_id uuid not null references public.users(id) on delete cascade,
  author_public_nickname text,
  post_type text not null
    check (post_type in ('discussion', 'question', 'proposal', 'announcement')),
  caption text,
  image_url text,
  image_storage_bucket text,
  image_storage_path text,
  image_mime_type text,
  image_size_bytes bigint check (image_size_bytes is null or image_size_bytes > 0),
  image_alt_text text,
  moderation_status text not null default 'moderation_pending'
    check (moderation_status in (
      'draft',
      'moderation_pending',
      'published',
      'review_required',
      'needs_edit',
      'blocked',
      'moderation_error',
      'appeal_pending',
      'appeal_approved',
      'appeal_rejected'
    )),
  moderation_model text,
  moderation_flagged boolean,
  moderation_categories jsonb,
  moderation_category_scores jsonb,
  moderation_applied_input_types jsonb,
  moderation_raw jsonb,
  moderated_at timestamptz,
  moderation_error text,
  moderation_policy_version text,
  gate2_status text,
  gate2_model text,
  gate2_result jsonb,
  human_review_status text,
  human_review_decision text,
  human_reviewed_at timestamptz,
  like_count integer not null default 0 check (like_count >= 0),
  comment_count integer not null default 0 check (comment_count >= 0),
  feed_score double precision not null default 0,
  deliberation_id uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (
    nullif(btrim(coalesce(caption, '')), '') is not null
    or image_url is not null
    or image_storage_path is not null
  )
);

create table if not exists public.discussion_post_likes (
  post_id uuid not null references public.discussion_posts(id) on delete cascade,
  user_id uuid not null references public.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (post_id, user_id)
);

create table if not exists public.discussion_comments (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.discussion_posts(id) on delete cascade,
  author_user_id uuid not null references public.users(id) on delete cascade,
  author_public_nickname text,
  body text not null,
  moderation_status text not null default 'moderation_pending'
    check (moderation_status in (
      'draft',
      'moderation_pending',
      'published',
      'review_required',
      'needs_edit',
      'blocked',
      'moderation_error',
      'appeal_pending',
      'appeal_approved',
      'appeal_rejected'
    )),
  moderation_model text,
  moderation_flagged boolean,
  moderation_categories jsonb,
  moderation_category_scores jsonb,
  moderation_applied_input_types jsonb,
  moderation_raw jsonb,
  moderated_at timestamptz,
  moderation_error text,
  moderation_policy_version text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create or replace function public.set_discussion_post_feed_score()
returns trigger
language plpgsql
as $$
begin
  new.feed_score =
    extract(epoch from new.created_at)
    + (coalesce(new.like_count, 0) * 3600)
    + (coalesce(new.comment_count, 0) * 7200);
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists discussion_posts_feed_score_trigger on public.discussion_posts;
create trigger discussion_posts_feed_score_trigger
before insert or update of created_at, like_count, comment_count
on public.discussion_posts
for each row execute function public.set_discussion_post_feed_score();

create or replace function public.increment_discussion_post_like_count()
returns trigger
language plpgsql
as $$
begin
  update public.discussion_posts
  set like_count = like_count + 1
  where id = new.post_id;
  return new;
end;
$$;

create or replace function public.decrement_discussion_post_like_count()
returns trigger
language plpgsql
as $$
begin
  update public.discussion_posts
  set like_count = greatest(like_count - 1, 0)
  where id = old.post_id;
  return old;
end;
$$;

drop trigger if exists discussion_post_likes_insert_count on public.discussion_post_likes;
create trigger discussion_post_likes_insert_count
after insert on public.discussion_post_likes
for each row execute function public.increment_discussion_post_like_count();

drop trigger if exists discussion_post_likes_delete_count on public.discussion_post_likes;
create trigger discussion_post_likes_delete_count
after delete on public.discussion_post_likes
for each row execute function public.decrement_discussion_post_like_count();

create or replace function public.refresh_discussion_post_comment_count()
returns trigger
language plpgsql
as $$
declare
  target_post_id uuid;
begin
  target_post_id = coalesce(new.post_id, old.post_id);
  update public.discussion_posts
  set comment_count = (
    select count(*)::integer
    from public.discussion_comments
    where post_id = target_post_id
      and moderation_status = 'published'
  )
  where id = target_post_id;
  return coalesce(new, old);
end;
$$;

drop trigger if exists discussion_comments_insert_count on public.discussion_comments;
create trigger discussion_comments_insert_count
after insert on public.discussion_comments
for each row execute function public.refresh_discussion_post_comment_count();

drop trigger if exists discussion_comments_update_count on public.discussion_comments;
create trigger discussion_comments_update_count
after update of moderation_status on public.discussion_comments
for each row execute function public.refresh_discussion_post_comment_count();

drop trigger if exists discussion_comments_delete_count on public.discussion_comments;
create trigger discussion_comments_delete_count
after delete on public.discussion_comments
for each row execute function public.refresh_discussion_post_comment_count();

create index if not exists discussion_posts_feed_idx
  on public.discussion_posts (moderation_status, feed_score desc, created_at desc, id desc);

create index if not exists discussion_posts_author_created_idx
  on public.discussion_posts (author_user_id, created_at desc);

create unique index if not exists discussion_posts_image_storage_path_idx
  on public.discussion_posts (image_storage_bucket, image_storage_path)
  where image_storage_path is not null;

create index if not exists discussion_posts_moderation_idx
  on public.discussion_posts (moderation_status, moderated_at desc);

create index if not exists discussion_comments_post_created_idx
  on public.discussion_comments (post_id, moderation_status, created_at asc);

create index if not exists discussion_post_likes_user_idx
  on public.discussion_post_likes (user_id, created_at desc);

commit;
