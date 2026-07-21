begin;

create table if not exists public.discussion_user_blocks (
  blocker_user_id uuid not null references public.users(id) on delete cascade,
  blocked_user_id uuid not null references public.users(id) on delete cascade,
  source_post_id uuid references public.discussion_posts(id) on delete set null,
  created_at timestamptz not null default now(),
  primary key (blocker_user_id, blocked_user_id),
  check (blocker_user_id <> blocked_user_id)
);

create index if not exists discussion_user_blocks_blocker_created_idx
  on public.discussion_user_blocks (blocker_user_id, created_at desc);

create index if not exists discussion_user_blocks_blocked_created_idx
  on public.discussion_user_blocks (blocked_user_id, created_at desc);

create index if not exists discussion_user_blocks_source_post_idx
  on public.discussion_user_blocks (source_post_id)
  where source_post_id is not null;

notify pgrst, 'reload schema';

commit;
