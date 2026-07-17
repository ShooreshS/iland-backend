begin;

create table if not exists public.admin_reviewers (
  id uuid primary key default gen_random_uuid(),
  verified_identity_id uuid not null unique
    references public.verified_identities(id) on delete cascade,
  role text not null default 'reviewer'
    check (role in ('owner', 'reviewer', 'viewer')),
  status text not null default 'active'
    check (status in ('active', 'disabled')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

drop trigger if exists admin_reviewers_set_updated_at on public.admin_reviewers;
create trigger admin_reviewers_set_updated_at
before update on public.admin_reviewers
for each row execute function public.set_updated_at();

create index if not exists admin_reviewers_status_idx
  on public.admin_reviewers (status, role);

alter table public.discussion_comments
  add column if not exists human_review_status text,
  add column if not exists human_review_decision text,
  add column if not exists human_reviewed_at timestamptz;

create table if not exists public.moderation_review_actions (
  id uuid primary key default gen_random_uuid(),
  content_type text not null
    check (content_type in ('poll', 'discussion_post', 'discussion_comment')),
  content_id uuid not null,
  reviewer_verified_identity_id uuid not null
    references public.verified_identities(id) on delete restrict,
  reviewer_user_id uuid not null references public.users(id) on delete restrict,
  action text not null
    check (action in ('approve', 'reject', 'request_edit')),
  previous_status text not null,
  new_status text not null,
  internal_note text,
  user_message text,
  created_at timestamptz not null default now()
);

create index if not exists moderation_review_actions_content_idx
  on public.moderation_review_actions (content_type, content_id, created_at desc);

create index if not exists moderation_review_actions_reviewer_idx
  on public.moderation_review_actions (reviewer_verified_identity_id, created_at desc);

create index if not exists discussion_comments_moderation_review_idx
  on public.discussion_comments (moderation_status, moderated_at desc, created_at desc);

notify pgrst, 'reload schema';

commit;
