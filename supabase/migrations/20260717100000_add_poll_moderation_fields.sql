begin;

alter table public.polls
  add column if not exists moderation_status text not null default 'published',
  add column if not exists moderation_model text,
  add column if not exists moderation_flagged boolean,
  add column if not exists moderation_categories jsonb,
  add column if not exists moderation_category_scores jsonb,
  add column if not exists moderation_applied_input_types jsonb,
  add column if not exists moderation_raw jsonb,
  add column if not exists moderated_at timestamptz,
  add column if not exists moderation_error text,
  add column if not exists moderation_policy_version text,
  add column if not exists gate2_status text,
  add column if not exists gate2_model text,
  add column if not exists gate2_result jsonb,
  add column if not exists human_review_status text,
  add column if not exists human_review_decision text,
  add column if not exists human_reviewed_at timestamptz;

alter table public.polls
  drop constraint if exists polls_moderation_status_check;

alter table public.polls
  add constraint polls_moderation_status_check
  check (
    moderation_status in (
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
    )
  );

update public.polls
set moderation_status = case
  when status = 'draft' then 'draft'
  else 'published'
end
where moderation_status is null
   or moderation_status = 'published';

create index if not exists polls_moderation_status_idx
  on public.polls (moderation_status);

create index if not exists polls_moderated_at_idx
  on public.polls (moderated_at);

create index if not exists polls_human_review_status_idx
  on public.polls (human_review_status);

commit;
