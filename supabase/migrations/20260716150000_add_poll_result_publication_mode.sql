-- CivicOS ZKP poll result publication mode.
--
-- auto_on_close: enqueue final tally/publication when a scheduled poll closes.
-- creator_managed: require the poll creator to press Publish audit.

alter table public.polls
  add column if not exists result_publication_mode text not null default 'auto_on_close';

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'polls_result_publication_mode_known'
  ) then
    alter table public.polls
      add constraint polls_result_publication_mode_known
      check (
        result_publication_mode in (
          'auto_on_close',
          'creator_managed'
        )
      );
  end if;
end;
$$;

create index if not exists idx_polls_auto_result_publication
  on public.polls(status, ends_at, result_publication_mode)
  where result_publication_mode = 'auto_on_close';

create or replace function public.enqueue_auto_result_publication_tally_job()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if
    new.status = 'closed'
    and old.status is distinct from new.status
    and new.result_publication_mode = 'auto_on_close'
    and new.vote_privacy_mode = 'zk_secret_ballot_v1'
    and exists (
      select 1
      from public.poll_zk_votes v
      where v.poll_id = new.id
        and v.proof_verification_status = 'verified'
      limit 1
    )
  then
    perform public.enqueue_zkp_tally_job(new.id, 100, 3);
  end if;

  return new;
end;
$$;

drop trigger if exists polls_enqueue_auto_result_publication_tally_job on public.polls;
create trigger polls_enqueue_auto_result_publication_tally_job
after update of status on public.polls
for each row
execute function public.enqueue_auto_result_publication_tally_job();

do $$
declare
  v_poll_id uuid;
begin
  for v_poll_id in
    select p.id
    from public.polls p
    where p.status in ('closed', 'archived')
      and p.result_publication_mode = 'auto_on_close'
      and p.vote_privacy_mode = 'zk_secret_ballot_v1'
      and exists (
        select 1
        from public.poll_zk_votes v
        where v.poll_id = p.id
          and v.proof_verification_status = 'verified'
        limit 1
      )
  loop
    perform public.enqueue_zkp_tally_job(v_poll_id, 100, 3);
  end loop;
end;
$$;

comment on column public.polls.result_publication_mode is
  'Controls final result publication. auto_on_close queues backend tally/publication when a scheduled ZKP poll closes; creator_managed requires the creator to press Publish audit.';
