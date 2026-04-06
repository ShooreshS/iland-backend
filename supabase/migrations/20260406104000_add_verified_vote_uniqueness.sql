begin;

alter table public.votes
  add column if not exists verified_identity_id uuid null;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'votes_verified_identity_id_fkey'
  ) then
    alter table public.votes
      add constraint votes_verified_identity_id_fkey
      foreign key (verified_identity_id)
      references public.verified_identities(id)
      on delete restrict;
  end if;
end;
$$;

create index if not exists idx_votes_verified_identity_id
  on public.votes(verified_identity_id);

create unique index if not exists ux_votes_poll_verified_identity
  on public.votes(poll_id, verified_identity_id)
  where verified_identity_id is not null;

comment on index public.ux_votes_poll_verified_identity is
  '0.0.86 verified polls: one vote per verified identity per poll.';

commit;
