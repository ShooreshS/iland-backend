begin;

create index if not exists idx_votes_poll_valid_snapshot_id
  on public.votes(poll_id, id)
  where is_valid = true
    and vote_latitude_l0 is not null
    and vote_longitude_l0 is not null;

commit;
