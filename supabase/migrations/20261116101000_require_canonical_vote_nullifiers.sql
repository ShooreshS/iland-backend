begin;

-- Never silently merge/delete accepted votes. Existing noncanonical rows
-- require investigation; validation deliberately fails if such rows exist.
alter table public.poll_zk_votes
  add constraint poll_zk_votes_nullifier_canonical_bn254
  check (nullifier collate "C" < '30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001')
  not valid;
alter table public.poll_zk_votes
  validate constraint poll_zk_votes_nullifier_canonical_bn254;

commit;
