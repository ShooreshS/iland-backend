begin;

create index if not exists idx_credential_roots_unpublished
  on public.credential_roots(merkle_depth, leaf_count asc, created_at asc)
  where solana_tx_signature is null;

comment on index public.idx_credential_roots_unpublished is
  'Supports the credential-root Solana publisher job by scanning unpublished roots in append order.';

commit;
