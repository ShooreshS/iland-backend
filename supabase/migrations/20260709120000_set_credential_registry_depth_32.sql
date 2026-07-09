begin;

truncate table public.credential_roots, public.credential_registry;

alter table public.credential_registry
  alter column merkle_depth set default 32;

alter table public.credential_roots
  alter column merkle_depth set default 32;

comment on column public.credential_registry.merkle_depth is
  'Sparse Poseidon Merkle tree depth for CivicOS credential commitments. v1 production depth is 32.';

comment on column public.credential_roots.merkle_depth is
  'Sparse Poseidon Merkle tree depth for this accepted credential root. v1 production depth is 32.';

commit;
