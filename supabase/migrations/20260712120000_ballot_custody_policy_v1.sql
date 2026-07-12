alter table public.poll_encryption_keys
  alter column custody_model set default 'operator-trusted-backend-db-v1';

update public.poll_encryption_keys
set custody_model = 'operator-trusted-backend-db-v1'
where custody_model = 'backend-db-service-role-v1';

comment on column public.poll_encryption_keys.private_key_jwk is
  'Private X25519 JWK kept behind Supabase service-role access for operator-trusted private beta tally/decryption. This is not public-production threshold custody.';

comment on column public.poll_encryption_keys.custody_model is
  'Ballot decryption custody model. v1 private beta uses operator-trusted-backend-db-v1. Public operator-secret ballot claims require future threshold-trustee-v1 custody.';
