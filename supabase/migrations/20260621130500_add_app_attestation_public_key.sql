alter table public.app_attestation_credentials
  add column if not exists public_key_pem text;

comment on column public.app_attestation_credentials.public_key_pem is
  'PEM-encoded public key captured from the verified mobile attestation so later request assertions can be verified server-side.';
