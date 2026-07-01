begin;

create table if not exists public.oidc_authorize_qr_transactions (
  id uuid primary key default gen_random_uuid(),
  request_id text not null unique,
  authorization_request_id uuid not null unique
    references public.oidc_authorization_requests(id) on delete cascade,
  client_id uuid not null references public.oidc_clients(id) on delete cascade,
  secret_hash text not null,
  poll_secret_hash text not null,
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'denied', 'expired')),
  user_id uuid references public.users(id) on delete cascade,
  auth_session_id uuid references public.auth_sessions(id) on delete set null,
  pairwise_subject_id uuid references public.oidc_pairwise_subjects(id) on delete set null,
  grant_id uuid references public.oidc_grants(id) on delete set null,
  approved_auth_generation integer check (
    approved_auth_generation is null or approved_auth_generation > 0
  ),
  approved_claims jsonb not null default '{}'::jsonb,
  approved_at timestamptz,
  denied_at timestamptz,
  code_delivered_at timestamptz,
  expires_at timestamptz not null,
  result_expires_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_oidc_authorize_qr_transactions_status_expires
  on public.oidc_authorize_qr_transactions(status, expires_at);

create index if not exists idx_oidc_authorize_qr_transactions_user_created
  on public.oidc_authorize_qr_transactions(user_id, created_at desc);

create index if not exists idx_oidc_authorize_qr_transactions_client_created
  on public.oidc_authorize_qr_transactions(client_id, created_at desc);

comment on table public.oidc_authorize_qr_transactions is
  'Short-lived QR coordination state for hosted OIDC authorize pages. Raw QR secrets, poll secrets, and authorization codes are never stored; only hashes and lifecycle metadata are persisted so the flow works across restarts and multiple replicas.';

comment on column public.oidc_authorize_qr_transactions.secret_hash is
  'SHA-256 hash of the QR approval secret. The raw secret is shown only in the QR/deep-link payload.';

comment on column public.oidc_authorize_qr_transactions.poll_secret_hash is
  'SHA-256 hash of the browser polling secret. The raw poll secret stays only in the hosted authorize page status URL.';

comment on column public.oidc_authorize_qr_transactions.code_delivered_at is
  'Set when the browser status poll has received a raw authorization code. The raw code is not persisted and cannot be delivered a second time.';

drop trigger if exists oidc_authorize_qr_transactions_set_updated_at
  on public.oidc_authorize_qr_transactions;
create trigger oidc_authorize_qr_transactions_set_updated_at
before update on public.oidc_authorize_qr_transactions
for each row
execute function public.set_updated_at();

create or replace function public.approve_oidc_authorize_qr_transaction(
  p_request_id text,
  p_secret_hash text,
  p_user_id uuid,
  p_auth_session_id uuid,
  p_pairwise_subject_id uuid,
  p_grant_id uuid,
  p_approved_auth_generation integer,
  p_approved_claims jsonb,
  p_result_expires_at timestamptz,
  p_now timestamptz default now()
)
returns public.oidc_authorize_qr_transactions
language plpgsql
security definer
set search_path = public
as $$
declare
  v_transaction public.oidc_authorize_qr_transactions;
begin
  update public.oidc_authorize_qr_transactions
  set
    status = 'approved',
    user_id = p_user_id,
    auth_session_id = p_auth_session_id,
    pairwise_subject_id = p_pairwise_subject_id,
    grant_id = p_grant_id,
    approved_auth_generation = p_approved_auth_generation,
    approved_claims = coalesce(p_approved_claims, '{}'::jsonb),
    approved_at = p_now,
    result_expires_at = p_result_expires_at
  where request_id = p_request_id
    and secret_hash = p_secret_hash
    and status = 'pending'
    and expires_at > p_now
  returning * into v_transaction;

  if not found then
    return null;
  end if;

  update public.oidc_authorization_requests
  set
    status = 'approved',
    user_id = p_user_id,
    auth_session_id = p_auth_session_id,
    approved_at = p_now,
    expires_at = p_result_expires_at
  where id = v_transaction.authorization_request_id
    and status = 'pending';

  if not found then
    raise exception 'OIDC QR authorization request could not be approved atomically';
  end if;

  return v_transaction;
end;
$$;

create or replace function public.deny_oidc_authorize_qr_transaction(
  p_request_id text,
  p_secret_hash text,
  p_result_expires_at timestamptz,
  p_now timestamptz default now()
)
returns public.oidc_authorize_qr_transactions
language plpgsql
security definer
set search_path = public
as $$
declare
  v_transaction public.oidc_authorize_qr_transactions;
begin
  update public.oidc_authorize_qr_transactions
  set
    status = 'denied',
    denied_at = p_now,
    result_expires_at = p_result_expires_at
  where request_id = p_request_id
    and secret_hash = p_secret_hash
    and status = 'pending'
    and expires_at > p_now
  returning * into v_transaction;

  if not found then
    return null;
  end if;

  update public.oidc_authorization_requests
  set
    status = 'denied',
    denied_at = p_now,
    expires_at = p_result_expires_at
  where id = v_transaction.authorization_request_id
    and status = 'pending';

  if not found then
    raise exception 'OIDC QR authorization request could not be denied atomically';
  end if;

  return v_transaction;
end;
$$;

create or replace function public.deliver_oidc_authorize_qr_code(
  p_request_id text,
  p_poll_secret_hash text,
  p_code_hash text,
  p_code_expires_at timestamptz,
  p_now timestamptz default now()
)
returns table (
  authorization_request_id uuid,
  client_id uuid,
  user_id uuid,
  auth_session_id uuid,
  pairwise_subject_id uuid,
  redirect_uri text,
  scopes text[],
  state text,
  nonce text,
  code_challenge text,
  code_challenge_method text,
  auth_generation integer
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_transaction public.oidc_authorize_qr_transactions;
  v_request public.oidc_authorization_requests;
begin
  update public.oidc_authorize_qr_transactions
  set code_delivered_at = p_now
  where request_id = p_request_id
    and poll_secret_hash = p_poll_secret_hash
    and status = 'approved'
    and code_delivered_at is null
    and result_expires_at > p_now
  returning * into v_transaction;

  if not found then
    return;
  end if;

  if v_transaction.user_id is null
    or v_transaction.pairwise_subject_id is null
    or v_transaction.approved_auth_generation is null then
    raise exception 'OIDC QR transaction is missing approval identity fields';
  end if;

  select *
  into v_request
  from public.oidc_authorization_requests
  where id = v_transaction.authorization_request_id
    and status = 'approved';

  if not found then
    raise exception 'OIDC QR approved authorization request was not found';
  end if;

  insert into public.oidc_authorization_codes (
    code_hash,
    authorization_request_id,
    client_id,
    user_id,
    auth_session_id,
    pairwise_subject_id,
    status,
    redirect_uri,
    scopes,
    nonce,
    code_challenge,
    code_challenge_method,
    auth_generation,
    expires_at
  ) values (
    p_code_hash,
    v_request.id,
    v_transaction.client_id,
    v_transaction.user_id,
    v_transaction.auth_session_id,
    v_transaction.pairwise_subject_id,
    'active',
    v_request.redirect_uri,
    v_request.scopes,
    v_request.nonce,
    v_request.code_challenge,
    v_request.code_challenge_method,
    v_transaction.approved_auth_generation,
    p_code_expires_at
  );

  return query
  select
    v_request.id,
    v_transaction.client_id,
    v_transaction.user_id,
    v_transaction.auth_session_id,
    v_transaction.pairwise_subject_id,
    v_request.redirect_uri,
    v_request.scopes,
    v_request.state,
    v_request.nonce,
    v_request.code_challenge,
    v_request.code_challenge_method,
    v_transaction.approved_auth_generation;
end;
$$;

revoke all on function public.approve_oidc_authorize_qr_transaction(
  text,
  text,
  uuid,
  uuid,
  uuid,
  uuid,
  integer,
  jsonb,
  timestamptz,
  timestamptz
) from public;
grant execute on function public.approve_oidc_authorize_qr_transaction(
  text,
  text,
  uuid,
  uuid,
  uuid,
  uuid,
  integer,
  jsonb,
  timestamptz,
  timestamptz
) to service_role;

revoke all on function public.deny_oidc_authorize_qr_transaction(
  text,
  text,
  timestamptz,
  timestamptz
) from public;
grant execute on function public.deny_oidc_authorize_qr_transaction(
  text,
  text,
  timestamptz,
  timestamptz
) to service_role;

revoke all on function public.deliver_oidc_authorize_qr_code(
  text,
  text,
  text,
  timestamptz,
  timestamptz
) from public;
grant execute on function public.deliver_oidc_authorize_qr_code(
  text,
  text,
  text,
  timestamptz,
  timestamptz
) to service_role;

alter table public.oidc_authorize_qr_transactions enable row level security;

commit;
