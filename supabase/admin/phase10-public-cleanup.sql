-- CivicOS ZKP Phase 10 public-release cleanup runbook.
--
-- This is intentionally NOT a migration. Run it manually only after:
--   1. exporting a database backup/snapshot;
--   2. stopping public writes or putting the backend in maintenance mode;
--   3. confirming that all current users, identities, credentials, sessions,
--      polls, votes, roots, proofs, audit rows, and OIDC grants/tokens are
--      disposable pre-release/test data.
--
-- It preserves schema, migrations, lands/reference data, OIDC client
-- registrations, OIDC client secrets/redirect URIs, signing-key metadata, and
-- rate-limit buckets. It deletes operational user/poll/vote/ZKP/auth/session
-- state so public v0.1 starts from a clean database.
--
-- Safety latch:
--   set app.phase10_cleanup_confirm = 'delete-public-test-data';

begin;

-- This is a one-time admin cleanup over pre-release data. Some statements may
-- touch many rows, especially users/identity profiles. Keep the timeout bounded
-- but longer than the API/default dashboard timeout.
set local statement_timeout = '15min';

do $$
begin
  if current_setting('app.phase10_cleanup_confirm', true) <>
     'delete-public-test-data' then
    raise exception
      'Set app.phase10_cleanup_confirm=delete-public-test-data before running Phase 10 cleanup.';
  end if;
end $$;

-- Preserve lands/reference rows but break optional links to users that will be
-- deleted below.
--
-- The FK from lands.founder_user_id to users(id) is ON DELETE SET NULL. Without
-- this index, deleting many users can repeatedly scan lands and hit
-- statement_timeout even after founder_user_id has been nulled.
create index if not exists idx_lands_founder_user_id
  on public.lands(founder_user_id);

update public.lands
set founder_user_id = null
where founder_user_id is not null;

-- Poll, vote, map, audit, and encryption-key state.
--
-- Normal app writes must not mutate options for non-draft polls. This admin
-- wipe is deleting all polls/options, so temporarily disable only that
-- immutability trigger inside this transaction. If any later statement fails,
-- the whole transaction rolls back and the trigger remains enabled.
alter table public.poll_options
  disable trigger poll_options_prevent_published_mutation;

delete from public.poll_map_refresh_queue;
delete from public.poll_map_marker_cache;
delete from public.poll_audit_events;
delete from public.poll_roots;
delete from public.poll_tally_proofs;
delete from public.poll_zk_votes;
delete from public.votes;
delete from public.poll_options;
delete from public.poll_encryption_keys;
delete from public.polls;

alter table public.poll_options
  enable trigger poll_options_prevent_published_mutation;

-- Credential registry/root state. The first real public user after cleanup will
-- issue a fresh registry leaf and accepted root chain.
delete from public.credential_roots;
delete from public.credential_registry;

-- First-party auth/session/recovery state.
delete from public.refresh_token_families;
delete from public.app_attestation_credentials;
delete from public.auth_sessions;

-- auth_credentials has a self-reference for supersession history. Break links
-- before deleting every credential.
update public.auth_credentials
set superseded_by_auth_credential_id = null
where superseded_by_auth_credential_id is not null;

delete from public.auth_credentials;
delete from public.auth_challenges;
delete from public.auth_audit_events;

-- OIDC user-specific/transactional state. Keep client registrations, client
-- secrets, redirect URIs, signing-key metadata, and rate-limit buckets.
delete from public.oidc_access_tokens;
delete from public.oidc_authorize_qr_transactions;
delete from public.oidc_authorization_codes;
delete from public.oidc_authorization_requests;
delete from public.oidc_refresh_token_families;
delete from public.oidc_grants;
delete from public.oidc_pairwise_subjects;
delete from public.oidc_audit_events;

-- Wallet/identity/user state.
delete from public.wallet_credentials;
delete from public.verified_identities;
delete from public.identity_profiles;
delete from public.users;

-- Backend audit hash-chain state from private/dev testing.
delete from public.backend_audit_events;

-- Post-cleanup invariants. These fail the transaction if operational data
-- survived the cleanup.
do $$
declare
  v_count integer;
begin
  select count(*) into v_count from public.users;
  if v_count <> 0 then
    raise exception 'Expected 0 users after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.identity_profiles;
  if v_count <> 0 then
    raise exception 'Expected 0 identity profiles after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.verified_identities;
  if v_count <> 0 then
    raise exception 'Expected 0 verified identities after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.wallet_credentials;
  if v_count <> 0 then
    raise exception 'Expected 0 wallet credentials after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.auth_credentials;
  if v_count <> 0 then
    raise exception 'Expected 0 auth credentials after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.app_attestation_credentials;
  if v_count <> 0 then
    raise exception 'Expected 0 app attestation credentials after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.auth_sessions;
  if v_count <> 0 then
    raise exception 'Expected 0 auth sessions after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.refresh_token_families;
  if v_count <> 0 then
    raise exception 'Expected 0 refresh token families after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.polls;
  if v_count <> 0 then
    raise exception 'Expected 0 polls after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.poll_options;
  if v_count <> 0 then
    raise exception 'Expected 0 poll options after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.votes;
  if v_count <> 0 then
    raise exception 'Expected 0 legacy votes after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.poll_zk_votes;
  if v_count <> 0 then
    raise exception 'Expected 0 ZKP votes after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.poll_roots;
  if v_count <> 0 then
    raise exception 'Expected 0 poll roots after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.poll_tally_proofs;
  if v_count <> 0 then
    raise exception 'Expected 0 poll tally proofs after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.poll_audit_events;
  if v_count <> 0 then
    raise exception 'Expected 0 poll audit events after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.poll_encryption_keys;
  if v_count <> 0 then
    raise exception 'Expected 0 poll encryption keys after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.credential_registry;
  if v_count <> 0 then
    raise exception 'Expected 0 credential registry rows after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.credential_roots;
  if v_count <> 0 then
    raise exception 'Expected 0 credential roots after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.oidc_access_tokens;
  if v_count <> 0 then
    raise exception 'Expected 0 OIDC access tokens after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.oidc_authorize_qr_transactions;
  if v_count <> 0 then
    raise exception 'Expected 0 OIDC QR transactions after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.oidc_authorization_codes;
  if v_count <> 0 then
    raise exception 'Expected 0 OIDC authorization codes after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.oidc_authorization_requests;
  if v_count <> 0 then
    raise exception 'Expected 0 OIDC authorization requests after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.oidc_refresh_token_families;
  if v_count <> 0 then
    raise exception 'Expected 0 OIDC refresh token families after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.oidc_grants;
  if v_count <> 0 then
    raise exception 'Expected 0 OIDC grants after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.oidc_pairwise_subjects;
  if v_count <> 0 then
    raise exception 'Expected 0 OIDC pairwise subjects after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.oidc_audit_events;
  if v_count <> 0 then
    raise exception 'Expected 0 OIDC audit events after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.backend_audit_events;
  if v_count <> 0 then
    raise exception 'Expected 0 backend audit events after cleanup, found %', v_count;
  end if;
end $$;

commit;
