-- CivicOS ZKP Phase 10 public-release cleanup runbook.
--
-- This is intentionally NOT a migration. Run it manually only after:
--   1. exporting a database backup/snapshot;
--   2. stopping public writes or putting the backend in maintenance mode;
--   3. confirming that all current users, polls, votes, credentials, and audit
--      rows are disposable pre-release/test data.
--
-- It preserves schema, migrations, lands/reference data, and OIDC client/signing
-- key configuration. It deletes operational user/poll/vote/ZKP/auth/session
-- state so the public v0.1 release starts cleanly.
--
-- Safety latch:
--   set app.phase10_cleanup_confirm = 'delete-public-test-data';

begin;

do $$
begin
  if current_setting('app.phase10_cleanup_confirm', true) <>
     'delete-public-test-data' then
    raise exception
      'Set app.phase10_cleanup_confirm=delete-public-test-data before running Phase 10 cleanup.';
  end if;
end $$;

-- Preserve lands/reference rows but break optional creator/founder links to
-- users that will be deleted below.
update public.lands
set founder_user_id = null
where founder_user_id is not null;

-- Poll, vote, map, audit, and encryption-key state.
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

-- Credential registry and accepted-root state. The first real user after
-- cleanup will issue a fresh root chain.
delete from public.credential_roots;
delete from public.credential_registry;

-- First-party auth/session/recovery state.
delete from public.refresh_token_families;
delete from public.app_attestation_credentials;
delete from public.auth_sessions;
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

commit;
