-- CivicOS ZKP Phase 10 public-release cleanup runbook.
--
-- This is intentionally NOT a migration. Run it manually only after:
--   1. exporting a database backup/snapshot;
--   2. stopping public writes or putting the backend in maintenance mode;
--   3. confirming that all current polls, votes, audit rows, synthetic users,
--      and non-preserved identities are disposable pre-release/test data.
--
-- It preserves schema, migrations, lands/reference data, and OIDC client/signing
-- key configuration. It also preserves exactly the three passport-verified
-- identity rows requested for public v0.1 continuity:
--
--   verified_identities.id=0ccf7dd6-9fbd-4eef-8952-29102f636422
--   verified_identities.id=4ccdcda5-2e9c-4a68-ad2c-e98a6d728f45
--   verified_identities.id=ffe5c615-b4a5-4b1e-885a-e7a818e72ec0
--
-- Kept for those identities only:
--   - users
--   - identity_profiles
--   - verified_identities
--   - wallet_credentials
--   - auth_credentials
--   - app_attestation_credentials
--   - auth_sessions
--   - refresh_token_families
--   - credential_registry rows tied to the preserved verified identities
--
-- All polls/votes/audit publications are deleted, including polls created by
-- the preserved users and votes cast by them.
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

create temp table phase10_keep_verified_identities (
  id uuid primary key
) on commit drop;

insert into phase10_keep_verified_identities (id)
values
  ('0ccf7dd6-9fbd-4eef-8952-29102f636422'),
  ('4ccdcda5-2e9c-4a68-ad2c-e98a6d728f45'),
  ('ffe5c615-b4a5-4b1e-885a-e7a818e72ec0');

create temp table phase10_keep_users (
  id uuid primary key
) on commit drop;

insert into phase10_keep_users (id)
select vi.user_id
from public.verified_identities vi
join phase10_keep_verified_identities keep on keep.id = vi.id
where vi.verification_method = 'passport_nfc';

do $$
declare
  v_verified_count integer;
  v_user_count integer;
begin
  select count(*) into v_verified_count
  from public.verified_identities vi
  join phase10_keep_verified_identities keep on keep.id = vi.id
  where vi.verification_method = 'passport_nfc';

  select count(*) into v_user_count
  from phase10_keep_users;

  if v_verified_count <> 3 or v_user_count <> 3 then
    raise exception
      'Phase 10 preserve set must resolve to exactly three passport_nfc verified identities and users. verified=%, users=%',
      v_verified_count,
      v_user_count;
  end if;
end $$;

-- Preserve lands/reference rows but break optional creator/founder links to
-- users that will be deleted below.
update public.lands
set founder_user_id = null
where founder_user_id is not null
  and founder_user_id not in (select id from phase10_keep_users);

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

-- Credential roots are removed because old roots may commit to synthetic leaves
-- deleted by this cleanup. Preserved users will reinsert an accepted root the
-- next time /verification/credential is called with their existing commitment.
delete from public.credential_roots;
delete from public.credential_registry
where verified_identity_id not in (
  select id from phase10_keep_verified_identities
);

-- First-party auth/session/recovery state. Preserve active device credentials
-- and sessions for the kept identities so the existing tester devices remain
-- valid where their local tokens still exist.
delete from public.refresh_token_families
where user_id not in (select id from phase10_keep_users);

delete from public.app_attestation_credentials
where user_id not in (select id from phase10_keep_users);

delete from public.auth_sessions
where user_id not in (select id from phase10_keep_users);

-- auth_credentials has a self-reference for supersession history. Break links
-- to credentials that will be deleted before deleting non-preserved users.
update public.auth_credentials ac
set superseded_by_auth_credential_id = null
where superseded_by_auth_credential_id is not null
  and not exists (
    select 1
    from public.auth_credentials target
    join phase10_keep_users keep on keep.id = target.user_id
    where target.id = ac.superseded_by_auth_credential_id
  );

delete from public.auth_credentials
where user_id not in (select id from phase10_keep_users);

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

-- Wallet/identity/user state. Preserve only the requested passport identities
-- and their linked rows.
delete from public.wallet_credentials
where user_id not in (select id from phase10_keep_users);

delete from public.verified_identities
where id not in (select id from phase10_keep_verified_identities);

delete from public.identity_profiles
where user_id not in (select id from phase10_keep_users);

delete from public.users
where id not in (select id from phase10_keep_users);

-- Backend audit hash-chain state from private/dev testing.
delete from public.backend_audit_events;

-- Post-cleanup invariants. These fail the transaction if any major debug data
-- survived or if the preserve set was damaged.
do $$
declare
  v_count integer;
begin
  select count(*) into v_count from public.verified_identities;
  if v_count <> 3 then
    raise exception 'Expected exactly 3 verified identities after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.users;
  if v_count <> 3 then
    raise exception 'Expected exactly 3 users after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.polls;
  if v_count <> 0 then
    raise exception 'Expected 0 polls after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.votes;
  if v_count <> 0 then
    raise exception 'Expected 0 legacy votes after cleanup, found %', v_count;
  end if;

  select count(*) into v_count from public.poll_zk_votes;
  if v_count <> 0 then
    raise exception 'Expected 0 ZKP votes after cleanup, found %', v_count;
  end if;

  select count(*) into v_count
  from public.identity_profiles
  where home_location_source = 'mock';
  if v_count <> 0 then
    raise exception 'Expected 0 mock identity profiles after cleanup, found %', v_count;
  end if;

  select count(*) into v_count
  from public.verified_identities
  where verification_method = 'civicos_zkp_seed';
  if v_count <> 0 then
    raise exception 'Expected 0 civicos_zkp_seed identities after cleanup, found %', v_count;
  end if;
end $$;

commit;
