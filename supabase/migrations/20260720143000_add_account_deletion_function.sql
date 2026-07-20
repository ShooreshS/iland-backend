begin;

create or replace function public.delete_account_for_user(target_user_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  deleted_votes integer := 0;
  deleted_discussion_posts integer := 0;
  deleted_discussion_comments integer := 0;
  deleted_discussion_post_likes integer := 0;
  deleted_discussion_post_bookmarks integer := 0;
  deleted_discussion_post_reports integer := 0;
  deleted_discussion_media_uploads integer := 0;
  deleted_wallet_credentials integer := 0;
  deleted_auth_credentials integer := 0;
  deleted_oidc_records integer := 0;
  anonymized_auth_audit_events integer := 0;
  anonymized_oidc_audit_events integer := 0;
  disabled_admin_reviewers integer := 0;
  cleared_poll_ownerships integer := 0;
  cleared_land_founderships integer := 0;
  revoked_credential_registry_entries integer := 0;
  user_anonymized boolean := false;
  affected integer := 0;
begin
  if target_user_id is null then
    raise exception 'target_user_id is required';
  end if;

  if not exists (select 1 from public.users where id = target_user_id) then
    return jsonb_build_object(
      'userFound', false,
      'userAnonymized', false
    );
  end if;

  update public.credential_registry registry
  set
    revoked_at = coalesce(registry.revoked_at, now()),
    revocation_reason = coalesce(registry.revocation_reason, 'account_deleted')
  from public.verified_identities identity
  where registry.verified_identity_id = identity.id
    and identity.user_id = target_user_id
    and registry.revoked_at is null;
  get diagnostics revoked_credential_registry_entries = row_count;

  update public.admin_reviewers
  set status = 'disabled'
  where verified_identity_id in (
    select id from public.verified_identities where user_id = target_user_id
  )
    and status <> 'disabled';
  get diagnostics disabled_admin_reviewers = row_count;

  update public.polls
  set created_by_user_id = null
  where created_by_user_id = target_user_id;
  get diagnostics cleared_poll_ownerships = row_count;

  update public.lands
  set founder_user_id = null
  where founder_user_id = target_user_id;
  get diagnostics cleared_land_founderships = row_count;

  delete from public.oidc_authorize_qr_transactions
  where user_id = target_user_id;
  get diagnostics affected = row_count;
  deleted_oidc_records := deleted_oidc_records + affected;

  delete from public.oidc_access_tokens
  where user_id = target_user_id;
  get diagnostics affected = row_count;
  deleted_oidc_records := deleted_oidc_records + affected;

  delete from public.oidc_refresh_token_families
  where user_id = target_user_id;
  get diagnostics affected = row_count;
  deleted_oidc_records := deleted_oidc_records + affected;

  delete from public.oidc_authorization_codes
  where user_id = target_user_id;
  get diagnostics affected = row_count;
  deleted_oidc_records := deleted_oidc_records + affected;

  delete from public.oidc_grants
  where user_id = target_user_id;
  get diagnostics affected = row_count;
  deleted_oidc_records := deleted_oidc_records + affected;

  delete from public.oidc_authorization_requests
  where user_id = target_user_id;
  get diagnostics affected = row_count;
  deleted_oidc_records := deleted_oidc_records + affected;

  delete from public.oidc_pairwise_subjects
  where user_id = target_user_id;
  get diagnostics affected = row_count;
  deleted_oidc_records := deleted_oidc_records + affected;

  delete from public.discussion_post_likes
  where user_id = target_user_id;
  get diagnostics deleted_discussion_post_likes = row_count;

  delete from public.discussion_post_bookmarks
  where user_id = target_user_id;
  get diagnostics deleted_discussion_post_bookmarks = row_count;

  delete from public.discussion_post_reports
  where reporter_user_id = target_user_id;
  get diagnostics deleted_discussion_post_reports = row_count;

  delete from public.discussion_comments
  where author_user_id = target_user_id;
  get diagnostics deleted_discussion_comments = row_count;

  delete from public.discussion_posts
  where author_user_id = target_user_id;
  get diagnostics deleted_discussion_posts = row_count;

  delete from public.discussion_media_uploads
  where uploader_user_id = target_user_id;
  get diagnostics deleted_discussion_media_uploads = row_count;

  delete from public.votes
  where user_id = target_user_id;
  get diagnostics deleted_votes = row_count;

  delete from public.wallet_credentials
  where user_id = target_user_id;
  get diagnostics deleted_wallet_credentials = row_count;

  delete from public.identity_profiles
  where user_id = target_user_id;

  delete from public.auth_credentials
  where user_id = target_user_id;
  get diagnostics deleted_auth_credentials = row_count;

  update public.auth_audit_events
  set
    user_id = null,
    auth_credential_id = null,
    session_id = null
  where user_id = target_user_id
     or auth_credential_id in (
       select id from public.auth_credentials where user_id = target_user_id
     )
     or session_id in (
       select id from public.auth_sessions where user_id = target_user_id
     );
  get diagnostics anonymized_auth_audit_events = row_count;

  update public.oidc_audit_events
  set
    user_id = null,
    auth_session_id = null
  where user_id = target_user_id
     or auth_session_id in (
       select id from public.auth_sessions where user_id = target_user_id
     );
  get diagnostics anonymized_oidc_audit_events = row_count;

  update public.users
  set
    username = null,
    display_name = null,
    public_nickname = null,
    onboarding_status = 'not_started',
    verification_level = 'anonymous',
    has_wallet = false,
    wallet_credential_id = null,
    selected_land_id = null,
    preferred_language = null,
    auth_generation = auth_generation + 1,
    account_status = 'disabled'
  where id = target_user_id
  returning true into user_anonymized;

  return jsonb_build_object(
    'userFound', true,
    'userAnonymized', coalesce(user_anonymized, false),
    'votes', deleted_votes,
    'discussionPosts', deleted_discussion_posts,
    'discussionComments', deleted_discussion_comments,
    'discussionPostLikes', deleted_discussion_post_likes,
    'discussionPostBookmarks', deleted_discussion_post_bookmarks,
    'discussionPostReports', deleted_discussion_post_reports,
    'discussionMediaUploads', deleted_discussion_media_uploads,
    'walletCredentials', deleted_wallet_credentials,
    'authCredentials', deleted_auth_credentials,
    'oidcRecords', deleted_oidc_records,
    'authAuditEventsAnonymized', anonymized_auth_audit_events,
    'oidcAuditEventsAnonymized', anonymized_oidc_audit_events,
    'adminReviewersDisabled', disabled_admin_reviewers,
    'pollOwnershipsCleared', cleared_poll_ownerships,
    'landFoundershipsCleared', cleared_land_founderships,
    'credentialRegistryEntriesRevoked', revoked_credential_registry_entries
  );
end;
$$;

comment on function public.delete_account_for_user(uuid) is
  'Irreversibly removes user-linked content and disables/anonymizes the account while preserving required audit anchors.';

notify pgrst, 'reload schema';

commit;
