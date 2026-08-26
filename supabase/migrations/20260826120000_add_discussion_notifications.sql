begin;

create extension if not exists pgcrypto;

create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  recipient_user_id uuid not null references public.users(id) on delete cascade,
  event_type text not null check (event_type in (
    'discussion.post_commented',
    'discussion.comment_replied',
    'discussion.post_liked',
    'discussion.comment_liked'
  )),
  actor_user_id uuid references public.users(id) on delete set null,
  subject_type text not null check (subject_type in (
    'discussion_post',
    'discussion_comment'
  )),
  subject_id uuid not null,
  parent_post_id uuid not null references public.discussion_posts(id) on delete cascade,
  target_url text not null,
  payload_version integer not null default 1 check (payload_version > 0),
  payload jsonb not null default '{}'::jsonb,
  aggregation_count integer not null default 1 check (aggregation_count > 0),
  first_event_at timestamptz not null default now(),
  last_event_at timestamptz not null default now(),
  last_push_enqueued_at timestamptz,
  push_generation integer not null default 1 check (push_generation > 0),
  read_at timestamptz,
  archived_at timestamptz,
  dedupe_key text not null unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists notifications_recipient_feed_idx
  on public.notifications (recipient_user_id, last_event_at desc, id desc)
  where archived_at is null;

create index if not exists notifications_recipient_unread_idx
  on public.notifications (recipient_user_id, last_event_at desc, id desc)
  where read_at is null and archived_at is null;

drop trigger if exists notifications_set_updated_at on public.notifications;
create trigger notifications_set_updated_at
before update on public.notifications
for each row execute function public.set_updated_at();

create table if not exists public.notification_preferences (
  user_id uuid primary key references public.users(id) on delete cascade,
  push_enabled boolean not null default false,
  comments_and_replies_push boolean not null default true,
  likes_push boolean not null default true,
  preferred_locale text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

drop trigger if exists notification_preferences_set_updated_at
  on public.notification_preferences;
create trigger notification_preferences_set_updated_at
before update on public.notification_preferences
for each row execute function public.set_updated_at();

create table if not exists public.push_installations (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  auth_session_id uuid not null references public.auth_sessions(id) on delete cascade,
  platform text not null check (platform in ('ios', 'android')),
  provider text not null check (provider in ('apns', 'fcm')),
  provider_environment text not null check (
    provider_environment in ('sandbox', 'production')
  ),
  token_ciphertext text not null,
  token_hash text not null,
  permission_status text not null check (
    permission_status in ('granted', 'denied', 'undetermined')
  ),
  locale text,
  app_version text,
  build_number text,
  status text not null default 'active' check (
    status in ('active', 'revoked', 'invalid', 'stale')
  ),
  last_registered_at timestamptz not null default now(),
  last_success_at timestamptz,
  invalidated_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (
    (platform = 'ios' and provider = 'apns')
    or (platform = 'android' and provider = 'fcm')
  ),
  check (provider = 'apns' or provider_environment = 'production'),
  unique (auth_session_id, provider)
);

create unique index if not exists push_installations_active_token_idx
  on public.push_installations (provider, provider_environment, token_hash)
  where status = 'active';

create index if not exists push_installations_user_status_idx
  on public.push_installations (user_id, status);

drop trigger if exists push_installations_set_updated_at
  on public.push_installations;
create trigger push_installations_set_updated_at
before update on public.push_installations
for each row execute function public.set_updated_at();

create or replace function public.register_push_installation(
  p_user_id uuid,
  p_auth_session_id uuid,
  p_platform text,
  p_provider text,
  p_provider_environment text,
  p_token_ciphertext text,
  p_token_hash text,
  p_permission_status text,
  p_locale text,
  p_app_version text,
  p_build_number text
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  installation_id uuid;
begin
  if not exists (
    select 1
    from public.auth_sessions
    where id = p_auth_session_id
      and user_id = p_user_id
      and status = 'active'
      and expires_at > now()
  ) then
    raise exception 'Push installation requires the active current auth session.'
      using errcode = '23514';
  end if;

  update public.push_installations
  set status = 'stale'
  where provider = p_provider
    and provider_environment = p_provider_environment
    and token_hash = p_token_hash
    and auth_session_id <> p_auth_session_id
    and status = 'active';

  insert into public.push_installations (
    user_id,
    auth_session_id,
    platform,
    provider,
    provider_environment,
    token_ciphertext,
    token_hash,
    permission_status,
    locale,
    app_version,
    build_number,
    status,
    invalidated_at,
    last_registered_at
  ) values (
    p_user_id,
    p_auth_session_id,
    p_platform,
    p_provider,
    p_provider_environment,
    p_token_ciphertext,
    p_token_hash,
    p_permission_status,
    p_locale,
    p_app_version,
    p_build_number,
    case when p_permission_status = 'granted' then 'active' else 'revoked' end,
    null,
    now()
  )
  on conflict (auth_session_id, provider) do update
  set
    user_id = excluded.user_id,
    platform = excluded.platform,
    provider_environment = excluded.provider_environment,
    token_ciphertext = excluded.token_ciphertext,
    token_hash = excluded.token_hash,
    permission_status = excluded.permission_status,
    locale = excluded.locale,
    app_version = excluded.app_version,
    build_number = excluded.build_number,
    status = excluded.status,
    invalidated_at = null,
    last_registered_at = now()
  returning id into installation_id;

  return installation_id;
end;
$$;

create table if not exists public.push_deliveries (
  id uuid primary key default gen_random_uuid(),
  notification_id uuid not null references public.notifications(id) on delete cascade,
  installation_id uuid not null references public.push_installations(id) on delete cascade,
  push_generation integer not null check (push_generation > 0),
  status text not null default 'pending' check (
    status in ('pending', 'processing', 'sent', 'retry', 'invalid_token', 'dead')
  ),
  available_at timestamptz not null default now(),
  leased_at timestamptz,
  leased_by text,
  attempt_count integer not null default 0 check (attempt_count >= 0),
  provider_message_id text,
  last_error_code text,
  last_error_message text,
  sent_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (notification_id, installation_id, push_generation)
);

create index if not exists push_deliveries_claim_idx
  on public.push_deliveries (available_at, created_at)
  where status in ('pending', 'retry', 'processing');

drop trigger if exists push_deliveries_set_updated_at on public.push_deliveries;
create trigger push_deliveries_set_updated_at
before update on public.push_deliveries
for each row execute function public.set_updated_at();

create or replace function public.notification_users_are_blocked(
  left_user_id uuid,
  right_user_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.discussion_user_blocks
    where (blocker_user_id = left_user_id and blocked_user_id = right_user_id)
       or (blocker_user_id = right_user_id and blocked_user_id = left_user_id)
  );
$$;

create or replace function public.enqueue_notification_push_deliveries(
  target_notification_id uuid
)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  inserted_count integer;
begin
  insert into public.push_deliveries (
    notification_id,
    installation_id,
    push_generation
  )
  select
    notification.id,
    installation.id,
    notification.push_generation
  from public.notifications as notification
  join public.notification_preferences as preference
    on preference.user_id = notification.recipient_user_id
  join public.push_installations as installation
    on installation.user_id = notification.recipient_user_id
   and installation.status = 'active'
   and installation.permission_status = 'granted'
  join public.auth_sessions as session
    on session.id = installation.auth_session_id
   and session.user_id = notification.recipient_user_id
   and session.status = 'active'
   and session.expires_at > now()
  where notification.id = target_notification_id
    and notification.archived_at is null
    and preference.push_enabled
    and (
      notification.event_type in (
        'discussion.post_commented',
        'discussion.comment_replied'
      ) and preference.comments_and_replies_push
      or notification.event_type in (
        'discussion.post_liked',
        'discussion.comment_liked'
      ) and preference.likes_push
    )
  on conflict (notification_id, installation_id, push_generation) do nothing;

  get diagnostics inserted_count = row_count;
  return inserted_count;
end;
$$;

create or replace function public.materialize_published_comment_notification()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  recipient_id uuid;
  notification_event_type text;
  notification_subject_type text;
  notification_subject_id uuid;
  notification_id uuid;
begin
  if new.moderation_status <> 'published'
    or (tg_op = 'UPDATE' and old.moderation_status = 'published') then
    return new;
  end if;

  if new.reply_to_comment_id is null then
    select author_user_id
    into recipient_id
    from public.discussion_posts
    where id = new.post_id
      and moderation_status = 'published';

    notification_event_type := 'discussion.post_commented';
    notification_subject_type := 'discussion_post';
    notification_subject_id := new.post_id;
  else
    select author_user_id
    into recipient_id
    from public.discussion_comments
    where id = new.reply_to_comment_id;

    notification_event_type := 'discussion.comment_replied';
    notification_subject_type := 'discussion_comment';
    notification_subject_id := new.reply_to_comment_id;
  end if;

  if recipient_id is null
    or recipient_id = new.author_user_id
    or public.notification_users_are_blocked(recipient_id, new.author_user_id)
    or not exists (
      select 1 from public.users
      where id = recipient_id and account_status = 'active'
    ) then
    return new;
  end if;

  insert into public.notifications (
    recipient_user_id,
    event_type,
    actor_user_id,
    subject_type,
    subject_id,
    parent_post_id,
    target_url,
    payload,
    last_push_enqueued_at,
    dedupe_key
  ) values (
    recipient_id,
    notification_event_type,
    new.author_user_id,
    notification_subject_type,
    notification_subject_id,
    new.post_id,
    'https://civicos.codeiland.com/discussions/' || new.post_id::text,
    jsonb_build_object('actorPublicNickname', new.author_public_nickname),
    now(),
    'discussion-comment-published:' || new.id::text
  )
  on conflict (dedupe_key) do nothing
  returning id into notification_id;

  if notification_id is not null then
    perform public.enqueue_notification_push_deliveries(notification_id);
  end if;

  return new;
end;
$$;

drop trigger if exists discussion_comments_materialize_notification
  on public.discussion_comments;
create trigger discussion_comments_materialize_notification
after insert or update of moderation_status on public.discussion_comments
for each row execute function public.materialize_published_comment_notification();

create or replace function public.materialize_discussion_like_notification(
  recipient_id uuid,
  actor_id uuid,
  notification_event_type text,
  notification_subject_type text,
  notification_subject_id uuid,
  notification_parent_post_id uuid,
  notification_actor_nickname text,
  notification_dedupe_key text,
  event_time timestamptz
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  existing_notification public.notifications%rowtype;
  notification_id uuid;
  should_enqueue_push boolean;
  next_generation integer;
begin
  if recipient_id is null
    or recipient_id = actor_id
    or public.notification_users_are_blocked(recipient_id, actor_id)
    or not exists (
      select 1 from public.users
      where id = recipient_id and account_status = 'active'
    ) then
    return null;
  end if;

  -- Serialize the first insert and later aggregation updates for one target.
  -- Without this lock, two first-time likes can both observe no row and make
  -- one of the source like transactions fail on the unique dedupe key.
  perform pg_advisory_xact_lock(hashtextextended(notification_dedupe_key, 0));

  select *
  into existing_notification
  from public.notifications
  where dedupe_key = notification_dedupe_key
  for update;

  if not found then
    insert into public.notifications (
      recipient_user_id,
      event_type,
      actor_user_id,
      subject_type,
      subject_id,
      parent_post_id,
      target_url,
      payload,
      first_event_at,
      last_event_at,
      last_push_enqueued_at,
      dedupe_key
    ) values (
      recipient_id,
      notification_event_type,
      actor_id,
      notification_subject_type,
      notification_subject_id,
      notification_parent_post_id,
      'https://civicos.codeiland.com/discussions/' || notification_parent_post_id::text,
      jsonb_build_object('actorPublicNickname', notification_actor_nickname),
      event_time,
      event_time,
      event_time,
      notification_dedupe_key
    )
    returning id into notification_id;
    should_enqueue_push := true;
  else
    should_enqueue_push := existing_notification.last_push_enqueued_at is null
      or existing_notification.last_push_enqueued_at <= event_time - interval '15 minutes';
    next_generation := existing_notification.push_generation
      + case when should_enqueue_push then 1 else 0 end;

    update public.notifications
    set
      actor_user_id = actor_id,
      payload = jsonb_build_object('actorPublicNickname', notification_actor_nickname),
      aggregation_count = case
        when existing_notification.read_at is null
          then existing_notification.aggregation_count + 1
        else 1
      end,
      first_event_at = case
        when existing_notification.read_at is null
          then existing_notification.first_event_at
        else event_time
      end,
      last_event_at = event_time,
      last_push_enqueued_at = case
        when should_enqueue_push then event_time
        else existing_notification.last_push_enqueued_at
      end,
      push_generation = next_generation,
      read_at = null,
      archived_at = null
    where id = existing_notification.id
    returning id into notification_id;
  end if;

  if should_enqueue_push then
    perform public.enqueue_notification_push_deliveries(notification_id);
  end if;

  return notification_id;
end;
$$;

create or replace function public.materialize_post_like_notification()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  post_author_id uuid;
  actor_nickname text;
begin
  select author_user_id into post_author_id
  from public.discussion_posts
  where id = new.post_id and moderation_status = 'published';

  select public_nickname into actor_nickname
  from public.users where id = new.user_id;

  perform public.materialize_discussion_like_notification(
    post_author_id,
    new.user_id,
    'discussion.post_liked',
    'discussion_post',
    new.post_id,
    new.post_id,
    actor_nickname,
    'discussion-post-liked:' || new.post_id::text || ':' || post_author_id::text,
    new.created_at
  );
  return new;
end;
$$;

drop trigger if exists discussion_post_likes_materialize_notification
  on public.discussion_post_likes;
create trigger discussion_post_likes_materialize_notification
after insert on public.discussion_post_likes
for each row execute function public.materialize_post_like_notification();

create or replace function public.materialize_comment_like_notification()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  comment_author_id uuid;
  parent_post_id uuid;
  actor_nickname text;
begin
  select author_user_id, post_id
  into comment_author_id, parent_post_id
  from public.discussion_comments
  where id = new.comment_id and moderation_status = 'published';

  select public_nickname into actor_nickname
  from public.users where id = new.user_id;

  perform public.materialize_discussion_like_notification(
    comment_author_id,
    new.user_id,
    'discussion.comment_liked',
    'discussion_comment',
    new.comment_id,
    parent_post_id,
    actor_nickname,
    'discussion-comment-liked:' || new.comment_id::text || ':' || comment_author_id::text,
    new.created_at
  );
  return new;
end;
$$;

drop trigger if exists discussion_comment_likes_materialize_notification
  on public.discussion_comment_likes;
create trigger discussion_comment_likes_materialize_notification
after insert on public.discussion_comment_likes
for each row execute function public.materialize_comment_like_notification();

create or replace function public.claim_notification_push_deliveries(
  worker_id text,
  batch_size integer default 25,
  lock_timeout_seconds integer default 120
)
returns table (
  delivery_id uuid,
  notification_id uuid,
  installation_id uuid,
  attempt_count integer,
  event_type text,
  aggregation_count integer,
  target_url text,
  payload jsonb,
  provider text,
  provider_environment text,
  token_ciphertext text,
  locale text
)
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.push_deliveries as delivery
  set
    status = 'dead',
    last_error_code = 'recipient_ineligible',
    last_error_message = 'Recipient, session, preference, or installation is no longer eligible.'
  from public.notifications as notification,
       public.push_installations as installation,
       public.auth_sessions as session,
       public.users as recipient
  where delivery.notification_id = notification.id
    and delivery.installation_id = installation.id
    and installation.auth_session_id = session.id
    and notification.recipient_user_id = recipient.id
    and delivery.status in ('pending', 'retry', 'processing')
    and (
      notification.archived_at is not null
      or installation.status <> 'active'
      or installation.permission_status <> 'granted'
      or session.status <> 'active'
      or session.expires_at <= now()
      or recipient.account_status <> 'active'
      or not exists (
        select 1
        from public.notification_preferences as preference
        where preference.user_id = notification.recipient_user_id
          and preference.push_enabled
          and (
            notification.event_type in (
              'discussion.post_commented',
              'discussion.comment_replied'
            ) and preference.comments_and_replies_push
            or notification.event_type in (
              'discussion.post_liked',
              'discussion.comment_liked'
            ) and preference.likes_push
          )
      )
    );

  return query
  with candidates as (
    select delivery.id
    from public.push_deliveries as delivery
    where (
      delivery.status in ('pending', 'retry')
      or (
        delivery.status = 'processing'
        and delivery.leased_at < now() - make_interval(secs => lock_timeout_seconds)
      )
    )
      and delivery.available_at <= now()
    order by delivery.available_at, delivery.created_at
    for update skip locked
    limit greatest(1, least(batch_size, 100))
  ), claimed as (
    update public.push_deliveries as delivery
    set
      status = 'processing',
      leased_at = now(),
      leased_by = worker_id,
      attempt_count = delivery.attempt_count + 1
    from candidates
    where delivery.id = candidates.id
    returning delivery.*
  )
  select
    claimed.id,
    notification.id,
    installation.id,
    claimed.attempt_count,
    notification.event_type,
    notification.aggregation_count,
    notification.target_url,
    notification.payload,
    installation.provider,
    installation.provider_environment,
    installation.token_ciphertext,
    coalesce(installation.locale, preference.preferred_locale, 'en')
  from claimed
  join public.notifications as notification
    on notification.id = claimed.notification_id
  join public.push_installations as installation
    on installation.id = claimed.installation_id
  left join public.notification_preferences as preference
    on preference.user_id = notification.recipient_user_id;
end;
$$;

create or replace function public.revoke_session_push_installations()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if old.status = 'active' and new.status <> 'active' then
    update public.push_installations
    set status = 'revoked'
    where auth_session_id = new.id and status = 'active';
  end if;
  return new;
end;
$$;

drop trigger if exists auth_sessions_revoke_push_installations
  on public.auth_sessions;
create trigger auth_sessions_revoke_push_installations
after update of status on public.auth_sessions
for each row execute function public.revoke_session_push_installations();

create or replace function public.cleanup_disabled_user_notifications()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if old.account_status = 'active' and new.account_status <> 'active' then
    delete from public.notification_preferences where user_id = new.id;
    delete from public.push_installations where user_id = new.id;
    delete from public.notifications where recipient_user_id = new.id;
    update public.notifications
    set
      actor_user_id = null,
      payload = payload - 'actorPublicNickname'
    where actor_user_id = new.id;
  end if;
  return new;
end;
$$;

drop trigger if exists users_cleanup_notifications on public.users;
create trigger users_cleanup_notifications
after update of account_status on public.users
for each row execute function public.cleanup_disabled_user_notifications();

comment on table public.notifications is
  'Authoritative in-app inbox. Discussion triggers materialize rows atomically with the source write.';
comment on column public.push_installations.token_ciphertext is
  'AES-256-GCM ciphertext. Raw APNs and FCM tokens must never be stored or logged.';
comment on table public.push_deliveries is
  'Per-installation push delivery queue. Network delivery is performed by the backend worker.';

alter table public.notifications enable row level security;
alter table public.notification_preferences enable row level security;
alter table public.push_installations enable row level security;
alter table public.push_deliveries enable row level security;

revoke all on table public.notifications from anon, authenticated;
revoke all on table public.notification_preferences from anon, authenticated;
revoke all on table public.push_installations from anon, authenticated;
revoke all on table public.push_deliveries from anon, authenticated;

revoke all on function public.notification_users_are_blocked(uuid, uuid) from public;
revoke all on function public.enqueue_notification_push_deliveries(uuid) from public;
revoke all on function public.materialize_discussion_like_notification(
  uuid, uuid, text, text, uuid, uuid, text, text, timestamptz
) from public;
revoke all on function public.register_push_installation(
  uuid, uuid, text, text, text, text, text, text, text, text, text
) from public;
revoke all on function public.claim_notification_push_deliveries(
  text, integer, integer
) from public;
grant execute on function public.register_push_installation(
  uuid, uuid, text, text, text, text, text, text, text, text, text
) to service_role;
grant execute on function public.claim_notification_push_deliveries(
  text, integer, integer
) to service_role;

notify pgrst, 'reload schema';

commit;
