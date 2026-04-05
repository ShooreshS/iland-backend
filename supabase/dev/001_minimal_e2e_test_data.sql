-- 0.0.86 minimal E2E helper data
-- Usage:
-- 1) Start app once with backend flags enabled (this bootstraps a provisional user).
-- 2) Run this script in Supabase SQL editor.
-- 3) It attaches a minimal home area to latest user and creates one active global poll.

do $$
declare
  target_user_id uuid;
  new_poll_id uuid;
  now_iso timestamptz := now();
begin
  select u.id
  into target_user_id
  from public.users u
  order by u.created_at desc
  limit 1;

  if target_user_id is null then
    raise exception 'No users found. Call POST /users/bootstrap first.';
  end if;

  update public.identity_profiles
  set home_country_code = coalesce(home_country_code, 'SE'),
      home_area_id = coalesce(home_area_id, 'se-stockholm-test'),
      home_location_source = 'admin_set',
      home_location_updated_at = coalesce(home_location_updated_at, now_iso)
  where user_id = target_user_id;

  insert into public.polls (
    slug,
    created_by_user_id,
    title,
    description,
    status,
    jurisdiction_type,
    starts_at
  ) values (
    concat('e2e-test-', floor(extract(epoch from now_iso))::bigint::text),
    target_user_id,
    'E2E Test Poll',
    'Minimal test poll for app-to-backend flow',
    'active',
    'global',
    now_iso
  )
  returning id into new_poll_id;

  insert into public.poll_options (poll_id, label, color, display_order, is_active)
  values
    (new_poll_id, 'Option A', '#3B82F6', 1, true),
    (new_poll_id, 'Option B', '#EF4444', 2, true);
end $$;
