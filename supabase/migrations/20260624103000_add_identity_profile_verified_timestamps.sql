begin;

alter table public.identity_profiles
  add column if not exists passport_verified_at timestamptz,
  add column if not exists national_id_verified_at timestamptz,
  add column if not exists face_verified_at timestamptz;

update public.identity_profiles as ip
set
  passport_scan_completed = case
    when vi.id is not null then true
    else ip.passport_scan_completed
  end,
  passport_nfc_completed = case
    when vi.id is not null then true
    else ip.passport_nfc_completed
  end,
  passport_verified_at = coalesce(ip.passport_verified_at, vi.verified_at),
  face_scan_completed = case
    when wc.id is not null then true
    else ip.face_scan_completed
  end,
  face_bound_to_identity = case
    when wc.id is not null then true
    else ip.face_bound_to_identity
  end,
  face_verified_at = coalesce(ip.face_verified_at, wc.issued_at)
from public.verified_identities as vi
left join public.wallet_credentials as wc
  on wc.user_id = vi.user_id
 and wc.issuance_status = 'issued'
where vi.user_id = ip.user_id;

comment on column public.identity_profiles.passport_verified_at is
  'Authoritative backend verification timestamp for passport-based identity verification. UI badges must use this instead of local scan progress.';

comment on column public.identity_profiles.national_id_verified_at is
  'Authoritative backend verification timestamp for national-id-based identity verification. UI badges must use this instead of local scan progress.';

comment on column public.identity_profiles.face_verified_at is
  'Authoritative backend verification timestamp for face verification accepted by the backend as part of a completed identity flow.';

commit;
