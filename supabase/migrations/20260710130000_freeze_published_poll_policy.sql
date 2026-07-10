begin;

create or replace function public.prevent_published_poll_policy_mutation()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  if old.status <> 'draft' then
    if new.status = 'draft' then
      raise exception 'Published poll policy is immutable; create a new poll/version instead.'
        using errcode = '23514';
    end if;

    if
      new.title is distinct from old.title
      or new.description is distinct from old.description
      or new.jurisdiction_type is distinct from old.jurisdiction_type
      or new.jurisdiction_country_code is distinct from old.jurisdiction_country_code
      or new.jurisdiction_area_ids is distinct from old.jurisdiction_area_ids
      or new.jurisdiction_land_ids is distinct from old.jurisdiction_land_ids
      or new.requires_verified_identity is distinct from old.requires_verified_identity
      or new.allowed_document_country_codes is distinct from old.allowed_document_country_codes
      or new.allowed_home_area_ids is distinct from old.allowed_home_area_ids
      or new.allowed_land_ids is distinct from old.allowed_land_ids
      or new.minimum_age is distinct from old.minimum_age
      or new.starts_at is distinct from old.starts_at
      or new.ends_at is distinct from old.ends_at
      or new.poll_policy_json is distinct from old.poll_policy_json
      or new.poll_policy_hash is distinct from old.poll_policy_hash
      or new.credential_schema_json is distinct from old.credential_schema_json
      or new.credential_schema_hash is distinct from old.credential_schema_hash
      or new.vote_privacy_mode is distinct from old.vote_privacy_mode
      or new.option_set_hash is distinct from old.option_set_hash
      or new.poll_encryption_key_id is distinct from old.poll_encryption_key_id
    then
      raise exception 'Published poll policy is immutable; create a new poll/version instead.'
        using errcode = '23514';
    end if;
  end if;

  return new;
end;
$$;

drop trigger if exists polls_prevent_published_policy_mutation on public.polls;
create trigger polls_prevent_published_policy_mutation
before update on public.polls
for each row
execute function public.prevent_published_poll_policy_mutation();

create or replace function public.prevent_published_poll_options_mutation()
returns trigger
language plpgsql
set search_path = public
as $$
declare
  old_poll_status text;
  new_poll_status text;
begin
  if tg_op in ('UPDATE', 'DELETE') then
    select status
      into old_poll_status
      from public.polls
      where id = old.poll_id;

    if old_poll_status is not null and old_poll_status <> 'draft' then
      raise exception 'Published poll options are immutable; create a new poll/version instead.'
        using errcode = '23514';
    end if;
  end if;

  if tg_op in ('INSERT', 'UPDATE') then
    select status
      into new_poll_status
      from public.polls
      where id = new.poll_id;

    if new_poll_status is not null and new_poll_status <> 'draft' then
      raise exception 'Published poll options are immutable; create a new poll/version instead.'
        using errcode = '23514';
    end if;
  end if;

  if tg_op = 'DELETE' then
    return old;
  end if;

  return new;
end;
$$;

drop trigger if exists poll_options_prevent_published_mutation on public.poll_options;
create trigger poll_options_prevent_published_mutation
before insert or update or delete on public.poll_options
for each row
execute function public.prevent_published_poll_options_mutation();

comment on trigger polls_prevent_published_policy_mutation on public.polls is
  'Phase 8 ZKP guard: once a poll leaves draft, policy/display/audit contract fields are immutable. Use a new poll/version for policy changes.';

comment on trigger poll_options_prevent_published_mutation on public.poll_options is
  'Phase 8 ZKP guard: poll options can only be changed while the parent poll is draft.';

commit;
