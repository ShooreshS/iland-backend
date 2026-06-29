begin;

alter table public.users
  add column if not exists public_nickname text;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'users_public_nickname_format'
      and conrelid = 'public.users'::regclass
  ) then
    alter table public.users
      add constraint users_public_nickname_format
      check (
        public_nickname is null
        or public_nickname ~ '^[a-z][a-z0-9-]{2,31}$'
      );
  end if;
end $$;

create unique index if not exists ux_users_public_nickname_lower
  on public.users (lower(public_nickname))
  where public_nickname is not null;

comment on column public.users.public_nickname is
  'User-controlled public display nickname. It is safe for first-release OIDC profile claims and must not contain legal identity data.';

commit;
