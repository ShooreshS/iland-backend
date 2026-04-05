begin;

create table if not exists public.lands (
  id text primary key,
  name text not null,
  slug text not null unique,
  type text not null default 'user_defined',
  flag_type text not null default 'user_defined',
  flag_asset text,
  flag_emoji text,
  founder_user_id uuid references public.users(id) on delete set null,
  description text,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_lands_is_active
  on public.lands(is_active);

create index if not exists idx_lands_created_at
  on public.lands(created_at desc);

drop trigger if exists lands_set_updated_at on public.lands;
create trigger lands_set_updated_at
before update on public.lands
for each row
execute function public.set_updated_at();

commit;
