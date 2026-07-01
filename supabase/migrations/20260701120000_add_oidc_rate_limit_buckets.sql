create table if not exists public.oidc_rate_limit_buckets (
  bucket_key text primary key,
  request_count integer not null default 0
    check (request_count >= 0),
  reset_at timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

comment on table public.oidc_rate_limit_buckets is
  'Opaque hashed OIDC rate-limit buckets. Keys must not contain raw IPs, tokens, client secrets, or QR secrets.';

drop trigger if exists oidc_rate_limit_buckets_set_updated_at on public.oidc_rate_limit_buckets;
create trigger oidc_rate_limit_buckets_set_updated_at
before update on public.oidc_rate_limit_buckets
for each row execute function public.set_updated_at();

alter table public.oidc_rate_limit_buckets enable row level security;

create or replace function public.consume_oidc_rate_limit(
  p_bucket_key text,
  p_limit integer,
  p_window_seconds integer,
  p_now timestamptz default now()
)
returns table (
  allowed boolean,
  request_count integer,
  reset_at timestamptz
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_current public.oidc_rate_limit_buckets%rowtype;
  v_reset_at timestamptz;
begin
  if p_bucket_key is null or length(trim(p_bucket_key)) = 0 then
    raise exception 'bucket key is required';
  end if;

  if p_limit < 1 then
    raise exception 'rate-limit limit must be positive';
  end if;

  if p_window_seconds < 1 then
    raise exception 'rate-limit window must be positive';
  end if;

  loop
    select *
      into v_current
      from public.oidc_rate_limit_buckets
      where bucket_key = p_bucket_key
      for update;

    if found then
      if v_current.reset_at <= p_now then
        v_reset_at := p_now + make_interval(secs => p_window_seconds);
        update public.oidc_rate_limit_buckets as b
          set request_count = 1,
              reset_at = v_reset_at,
              updated_at = p_now
          where b.bucket_key = p_bucket_key;

        allowed := true;
        request_count := 1;
        reset_at := v_reset_at;
        return next;
        return;
      end if;

      if v_current.request_count >= p_limit then
        allowed := false;
        request_count := v_current.request_count;
        reset_at := v_current.reset_at;
        return next;
        return;
      end if;

      update public.oidc_rate_limit_buckets as b
        set request_count = b.request_count + 1,
            updated_at = p_now
        where b.bucket_key = p_bucket_key
        returning b.request_count,
                  b.reset_at
          into request_count, reset_at;

      allowed := true;
      return next;
      return;
    end if;

    begin
      v_reset_at := p_now + make_interval(secs => p_window_seconds);
      insert into public.oidc_rate_limit_buckets (
        bucket_key,
        request_count,
        reset_at,
        created_at,
        updated_at
      )
      values (
        p_bucket_key,
        1,
        v_reset_at,
        p_now,
        p_now
      );

      allowed := true;
      request_count := 1;
      reset_at := v_reset_at;
      return next;
      return;
    exception
      when unique_violation then
        -- Another replica created the bucket between our SELECT and INSERT.
        -- Loop and re-read it under row lock.
    end;
  end loop;
end;
$$;

revoke all on function public.consume_oidc_rate_limit(text, integer, integer, timestamptz) from public;
grant execute on function public.consume_oidc_rate_limit(text, integer, integer, timestamptz) to service_role;
