begin;

-- The API uses service_role. Direct browser/mobile roles must not invoke
-- internal functions with their owner's authority. Exclude extension members.
do $$
declare
  fn record;
begin
  for fn in
    select p.oid::regprocedure as signature, p.prosecdef
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.prokind = 'f'
      and not exists (
        select 1 from pg_depend d
        where d.classid = 'pg_proc'::regclass and d.objid = p.oid
          and d.deptype = 'e'
      )
  loop
    execute format('revoke execute on function %s from public, anon, authenticated', fn.signature);
    execute format('grant execute on function %s to service_role', fn.signature);
    if fn.prosecdef then
      execute format('alter function %s set search_path = pg_catalog, public, pg_temp', fn.signature);
    end if;
  end loop;
end $$;

revoke create on schema public from public, anon, authenticated;

-- Schema defaults are additive: remove the built-in global PUBLIC execute
-- privilege as well as Supabase's explicit per-schema application grants.
-- Repository migrations and the inspected hosted functions are owned by postgres.
alter default privileges for role postgres revoke execute on functions from public, anon, authenticated;
alter default privileges for role postgres in schema public revoke execute on functions from public, anon, authenticated;
alter default privileges for role postgres in schema public grant execute on functions to service_role;

commit;
