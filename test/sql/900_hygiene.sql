-- Schema-wide invariants. These guard against a new function or table being
-- added without the usual hardening.
begin;
select plan(7);

select matches(tenant_guard.version(), '^\d+\.\d+\.\d+$', 'version() returns a semantic version');

select is_empty(
  $$ select p.oid::regprocedure::text
     from pg_proc p
     where p.pronamespace = 'tenant_guard'::regnamespace
       and not coalesce('search_path=""' = any (p.proconfig), false) $$,
  'every tenant_guard function pins search_path to an empty string'
);

select is_empty(
  $$ select p.oid::regprocedure::text
     from pg_proc p
     cross join lateral aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
     where p.pronamespace = 'tenant_guard'::regnamespace
       and a.grantee = 0 $$,
  'no tenant_guard function is executable by PUBLIC'
);

select is_empty(
  $$ select c.oid::regclass::text
     from pg_class c
     where c.relnamespace = 'tenant_guard'::regnamespace
       and c.relkind = 'r'
       and not c.relrowsecurity $$,
  'every tenant_guard table has row-level security enabled'
);

select is_empty(
  $$ select c.oid::regclass::text
     from pg_class c
     cross join lateral aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
     where c.relnamespace = 'tenant_guard'::regnamespace
       and a.grantee = 0 $$,
  'no tenant_guard table is accessible to PUBLIC'
);

-- The helpers that read membership and permission data must be SECURITY DEFINER and STABLE.
select is(
  (select array_agg(p.proname::text order by p.proname)
   from pg_proc p
   where p.pronamespace = 'tenant_guard'::regnamespace
     and p.prosecdef and p.provolatile = 's'),
  array['has_permission', 'is_locked', 'is_member', 'member_role', 'my_tenant_ids', 'permitted_tenant_ids'],
  'access helpers are SECURITY DEFINER and STABLE'
);

-- Client roles can execute exactly the client-facing functions. Everything
-- else (DDL helpers, lock administration, grant_to) is owner-only.
select is(
  (select array_agg(p.proname::text order by p.proname)
   from pg_proc p
   where p.pronamespace = 'tenant_guard'::regnamespace
     and has_function_privilege('app_user', p.oid, 'execute')),
  array['create_tenant', 'current_user_id', 'has_permission', 'is_locked',
        'is_member', 'member_role', 'my_tenant_ids', 'permitted_tenant_ids'],
  'client roles can execute exactly the client-facing functions'
);

select * from finish();
rollback;
