-- Schema-wide invariants. These guard against a new function or table being
-- added without the usual hardening.
begin;
select plan(6);

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

-- The helpers that read membership data must be SECURITY DEFINER and STABLE.
select is(
  (select array_agg(p.proname::text order by p.proname)
   from pg_proc p
   where p.pronamespace = 'tenant_guard'::regnamespace
     and p.prosecdef and p.provolatile = 's'),
  array['is_member', 'member_role', 'my_tenant_ids'],
  'membership helpers are SECURITY DEFINER and STABLE'
);

-- Administrative functions stay out of reach of client roles.
select ok(
  not has_function_privilege('app_user', 'tenant_guard.grant_to(name)', 'execute'),
  'client roles cannot call grant_to()'
);

select * from finish();
rollback;
