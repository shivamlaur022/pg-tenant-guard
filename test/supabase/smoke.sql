-- Smoke test against the supabase/postgres image, run by scripts/test-supabase.sh.
--
-- The main suite runs on stock PostgreSQL with a stand-in role and a stub
-- auth.uid(). This file checks the parts that only exist on Supabase: the
-- installer running as the non-superuser "postgres" role, the automatic grants
-- to anon/authenticated, identity coming from the real auth.uid() and the
-- PostgREST JWT settings, and service_role bypassing RLS but not the lock.
--
-- Output is TAP; the runner fails on any "not ok" line or a plan mismatch.
\set ON_ERROR_STOP on
\pset format unaligned
\pset tuples_only on

create extension if not exists pgtap;

begin;
select plan(22);

-- pgTAP keeps its state in temp tables owned by the current role; share them
-- with the API roles so assertions still work after `set local role`.
do $$
declare
  obj record;
  r   text;
begin
  foreach r in array array['anon', 'authenticated', 'service_role'] loop
    for obj in
      select c.oid::regclass as rel, c.relkind from pg_class c
      where c.relnamespace = pg_my_temp_schema() and c.relkind in ('r', 'S')
    loop
      if obj.relkind = 'S' then
        execute format('grant usage, select, update on sequence %s to %I', obj.rel, r);
      else
        execute format('grant select, insert, update, delete on %s to %I', obj.rel, r);
      end if;
    end loop;
  end loop;
end;
$$;

-- Sets the request settings the way PostgREST does for a signed-in user. Both
-- forms are set because the bare supabase/postgres image ships the legacy
-- auth.uid() that reads only request.jwt.claim.sub; on hosted projects the
-- auth service installs a version that also reads request.jwt.claims.
create function pg_temp.tests_login(sub uuid) returns void language sql as $$
  select set_config('request.jwt.claim.sub', sub::text, true),
         set_config('request.jwt.claims', json_build_object('sub', sub, 'role', 'authenticated')::text, true);
$$;

-- Installer ---------------------------------------------------------------------
select ok(
  not (select rolsuper from pg_roles where rolname = current_user),
  'running as a non-superuser, like the Supabase SQL editor'
);
select ok(
  has_function_privilege('authenticated', 'tenant_guard.has_permission(uuid, text, tenant_guard.access_mode)', 'execute'),
  'installer granted the helpers to authenticated'
);
select ok(
  has_function_privilege('anon', 'tenant_guard.permitted_tenant_ids(text, tenant_guard.access_mode)', 'execute'),
  'installer granted the helpers to anon'
);
select ok(
  not has_function_privilege('authenticated', 'tenant_guard.lock_tenant(uuid, text)', 'execute'),
  'authenticated cannot lock tenants'
);

-- Fixture -------------------------------------------------------------------------
insert into tenant_guard.tenants (id, name) values
  ('a0000000-0000-0000-0000-000000000000', 'Acme'),
  ('b0000000-0000-0000-0000-000000000000', 'Globex');
insert into tenant_guard.tenant_members (tenant_id, user_id, role) values
  ('a0000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-00000000a11c', 'owner'),
  ('b0000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-0000000ca201', 'owner');

-- Supabase's default privileges grant new public tables to the API roles.
create table public.projects (
  id        bigint generated always as identity primary key,
  tenant_id uuid not null references tenant_guard.tenants (id),
  title     text not null
);
create index on public.projects (tenant_id);
select tenant_guard.protect_table('public.projects');

insert into public.projects (tenant_id, title) values
  ('a0000000-0000-0000-0000-000000000000', 'acme roadmap'),
  ('b0000000-0000-0000-0000-000000000000', 'globex plan');

-- Authenticated request, identity from the JWT via auth.uid() ----------------------
set local role authenticated;
select pg_temp.tests_login('00000000-0000-0000-0000-00000000a11c');

select is(auth.uid(), '00000000-0000-0000-0000-00000000a11c'::uuid, 'auth.uid() reads the JWT claims');
select is(tenant_guard.current_user_id(), auth.uid(), 'current_user_id() follows auth.uid()');
select results_eq('select title from public.projects', array['acme roadmap'], 'alice sees only acme rows');
select results_eq('select name from tenant_guard.tenants', array['Acme'], 'alice sees only her tenant');
select throws_ok(
  $$ insert into public.projects (tenant_id, title) values ('b0000000-0000-0000-0000-000000000000', 'planted') $$,
  '42501', null,
  'alice cannot insert into globex'
);
select lives_ok(
  $$ insert into public.projects (tenant_id, title) values ('a0000000-0000-0000-0000-000000000000', 'acme new') $$,
  'alice can insert into acme'
);
select lives_ok($$ select tenant_guard.create_tenant('Alice Side Project') $$, 'alice can create a tenant');
select throws_ok(
  $$ select tenant_guard.unlock_tenant('a0000000-0000-0000-0000-000000000000') $$,
  '42501', null,
  'alice cannot call unlock_tenant'
);

-- Anonymous request ---------------------------------------------------------------
reset role;
set local role anon;
set local request.jwt.claim.sub = '';
set local request.jwt.claims = '{"role": "anon"}';
select is(tenant_guard.current_user_id(), null, 'anon has no user id');
select is_empty('select * from public.projects', 'anon sees no rows (and no permission error)');
select is_empty('select * from tenant_guard.tenants', 'anon sees no tenants');

-- service_role bypasses RLS --------------------------------------------------------
reset role;
set local role service_role;
set local request.jwt.claim.sub = '';
set local request.jwt.claims = '{"role": "service_role"}';
select is((select count(*)::int from public.projects), 3, 'service_role sees every row (BYPASSRLS)');

-- Lock acme -------------------------------------------------------------------------
reset role;
select tenant_guard.lock_tenant('a0000000-0000-0000-0000-000000000000', 'trial ended');

set local role service_role;
select throws_ok(
  $$ insert into public.projects (tenant_id, title) values ('a0000000-0000-0000-0000-000000000000', 'by backend') $$,
  '25006', null,
  'the lock applies to service_role too'
);

reset role;
set local role authenticated;
select pg_temp.tests_login('00000000-0000-0000-0000-00000000a11c');
select ok(tenant_guard.is_locked('a0000000-0000-0000-0000-000000000000'), 'alice sees that acme is locked');
select is((select count(*)::int from public.projects), 2, 'alice can still read while locked');
select throws_ok(
  $$ update public.projects set title = 'edited' $$,
  '25006', null,
  'alice cannot write while locked'
);

reset role;
select ok(tenant_guard.unlock_tenant('a0000000-0000-0000-0000-000000000000'), 'unlock succeeds');
set local role authenticated;
select pg_temp.tests_login('00000000-0000-0000-0000-00000000a11c');
select lives_ok($$ update public.projects set title = 'edited' $$, 'alice can write again after unlock');

select * from finish();
rollback;
