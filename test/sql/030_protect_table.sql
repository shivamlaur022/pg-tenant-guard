-- protect_table(): the standard policies on an application table.
begin;
select plan(40);
select tests.share_tap_state();
select tests.seed();

-- An application table, owned by the superuser, with the usual client grants.
create table public.projects (
  id        bigint generated always as identity primary key,
  tenant_id uuid not null references tenant_guard.tenants (id),
  title     text not null
);
create index on public.projects (tenant_id);
grant select, insert, update, delete on public.projects to app_user;

insert into public.projects (tenant_id, title) values
  (tests.tenant_id('acme'),   'acme roadmap'),
  (tests.tenant_id('acme'),   'acme launch'),
  (tests.tenant_id('globex'), 'globex secret plan');

select lives_ok($$ select tenant_guard.protect_table('public.projects') $$, 'protect_table succeeds');
select ok(
  (select relrowsecurity from pg_class where oid = 'public.projects'::regclass),
  'RLS is enabled on the table'
);
select policies_are(
  'public', 'projects',
  array['tenant_guard_select', 'tenant_guard_insert', 'tenant_guard_update', 'tenant_guard_delete'],
  'the four tenant_guard policies are in place'
);
select lives_ok($$ select tenant_guard.protect_table('public.projects') $$, 'protect_table is idempotent');
select policies_are(
  'public', 'projects',
  array['tenant_guard_select', 'tenant_guard_insert', 'tenant_guard_update', 'tenant_guard_delete'],
  'still exactly four policies after a second call'
);

-- Member with edit access: reads and writes their own tenant -----------------------
select tests.authenticate_as(tests.user_id('bob'));
select results_eq(
  'select title from public.projects order by title',
  array['acme launch', 'acme roadmap'],
  'editor sees only their tenant''s rows'
);
select lives_ok(
  format($$ insert into public.projects (tenant_id, title) values (%L, 'acme new') $$, tests.tenant_id('acme')),
  'editor can insert into their tenant'
);
select lives_ok(
  $$ update public.projects set title = 'acme launch v2' where title = 'acme launch' $$,
  'editor can update rows of their tenant'
);
select lives_ok($$ delete from public.projects where title = 'acme new' $$, 'editor can delete rows of their tenant');
select results_eq(
  'select title from public.projects order by title',
  array['acme launch v2', 'acme roadmap'],
  'the editor''s writes took effect'
);

-- The policy must stay index-friendly: with sequential scans discouraged, the
-- planner has to be able to answer the RLS filter from the tenant_id index.
set local enable_seqscan = off;
select matches(
  tests.plan_of('select * from public.projects'),
  'Index',
  'the RLS filter can use the tenant_id index'
);
reset enable_seqscan;

-- Tenant hopping is rejected -----------------------------------------------------
select throws_ok(
  format($$ insert into public.projects (tenant_id, title) values (%L, 'planted') $$, tests.tenant_id('globex')),
  '42501', 'new row violates row-level security policy for table "projects"',
  'insert with another tenant''s tenant_id is rejected'
);
select throws_ok(
  format($$ update public.projects set tenant_id = %L where title = 'acme roadmap' $$, tests.tenant_id('globex')),
  '42501', 'new row violates row-level security policy for table "projects"',
  'update that moves a row to another tenant is rejected'
);
select throws_ok(
  $$ insert into public.projects (tenant_id, title) values (null, 'orphan') $$,
  '42501', null,
  'insert with a NULL tenant_id is rejected by the policy before the NOT NULL check'
);
update public.projects set title = 'hacked' where title = 'globex secret plan';
delete from public.projects where title = 'globex secret plan';

-- Viewer: reads, but cannot write ------------------------------------------------
select tests.authenticate_as(tests.user_id('vera'));
select results_eq(
  'select count(*)::int from public.projects',
  array[2],
  'viewer sees their tenant''s rows'
);
select throws_ok(
  format($$ insert into public.projects (tenant_id, title) values (%L, 'viewer insert') $$, tests.tenant_id('acme')),
  '42501', null,
  'viewer cannot insert'
);
update public.projects set title = 'changed by viewer';
select is(
  (select count(*)::int from public.projects where title = 'changed by viewer'),
  0,
  'viewer update changes no rows'
);
delete from public.projects;
select is((select count(*)::int from public.projects), 2, 'viewer delete removes no rows');

-- Non-member and anonymous: see nothing, change nothing ------------------------------
select tests.authenticate_as(tests.user_id('dave'));
select is_empty('select * from public.projects', 'non-member sees no rows');
select throws_ok(
  format($$ insert into public.projects (tenant_id, title) values (%L, 'dave was here') $$, tests.tenant_id('acme')),
  '42501', null,
  'non-member cannot insert'
);
update public.projects set title = 'dave was here';
delete from public.projects;

select tests.authenticate_anonymous();
select is_empty('select * from public.projects', 'anonymous request sees no rows');
select throws_ok(
  format($$ insert into public.projects (tenant_id, title) values (%L, 'anon') $$, tests.tenant_id('acme')),
  '42501', null,
  'anonymous request cannot insert'
);

reset role;
select results_eq(
  'select title from public.projects order by title',
  array['acme launch v2', 'acme roadmap', 'globex secret plan'],
  'rejected and filtered writes left every row intact'
);

-- Other tenant's owner sees only their own row -------------------------------------
select tests.authenticate_as(tests.user_id('carol'));
select results_eq(
  'select title from public.projects',
  array['globex secret plan'],
  'globex owner sees only globex rows'
);

-- Explicit permission name ---------------------------------------------------------
reset role;
create table public.invoices (
  id        bigint generated always as identity primary key,
  tenant_id uuid not null references tenant_guard.tenants (id),
  amount    numeric not null
);
create index on public.invoices (tenant_id);
grant select, insert, update, delete on public.invoices to app_user;
insert into public.invoices (tenant_id, amount) values (tests.tenant_id('acme'), 100);

insert into tenant_guard.roles (name) values ('billing');
insert into tenant_guard.role_permissions (role, permission, access) values ('billing', 'billing', 'edit');
insert into tenant_guard.tenant_members (tenant_id, user_id, role)
  values (tests.tenant_id('acme'), tests.user_id('bill'), 'billing');
select lives_ok($$ select tenant_guard.protect_table('public.invoices', 'billing') $$, 'protect_table with an explicit permission');

select tests.authenticate_as(tests.user_id('bill'));
select is((select count(*)::int from public.invoices), 1, 'billing role reads invoices');
select lives_ok(
  format($$ insert into public.invoices (tenant_id, amount) values (%L, 50) $$, tests.tenant_id('acme')),
  'billing role writes invoices'
);
select is_empty('select * from public.projects', 'billing role cannot see projects');

-- Policies use the permission name, not the table name, once one is given.
reset role;
insert into tenant_guard.role_permissions (role, permission, access) values ('viewer', 'invoices', 'edit');
select tests.authenticate_as(tests.user_id('vera'));
select throws_ok(
  format($$ insert into public.invoices (tenant_id, amount) values (%L, 1) $$, tests.tenant_id('acme')),
  '42501', null,
  'a grant on the table name does not apply when a permission name was given'
);

-- Validation -----------------------------------------------------------------------
reset role;
create table public.no_tenant (id int);
create table public.text_tenant (tenant_id text);
create view public.a_view as select 1 as tenant_id;
select throws_ok(
  $$ select tenant_guard.protect_table('public.no_tenant') $$,
  '42703', 'protect_table: public.no_tenant has no tenant_id column',
  'a table without tenant_id is rejected'
);
select throws_ok(
  $$ select tenant_guard.protect_table('public.text_tenant') $$,
  '42804', 'protect_table: public.text_tenant.tenant_id must be uuid, not text',
  'a non-uuid tenant_id is rejected'
);
select throws_ok(
  $$ select tenant_guard.protect_table('public.a_view') $$,
  '42809', 'protect_table: public.a_view is not a table',
  'a view is rejected'
);

-- unprotected_tables() and unprotect_table() -------------------------------------------
create table public.leaky (tenant_id uuid, body text);
select results_eq(
  'select t::text from tenant_guard.unprotected_tables() t',
  array['leaky', 'text_tenant'],
  'unprotected_tables() lists tables with tenant_id but without the policies'
);
select lives_ok($$ select tenant_guard.unprotect_table('public.projects') $$, 'unprotect_table succeeds');
select policies_are('public', 'projects', array[]::name[], 'unprotect_table drops the policies');
select ok(
  (select relrowsecurity from pg_class where oid = 'public.projects'::regclass),
  'RLS stays enabled after unprotect_table'
);
select tests.authenticate_as(tests.user_id('alice'));
select is_empty('select * from public.projects', 'an unprotected table is deny-all, not open');
reset role;
select ok(
  'public.projects'::regclass in (select tenant_guard.unprotected_tables()),
  'unprotected_tables() reports the table again'
);

-- Client roles cannot run the DDL helpers ---------------------------------------------
select ok(
  not has_function_privilege('app_user', 'tenant_guard.protect_table(regclass, text)', 'execute'),
  'clients cannot call protect_table'
);
select ok(
  not has_function_privilege('app_user', 'tenant_guard.unprotect_table(regclass)', 'execute'),
  'clients cannot call unprotect_table'
);

select * from finish();
rollback;
