-- Tenant lock: locked tenants are read-only, with per-table allow-lists.
begin;
select plan(35);
select tests.share_tap_state();
select tests.seed();

create table public.projects (
  id        bigint generated always as identity primary key,
  tenant_id uuid not null references tenant_guard.tenants (id),
  title     text not null
);
create index on public.projects (tenant_id);

-- Payments must keep working while locked: that is how a tenant pays to
-- unlock. Inserting and updating is allowed, deleting is not.
create table public.payments (
  id        bigint generated always as identity primary key,
  tenant_id uuid not null references tenant_guard.tenants (id),
  amount    numeric not null,
  status    text not null default 'pending'
);
create index on public.payments (tenant_id);

grant select, insert, update, delete on public.projects, public.payments to app_user;

select tenant_guard.protect_table('public.projects');
select tenant_guard.protect_table('public.payments', allow_when_locked => array['insert', 'UPDATE']);

insert into public.projects (tenant_id, title) values
  (tests.tenant_id('acme'),   'acme roadmap'),
  (tests.tenant_id('globex'), 'globex plan');
insert into public.payments (tenant_id, amount) values (tests.tenant_id('acme'), 10);

-- Structure and privileges ------------------------------------------------------
select has_trigger('public', 'projects', 'tenant_guard_lock', 'protect_table attaches the lock trigger');
select trigger_is('public', 'projects', 'tenant_guard_lock', 'tenant_guard', 'enforce_tenant_lock',
                  'the trigger calls enforce_tenant_lock()');
select ok(
  not has_table_privilege('app_user', 'tenant_guard.tenant_locks', 'select'),
  'clients cannot read tenant_locks'
);
select ok(
  not has_function_privilege('app_user', 'tenant_guard.lock_tenant(uuid, text)', 'execute'),
  'clients cannot lock tenants'
);
select ok(
  not has_function_privilege('app_user', 'tenant_guard.unlock_tenant(uuid)', 'execute'),
  'clients cannot unlock tenants'
);

-- Lock acme ------------------------------------------------------------------------
select lives_ok(
  format($$ select tenant_guard.lock_tenant(%L, 'subscription expired') $$, tests.tenant_id('acme')),
  'lock_tenant succeeds'
);
select lives_ok(
  format($$ select tenant_guard.lock_tenant(%L, 'payment overdue') $$, tests.tenant_id('acme')),
  'locking an already locked tenant updates the reason'
);
select is(
  (select reason from tenant_guard.tenant_locks where tenant_id = tests.tenant_id('acme')),
  'payment overdue',
  'the latest reason is stored'
);
select throws_ok(
  format($$ select tenant_guard.lock_tenant(%L) $$, tests.tenant_id('nobody')),
  'P0002', null,
  'locking an unknown tenant fails'
);

-- Reads keep working, writes are rejected ---------------------------------------------
select tests.authenticate_as(tests.user_id('bob'));
select ok(tenant_guard.is_locked(tests.tenant_id('acme')), 'is_locked() reports the lock to members');
select is(tenant_guard.is_locked(tests.tenant_id('globex')), null, 'is_locked() is NULL for tenants the user is not in');
select results_eq(
  'select title from public.projects',
  array['acme roadmap'],
  'reads keep working on a locked tenant'
);
select throws_ok(
  format($$ insert into public.projects (tenant_id, title) values (%L, 'new') $$, tests.tenant_id('acme')),
  '25006',
  format('tenant %s is locked: INSERT on public.projects is not allowed', tests.tenant_id('acme')),
  'insert into a locked tenant is rejected'
);
select throws_ok(
  $$ update public.projects set title = 'changed' $$,
  '25006', null,
  'update in a locked tenant is rejected'
);
select throws_ok(
  $$ delete from public.projects $$,
  '25006', null,
  'delete in a locked tenant is rejected'
);
select is(
  tests.error_detail($$ delete from public.projects $$),
  'Reason: payment overdue',
  'the error detail carries the lock reason'
);

-- Allow-listed operations stay writable -------------------------------------------------
select lives_ok(
  format($$ insert into public.payments (tenant_id, amount) values (%L, 99) $$, tests.tenant_id('acme')),
  'allow-listed INSERT works while locked'
);
select lives_ok(
  $$ update public.payments set status = 'paid' $$,
  'allow-listed UPDATE works while locked'
);
select is(
  (select count(*)::int from public.payments where status = 'paid'), 2,
  'the allow-listed writes took effect'
);
select throws_ok(
  $$ delete from public.payments $$,
  '25006', null,
  'operations missing from the allow-list are still rejected'
);

-- The lock is per tenant --------------------------------------------------------------
select tests.authenticate_as(tests.user_id('carol'));
select lives_ok(
  format($$ insert into public.projects (tenant_id, title) values (%L, 'globex new') $$, tests.tenant_id('globex')),
  'other tenants are unaffected'
);

-- The lock is not an RLS policy: it applies to privileged roles as well -----------------
reset role;
select throws_ok(
  format($$ insert into public.projects (tenant_id, title) values (%L, 'by owner') $$, tests.tenant_id('acme')),
  '25006', null,
  'the lock also applies to the table owner'
);
select throws_ok(
  format($$ update public.projects set tenant_id = %L where title = 'globex plan' $$, tests.tenant_id('acme')),
  '25006', null,
  'a row cannot be moved into a locked tenant'
);

-- Locking cannot be undone through tenant-level permissions --------------------------
select tests.authenticate_as(tests.user_id('alice'));
select throws_ok(
  format($$ delete from tenant_guard.tenant_locks where tenant_id = %L $$, tests.tenant_id('acme')),
  '42501', null,
  'even the tenant owner cannot remove the lock row'
);
select throws_ok(
  format($$ select tenant_guard.unlock_tenant(%L) $$, tests.tenant_id('acme')),
  '42501', null,
  'even the tenant owner cannot call unlock_tenant'
);

-- Unlock restores writes ------------------------------------------------------------
reset role;
select ok(tenant_guard.unlock_tenant(tests.tenant_id('acme')), 'unlock_tenant returns true for a locked tenant');
select ok(not tenant_guard.unlock_tenant(tests.tenant_id('acme')), 'unlock_tenant returns false when not locked');

select tests.authenticate_as(tests.user_id('bob'));
select ok(not tenant_guard.is_locked(tests.tenant_id('acme')), 'is_locked() is false after unlock');
select lives_ok(
  format($$ insert into public.projects (tenant_id, title) values (%L, 'after unlock') $$, tests.tenant_id('acme')),
  'insert works again after unlock'
);
select lives_ok($$ delete from public.payments $$, 'delete works again after unlock');

-- attach_lock_trigger on its own ----------------------------------------------------
reset role;
create table public.exports (tenant_id uuid not null, requested_at timestamptz default now());
select lives_ok(
  $$ select tenant_guard.attach_lock_trigger('public.exports', array['insert']) $$,
  'attach_lock_trigger works without protect_table (operations are case-insensitive)'
);
select tenant_guard.lock_tenant(tests.tenant_id('acme'));
select lives_ok(
  format($$ insert into public.exports (tenant_id) values (%L) $$, tests.tenant_id('acme')),
  'allow-listed insert into exports while locked'
);
select throws_ok(
  $$ select tenant_guard.attach_lock_trigger('public.exports', array['TRUNCATE']) $$,
  '22023', null,
  'unknown operations are rejected'
);
select lives_ok($$ select tenant_guard.detach_lock_trigger('public.exports') $$, 'detach_lock_trigger succeeds');
select hasnt_trigger('public', 'exports', 'tenant_guard_lock', 'the trigger is gone');

select * from finish();
rollback;
