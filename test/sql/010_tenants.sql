-- Tenants, memberships and the membership helpers.
begin;
select plan(26);
select tests.share_tap_state();
select tests.seed();

-- Structure ------------------------------------------------------------------
select has_table('tenant_guard', 'tenants', 'tenants table exists');
select has_table('tenant_guard', 'tenant_members', 'tenant_members table exists');
select col_is_pk('tenant_guard', 'tenant_members', array['tenant_id', 'user_id'], 'one membership per user and tenant');
select is(
  (select bool_and(relrowsecurity) from pg_class
   where oid in ('tenant_guard.tenants'::regclass, 'tenant_guard.tenant_members'::regclass)),
  true,
  'RLS is enabled on tenants and tenant_members'
);

-- A member sees their own tenant and nothing else -----------------------------
select tests.authenticate_as(tests.user_id('alice'));

select ok(tenant_guard.is_member(tests.tenant_id('acme')), 'alice is a member of acme');
select ok(not tenant_guard.is_member(tests.tenant_id('globex')), 'alice is not a member of globex');
select is(tenant_guard.member_role(tests.tenant_id('acme')), 'owner', 'alice is the owner of acme');
select is(tenant_guard.member_role(tests.tenant_id('globex')), null, 'alice has no role in globex');
select results_eq(
  'select tenant_guard.my_tenant_ids()',
  array[tests.tenant_id('acme')],
  'my_tenant_ids() returns only acme for alice'
);
select results_eq('select name from tenant_guard.tenants', array['Acme'], 'alice sees only Acme');
select is(
  (select count(*)::int from tenant_guard.tenant_members), 3,
  'alice sees the three acme memberships and none from globex'
);

-- A non-member sees nothing --------------------------------------------------
select tests.authenticate_as(tests.user_id('dave'));
select is_empty('select * from tenant_guard.tenants', 'dave sees no tenants');
select is_empty('select * from tenant_guard.tenant_members', 'dave sees no memberships');
select ok(not tenant_guard.is_member(tests.tenant_id('acme')), 'dave is not a member of acme');

select tests.authenticate_anonymous();
select is_empty('select * from tenant_guard.tenants', 'an anonymous request sees no tenants');

-- create_tenant ---------------------------------------------------------------
select tests.authenticate_as(tests.user_id('dave'));
select lives_ok($$ select tenant_guard.create_tenant('Dave Co') $$, 'dave can create a tenant');
select results_eq('select name from tenant_guard.tenants', array['Dave Co'], 'dave now sees his new tenant');
select results_eq(
  'select role from tenant_guard.tenant_members',
  array['owner'],
  'the creator becomes owner'
);

select tests.authenticate_anonymous();
select throws_ok(
  $$ select tenant_guard.create_tenant('Nobody Inc') $$,
  '42501', 'create_tenant requires an authenticated user',
  'anonymous requests cannot create tenants'
);
select throws_ok(
  $$ insert into tenant_guard.tenants (name) values ('Sneaky') $$,
  '42501', null,
  'clients cannot insert into tenants directly'
);

-- Managing members (owner only for now) --------------------------------------
select tests.authenticate_as(tests.user_id('alice'));
select lives_ok(
  format($$ insert into tenant_guard.tenant_members (tenant_id, user_id, role) values (%L, %L, 'viewer') $$,
         tests.tenant_id('acme'), tests.user_id('erin')),
  'an owner can add a member to their tenant'
);
select throws_ok(
  format($$ insert into tenant_guard.tenant_members (tenant_id, user_id, role) values (%L, %L, 'owner') $$,
         tests.tenant_id('globex'), tests.user_id('alice')),
  '42501', null,
  'an owner cannot add members to another tenant'
);
select throws_ok(
  format($$ update tenant_guard.tenant_members set tenant_id = %L where user_id = %L $$,
         tests.tenant_id('globex'), tests.user_id('bob')),
  '42501', null,
  'a membership cannot be moved to another tenant'
);

select tests.authenticate_as(tests.user_id('bob'));
select throws_ok(
  format($$ insert into tenant_guard.tenant_members (tenant_id, user_id, role) values (%L, %L, 'owner') $$,
         tests.tenant_id('acme'), tests.user_id('mallory')),
  '42501', null,
  'an editor cannot add members'
);

-- Renaming a tenant -----------------------------------------------------------
select tests.authenticate_as(tests.user_id('carol'));
update tenant_guard.tenants set name = 'Hijacked' where id = tests.tenant_id('acme');
select tests.authenticate_as(tests.user_id('alice'));
select results_eq('select name from tenant_guard.tenants', array['Acme'], 'a non-member cannot rename a tenant');
update tenant_guard.tenants set name = 'Acme Ltd' where id = tests.tenant_id('acme');
select results_eq('select name from tenant_guard.tenants', array['Acme Ltd'], 'the owner can rename their tenant');

select * from finish();
rollback;
