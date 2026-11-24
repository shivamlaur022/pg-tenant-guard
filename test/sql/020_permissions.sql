-- Role permissions: view vs edit, the '*' wildcard, built-in permissions.
begin;
select plan(27);
select tests.share_tap_state();
select tests.seed();

-- Extra configuration, set up as the superuser:
--   viewers may also edit comments;
--   a "billing" role that can only work with invoices.
insert into tenant_guard.role_permissions (role, permission, access) values ('viewer', 'comments', 'edit');
insert into tenant_guard.roles (name) values ('billing');
insert into tenant_guard.role_permissions (role, permission, access) values ('billing', 'invoices', 'edit');
insert into tenant_guard.tenant_members (tenant_id, user_id, role)
  values (tests.tenant_id('acme'), tests.user_id('bill'), 'billing');

-- viewer ---------------------------------------------------------------------
select tests.authenticate_as(tests.user_id('vera'));
select ok(tenant_guard.has_permission(tests.tenant_id('acme'), 'projects', 'view'), 'viewer can view projects');
select ok(not tenant_guard.has_permission(tests.tenant_id('acme'), 'projects', 'edit'), 'viewer cannot edit projects');
select ok(tenant_guard.has_permission(tests.tenant_id('acme'), 'projects'), 'mode defaults to view');
select ok(tenant_guard.has_permission(tests.tenant_id('acme'), 'comments', 'edit'), 'an explicit grant adds to the wildcard');
select results_eq(
  $$ select tenant_guard.permitted_tenant_ids('projects', 'view') $$,
  array[tests.tenant_id('acme')],
  'permitted_tenant_ids: viewer can view projects in acme'
);
select is_empty(
  $$ select tenant_guard.permitted_tenant_ids('projects', 'edit') $$,
  'permitted_tenant_ids: viewer can edit projects nowhere'
);

-- editor ---------------------------------------------------------------------
select tests.authenticate_as(tests.user_id('bob'));
select ok(tenant_guard.has_permission(tests.tenant_id('acme'), 'projects', 'edit'), 'editor can edit projects');
select ok(tenant_guard.has_permission(tests.tenant_id('acme'), 'projects', 'view'), 'edit implies view');
select ok(not tenant_guard.has_permission(tests.tenant_id('globex'), 'projects', 'view'), 'editor has no access to another tenant');
select ok(
  not tenant_guard.has_permission(tests.tenant_id('acme'), 'tenant_guard.members', 'edit'),
  'the * wildcard does not grant built-in tenant_guard.* permissions'
);
select results_eq(
  $$ select tenant_guard.permitted_tenant_ids('projects', 'edit') $$,
  array[tests.tenant_id('acme')],
  'permitted_tenant_ids: editor can edit projects in acme only'
);

-- owner ----------------------------------------------------------------------
select tests.authenticate_as(tests.user_id('alice'));
select ok(tenant_guard.has_permission(tests.tenant_id('acme'), 'tenant_guard.members', 'edit'), 'owner can manage members');
select ok(tenant_guard.has_permission(tests.tenant_id('acme'), 'tenant_guard.tenant', 'edit'), 'owner can change the tenant');

-- role without the wildcard ---------------------------------------------------
select tests.authenticate_as(tests.user_id('bill'));
select ok(tenant_guard.has_permission(tests.tenant_id('acme'), 'invoices', 'edit'), 'billing can edit invoices');
select ok(not tenant_guard.has_permission(tests.tenant_id('acme'), 'projects', 'view'), 'billing cannot view projects');

-- non-member and anonymous ------------------------------------------------------
select tests.authenticate_as(tests.user_id('dave'));
select ok(not tenant_guard.has_permission(tests.tenant_id('acme'), 'projects', 'view'), 'non-member has no permissions');
select is_empty($$ select tenant_guard.permitted_tenant_ids('projects') $$, 'non-member: no permitted tenants');

select tests.authenticate_anonymous();
select ok(not tenant_guard.has_permission(tests.tenant_id('acme'), 'projects', 'view'), 'anonymous has no permissions');

-- argument handling ------------------------------------------------------------
select tests.authenticate_as(tests.user_id('alice'));
select ok(not tenant_guard.has_permission(tests.tenant_id('acme'), 'projects', null), 'NULL mode is denied');
select ok(not tenant_guard.has_permission(tests.tenant_id('acme'), null, 'view'), 'NULL permission is denied');
select ok(not tenant_guard.has_permission(null, 'projects', 'view'), 'NULL tenant is denied');
select throws_ok(
  $$ select tenant_guard.has_permission(tests.tenant_id('acme'), 'projects', 'admin') $$,
  '22P02', null,
  'an unknown mode is rejected'
);

-- member management follows tenant_guard.members --------------------------------
select tests.authenticate_as(tests.user_id('bob'));
select throws_ok(
  format($$ insert into tenant_guard.tenant_members (tenant_id, user_id, role) values (%L, %L, 'owner') $$,
         tests.tenant_id('acme'), tests.user_id('bob2')),
  '42501', null,
  'editor (wildcard only) cannot add members'
);

reset role;
insert into tenant_guard.role_permissions (role, permission, access) values ('editor', 'tenant_guard.members', 'edit');
select tests.authenticate_as(tests.user_id('bob'));
select lives_ok(
  format($$ insert into tenant_guard.tenant_members (tenant_id, user_id, role) values (%L, %L, 'viewer') $$,
         tests.tenant_id('acme'), tests.user_id('bob2')),
  'editor can add members once granted tenant_guard.members'
);

-- configuration is read-only for clients --------------------------------------
select results_eq(
  $$ select count(*)::int from tenant_guard.role_permissions where role = 'owner' $$,
  array[3],
  'clients can read the permission matrix'
);
select throws_ok(
  $$ insert into tenant_guard.role_permissions (role, permission, access) values ('viewer', '*', 'edit') $$,
  '42501', null,
  'clients cannot change the permission matrix'
);
select throws_ok(
  $$ insert into tenant_guard.roles (name) values ('superuser') $$,
  '42501', null,
  'clients cannot create roles'
);

select * from finish();
rollback;
