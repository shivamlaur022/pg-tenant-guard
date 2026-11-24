-- pg-tenant-guard 020: role permissions with view/edit access.
--
-- A permission is a free-form name, usually the name of a table or feature
-- ("projects", "invoices", "reports.export"). Each role is granted a set of
-- permissions, each with an access mode:
--
--   view  read only
--   edit  read and write (edit implies view)
--
-- The special permission '*' matches every permission except the built-in
-- ones, whose names start with "tenant_guard.":
--
--   tenant_guard.members  add, change or remove members of a tenant
--   tenant_guard.tenant   change the tenant row itself (e.g. rename it)
--
-- The exception exists so that granting a role '*' edit ("can change all
-- tenant data") does not silently let it promote itself to owner. Built-in
-- permissions must always be granted explicitly.

do $$
begin
  create type tenant_guard.access_mode as enum ('view', 'edit');
exception
  when duplicate_object then null;
end;
$$;

comment on type tenant_guard.access_mode is
  'Access level for a permission; edit implies view (the enum is ordered)';

create table if not exists tenant_guard.role_permissions (
  role       text not null references tenant_guard.roles (name) on update cascade on delete cascade,
  permission text not null check (btrim(permission) <> ''),
  access     tenant_guard.access_mode not null,
  primary key (role, permission)
);

comment on table tenant_guard.role_permissions is
  'Permissions granted to each role. permission = ''*'' matches everything except tenant_guard.* permissions';

insert into tenant_guard.role_permissions (role, permission, access) values
  ('owner',  '*',                    'edit'),
  ('owner',  'tenant_guard.members', 'edit'),
  ('owner',  'tenant_guard.tenant',  'edit'),
  ('editor', '*',                    'edit'),
  ('viewer', '*',                    'view')
on conflict (role, permission) do nothing;

alter table tenant_guard.role_permissions enable row level security;

-- Like roles, the permission matrix is configuration, not tenant data.
drop policy if exists role_permissions_select on tenant_guard.role_permissions;
create policy role_permissions_select on tenant_guard.role_permissions
  for select
  using (true);

-- True when the current user's role in the tenant grants `permission` with
-- at least `mode` access. NULL arguments return false.
--
-- Comparing enum values (`rp.access >= p_mode`) relies on the declaration
-- order of access_mode: view < edit.
create or replace function tenant_guard.has_permission(
  p_tenant_id  uuid,
  p_permission text,
  p_mode       tenant_guard.access_mode default 'view'
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from tenant_guard.tenant_members m
    join tenant_guard.role_permissions rp on rp.role = m.role
    where m.tenant_id = p_tenant_id
      and m.user_id = tenant_guard.current_user_id()
      and rp.access >= p_mode
      and (
        rp.permission = p_permission
        or (rp.permission = '*' and not starts_with(p_permission, 'tenant_guard.'))
      )
  );
$$;

comment on function tenant_guard.has_permission(uuid, text, tenant_guard.access_mode) is
  'True when the current user has `permission` with at least `mode` access in the tenant';

-- Set-returning form for policies:
--
--   tenant_id in (select tenant_guard.permitted_tenant_ids('projects', 'edit'))
--
-- PostgreSQL evaluates the subquery once per statement and then checks each
-- row against the result, instead of calling a function for every row.
create or replace function tenant_guard.permitted_tenant_ids(
  p_permission text,
  p_mode       tenant_guard.access_mode default 'view'
)
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select distinct m.tenant_id
  from tenant_guard.tenant_members m
  join tenant_guard.role_permissions rp on rp.role = m.role
  where m.user_id = tenant_guard.current_user_id()
    and rp.access >= p_mode
    and (
      rp.permission = p_permission
      or (rp.permission = '*' and not starts_with(p_permission, 'tenant_guard.'))
    );
$$;

comment on function tenant_guard.permitted_tenant_ids(text, tenant_guard.access_mode) is
  'Ids of the tenants in which the current user has `permission` with at least `mode` access';

-- Write policies on the kit's own tables -------------------------------------

drop policy if exists tenants_update on tenant_guard.tenants;
create policy tenants_update on tenant_guard.tenants
  for update
  using (id in (select tenant_guard.permitted_tenant_ids('tenant_guard.tenant', 'edit')))
  with check (id in (select tenant_guard.permitted_tenant_ids('tenant_guard.tenant', 'edit')));

drop policy if exists tenant_members_insert on tenant_guard.tenant_members;
create policy tenant_members_insert on tenant_guard.tenant_members
  for insert
  with check (tenant_id in (select tenant_guard.permitted_tenant_ids('tenant_guard.members', 'edit')));

drop policy if exists tenant_members_update on tenant_guard.tenant_members;
create policy tenant_members_update on tenant_guard.tenant_members
  for update
  using (tenant_id in (select tenant_guard.permitted_tenant_ids('tenant_guard.members', 'edit')))
  with check (tenant_id in (select tenant_guard.permitted_tenant_ids('tenant_guard.members', 'edit')));

drop policy if exists tenant_members_delete on tenant_guard.tenant_members;
create policy tenant_members_delete on tenant_guard.tenant_members
  for delete
  using (tenant_id in (select tenant_guard.permitted_tenant_ids('tenant_guard.members', 'edit')));
