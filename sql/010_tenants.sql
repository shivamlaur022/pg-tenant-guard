-- pg-tenant-guard 010: tenants, roles, memberships and membership helpers.

-- Roles a member can hold inside a tenant. Roles are global (the same set for
-- every tenant); what each role may do is defined in 020_permissions.sql.
create table if not exists tenant_guard.roles (
  name        text primary key check (name ~ '^[a-z][a-z0-9_]*$'),
  description text
);

insert into tenant_guard.roles (name, description) values
  ('owner',  'Full control of the tenant, including members and settings'),
  ('editor', 'Can read and change tenant data'),
  ('viewer', 'Can read tenant data')
on conflict (name) do nothing;

create table if not exists tenant_guard.tenants (
  id         uuid primary key default gen_random_uuid(),
  name       text not null check (btrim(name) <> ''),
  created_at timestamptz not null default now()
);

create table if not exists tenant_guard.tenant_members (
  tenant_id  uuid not null references tenant_guard.tenants (id) on delete cascade,
  user_id    uuid not null,
  role       text not null references tenant_guard.roles (name) on update cascade,
  created_at timestamptz not null default now(),
  primary key (tenant_id, user_id)
);

-- Every access check looks up the current user's memberships. This index
-- answers "which tenants does user X belong to, and with which role" with an
-- index-only scan.
create index if not exists tenant_members_user_idx
  on tenant_guard.tenant_members (user_id) include (tenant_id, role);

comment on table tenant_guard.tenants is 'One row per tenant (organisation, workspace, school, ...)';
comment on table tenant_guard.tenant_members is 'Which users belong to which tenant, and with which role';
comment on table tenant_guard.roles is 'Roles a member can hold; permissions per role live in role_permissions';

-- Membership helpers ---------------------------------------------------------
--
-- These read tenant_members, which is itself protected by RLS. They are
-- SECURITY DEFINER so that a policy on tenant_members can call them without
-- recursing into its own policy, and so that callers never need direct access
-- to the membership table. Each one pins search_path to '' and fully
-- qualifies every name, so a caller cannot redirect a lookup by creating
-- objects in a schema that appears earlier on their search_path.

create or replace function tenant_guard.is_member(p_tenant_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from tenant_guard.tenant_members m
    where m.tenant_id = p_tenant_id
      and m.user_id = tenant_guard.current_user_id()
  );
$$;

comment on function tenant_guard.is_member(uuid) is
  'True when the current user is a member of the tenant';

create or replace function tenant_guard.member_role(p_tenant_id uuid)
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select m.role
  from tenant_guard.tenant_members m
  where m.tenant_id = p_tenant_id
    and m.user_id = tenant_guard.current_user_id();
$$;

comment on function tenant_guard.member_role(uuid) is
  'Role of the current user in the tenant, or NULL when not a member';

-- Set-returning form for policies: `tenant_id in (select tenant_guard.my_tenant_ids())`
-- is evaluated once per statement instead of once per row.
create or replace function tenant_guard.my_tenant_ids()
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select m.tenant_id
  from tenant_guard.tenant_members m
  where m.user_id = tenant_guard.current_user_id();
$$;

comment on function tenant_guard.my_tenant_ids() is
  'Ids of every tenant the current user belongs to';

-- Creates a tenant and makes the calling user its owner, in one step. Clients
-- have no INSERT privilege on tenants, so this is the only self-service way to
-- create one.
create or replace function tenant_guard.create_tenant(p_name text)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_user   uuid := tenant_guard.current_user_id();
  v_tenant uuid;
begin
  if v_user is null then
    raise exception 'create_tenant requires an authenticated user'
      using errcode = 'insufficient_privilege';
  end if;

  insert into tenant_guard.tenants (name) values (p_name)
  returning id into v_tenant;

  insert into tenant_guard.tenant_members (tenant_id, user_id, role)
  values (v_tenant, v_user, 'owner');

  return v_tenant;
end;
$$;

comment on function tenant_guard.create_tenant(text) is
  'Creates a tenant owned by the current user and returns its id';

-- Row-level security on the kit's own tables ---------------------------------

alter table tenant_guard.tenants enable row level security;
alter table tenant_guard.tenant_members enable row level security;
alter table tenant_guard.roles enable row level security;

drop policy if exists tenants_select on tenant_guard.tenants;
create policy tenants_select on tenant_guard.tenants
  for select
  using (id in (select tenant_guard.my_tenant_ids()));

drop policy if exists tenants_update on tenant_guard.tenants;
create policy tenants_update on tenant_guard.tenants
  for update
  using (tenant_guard.member_role(id) = 'owner')
  with check (tenant_guard.member_role(id) = 'owner');

-- Members can see who else belongs to their tenants.
drop policy if exists tenant_members_select on tenant_guard.tenant_members;
create policy tenant_members_select on tenant_guard.tenant_members
  for select
  using (tenant_id in (select tenant_guard.my_tenant_ids()));

drop policy if exists tenant_members_insert on tenant_guard.tenant_members;
create policy tenant_members_insert on tenant_guard.tenant_members
  for insert
  with check (tenant_guard.member_role(tenant_id) = 'owner');

drop policy if exists tenant_members_update on tenant_guard.tenant_members;
create policy tenant_members_update on tenant_guard.tenant_members
  for update
  using (tenant_guard.member_role(tenant_id) = 'owner')
  with check (tenant_guard.member_role(tenant_id) = 'owner');

drop policy if exists tenant_members_delete on tenant_guard.tenant_members;
create policy tenant_members_delete on tenant_guard.tenant_members
  for delete
  using (tenant_guard.member_role(tenant_id) = 'owner');

-- Role definitions are not secret; anyone with access to the schema may read them.
drop policy if exists roles_select on tenant_guard.roles;
create policy roles_select on tenant_guard.roles
  for select
  using (true);
