-- pg-tenant-guard 040: protect_table() applies the standard tenant policies
-- to any table that has a `tenant_id uuid` column.
--
-- These are DDL helpers for migrations, run by the table owner. They are
-- SECURITY INVOKER on purpose: running them as anyone other than the caller
-- would let a client enable or drop policies on tables it does not own.

-- Applies four policies to `tbl`:
--
--   SELECT  rows of tenants where the user has `permission` view access
--   INSERT  new rows must belong to a tenant where the user has edit access
--   UPDATE  only rows the user can edit, and the new row must still belong
--           to a tenant where the user has edit access (so tenant_id cannot
--           be changed to a tenant the user cannot edit)
--   DELETE  only rows the user can edit
--
-- It also attaches the tenant lock trigger (030_tenant_lock.sql), passing
-- `allow_when_locked` through: the operations that stay allowed on this
-- table while the tenant is locked.
--
-- `permission` defaults to the table's name (without schema), which the
-- default roles match through the '*' wildcard. Safe to call again: the
-- policies are dropped and recreated, so it also works for changing the
-- permission name.
create or replace function tenant_guard.protect_table(
  tbl               regclass,
  permission        text default null,
  allow_when_locked text[] default '{}'
)
returns void
language plpgsql
volatile
set search_path = ''
as $$
declare
  v_attnum     smallint;
  v_permission text;
  v_view_check text;
  v_edit_check text;
  v_policy     name;
begin
  v_attnum := tenant_guard.assert_tenant_table(tbl);

  select coalesce(protect_table.permission, c.relname) into v_permission
  from pg_catalog.pg_class c
  where c.oid = tbl;

  v_view_check := format(
    'tenant_id = any (array(select tenant_guard.permitted_tenant_ids(%L, %L)))', v_permission, 'view');
  v_edit_check := format(
    'tenant_id = any (array(select tenant_guard.permitted_tenant_ids(%L, %L)))', v_permission, 'edit');

  -- With search_path = '', regclass prints schema-qualified, quoted names.
  execute format('alter table %s enable row level security', tbl);

  for v_policy in
    select p.polname from pg_catalog.pg_policy p
    where p.polrelid = tbl
      and p.polname in ('tenant_guard_select', 'tenant_guard_insert',
                        'tenant_guard_update', 'tenant_guard_delete')
  loop
    execute format('drop policy %I on %s', v_policy, tbl);
  end loop;

  execute format('create policy tenant_guard_select on %s for select using (%s)',
                 tbl, v_view_check);
  execute format('create policy tenant_guard_insert on %s for insert with check (%s)',
                 tbl, v_edit_check);
  execute format('create policy tenant_guard_update on %s for update using (%s) with check (%s)',
                 tbl, v_edit_check, v_edit_check);
  execute format('create policy tenant_guard_delete on %s for delete using (%s)',
                 tbl, v_edit_check);

  perform tenant_guard.attach_lock_trigger(tbl, allow_when_locked);

  -- RLS adds a tenant_id filter to every query. Without an index that starts
  -- with tenant_id, that filter is a sequential scan.
  if not exists (
    select 1 from pg_catalog.pg_index i
    where i.indrelid = tbl and i.indkey[0] = v_attnum
  ) then
    raise notice 'protect_table: % has no index starting with tenant_id; consider: create index on % (tenant_id)',
      tbl, tbl;
  end if;
end;
$$;

comment on function tenant_guard.protect_table(regclass, text, text[]) is
  'Enables RLS and applies the tenant_guard policies and lock trigger to a table with a tenant_id uuid column';

-- Removes what protect_table() added (policies and lock trigger). Row-level
-- security stays enabled, so
-- the table becomes deny-all for client roles rather than wide open. Disable
-- it yourself if that is really what you want.
create or replace function tenant_guard.unprotect_table(tbl regclass)
returns void
language plpgsql
volatile
set search_path = ''
as $$
declare
  v_policy name;
begin
  for v_policy in
    select p.polname from pg_catalog.pg_policy p
    where p.polrelid = tbl
      and p.polname in ('tenant_guard_select', 'tenant_guard_insert',
                        'tenant_guard_update', 'tenant_guard_delete')
  loop
    execute format('drop policy %I on %s', v_policy, tbl);
  end loop;

  perform tenant_guard.detach_lock_trigger(tbl);
end;
$$;

comment on function tenant_guard.unprotect_table(regclass) is
  'Drops the tenant_guard policies and lock trigger from a table; RLS stays enabled (deny-all)';

-- Lists tables that have a tenant_id column but are not fully protected:
-- RLS is disabled, a tenant_guard policy is missing, or the lock trigger is
-- missing. Useful as a
-- check in your own migration tests:
--
--   select * from tenant_guard.unprotected_tables();  -- expect no rows
create or replace function tenant_guard.unprotected_tables()
returns setof regclass
language sql
stable
set search_path = ''
as $$
  select c.oid::regclass
  from pg_catalog.pg_class c
  join pg_catalog.pg_namespace n on n.oid = c.relnamespace
  join pg_catalog.pg_attribute a
    on a.attrelid = c.oid and a.attname = 'tenant_id' and a.attnum > 0 and not a.attisdropped
  where c.relkind in ('r', 'p')
    and not c.relispartition
    and n.nspname not in ('pg_catalog', 'information_schema', 'tenant_guard')
    and n.nspname not like 'pg\_%'
    and (
      not c.relrowsecurity
      or (
        select count(*)
        from pg_catalog.pg_policy p
        where p.polrelid = c.oid
          and p.polname in ('tenant_guard_select', 'tenant_guard_insert',
                            'tenant_guard_update', 'tenant_guard_delete')
      ) < 4
      or not exists (
        select 1 from pg_catalog.pg_trigger t
        where t.tgrelid = c.oid and t.tgname = 'tenant_guard_lock'
      )
    )
  order by c.oid::regclass::text;
$$;

comment on function tenant_guard.unprotected_tables() is
  'Tables with a tenant_id column that lack RLS, the tenant_guard policies or the lock trigger';
