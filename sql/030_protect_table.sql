-- pg-tenant-guard 030: protect_table() applies the standard tenant policies
-- to any table that has a `tenant_id uuid` column.
--
-- These are DDL helpers for migrations, run by the table owner. They are
-- SECURITY INVOKER on purpose: running them as anyone other than the caller
-- would let a client enable or drop policies on tables it does not own.

-- Applies four policies to `p_table`:
--
--   SELECT  rows of tenants where the user has `permission` view access
--   INSERT  new rows must belong to a tenant where the user has edit access
--   UPDATE  only rows the user can edit, and the new row must still belong
--           to a tenant where the user has edit access (so tenant_id cannot
--           be changed to a tenant the user cannot edit)
--   DELETE  only rows the user can edit
--
-- `p_permission` defaults to the table's name (without schema), which the
-- default roles match through the '*' wildcard. Safe to call again: the
-- policies are dropped and recreated, so it also works for changing the
-- permission name.
create or replace function tenant_guard.protect_table(
  p_table      regclass,
  p_permission text default null
)
returns void
language plpgsql
volatile
set search_path = ''
as $$
declare
  v_relkind    "char";
  v_relname    name;
  v_col_type   regtype;
  v_col_attnum smallint;
  v_permission text;
  v_view_check text;
  v_edit_check text;
  v_policy     name;
begin
  select c.relkind, c.relname into v_relkind, v_relname
  from pg_catalog.pg_class c
  where c.oid = p_table;

  if v_relkind is null or v_relkind not in ('r', 'p') then
    raise exception 'protect_table: % is not a table', p_table
      using errcode = 'wrong_object_type';
  end if;

  select a.atttypid::regtype, a.attnum into v_col_type, v_col_attnum
  from pg_catalog.pg_attribute a
  where a.attrelid = p_table
    and a.attname = 'tenant_id'
    and a.attnum > 0
    and not a.attisdropped;

  if v_col_type is null then
    raise exception 'protect_table: % has no tenant_id column', p_table
      using errcode = 'undefined_column';
  end if;

  if v_col_type <> 'uuid'::regtype then
    raise exception 'protect_table: %.tenant_id must be uuid, not %', p_table, v_col_type
      using errcode = 'datatype_mismatch';
  end if;

  v_permission := coalesce(p_permission, v_relname);

  v_view_check := format(
    'tenant_id = any (array(select tenant_guard.permitted_tenant_ids(%L, %L)))', v_permission, 'view');
  v_edit_check := format(
    'tenant_id = any (array(select tenant_guard.permitted_tenant_ids(%L, %L)))', v_permission, 'edit');

  -- With search_path = '', regclass prints schema-qualified, quoted names.
  execute format('alter table %s enable row level security', p_table);

  for v_policy in
    select p.polname from pg_catalog.pg_policy p
    where p.polrelid = p_table
      and p.polname in ('tenant_guard_select', 'tenant_guard_insert',
                        'tenant_guard_update', 'tenant_guard_delete')
  loop
    execute format('drop policy %I on %s', v_policy, p_table);
  end loop;

  execute format('create policy tenant_guard_select on %s for select using (%s)',
                 p_table, v_view_check);
  execute format('create policy tenant_guard_insert on %s for insert with check (%s)',
                 p_table, v_edit_check);
  execute format('create policy tenant_guard_update on %s for update using (%s) with check (%s)',
                 p_table, v_edit_check, v_edit_check);
  execute format('create policy tenant_guard_delete on %s for delete using (%s)',
                 p_table, v_edit_check);

  -- RLS adds a tenant_id filter to every query. Without an index that starts
  -- with tenant_id, that filter is a sequential scan.
  if not exists (
    select 1 from pg_catalog.pg_index i
    where i.indrelid = p_table and i.indkey[0] = v_col_attnum
  ) then
    raise notice 'protect_table: % has no index starting with tenant_id; consider: create index on % (tenant_id)',
      p_table, p_table;
  end if;
end;
$$;

comment on function tenant_guard.protect_table(regclass, text) is
  'Enables RLS on a table with a tenant_id uuid column and applies the tenant_guard policies';

-- Removes what protect_table() added. Row-level security stays enabled, so
-- the table becomes deny-all for client roles rather than wide open. Disable
-- it yourself if that is really what you want.
create or replace function tenant_guard.unprotect_table(p_table regclass)
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
    where p.polrelid = p_table
      and p.polname in ('tenant_guard_select', 'tenant_guard_insert',
                        'tenant_guard_update', 'tenant_guard_delete')
  loop
    execute format('drop policy %I on %s', v_policy, p_table);
  end loop;
end;
$$;

comment on function tenant_guard.unprotect_table(regclass) is
  'Drops the tenant_guard policies from a table; RLS stays enabled (deny-all)';

-- Lists tables that have a tenant_id column but are not protected: either
-- RLS is disabled or the tenant_guard policies are missing. Useful as a
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
    )
  order by c.oid::regclass::text;
$$;

comment on function tenant_guard.unprotected_tables() is
  'Tables with a tenant_id column that lack RLS or the tenant_guard policies';
