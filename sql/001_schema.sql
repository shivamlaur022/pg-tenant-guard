-- pg-tenant-guard 001: schema and caller identity.
--
-- Everything this kit creates lives in the tenant_guard schema so it does not
-- collide with application objects and can be dropped in one statement.

create schema if not exists tenant_guard;

comment on schema tenant_guard is
  'pg-tenant-guard: tenant isolation (RLS) and tenant lock helpers';

-- Nothing in this schema is reachable by default. Client roles are granted
-- access explicitly with tenant_guard.grant_to() (see the grants file).
revoke all on schema tenant_guard from public;

-- Installed version. scripts/build.sh reads the version from this function
-- for the header of dist/pg-tenant-guard.sql.
create or replace function tenant_guard.version()
returns text
language sql
immutable
set search_path = ''
as $$ select '0.1.0' $$;

comment on function tenant_guard.version() is 'Installed pg-tenant-guard version';

-- Returns the id of the end user making the current request, or NULL for an
-- anonymous request. Resolution order:
--
--   1. auth.uid(), when such a function exists (Supabase).
--   2. The PostgREST JWT settings: request.jwt.claim.sub, then the "sub" key
--      of request.jwt.claims.
--   3. The tenant_guard.user_id setting, for applications that connect to
--      plain PostgreSQL and run `set local tenant_guard.user_id = '...'`
--      at the start of each transaction.
--
-- The function only reads session state, so it runs with the privileges of
-- the caller (SECURITY INVOKER). To use a different source of identity,
-- replace it with `create or replace function tenant_guard.current_user_id()`;
-- every other helper goes through this function.
--
-- PL/pgSQL plans statements lazily, so the reference to auth.uid() below is
-- only resolved when that branch runs. The function can therefore be created
-- on databases that have no auth schema.
create or replace function tenant_guard.current_user_id()
returns uuid
language plpgsql
stable
set search_path = ''
as $$
declare
  claim text;
begin
  if to_regprocedure('auth.uid()') is not null then
    return auth.uid();
  end if;

  claim := nullif(current_setting('request.jwt.claim.sub', true), '');

  if claim is null then
    claim := nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub';
  end if;

  if claim is null then
    claim := nullif(current_setting('tenant_guard.user_id', true), '');
  end if;

  -- An id that is not a valid uuid raises invalid_text_representation
  -- (22P02). Failing loudly is deliberate: a malformed identity must never
  -- be treated as anonymous or matched loosely.
  return claim::uuid;
end;
$$;

comment on function tenant_guard.current_user_id() is
  'Id of the requesting end user: auth.uid() if present, else JWT claim sub, else the tenant_guard.user_id setting';

-- Internal: checks that a relation is a table with a `tenant_id uuid` column
-- and returns that column's attribute number. Used by the DDL helpers.
create or replace function tenant_guard.assert_tenant_table(tbl regclass)
returns smallint
language plpgsql
stable
set search_path = ''
as $$
declare
  v_relkind "char";
  v_type    regtype;
  v_attnum  smallint;
begin
  select c.relkind into v_relkind
  from pg_catalog.pg_class c
  where c.oid = tbl;

  if v_relkind is null or v_relkind not in ('r', 'p') then
    raise exception '% is not a table', tbl
      using errcode = 'wrong_object_type';
  end if;

  select a.atttypid::regtype, a.attnum into v_type, v_attnum
  from pg_catalog.pg_attribute a
  where a.attrelid = tbl
    and a.attname = 'tenant_id'
    and a.attnum > 0
    and not a.attisdropped;

  if v_type is null then
    raise exception '% has no tenant_id column', tbl
      using errcode = 'undefined_column';
  end if;

  if v_type <> 'uuid'::regtype then
    raise exception '%.tenant_id must be uuid, not %', tbl, v_type
      using errcode = 'datatype_mismatch';
  end if;

  return v_attnum;
end;
$$;

comment on function tenant_guard.assert_tenant_table(regclass) is
  'Internal: raises unless the relation is a table with a tenant_id uuid column';
