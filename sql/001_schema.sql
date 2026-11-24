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
