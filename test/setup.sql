-- Test fixtures shared by every file in test/sql. Run once after install.

-- An unprivileged role that stands in for the API role of a real application
-- (Supabase "authenticated", or the role your backend connects as).
create role app_user nologin noinherit;

-- Helpers for switching identity inside a test transaction.
create schema tests;
grant usage on schema tests to public;

-- Acts as end user `user_id` for the rest of the transaction: switches to the
-- unprivileged role (so RLS applies) and sets the identity GUC.
create function tests.authenticate_as(user_id uuid)
returns void
language plpgsql
as $$
begin
  perform set_config('tenant_guard.user_id', user_id::text, true);
  perform set_config('role', 'app_user', true);
end;
$$;

-- Acts as an anonymous request: unprivileged role, no identity.
create function tests.authenticate_anonymous()
returns void
language plpgsql
as $$
begin
  perform set_config('tenant_guard.user_id', '', true);
  perform set_config('role', 'app_user', true);
end;
$$;

-- pgTAP keeps its bookkeeping in temporary tables created by the role that
-- called plan(). Let app_user write to them so assertions can run after a
-- role switch. Call right after plan().
create function tests.share_tap_state()
returns void
language plpgsql
as $$
declare
  obj record;
begin
  for obj in
    select c.oid::regclass as rel, c.relkind
    from pg_class c
    where c.relnamespace = pg_my_temp_schema()
      and c.relkind in ('r', 'S')
  loop
    if obj.relkind = 'S' then
      execute format('grant usage, select, update on sequence %s to app_user', obj.rel);
    else
      execute format('grant select, insert, update, delete on %s to app_user', obj.rel);
    end if;
  end loop;
end;
$$;

select tenant_guard.grant_to('app_user');

-- Deterministic ids so tests can refer to users and tenants by name.
create function tests.user_id(p_name text)
returns uuid
language sql
immutable
as $$ select md5('user:' || p_name)::uuid $$;

create function tests.tenant_id(p_name text)
returns uuid
language sql
immutable
as $$ select md5('tenant:' || p_name)::uuid $$;

-- Standard fixture, created as the superuser before switching roles:
--
--   acme:   alice (owner), bob (editor), vera (viewer)
--   globex: carol (owner)
--   dave belongs to no tenant.
create function tests.seed()
returns void
language sql
as $$
  insert into tenant_guard.tenants (id, name) values
    (tests.tenant_id('acme'), 'Acme'),
    (tests.tenant_id('globex'), 'Globex');

  insert into tenant_guard.tenant_members (tenant_id, user_id, role) values
    (tests.tenant_id('acme'),   tests.user_id('alice'), 'owner'),
    (tests.tenant_id('acme'),   tests.user_id('bob'),   'editor'),
    (tests.tenant_id('acme'),   tests.user_id('vera'),  'viewer'),
    (tests.tenant_id('globex'), tests.user_id('carol'), 'owner');
$$;

-- EXPLAIN output of a query as one text value, for plan-shape assertions.
create function tests.plan_of(p_query text)
returns text
language plpgsql
as $$
declare
  line text;
  result text := '';
begin
  for line in execute 'explain (costs off) ' || p_query loop
    result := result || line || E'\n';
  end loop;
  return result;
end;
$$;

-- Runs a statement that is expected to fail and returns the error's DETAIL.
create function tests.error_detail(p_sql text)
returns text
language plpgsql
as $$
declare
  v_detail text;
begin
  execute p_sql;
  return null;
exception when others then
  get stacked diagnostics v_detail = pg_exception_detail;
  return v_detail;
end;
$$;
