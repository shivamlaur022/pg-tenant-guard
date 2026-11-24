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
  loop
    if obj.relkind = 'S' then
      execute format('grant usage, select, update on sequence %s to app_user', obj.rel);
    else
      execute format('grant select, insert, update, delete on %s to app_user', obj.rel);
    end if;
  end loop;
  execute format('grant usage on schema %s to app_user', pg_my_temp_schema()::regnamespace);
end;
$$;
