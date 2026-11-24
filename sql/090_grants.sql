-- pg-tenant-guard 090: privileges for client roles.
--
-- Nothing in tenant_guard is granted to PUBLIC. A client role (the role your
-- API runs queries as) gets exactly what it needs through grant_to(). On
-- Supabase this runs automatically for "authenticated" and "anon".

-- Functions are executable by PUBLIC by default in PostgreSQL. Take that away
-- for the whole schema; grant_to() hands back the client-facing ones.
revoke execute on all functions in schema tenant_guard from public;

create or replace function tenant_guard.grant_to(p_role name)
returns void
language plpgsql
volatile
set search_path = ''
as $$
begin
  execute format('grant usage on schema tenant_guard to %I', p_role);

  -- Column-level UPDATE: clients may rename a tenant or change a member's
  -- role, but never move a row to another tenant or rewrite its id.
  execute format('grant select, update (name) on tenant_guard.tenants to %I', p_role);
  execute format('grant select, insert, update (role), delete on tenant_guard.tenant_members to %I', p_role);
  execute format('grant select on tenant_guard.roles to %I', p_role);

  execute format(
    'grant execute on function
       tenant_guard.current_user_id(),
       tenant_guard.is_member(uuid),
       tenant_guard.member_role(uuid),
       tenant_guard.my_tenant_ids(),
       tenant_guard.create_tenant(text)
     to %I', p_role);
end;
$$;

comment on function tenant_guard.grant_to(name) is
  'Grants a client role the privileges it needs to use tenant_guard from RLS policies and the API';

revoke all on function tenant_guard.grant_to(name) from public;

-- Supabase: grant to the API roles when they exist. "anon" needs the grants
-- too: policies on your tables call tenant_guard functions, and a missing
-- privilege would turn "no rows" into a permission error for anonymous requests.
do $$
declare
  r name;
begin
  foreach r in array array['authenticated', 'anon']::name[] loop
    if exists (select 1 from pg_roles where rolname = r) then
      perform tenant_guard.grant_to(r);
    end if;
  end loop;
end;
$$;
