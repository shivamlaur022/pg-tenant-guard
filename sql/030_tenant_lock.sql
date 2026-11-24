-- pg-tenant-guard 030: tenant lock (read-only mode).
--
-- Locking a tenant (for example when its subscription lapses) makes its data
-- read-only at the database level. A row trigger on each protected table
-- rejects INSERT, UPDATE and DELETE for rows that belong to a locked tenant,
-- while SELECT keeps working. Because it is a trigger rather than a policy,
-- the lock applies to every role, including the table owner and roles that
-- bypass RLS (such as Supabase's service_role).
--
-- Some writes must keep working while a tenant is locked: recording the
-- payment that unlocks it, requesting a data export, and so on. Each table
-- can allow-list operations when the trigger is attached:
--
--   select tenant_guard.attach_lock_trigger('public.payments', array['INSERT', 'UPDATE']);
--
-- protect_table() attaches the trigger for you and takes the same allow-list.

create table if not exists tenant_guard.tenant_locks (
  tenant_id uuid primary key references tenant_guard.tenants (id) on delete cascade,
  reason    text,
  locked_at timestamptz not null default now()
);

comment on table tenant_guard.tenant_locks is
  'Locked tenants. A row here makes the tenant read-only on every table with the lock trigger';

-- The lock state is administrative. It lives in its own table, not in a
-- column on tenants, so that no tenant-level permission (such as renaming the
-- tenant) can ever be used to unlock it. Clients get no privileges and no
-- policies on this table; they use is_locked() instead.
alter table tenant_guard.tenant_locks enable row level security;

-- Locks a tenant, or updates the reason if it is already locked (keeping the
-- original locked_at). Intended for your billing backend or admin tooling;
-- not granted to client roles.
create or replace function tenant_guard.lock_tenant(p_tenant_id uuid, p_reason text default null)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  if not exists (select 1 from tenant_guard.tenants t where t.id = p_tenant_id) then
    raise exception 'tenant % does not exist', p_tenant_id
      using errcode = 'no_data_found';
  end if;

  insert into tenant_guard.tenant_locks (tenant_id, reason)
  values (p_tenant_id, p_reason)
  on conflict (tenant_id) do update set reason = excluded.reason;
end;
$$;

comment on function tenant_guard.lock_tenant(uuid, text) is
  'Makes a tenant read-only on all tables with the lock trigger';

-- Unlocks a tenant. Returns true if it was locked.
create or replace function tenant_guard.unlock_tenant(p_tenant_id uuid)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  delete from tenant_guard.tenant_locks l where l.tenant_id = p_tenant_id;
  return found;
end;
$$;

comment on function tenant_guard.unlock_tenant(uuid) is
  'Restores writes for a locked tenant; returns true if it was locked';

-- Lets the application show a "read-only" banner. Answers only for tenants
-- the current user belongs to and returns NULL otherwise, so it cannot be
-- used to probe the billing state of other tenants. Admin tooling should
-- read tenant_guard.tenant_locks directly.
create or replace function tenant_guard.is_locked(p_tenant_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select case
    when tenant_guard.is_member(p_tenant_id)
      then exists (select 1 from tenant_guard.tenant_locks l where l.tenant_id = p_tenant_id)
  end;
$$;

comment on function tenant_guard.is_locked(uuid) is
  'True if a tenant the current user belongs to is locked; NULL for other tenants';

-- Row trigger that enforces the lock. Trigger arguments are the operations
-- that stay allowed while the tenant is locked ('INSERT', 'UPDATE', 'DELETE').
--
-- For UPDATE both the old and the new tenant_id are checked, so a row can
-- neither be changed inside a locked tenant nor moved into one.
--
-- SECURITY DEFINER so it can read tenant_locks, which clients cannot.
create or replace function tenant_guard.enforce_tenant_lock()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_tenant uuid;
  v_reason text;
begin
  if tg_op = any (tg_argv) then
    return case tg_op when 'DELETE' then old else new end;
  end if;

  -- OLD is NULL for INSERT and NEW is NULL for DELETE; a NULL in the list
  -- simply matches nothing.
  select l.tenant_id, l.reason
    into v_tenant, v_reason
  from tenant_guard.tenant_locks l
  where l.tenant_id in (old.tenant_id, new.tenant_id)
  limit 1;

  if v_tenant is not null then
    raise exception 'tenant % is locked: % on %.% is not allowed',
        v_tenant, tg_op, tg_table_schema, tg_table_name
      using errcode = 'read_only_sql_transaction',
            detail  = coalesce('Reason: ' || v_reason, 'No reason given.'),
            hint    = 'Reads still work. Writes resume after tenant_guard.unlock_tenant() is called.';
  end if;

  return case tg_op when 'DELETE' then old else new end;
end;
$$;

comment on function tenant_guard.enforce_tenant_lock() is
  'Trigger: rejects writes to rows of locked tenants, except the operations passed as trigger arguments';

-- Attaches (or re-attaches) the lock trigger to a table with a tenant_id
-- column. p_allow_when_locked lists operations that stay allowed while the
-- tenant is locked; case-insensitive.
--
-- The trigger is named tenant_guard_lock. BEFORE triggers fire in name
-- order, so a BEFORE trigger whose name sorts after it and that changes
-- tenant_id would not be re-checked. Avoid changing tenant_id in triggers.
create or replace function tenant_guard.attach_lock_trigger(
  p_table             regclass,
  p_allow_when_locked text[] default '{}'
)
returns void
language plpgsql
volatile
set search_path = ''
as $$
declare
  v_ops  text[];
  v_bad  text[];
  v_args text;
begin
  perform tenant_guard.assert_tenant_table(p_table);

  select coalesce(array_agg(distinct upper(btrim(op)) order by upper(btrim(op))), '{}')
    into v_ops
  from unnest(coalesce(p_allow_when_locked, '{}')) as op;

  select array_agg(op) into v_bad
  from unnest(v_ops) as op
  where op not in ('INSERT', 'UPDATE', 'DELETE');

  if v_bad is not null then
    raise exception 'attach_lock_trigger: unknown operation(s) %; expected INSERT, UPDATE or DELETE', v_bad
      using errcode = 'invalid_parameter_value';
  end if;

  select string_agg(format('%L', op), ', ') into v_args from unnest(v_ops) as op;

  if exists (select 1 from pg_catalog.pg_trigger t
             where t.tgrelid = p_table and t.tgname = 'tenant_guard_lock') then
    execute format('drop trigger tenant_guard_lock on %s', p_table);
  end if;

  execute format(
    'create trigger tenant_guard_lock before insert or update or delete on %s
       for each row execute function tenant_guard.enforce_tenant_lock(%s)',
    p_table, coalesce(v_args, ''));
end;
$$;

comment on function tenant_guard.attach_lock_trigger(regclass, text[]) is
  'Attaches the tenant lock trigger to a table; the array lists operations allowed while locked';

create or replace function tenant_guard.detach_lock_trigger(p_table regclass)
returns void
language plpgsql
volatile
set search_path = ''
as $$
begin
  if exists (select 1 from pg_catalog.pg_trigger t
             where t.tgrelid = p_table and t.tgname = 'tenant_guard_lock') then
    execute format('drop trigger tenant_guard_lock on %s', p_table);
  end if;
end;
$$;

comment on function tenant_guard.detach_lock_trigger(regclass) is
  'Removes the tenant lock trigger from a table';
