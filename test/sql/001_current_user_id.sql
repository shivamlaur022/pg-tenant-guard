-- tenant_guard.current_user_id(): identity resolution order and failure modes.
begin;
select plan(10);

select has_schema('tenant_guard');
select has_function('tenant_guard', 'current_user_id', '{}'::name[]);
select volatility_is('tenant_guard', 'current_user_id', '{}'::name[], 'stable');
select is(
  (select proconfig from pg_proc where oid = 'tenant_guard.current_user_id()'::regprocedure),
  array['search_path=""'],
  'current_user_id pins an empty search_path'
);

select is(tenant_guard.current_user_id(), null, 'no identity set: NULL (anonymous)');

select set_config('tenant_guard.user_id', '00000000-0000-0000-0000-00000000000a', true);
select is(
  tenant_guard.current_user_id(), '00000000-0000-0000-0000-00000000000a'::uuid,
  'falls back to the tenant_guard.user_id setting'
);

select set_config('request.jwt.claims', '{"sub": "00000000-0000-0000-0000-00000000000b", "role": "authenticated"}', true);
select is(
  tenant_guard.current_user_id(), '00000000-0000-0000-0000-00000000000b'::uuid,
  'request.jwt.claims sub wins over tenant_guard.user_id'
);

select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000c', true);
select is(
  tenant_guard.current_user_id(), '00000000-0000-0000-0000-00000000000c'::uuid,
  'request.jwt.claim.sub wins over request.jwt.claims'
);

select set_config('request.jwt.claim.sub', 'not-a-uuid', true);
select throws_ok(
  'select tenant_guard.current_user_id()',
  '22P02',
  null,
  'a malformed user id raises instead of being treated as anonymous'
);

-- Simulate Supabase: once auth.uid() exists it takes precedence.
create schema auth;
create function auth.uid() returns uuid language sql stable
  as $$ select '00000000-0000-0000-0000-00000000000d'::uuid $$;
select is(
  tenant_guard.current_user_id(), '00000000-0000-0000-0000-00000000000d'::uuid,
  'auth.uid() is used when it exists'
);

select * from finish();
rollback;
