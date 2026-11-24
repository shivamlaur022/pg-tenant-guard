# Contributing

Thanks for taking the time to improve pg-tenant-guard. Issues and pull
requests are welcome.

## Setup

You need Docker and `make`. Nothing is installed on your machine. Tests run in
a throwaway PostgreSQL container that is removed afterwards.

```sh
make test                  # PostgreSQL 17
make test PG_VERSION=16
make test-supabase         # smoke test against the supabase/postgres image
KEEP=1 ./scripts/test.sh   # keep the container around to poke at it with psql
./scripts/test.sh test/sql/030_tenant_lock.sql   # run one file
```

## Making changes

- Edit the files in `sql/`. They are installed in file-name order, so a file
  may only depend on files that sort before it.
- Never edit `dist/pg-tenant-guard.sql` by hand. Run `make dist` and commit the
  result. CI fails if it is out of date.
- Every installer statement must be re-runnable: `create ... if not exists`,
  `create or replace`, `drop policy if exists` before `create policy`, and
  `on conflict do nothing` for seed rows.
- Add or update tests in `test/sql/` for every behaviour change. Each file runs
  in one transaction and rolls back. Use the fixtures in `test/setup.sql`
  (`tests.seed()`, `tests.authenticate_as(tests.user_id('alice'))`, ...).

## Rules for functions

`test/sql/900_hygiene.sql` enforces most of these, so a missed one fails CI.

- Pin the search path: `set search_path = ''`, and schema-qualify every object,
  including `pg_catalog` tables in dynamic SQL.
- `SECURITY DEFINER` only when the function must read data the caller cannot,
  and never with dynamic SQL built from arguments.
- Helpers used in policies are `STABLE`.
- In SQL-language functions, refer to parameters as `function_name.param`,
  because parameter names often match column names (`tenant_id`).
- Execute is revoked from `PUBLIC` for the whole schema. A new client-facing
  function must be added to `grant_to()` and to the allow-list in
  `900_hygiene.sql`.
- Parameter names are public API (PostgREST uses them as RPC argument names),
  so don't rename them casually.

## Pull requests

- Keep each PR focused on one change, and describe what changed and why.
- Note user-facing changes under `Unreleased` in `CHANGELOG.md`.
- CI must be green on PostgreSQL 16, 17 and the Supabase smoke test.

## Reporting security issues

Please don't open a public issue for a vulnerability. Use GitHub's private
reporting (the Security tab, "Report a vulnerability") instead.
