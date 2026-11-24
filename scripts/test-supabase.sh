#!/usr/bin/env bash
# Installs dist/pg-tenant-guard.sql into the supabase/postgres image as the
# "postgres" role (as the Supabase SQL editor does) and runs
# test/supabase/smoke.sql.
#
#   scripts/test-supabase.sh
#   SUPABASE_IMAGE=supabase/postgres:<tag> scripts/test-supabase.sh
set -euo pipefail

SUPABASE_IMAGE="${SUPABASE_IMAGE:-supabase/postgres:17.6.1.136}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTAINER="pg-tenant-guard-supabase-$$"

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

"$ROOT/scripts/build.sh" --check

psql_in() {
  docker exec -i "$CONTAINER" psql -X -q -v ON_ERROR_STOP=1 -h 127.0.0.1 -U postgres -d postgres "$@"
}

echo "==> Starting ${SUPABASE_IMAGE}"
docker run -d --name "$CONTAINER" -e POSTGRES_PASSWORD=postgres \
  -v "$ROOT:/work:ro" "$SUPABASE_IMAGE" >/dev/null

# Ready means: the server accepts TCP connections and the image's own
# migrations have created the API roles and auth.uid().
ready=0
for _ in $(seq 1 120); do
  if [[ "$(psql_in -tA -c "select to_regprocedure('auth.uid()') is not null
                               and exists (select 1 from pg_roles where rolname = 'service_role')" 2>/dev/null)" == "t" ]]; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" != "1" ]]; then
  docker logs "$CONTAINER" >&2
  echo "Supabase Postgres did not become ready" >&2
  exit 1
fi
psql_in -tA -c "select version()" | sed 's/^/    /'

echo "==> Installing dist/pg-tenant-guard.sql as role postgres"
psql_in -o /dev/null -f /work/dist/pg-tenant-guard.sql

echo "==> Running test/supabase/smoke.sql"
output="$(psql_in -f /work/test/supabase/smoke.sql 2>&1)" || { echo "$output"; exit 1; }
grep -v '^$' <<<"$output"

if grep -qE '^not ok|^# Looks like' <<<"$output"; then
  echo "Result: FAIL" >&2
  exit 1
fi
echo "Result: PASS"
