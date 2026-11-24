#!/usr/bin/env bash
# Runs the pgTAP suite against a throwaway PostgreSQL container.
#
#   PG_VERSION=16 scripts/test.sh             # pick the server version (default 17)
#   scripts/test.sh test/sql/010_tenants.sql  # run selected test files only
#   KEEP=1 scripts/test.sh                    # keep the container for debugging
#
# The container is removed on exit unless KEEP=1 is set.
set -euo pipefail

PG_VERSION="${PG_VERSION:-17}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="pg-tenant-guard-test:${PG_VERSION}"
CONTAINER="pg-tenant-guard-test-${PG_VERSION}-$$"
DB="tenant_guard_test"

cleanup() {
  if [[ "${KEEP:-0}" == "1" ]]; then
    echo "Keeping container ${CONTAINER} (remove with: docker rm -f ${CONTAINER})"
  else
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

psql_in() {
  docker exec -i -e PGOPTIONS="-c client_min_messages=warning" "$CONTAINER" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$DB" "$@"
}

# Tests run against the generated installer, i.e. exactly what users install.
"$ROOT/scripts/build.sh" --check

echo "==> Building test image for PostgreSQL ${PG_VERSION}"
docker build --quiet --build-arg PG_VERSION="$PG_VERSION" -t "$IMAGE" "$ROOT/test/docker" >/dev/null

echo "==> Starting container ${CONTAINER}"
docker run -d --name "$CONTAINER" \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -v "$ROOT:/work:ro" \
  "$IMAGE" -c fsync=off -c synchronous_commit=off -c full_page_writes=off >/dev/null

# The entrypoint starts a temporary server (Unix socket only) while it
# initialises the cluster, so wait for the real server on TCP instead.
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -q -h 127.0.0.1 -U postgres; then
    break
  fi
  sleep 1
done
if ! docker exec "$CONTAINER" pg_isready -q -h 127.0.0.1 -U postgres; then
  docker logs "$CONTAINER" >&2
  echo "PostgreSQL did not become ready" >&2
  exit 1
fi
docker exec "$CONTAINER" psql -X -qtA -U postgres -c "select version()" | sed "s/^/    /"

docker exec "$CONTAINER" createdb -U postgres "$DB"
psql_in -c "create extension pgtap"

echo "==> Installing dist/pg-tenant-guard.sql (twice, to prove re-running it is safe)"
psql_in -o /dev/null -f /work/dist/pg-tenant-guard.sql
psql_in -c "insert into tenant_guard.tenants (name) values ('survives reinstall')"
psql_in -o /dev/null -f /work/dist/pg-tenant-guard.sql
if [[ "$(psql_in -tA -c "select count(*) from tenant_guard.tenants where name = 'survives reinstall'")" != "1" ]]; then
  echo "Re-running the installer lost data" >&2
  exit 1
fi
psql_in -c "delete from tenant_guard.tenants"
psql_in -o /dev/null -f /work/test/setup.sql

echo "==> Running tests"
if [[ $# -gt 0 ]]; then
  tests=("$@")
else
  tests=()
  for f in "$ROOT"/test/sql/*.sql; do tests+=("test/sql/$(basename "$f")"); done
fi
container_paths=()
for t in "${tests[@]}"; do container_paths+=("/work/${t#./}"); done

docker exec "$CONTAINER" pg_prove -U postgres -d "$DB" ${VERBOSE:+--verbose} "${container_paths[@]}"
