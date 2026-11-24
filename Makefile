PG_VERSION ?= 17

.PHONY: help dist check-dist test test-all

help:
	@echo "make dist        Build dist/pg-tenant-guard.sql from sql/*.sql"
	@echo "make check-dist  Fail if dist/pg-tenant-guard.sql is out of date"
	@echo "make test        Rebuild dist, then run the test suite in Docker (PG_VERSION=$(PG_VERSION))"
	@echo "make test-all    Run the test suite on PostgreSQL 16 and 17, one after the other"

dist:
	./scripts/build.sh

check-dist:
	./scripts/build.sh --check

test: dist
	PG_VERSION=$(PG_VERSION) ./scripts/test.sh

test-all: dist
	PG_VERSION=16 ./scripts/test.sh
	PG_VERSION=17 ./scripts/test.sh
