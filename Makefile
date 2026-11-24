PG_VERSION ?= 17

.PHONY: help test test-all

help:
	@echo "make test        Run the test suite in Docker (PG_VERSION=$(PG_VERSION))"
	@echo "make test-all    Run the test suite on PostgreSQL 16 and 17, one after the other"

test:
	PG_VERSION=$(PG_VERSION) ./scripts/test.sh

test-all:
	$(MAKE) test PG_VERSION=16
	$(MAKE) test PG_VERSION=17
