# Test image: the official PostgreSQL image plus pgTAP and pg_prove.
# Built and used by scripts/test.sh; not meant for production use.
ARG PG_VERSION=17
FROM postgres:${PG_VERSION}

# PG_MAJOR is set by the official image. The PGDG apt repository it ships
# with provides a pgTAP build that matches the server version.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      "postgresql-${PG_MAJOR}-pgtap" \
      libtap-parser-sourcehandler-pgtap-perl \
 && rm -rf /var/lib/apt/lists/*
