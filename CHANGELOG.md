# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Until 1.0, minor versions may
change the API; changes will be listed here with upgrade notes.

## [Unreleased]

## [0.1.0] - 2026-11-24

First release.

### Added

- `tenant_guard` schema with `tenants`, `tenant_members`, `roles`,
  `role_permissions` and `tenant_locks`, all with row-level security enabled.
- Caller identity through `current_user_id()`: `auth.uid()` on Supabase,
  otherwise the PostgREST JWT settings, otherwise the `tenant_guard.user_id`
  setting.
- Membership helpers `is_member()`, `member_role()`, `my_tenant_ids()` and
  `create_tenant()`.
- Role permissions with `view`/`edit` access, a `*` wildcard that excludes
  built-in `tenant_guard.*` permissions, `has_permission()` and
  `permitted_tenant_ids()`.
- `protect_table()`, `unprotect_table()` and `unprotected_tables()`. Policies
  use an index-friendly `= any (array(select ...))` form.
- Tenant lock: `lock_tenant()`, `unlock_tenant()`, `is_locked()`, the
  `enforce_tenant_lock()` trigger with per-table allow-lists, and
  `attach_lock_trigger()` / `detach_lock_trigger()`.
- `grant_to()` for client roles, applied automatically to Supabase's `anon`
  and `authenticated`.
- Single-file installer `dist/pg-tenant-guard.sql`, safe to re-run.
- pgTAP suite (146 tests) on PostgreSQL 16 and 17, plus a smoke test against
  the `supabase/postgres` image.

[Unreleased]: https://github.com/shivamlaur022/pg-tenant-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/shivamlaur022/pg-tenant-guard/releases/tag/v0.1.0
