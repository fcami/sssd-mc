# User Story 003: Test fixtures for initgroups and sid caches

**As a** developer working on sssd-mc,
**I want** test fixtures and integration tests for initgroups and sid cache types,
**so that** all four cache types have ground-truth validation, not just passwd and group.

## Acceptance criteria

- gen_cache.c generates initgroups.cache and sid.cache with known entries
- Integration tests verify parsing of initgroups and sid records
- At least one expired entry per cache type

## Status

- [x] Accepted (2026-03-25)
- [ ] Implemented
