# User Story 002: Handle non-UTF-8 strings in cache records

**As a** sysadmin inspecting SSSD caches in environments with non-ASCII
usernames (IDN, CJK, legacy encodings),
**I want** sssd-mc to preserve and display all string data from cache records,
**so that** I don't silently lose data when inspecting caches with non-UTF-8 content.

## Acceptance criteria

- `extract_strings` returns lossy representations instead of silently dropping
  non-UTF-8 segments
- Existing tests continue to pass
- New test covering non-UTF-8 input

## Status

- [x] Accepted (2026-03-25)
- [ ] Implemented
