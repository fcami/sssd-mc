# User Story 004: Negative / error path tests

**As a** developer working on sssd-mc,
**I want** tests that exercise error paths (truncated files, bad versions,
corrupted barriers, invalid record lengths),
**so that** the parser fails gracefully with meaningful errors instead of
panicking or returning garbage on malformed input.

## Acceptance criteria

- Tests for: truncated file, wrong version, RECYCLED status, UNINIT status,
  barrier mismatch, record length out of bounds, empty cache (valid header,
  no records)
- All error variants in McError are exercised by at least one test

## Status

- [x] Accepted (2026-03-25)
- [ ] Implemented
