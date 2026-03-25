# User Story 001: Test cache file generator

**As a** developer working on sssd-mc,
**I want** a C-based test cache file generator that uses SSSD's actual struct
definitions and murmurhash3 implementation,
**so that** I can validate the Rust parser against ground-truth cache files
and cross-validate the murmurhash3 port.

## Acceptance criteria

- Generator uses SSSD's `mmap_cache.h` and `murmurhash3.c` verbatim
- SSSD source files are versioned (one directory per SSSD version)
- Starts with current SSSD head; architecture supports adding more versions
- Generator produces valid cache files for all 4 types (passwd, group,
  initgroups, sid) with known contents
- Rust integration tests parse the generated files and assert exact values
- murmurhash3 cross-validation: Rust and C produce identical hashes
- Reference fixtures can be committed for CI (no C compiler needed to run tests)

## Status

- [x] Accepted (2026-03-25)
- [ ] Implemented
