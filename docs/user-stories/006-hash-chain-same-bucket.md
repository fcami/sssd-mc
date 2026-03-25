# User Story 006: Detect hash2 unreachable records (same-bucket collision)

**As a** sysadmin debugging "user not found by UID" issues,
**I want** sssd-mc to detect records that are unreachable via their
secondary hash (hash2) due to same-bucket collisions,
**so that** I can confirm whether a cache corruption / SSSD defect is
causing `getpwuid()` or `getgrgid()` to fail while name lookups work.

## Background

SSSD's `sss_mc_add_rec_to_chain()` skips linking hash2 when bucket1 ==
bucket2, leaving `next2 = MC_INVALID_VAL`. If a later insert pushes the
record down the chain, it becomes unreachable via hash2 lookup. See
`~/claude/sssd-memcache-hash-collision-defect.md` for the full analysis.

## Acceptance criteria

- New `verify` subcommand that checks cache integrity
- Detects records unreachable via hash2 chain walk
- Flags same-bucket (hash1 % ht == hash2 % ht) conditions
- Reports hash chain lengths per bucket
- gen_cache.c produces a collision fixture that triggers the bug
- Integration tests verify detection works
- Analysis logic in `src/analysis.rs` (separate from parsing and display)

## Status

- [x] Accepted (2026-03-25)
- [ ] Implemented
