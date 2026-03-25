# User Story 005: Separate parsed entry types from display

**As a** developer using sssd-mc as a library,
**I want** typed structs (PasswdEntry, GroupEntry, InitgrEntry, SidEntry)
returned by the parser,
**so that** I can programmatically access cache data without coupling to
the display layer or doing unsafe struct reads in calling code.

## Acceptance criteria

- New parsed entry types with owned String fields
- Parser methods that return these types from raw record data
- Display logic in a separate module, consuming the parsed types
- main.rs uses the new API, no unsafe code remains there
- Existing tests continue to pass

## Status

- [x] Accepted (2026-03-25)
- [ ] Implemented
