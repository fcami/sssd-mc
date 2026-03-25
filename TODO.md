# TODO

## Bugs
- [ ] Fix chain length measurement in `analysis.rs` — `chain_length()` picks the first record's hash1 to follow, but a bucket can contain records chained by different hashes. Should measure reachability per-hash, not per-bucket. `max_chain_length` stat is unreliable.

## Testing
- [ ] `verify_collision` test should read `collision_meta.txt` and assert the *specific* victim slot and name are in the `UnreachableByHash2` problem list, not just `unreachable_count > 0`.
- [ ] Hash reference test (`hashes.txt`) doesn't cover the collision fixture's key combinations — add collision-specific names+UIDs to the reference values.
- [ ] `verify_record_hashes` has no dedicated test — only exercised indirectly via `verify_cache`. Add unit tests with intentionally corrupted hashes.
- [ ] No `initgroups` or `sid` support in `verify_record_hashes` — returns `None` for these types. Implement or document the gap.
- [ ] Add CLI integration tests for `lookup` subcommand (by name, by ID, not found, --json).

## Architecture
- [ ] `CacheFile` stores `cache_type` but doesn't enforce it — you can open a passwd cache as `CacheType::Group` and get garbage. Document this or infer type from path.
- [ ] No `lib.rs` re-exports — users must write `sssd_mc::parsers::cache::CacheFile` instead of `sssd_mc::CacheFile`. Add a flat re-export of key types.

## Features
- [ ] Support reading cache files from SOS reports (they're under `var/lib/sss/mc/` in the extracted tarball).
- [ ] `verify --json` output for scripting.
- [ ] `lookup` should support `--by-name` / `--by-id` flags to force hash1 or hash2 lookup specifically (useful for diagnosing which lookup path is broken).
- [ ] Document the SSSD hash collision defect in the README (reference `~/claude/sssd-memcache-hash-collision-defect.md`).

## Code quality
- [ ] `gen_cache.c` payload builders follow the same pattern — consider a macro or helper for "serialize struct + string buffer."
- [ ] `lookup` in `parsers/cache.rs` does key comparison with `format!("{}", e.uid) == key` which allocates on every record. Use `key.parse::<u32>()` once and compare numerically.
