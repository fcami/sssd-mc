# TODO

## Bugs
- [ ] Fix chain length measurement in `analysis.rs` — `chain_length()` picks the first record's hash1 to follow, but a bucket can contain records chained by different hashes. Should measure reachability per-hash, not per-bucket. `max_chain_length` stat is unreliable.

## Testing
- [ ] `verify_collision` test should read `collision_meta.txt` and assert the *specific* victim slot is in the `UnreachableByHash2` problem list, not just `unreachable_count > 0`.
- [ ] Hash reference test (`hashes.txt`) doesn't cover the collision fixture's key combinations — add the collision-specific names+UIDs to the reference values.
- [ ] `verify_record_hashes` has no dedicated test — only exercised indirectly via `verify_cache`. Add unit tests with intentionally corrupted hashes.
- [ ] No `initgroups` or `sid` support in `verify_record_hashes` — it returns `None` for these types. Either implement or document the gap.

## Architecture
- [ ] `CacheFile` stores `cache_type` but doesn't enforce it — you can open a passwd cache as `CacheType::Group` and get garbage. The cache file itself has no type marker (SSSD determines type from filename). Document this or infer type from path.
- [ ] No `lib.rs` re-exports — users must write `sssd_mc::parsers::cache::CacheFile` instead of `sssd_mc::CacheFile`. Add a flat re-export of key types.
- [ ] `analysis::verify_cache` mixes two concerns: structural checks (barriers, reachability) and data checks (hash integrity). Consider splitting into `verify_structure` and `verify_hashes`.

## Features
- [ ] `dump` subcommand should support `--json` output for scripting.
- [ ] `verify` subcommand should exit non-zero when CRITICAL problems are found.
- [ ] Support reading cache files from SOS reports (they're under `var/lib/sss/mc/` in the extracted tarball).
- [ ] `lookup` subcommand: look up a specific name or UID/GID via hash table walk and display the result, mimicking what SSSD's NSS client does.

## Documentation
- [ ] Update README with `verify` subcommand usage and example output.
- [ ] Document the SSSD hash collision defect in the README (reference `~/claude/sssd-memcache-hash-collision-defect.md`).

## Code quality
- [ ] `gen_cache.c` payload builders (`build_passwd_payload`, `build_group_payload`, etc.) follow the same pattern — consider a macro or helper for "serialize struct + string buffer."
