# sssd-mc

Read-only parser and inspector for SSSD memory cache files (`/var/lib/sss/mc/`).

Supports all four cache types: `passwd`, `group`, `initgroups`, and `sid`.

## Building

### Prerequisites

- Rust 1.71+ (RHEL 8: `dnf install rust-toolset`)
- [just](https://github.com/casey/just) task runner (optional but recommended)
- podman (for container builds only)

### Local build

```sh
# Debug build + lint + test
just

# Or without just:
cargo build
cargo clippy -- -D warnings
cargo test

# Release build
just release
# or: cargo build --release
```

### Container builds (UBI)

Container builds use Red Hat Universal Base Images to produce binaries
compatible with RHEL 8, 9, or 10. Builder images are tagged with
the build date and automatically rebuilt when older than 90 days.

```sh
# RHEL 8
just release-rhel8

# RHEL 9
just release-rhel9

# RHEL 10
just release-rhel10
```

The resulting binary is at `target/release/sssd-mc`.

### Vendored / air-gapped builds

```sh
# Vendor all dependencies into vendor/
just vendor

# Build as usual (cargo will use vendored sources)
just release

# Remove vendored sources when done
just unvendor
```

## Usage

The SSSD memory cache files are owned by root, so `sssd-mc` typically
needs to be run with `sudo` or as root.

### Expiry calculations

The `[EXPIRED]` tag and expired/active record counts are computed
against a reference time. By default this is the **file modification
time**, which is correct when analyzing cache files offline (e.g. from
SOS reports). Both timestamps are always shown:

```
File modified:  2026-03-25 14:30:12 UTC (used for expiry calculations)
Current time:   2026-03-25 18:45:03 UTC
```

Override with `--now`:

```sh
# Use current system time (for live analysis)
sudo sssd-mc dump /var/lib/sss/mc/passwd -t passwd --now=system

# Use a specific UNIX epoch timestamp
sssd-mc dump passwd.cache -t passwd --now=1742998000
```

### Show cache header

```sh
sudo sssd-mc header /var/lib/sss/mc/passwd -t passwd
```

```
Cache type:     passwd
Version:        1.1
Status:         1 (ALIVE)
Seed:           0x3a8b1c4f
Data table:     offset=0x00000280 size=1048576
Free table:     offset=0x00100280 size=3277
Hash table:     offset=0x00100f51 size=104857
Barriers:       b1=0xf0000001 b2=0xf0000001
Total slots:    26214
File modified:  2026-03-25 14:30:12 UTC (used for expiry calculations)
Current time:   2026-03-25 18:45:03 UTC
```

### Dump all records

```sh
sudo sssd-mc dump /var/lib/sss/mc/passwd -t passwd
sudo sssd-mc dump /var/lib/sss/mc/group -t group
sudo sssd-mc dump /var/lib/sss/mc/initgroups -t initgroups
sudo sssd-mc dump /var/lib/sss/mc/sid -t sid
```

Example output for passwd:
```
Records:
  [slot     0] admin uid=1000 gid=1000 expire=1742998800
              gecos=Admin User dir=/home/admin shell=/bin/bash
  [slot     4] testuser uid=1001 gid=1001 expire=1742998800 [EXPIRED]
              gecos=Test User dir=/home/testuser shell=/bin/bash
```

JSON output (one object per line, pipe to `jq`):
```sh
sudo sssd-mc dump /var/lib/sss/mc/passwd -t passwd --json
```

```json
{"type":"passwd","name":"root","passwd":"x","uid":0,"gid":0,"gecos":"root","dir":"/root","shell":"/bin/bash","expire":4102444800}
```

### Look up a record

Look up by name, UID/GID, or slot number:

```sh
# By name
sudo sssd-mc lookup /var/lib/sss/mc/passwd -t passwd root

# By UID
sudo sssd-mc lookup /var/lib/sss/mc/passwd -t passwd 1000

# By slot number (useful for inspecting records flagged by verify)
sudo sssd-mc lookup /var/lib/sss/mc/passwd -t passwd 179 --slot

# JSON output
sudo sssd-mc lookup /var/lib/sss/mc/passwd -t passwd root --json
```

Exit code 2 if the key is not found.

### Show cache statistics

```sh
sudo sssd-mc stats /var/lib/sss/mc/passwd -t passwd
```

```
Cache type:       passwd
Total records:    42
Active records:   38
Expired records:  4
Total slots:      26214
Hash buckets:     26214 (42 used, 0.2% load)
```

### Verify cache integrity

Check a cache for structural problems: barrier consistency, hash chain
reachability, and hash value integrity.

```sh
sudo sssd-mc verify /var/lib/sss/mc/passwd -t passwd
```

Clean cache:
```
Cache type:         passwd
Total records:      42
Same-bucket hashes: 0
Unreachable (hash2):0
Hash mismatches:    0
Max chain length:   2

No problems found.
```

Cache with corruption:
```
Cache type:         passwd
Total records:      42
Same-bucket hashes: 0
Unreachable (hash2):1
Hash mismatches:    0
Max chain length:   3

Problems:
  CRITICAL: record at slot 12 (jdoe, id=10042) unreachable via hash2
    (hash1=0x1a2b hash2=0x3c4d bucket=1234) — UID/GID lookup will fail

CRITICAL: 1 record(s) unreachable by UID/GID lookup.
Workaround: sss_cache -E (flush all caches)
```

Exit codes: 0 = clean, 1 = error opening file, 2 = problems detected.

## Debugging: memcache vs non-memcache mismatch

If `id USER` and `SSS_NSS_USE_MEMCACHE=NO id USER` show different
group names for the same GID, use sssd-mc to investigate:

```sh
# Find the mismatched GID (example: 12345)
diff <(id USER) <(SSS_NSS_USE_MEMCACHE=NO id USER)

# Look up that GID in the group cache
sudo sssd-mc lookup /var/lib/sss/mc/group -t group 12345

# Check if multiple groups share the GID (GID conflict)
sudo sssd-mc dump /var/lib/sss/mc/group -t group --json \
  | jq 'select(.gid == 12345)'

# Check structural integrity
sudo sssd-mc verify /var/lib/sss/mc/group -t group

# Check if the entry is stale (compare expire vs current epoch)
sudo sssd-mc lookup /var/lib/sss/mc/group -t group 12345 --json \
  | jq '.expire'
date +%s
```

Common causes:

- **GID conflict**: two groups from different AD domains map to the
  same GID. The memcache stores whichever was cached first.
- **Stale entry**: the group was renamed or GID reassigned but the
  cache hasn't expired yet.
- **Corruption**: crash during update or concurrent access left
  inconsistent chain pointers or overlapping records.

## Testing with multiple SSSD versions

Integration tests parse binary cache files generated by a C program
that uses SSSD's actual struct definitions and `murmurhash3()`. This
ensures the Rust parser matches SSSD's on-disk format byte-for-byte.

Test fixtures are committed under `tests/fixtures/<version>/` so that
`cargo test` works without a C compiler. Regenerate them with `just
gen-fixtures <version>` after any change to the generator.

### Directory layout

```
tests/
  sssd-sources/
    head/              # SSSD git head (2.12.0)
      VERSION          # version string
      compat.h         # standalone build shims
      mmap_cache.h     # from SSSD src/util/
      murmurhash3.{h,c}# from SSSD src/shared/ and src/util/
      sss_endian.h     # from SSSD src/util/
    2.9.5/             # (example) older SSSD version
      ...
  gen_cache.c          # C generator (version-independent)
  fixtures/
    head/              # generated binary fixtures
      passwd.cache
      group.cache
      initgroups.cache
      sid.cache
      hashes.txt       # murmurhash3 reference values
```

### Adding a new SSSD version

1. **Get the source files.** Extract them from a src.rpm or git tag:

   ```sh
   # From src.rpm:
   rpm2cpio sssd-2.9.5-1.el9.src.rpm | cpio -idmv
   tar xf sssd-2.9.5.tar.gz

   # Or from git:
   cd ~/clone/sssd && git checkout sssd-2_9_5
   ```

2. **Create the version directory and copy files:**

   ```sh
   mkdir -p tests/sssd-sources/2.9.5
   cp sssd-2.9.5/src/util/mmap_cache.h    tests/sssd-sources/2.9.5/
   cp sssd-2.9.5/src/shared/murmurhash3.h tests/sssd-sources/2.9.5/
   cp sssd-2.9.5/src/util/murmurhash3.c   tests/sssd-sources/2.9.5/
   cp sssd-2.9.5/src/util/sss_endian.h    tests/sssd-sources/2.9.5/
   echo "2.9.5" > tests/sssd-sources/2.9.5/VERSION
   cp tests/sssd-sources/head/compat.h    tests/sssd-sources/2.9.5/
   ```

3. **Adjust include paths** in the copied `murmurhash3.c` and
   `mmap_cache.h` for standalone compilation (replace
   `"config.h"` / `"shared/murmurhash3.h"` / `"util/sss_endian.h"`
   with flat includes — see `head/` for the pattern).

4. **Generate fixtures:**

   ```sh
   just gen-fixtures 2.9.5
   ```

5. **Add integration tests.** In `tests/murmurhash3_crossval.rs`:

   ```rust
   #[test]
   fn crossval_2_9_5() {
       verify_hashes("2.9.5");
   }
   ```

   In `tests/parse_fixtures.rs`, add version-parameterized tests or
   duplicate the `*_head_*` tests for the new version.

6. **Commit the fixtures** (`tests/fixtures/2.9.5/`) so CI doesn't
   need a C compiler.

7. **Regenerate all fixtures at once** (optional):

   ```sh
   just gen-all-fixtures
   ```

## Cache files

SSSD creates these memory cache files under `/var/lib/sss/mc/`:

| File | Cache type | Contents |
|------|-----------|----------|
| `passwd` | `passwd` | User entries (name, uid, gid, gecos, homedir, shell) |
| `group` | `group` | Group entries (name, gid, members) |
| `initgroups` | `initgroups` | Initgroups data (user to group memberships) |
| `sid` | `sid` | SID-to-ID mappings (AD/IPA trust environments) |

## License

GPLv3 — see [COPYING](COPYING).
