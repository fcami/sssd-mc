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
