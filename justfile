# sssd-mc — task runner

# Default: run all checks
default: check

# Full check: build + lint + test
check: build lint test

# Build (debug)
build:
    cargo build

# Clippy with warnings as errors
lint:
    cargo clippy -- -D warnings

# Run all tests (unit + integration, skip ignored)
test:
    cargo test

# Run only unit tests
unit:
    cargo test --lib

# Run only integration tests
integration:
    cargo test --test '*'

# Build release binary
release:
    cargo build --release

# --- Container builds (UBI) ---

# Build or refresh a UBI builder image for a given RHEL version
_ensure-image ver:
    python3 {{ justfile_directory() }}/scripts/ensure-builder-image.py {{ ver }}

# Podman format string (just can't escape Go templates cleanly in shebang recipes)

[private]
_podman_fmt := '{{.Repository}}:{{.Tag}}'

# Run a containerized release build for a given RHEL version
_release-ubi ver: (_ensure-image ver)
    #!/usr/bin/env bash
    set -euo pipefail
    image="sssd-mc-builder-rhel{{ ver }}"
    fmt='{{ _podman_fmt }}'
    latest=$(podman images --format "$fmt" \
        | grep "^localhost/${image}:" \
        | sort -t: -k2 -r | head -1)
    echo "[build] Using $latest"
    podman run --rm -v {{ justfile_directory() }}:/src:Z "$latest" \
        bash -c "cd /src && cargo build --release"

# Build release binary for RHEL 8 using UBI8 container
release-rhel8: (_release-ubi "8")

# Build release binary for RHEL 9 using UBI9 container
release-rhel9: (_release-ubi "9")

# Build release binary for RHEL 10 using UBI10 container
release-rhel10: (_release-ubi "10")

# Vendor dependencies for offline/air-gapped builds
vendor:
    cargo vendor
    mkdir -p .cargo
    @echo '[source.crates-io]' > .cargo/config.toml
    @echo 'replace-with = "vendored-sources"' >> .cargo/config.toml
    @echo '[source.vendored-sources]' >> .cargo/config.toml
    @echo 'directory = "vendor"' >> .cargo/config.toml
    @echo "[vendor] Vendored sources written to vendor/ and .cargo/config.toml"

# Remove vendored dependencies (reverts to crates.io downloads)
unvendor:
    rm -rf vendor .cargo/config.toml
    @echo "[unvendor] Removed vendor/ and .cargo/config.toml"

# --- Test fixture generation ---

# Build the C test cache generator for a given SSSD version
build-gen version="head":
    cc -Wall -Wextra -O2 \
        -I {{ justfile_directory() }}/tests/sssd-sources/{{ version }} \
        {{ justfile_directory() }}/tests/gen_cache.c \
        {{ justfile_directory() }}/tests/sssd-sources/{{ version }}/murmurhash3.c \
        -o {{ justfile_directory() }}/tests/gen_cache_{{ version }}

# Generate test fixtures for a given SSSD version
gen-fixtures version="head": (build-gen version)
    {{ justfile_directory() }}/tests/gen_cache_{{ version }} \
        {{ justfile_directory() }}/tests/fixtures/{{ version }}
    @echo "[fixtures] Generated for SSSD {{ version }}"

# Generate fixtures for all known SSSD versions
gen-all-fixtures:
    #!/usr/bin/env bash
    set -euo pipefail
    for ver in {{ justfile_directory() }}/tests/sssd-sources/*/; do
        ver=$(basename "$ver")
        echo "[fixtures] Building for SSSD $ver"
        just gen-fixtures "$ver"
    done

# Clean build artifacts
clean:
    cargo clean
    rm -f tests/gen_cache_*
