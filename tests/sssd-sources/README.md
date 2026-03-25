# SSSD source files for test cache generation

Each subdirectory contains SSSD source files needed to build the test
cache generator (`gen_cache`). Files are copied verbatim from the SSSD
source tree, except for include path adjustments noted below.

## Directory layout

```
sssd-sources/
  head/           # current SSSD git head
    VERSION       # SSSD version string
    compat.h      # standalone build compatibility defines
    mmap_cache.h  # from src/util/mmap_cache.h (verbatim)
    murmurhash3.h # from src/shared/murmurhash3.h (verbatim)
    murmurhash3.c # from src/util/murmurhash3.c (include paths adjusted)
    sss_endian.h  # from src/util/sss_endian.h (verbatim)
  2.9.5/          # (future) extracted from sssd-2.9.5 src.rpm
    ...
```

## Adding a new version

1. Create a new directory named after the SSSD version
2. Copy the four source files from the SSSD source tree or src.rpm
3. Add a `VERSION` file with the exact version string
4. Add `compat.h` (copy from head/ and adjust if needed)
5. Adjust include paths in `murmurhash3.c` if they differ
6. Run `just gen-fixtures <version>` to generate test fixtures
7. Commit the fixtures under `tests/fixtures/<version>/`
