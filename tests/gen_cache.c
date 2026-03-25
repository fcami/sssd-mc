/*
 * gen_cache — Generate SSSD memory cache test fixtures.
 *
 * Uses SSSD's actual struct definitions and murmurhash3 to produce
 * byte-identical cache files. Built against a specific SSSD version's
 * headers (see tests/sssd-sources/<version>/).
 *
 * Usage: gen_cache <output_dir>
 *
 * Produces:
 *   <output_dir>/passwd.cache      — passwd cache with known entries
 *   <output_dir>/group.cache       — group cache with known entries
 *   <output_dir>/initgroups.cache  — initgroups cache with known entries
 *   <output_dir>/sid.cache         — SID cache with known entries
 *   <output_dir>/hashes.txt        — murmurhash3 reference values
 *
 * Copyright (C) 2026 Francois Cami <contribs@fcami.net>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stddef.h>

#include "mmap_cache.h"

/* ------------------------------------------------------------------ */
/* Constants                                                          */
/* ------------------------------------------------------------------ */

#define TEST_SEED       0xdeadbeef
#define BARRIER_INIT    0xf0000001
#define NUM_HT_ENTRIES  64

/* Expire far in the future so tests don't break */
#define EXPIRE_FUTURE   ((uint64_t)4102444800)  /* 2100-01-01 */
#define EXPIRE_PAST     ((uint64_t)1000000000)  /* 2001-09-08 */

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static uint32_t mc_hash(const char *key, size_t len, uint32_t seed)
{
    return murmurhash3(key, (int)len, seed) % NUM_HT_ENTRIES;
}

/* Write a complete cache file.
 * Layout:
 *   [header]  MC_HEADER_SIZE bytes (64-byte aligned)
 *   [hash_table]  NUM_HT_ENTRIES * 4 bytes
 *   [free_table]  ft_size bytes
 *   [data_table]  dt_size bytes
 */

struct cache_builder {
    uint8_t *buf;
    size_t   buf_size;

    /* Offsets within buf */
    uint32_t ht_offset;
    uint32_t ft_offset;
    uint32_t dt_offset;

    uint32_t ht_size;
    uint32_t ft_size;
    uint32_t dt_size;

    /* Next free position in data table (relative to data table start) */
    uint32_t dt_pos;

    uint32_t seed;
};

static void builder_init(struct cache_builder *b, uint32_t num_slots)
{
    b->seed = TEST_SEED;
    b->ht_size = NUM_HT_ENTRIES * sizeof(uint32_t);
    b->dt_size = num_slots * MC_SLOT_SIZE;
    b->ft_size = (num_slots + 7) / 8;  /* 1 bit per slot */

    b->ht_offset = MC_HEADER_SIZE;
    b->ft_offset = b->ht_offset + b->ht_size;
    b->dt_offset = b->ft_offset + MC_ALIGN64(b->ft_size);

    b->buf_size = b->dt_offset + b->dt_size;
    b->buf = calloc(1, b->buf_size);
    if (!b->buf) {
        perror("calloc");
        exit(1);
    }

    b->dt_pos = 0;

    /* Initialize hash table to MC_INVALID_VAL */
    uint32_t *ht = (uint32_t *)(b->buf + b->ht_offset);
    for (uint32_t i = 0; i < NUM_HT_ENTRIES; i++) {
        ht[i] = MC_INVALID_VAL;
    }

    /* Initialize free table: all slots free (all bits 0) */
    /* (calloc already zeroed it) */
}

static void builder_write_header(struct cache_builder *b)
{
    struct sss_mc_header *h = (struct sss_mc_header *)b->buf;
    h->b1 = BARRIER_INIT;
    h->major_vno = SSS_MC_MAJOR_VNO;
    h->minor_vno = SSS_MC_MINOR_VNO;
    h->status = SSS_MC_HEADER_ALIVE;
    h->seed = b->seed;
    h->dt_size = b->dt_size;
    h->ft_size = MC_ALIGN64(b->ft_size);
    h->ht_size = b->ht_size;
    h->data_table = b->dt_offset;
    h->free_table = b->ft_offset;
    h->hash_table = b->ht_offset;
    h->reserved = 0;
    h->b2 = BARRIER_INIT;
}

/* Add a record to the data table and link it into the hash table.
 * Returns the slot number, or (uint32_t)-1 on failure. */
static uint32_t builder_add_record(struct cache_builder *b,
                                   uint32_t hash1, uint32_t hash2,
                                   uint64_t expire,
                                   const void *payload, uint32_t payload_len)
{
    uint32_t rec_len = sizeof(struct sss_mc_rec) + payload_len;
    uint32_t slots_needed = MC_SIZE_TO_SLOTS(rec_len);
    uint32_t slot = b->dt_pos / MC_SLOT_SIZE;

    if (b->dt_pos + slots_needed * MC_SLOT_SIZE > b->dt_size) {
        fprintf(stderr, "Data table full\n");
        return MC_INVALID_VAL;
    }

    uint8_t *rec_ptr = b->buf + b->dt_offset + b->dt_pos;
    struct sss_mc_rec *rec = (struct sss_mc_rec *)rec_ptr;

    rec->b1 = BARRIER_INIT;
    rec->len = rec_len;
    rec->expire = expire;
    rec->hash1 = hash1;
    rec->hash2 = hash2;
    rec->next1 = MC_INVALID_VAL;
    rec->next2 = MC_INVALID_VAL;
    rec->padding = 0;
    rec->b2 = BARRIER_INIT;

    memcpy(rec->data, payload, payload_len);

    /* Mark slots as used in free table */
    uint8_t *ft = b->buf + b->ft_offset;
    for (uint32_t i = 0; i < slots_needed; i++) {
        uint32_t s = slot + i;
        ft[s / 8] |= (0x80 >> (s % 8));
    }

    /* Link into hash table chain for hash1 */
    uint32_t *ht = (uint32_t *)(b->buf + b->ht_offset);
    uint32_t bucket1 = hash1 % NUM_HT_ENTRIES;
    if (ht[bucket1] != MC_INVALID_VAL) {
        rec->next1 = ht[bucket1];
    }
    ht[bucket1] = slot;

    /* Link into hash table chain for hash2.
     *
     * When bucket1 == bucket2, SSSD's sss_mc_add_rec_to_chain() detects
     * that the record is already in the chain (added by hash1) and skips
     * it. The record is findable by hash2 because sss_mc_next_slot_with_hash
     * checks rec->hash2 == hash and returns next2. We replicate this by
     * only linking hash2 into a *different* bucket. */
    uint32_t bucket2 = hash2 % NUM_HT_ENTRIES;
    if (bucket1 != bucket2) {
        if (ht[bucket2] != MC_INVALID_VAL) {
            rec->next2 = ht[bucket2];
        }
        ht[bucket2] = slot;
    }

    b->dt_pos += slots_needed * MC_SLOT_SIZE;
    return slot;
}

static int builder_write_file(struct cache_builder *b, const char *path)
{
    builder_write_header(b);

    FILE *f = fopen(path, "wb");
    if (!f) {
        perror(path);
        return -1;
    }
    if (fwrite(b->buf, 1, b->buf_size, f) != b->buf_size) {
        perror("fwrite");
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static void builder_free(struct cache_builder *b)
{
    free(b->buf);
    b->buf = NULL;
}

/* ------------------------------------------------------------------ */
/* Passwd cache builder                                               */
/* ------------------------------------------------------------------ */

static uint32_t build_passwd_payload(uint8_t *out, size_t out_size,
                                     const char *name, const char *passwd,
                                     uint32_t uid, uint32_t gid,
                                     const char *gecos, const char *dir,
                                     const char *shell)
{
    /* Build the strings buffer: name\0passwd\0gecos\0dir\0shell\0 */
    char strs[1024];
    uint32_t strs_len = 0;
    size_t len;

    len = strlen(name) + 1;
    memcpy(strs + strs_len, name, len); strs_len += len;
    len = strlen(passwd) + 1;
    memcpy(strs + strs_len, passwd, len); strs_len += len;
    len = strlen(gecos) + 1;
    memcpy(strs + strs_len, gecos, len); strs_len += len;
    len = strlen(dir) + 1;
    memcpy(strs + strs_len, dir, len); strs_len += len;
    len = strlen(shell) + 1;
    memcpy(strs + strs_len, shell, len); strs_len += len;

    struct sss_mc_pwd_data pwd;
    pwd.name = offsetof(struct sss_mc_pwd_data, strs);  /* points to start of strs */
    pwd.uid = uid;
    pwd.gid = gid;
    pwd.strs_len = strs_len;

    uint32_t total = sizeof(struct sss_mc_pwd_data) + strs_len;
    if (total > out_size) {
        fprintf(stderr, "Payload too large\n");
        exit(1);
    }

    memcpy(out, &pwd, sizeof(pwd));
    memcpy(out + sizeof(pwd), strs, strs_len);
    return total;
}

static int generate_passwd_cache(const char *output_dir)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/passwd.cache", output_dir);

    struct cache_builder b;
    builder_init(&b, 256);  /* 256 slots = 10240 bytes of data */

    uint8_t payload[1024];
    uint32_t plen;
    uint32_t hash1, hash2;
    char uidstr[11];

    /* Entry 1: root — active */
    plen = build_passwd_payload(payload, sizeof(payload),
                                "root", "x", 0, 0,
                                "root", "/root", "/bin/bash");
    hash1 = mc_hash("root", strlen("root") + 1, b.seed);
    snprintf(uidstr, sizeof(uidstr), "%d", 0);
    hash2 = mc_hash(uidstr, strlen(uidstr) + 1, b.seed);
    builder_add_record(&b, hash1, hash2, EXPIRE_FUTURE, payload, plen);

    /* Entry 2: testuser — active */
    plen = build_passwd_payload(payload, sizeof(payload),
                                "testuser", "x", 1000, 1000,
                                "Test User", "/home/testuser", "/bin/bash");
    hash1 = mc_hash("testuser", strlen("testuser") + 1, b.seed);
    snprintf(uidstr, sizeof(uidstr), "%d", 1000);
    hash2 = mc_hash(uidstr, strlen(uidstr) + 1, b.seed);
    builder_add_record(&b, hash1, hash2, EXPIRE_FUTURE, payload, plen);

    /* Entry 3: expired — expired */
    plen = build_passwd_payload(payload, sizeof(payload),
                                "expired", "x", 9999, 9999,
                                "Expired User", "/home/expired", "/sbin/nologin");
    hash1 = mc_hash("expired", strlen("expired") + 1, b.seed);
    snprintf(uidstr, sizeof(uidstr), "%d", 9999);
    hash2 = mc_hash(uidstr, strlen(uidstr) + 1, b.seed);
    builder_add_record(&b, hash1, hash2, EXPIRE_PAST, payload, plen);

    int ret = builder_write_file(&b, path);
    builder_free(&b);
    printf("  passwd.cache: 3 entries (2 active, 1 expired)\n");
    return ret;
}

/* ------------------------------------------------------------------ */
/* Group cache builder                                                */
/* ------------------------------------------------------------------ */

static uint32_t build_group_payload(uint8_t *out, size_t out_size,
                                    const char *name, const char *passwd,
                                    uint32_t gid, uint32_t num_members,
                                    const char **members)
{
    char strs[4096];
    uint32_t strs_len = 0;
    size_t len;

    len = strlen(name) + 1;
    memcpy(strs + strs_len, name, len); strs_len += len;
    len = strlen(passwd) + 1;
    memcpy(strs + strs_len, passwd, len); strs_len += len;
    for (uint32_t i = 0; i < num_members; i++) {
        len = strlen(members[i]) + 1;
        memcpy(strs + strs_len, members[i], len); strs_len += len;
    }

    struct sss_mc_grp_data grp;
    grp.name = offsetof(struct sss_mc_grp_data, strs);
    grp.gid = gid;
    grp.members = num_members;
    grp.strs_len = strs_len;

    uint32_t total = sizeof(struct sss_mc_grp_data) + strs_len;
    if (total > out_size) {
        fprintf(stderr, "Payload too large\n");
        exit(1);
    }

    memcpy(out, &grp, sizeof(grp));
    memcpy(out + sizeof(grp), strs, strs_len);
    return total;
}

static int generate_group_cache(const char *output_dir)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/group.cache", output_dir);

    struct cache_builder b;
    builder_init(&b, 256);

    uint8_t payload[4096];
    uint32_t plen;
    uint32_t hash1, hash2;
    char gidstr[11];

    /* Group 1: root — no members */
    plen = build_group_payload(payload, sizeof(payload),
                               "root", "x", 0, 0, NULL);
    hash1 = mc_hash("root", strlen("root") + 1, b.seed);
    snprintf(gidstr, sizeof(gidstr), "%d", 0);
    hash2 = mc_hash(gidstr, strlen(gidstr) + 1, b.seed);
    builder_add_record(&b, hash1, hash2, EXPIRE_FUTURE, payload, plen);

    /* Group 2: developers — 2 members */
    const char *dev_members[] = {"alice", "bob"};
    plen = build_group_payload(payload, sizeof(payload),
                               "developers", "x", 2000, 2, dev_members);
    hash1 = mc_hash("developers", strlen("developers") + 1, b.seed);
    snprintf(gidstr, sizeof(gidstr), "%d", 2000);
    hash2 = mc_hash(gidstr, strlen(gidstr) + 1, b.seed);
    builder_add_record(&b, hash1, hash2, EXPIRE_FUTURE, payload, plen);

    /* Group 3: empty — no members, expired */
    plen = build_group_payload(payload, sizeof(payload),
                               "oldgroup", "x", 5000, 0, NULL);
    hash1 = mc_hash("oldgroup", strlen("oldgroup") + 1, b.seed);
    snprintf(gidstr, sizeof(gidstr), "%d", 5000);
    hash2 = mc_hash(gidstr, strlen(gidstr) + 1, b.seed);
    builder_add_record(&b, hash1, hash2, EXPIRE_PAST, payload, plen);

    int ret = builder_write_file(&b, path);
    builder_free(&b);
    printf("  group.cache: 3 entries (2 active, 1 expired)\n");
    return ret;
}

/* ------------------------------------------------------------------ */
/* Initgroups cache builder                                           */
/* ------------------------------------------------------------------ */

static uint32_t build_initgr_payload(uint8_t *out, size_t out_size,
                                     const char *name,
                                     const char *unique_name,
                                     uint32_t num_groups,
                                     const uint32_t *gids)
{
    /*
     * Layout of sss_mc_initgr_data + variable data:
     *   struct sss_mc_initgr_data header (24 bytes)
     *   uint32_t gids[num_groups]
     *   char name\0unique_name\0
     */
    struct sss_mc_initgr_data initgr;
    uint32_t gids_size = num_groups * sizeof(uint32_t);

    size_t name_len = strlen(name) + 1;
    size_t uname_len = strlen(unique_name) + 1;
    uint32_t strs_len = name_len + uname_len;

    /* strs pointer is relative to start of the data payload (after McRec) */
    uint32_t strs_offset = sizeof(struct sss_mc_initgr_data) + gids_size;

    initgr.unique_name = strs_offset + name_len; /* unique_name follows name */
    initgr.name = strs_offset;                   /* name is first string */
    initgr.strs = strs_offset;
    initgr.strs_len = strs_len;
    initgr.data_len = gids_size;
    initgr.num_groups = num_groups;

    uint32_t total = sizeof(struct sss_mc_initgr_data) + gids_size + strs_len;
    if (total > out_size) {
        fprintf(stderr, "Initgr payload too large\n");
        exit(1);
    }

    uint8_t *p = out;
    memcpy(p, &initgr, sizeof(initgr));
    p += sizeof(initgr);
    if (gids_size > 0) {
        memcpy(p, gids, gids_size);
        p += gids_size;
    }
    memcpy(p, name, name_len);
    p += name_len;
    memcpy(p, unique_name, uname_len);

    return total;
}

static int generate_initgroups_cache(const char *output_dir)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/initgroups.cache", output_dir);

    struct cache_builder b;
    builder_init(&b, 256);

    uint8_t payload[1024];
    uint32_t plen;
    uint32_t hash1, hash2;

    /* Entry 1: testuser in groups 1000, 2000 — active */
    uint32_t gids1[] = {1000, 2000};
    plen = build_initgr_payload(payload, sizeof(payload),
                                "testuser", "testuser@EXAMPLE.COM",
                                2, gids1);
    /* initgroups hashes by name (hash1) and unique_name (hash2) */
    hash1 = mc_hash("testuser", strlen("testuser") + 1, b.seed);
    hash2 = mc_hash("testuser@EXAMPLE.COM",
                     strlen("testuser@EXAMPLE.COM") + 1, b.seed);
    builder_add_record(&b, hash1, hash2, EXPIRE_FUTURE, payload, plen);

    /* Entry 2: admin in groups 1000, 2000, 3000 — active */
    uint32_t gids2[] = {1000, 2000, 3000};
    plen = build_initgr_payload(payload, sizeof(payload),
                                "admin", "admin@EXAMPLE.COM",
                                3, gids2);
    hash1 = mc_hash("admin", strlen("admin") + 1, b.seed);
    hash2 = mc_hash("admin@EXAMPLE.COM",
                     strlen("admin@EXAMPLE.COM") + 1, b.seed);
    builder_add_record(&b, hash1, hash2, EXPIRE_FUTURE, payload, plen);

    /* Entry 3: olduser — expired */
    uint32_t gids3[] = {9999};
    plen = build_initgr_payload(payload, sizeof(payload),
                                "olduser", "olduser@EXAMPLE.COM",
                                1, gids3);
    hash1 = mc_hash("olduser", strlen("olduser") + 1, b.seed);
    hash2 = mc_hash("olduser@EXAMPLE.COM",
                     strlen("olduser@EXAMPLE.COM") + 1, b.seed);
    builder_add_record(&b, hash1, hash2, EXPIRE_PAST, payload, plen);

    int ret = builder_write_file(&b, path);
    builder_free(&b);
    printf("  initgroups.cache: 3 entries (2 active, 1 expired)\n");
    return ret;
}

/* ------------------------------------------------------------------ */
/* SID cache builder                                                  */
/* ------------------------------------------------------------------ */

static uint32_t build_sid_payload(uint8_t *out, size_t out_size,
                                  const char *sid_str, uint32_t id,
                                  uint32_t id_type, uint32_t populated_by)
{
    struct sss_mc_sid_data sid;
    uint32_t sid_len = strlen(sid_str) + 1;

    sid.name = sizeof(struct sss_mc_sid_data);  /* SID string follows struct */
    sid.type = id_type;
    sid.id = id;
    sid.populated_by = populated_by;
    sid.sid_len = sid_len;

    uint32_t total = sizeof(struct sss_mc_sid_data) + sid_len;
    if (total > out_size) {
        fprintf(stderr, "SID payload too large\n");
        exit(1);
    }

    memcpy(out, &sid, sizeof(sid));
    memcpy(out + sizeof(sid), sid_str, sid_len);
    return total;
}

static int generate_sid_cache(const char *output_dir)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/sid.cache", output_dir);

    struct cache_builder b;
    builder_init(&b, 256);

    uint8_t payload[1024];
    uint32_t plen;
    uint32_t hash1, hash2;
    char idstr[11];

    /* SID 1: user SID — active, populated by by_id() */
    const char *sid1 = "S-1-5-21-123456789-123456789-123456789-1001";
    plen = build_sid_payload(payload, sizeof(payload),
                             sid1, 1001, 1 /* SSS_ID_TYPE_UID */, 0);
    hash1 = mc_hash(sid1, strlen(sid1) + 1, b.seed);
    snprintf(idstr, sizeof(idstr), "%u", 1001);
    hash2 = mc_hash(idstr, strlen(idstr) + 1, b.seed);
    builder_add_record(&b, hash1, hash2, EXPIRE_FUTURE, payload, plen);

    /* SID 2: group SID — active, populated by by_gid() */
    const char *sid2 = "S-1-5-21-123456789-123456789-123456789-2001";
    plen = build_sid_payload(payload, sizeof(payload),
                             sid2, 2001, 2 /* SSS_ID_TYPE_GID */, 1);
    hash1 = mc_hash(sid2, strlen(sid2) + 1, b.seed);
    snprintf(idstr, sizeof(idstr), "%u", 2001);
    hash2 = mc_hash(idstr, strlen(idstr) + 1, b.seed);
    builder_add_record(&b, hash1, hash2, EXPIRE_FUTURE, payload, plen);

    /* SID 3: expired SID */
    const char *sid3 = "S-1-5-21-123456789-123456789-123456789-9999";
    plen = build_sid_payload(payload, sizeof(payload),
                             sid3, 9999, 1, 0);
    hash1 = mc_hash(sid3, strlen(sid3) + 1, b.seed);
    snprintf(idstr, sizeof(idstr), "%u", 9999);
    hash2 = mc_hash(idstr, strlen(idstr) + 1, b.seed);
    builder_add_record(&b, hash1, hash2, EXPIRE_PAST, payload, plen);

    int ret = builder_write_file(&b, path);
    builder_free(&b);
    printf("  sid.cache: 3 entries (2 active, 1 expired)\n");
    return ret;
}

/* ------------------------------------------------------------------ */
/* Collision fixture: passwd cache that triggers the hash2             */
/* unreachability bug.                                                 */
/* ------------------------------------------------------------------ */

/*
 * To trigger the bug we need:
 * 1. Record B where hash1("name") % ht == hash2("uid") % ht (same bucket)
 * 2. Record C inserted after B, where hash1("name_c") % ht == same bucket
 * 3. C pushes B down the chain via next1; B's next2 is MC_INVALID_VAL
 * 4. Lookup by B's UID walks chain from head (C), C's hash2 != B's hash2,
 *    follows next2 = MC_INVALID_VAL → B is unreachable.
 *
 * We use NUM_COLLISION_HT_ENTRIES = 4 to make collisions easy to find.
 */

#define NUM_COLLISION_HT_ENTRIES 4

static uint32_t collision_mc_hash(const char *key, size_t len, uint32_t seed)
{
    return murmurhash3(key, (int)len, seed) % NUM_COLLISION_HT_ENTRIES;
}

static void collision_builder_init(struct cache_builder *b, uint32_t num_slots)
{
    b->seed = TEST_SEED;
    b->ht_size = NUM_COLLISION_HT_ENTRIES * sizeof(uint32_t);
    b->dt_size = num_slots * MC_SLOT_SIZE;
    b->ft_size = (num_slots + 7) / 8;

    b->ht_offset = MC_HEADER_SIZE;
    b->ft_offset = b->ht_offset + b->ht_size;
    b->dt_offset = b->ft_offset + MC_ALIGN64(b->ft_size);

    b->buf_size = b->dt_offset + b->dt_size;
    b->buf = calloc(1, b->buf_size);
    if (!b->buf) {
        perror("calloc");
        exit(1);
    }

    b->dt_pos = 0;

    uint32_t *ht = (uint32_t *)(b->buf + b->ht_offset);
    for (uint32_t i = 0; i < NUM_COLLISION_HT_ENTRIES; i++) {
        ht[i] = MC_INVALID_VAL;
    }
}

static uint32_t collision_builder_add_record(struct cache_builder *b,
                                             uint32_t hash1, uint32_t hash2,
                                             uint64_t expire,
                                             const void *payload, uint32_t payload_len)
{
    uint32_t rec_len = sizeof(struct sss_mc_rec) + payload_len;
    uint32_t slots_needed = MC_SIZE_TO_SLOTS(rec_len);
    uint32_t slot = b->dt_pos / MC_SLOT_SIZE;

    if (b->dt_pos + slots_needed * MC_SLOT_SIZE > b->dt_size) {
        fprintf(stderr, "Data table full\n");
        return MC_INVALID_VAL;
    }

    uint8_t *rec_ptr = b->buf + b->dt_offset + b->dt_pos;
    struct sss_mc_rec *rec = (struct sss_mc_rec *)rec_ptr;

    rec->b1 = BARRIER_INIT;
    rec->len = rec_len;
    rec->expire = expire;
    rec->hash1 = hash1;
    rec->hash2 = hash2;
    rec->next1 = MC_INVALID_VAL;
    rec->next2 = MC_INVALID_VAL;
    rec->padding = 0;
    rec->b2 = BARRIER_INIT;

    memcpy(rec->data, payload, payload_len);

    uint8_t *ft = b->buf + b->ft_offset;
    for (uint32_t i = 0; i < slots_needed; i++) {
        uint32_t s = slot + i;
        ft[s / 8] |= (0x80 >> (s % 8));
    }

    /* Replicate SSSD's sss_mc_add_rec_to_chain() behavior exactly:
     * - Insert into hash1's bucket chain
     * - If bucket1 != bucket2, also insert into hash2's bucket chain
     * - If bucket1 == bucket2, skip hash2 (this is the bug) */
    uint32_t *ht = (uint32_t *)(b->buf + b->ht_offset);
    uint32_t bucket1 = hash1 % NUM_COLLISION_HT_ENTRIES;
    if (ht[bucket1] != MC_INVALID_VAL) {
        rec->next1 = ht[bucket1];
    }
    ht[bucket1] = slot;

    uint32_t bucket2 = hash2 % NUM_COLLISION_HT_ENTRIES;
    if (bucket1 != bucket2) {
        if (ht[bucket2] != MC_INVALID_VAL) {
            rec->next2 = ht[bucket2];
        }
        ht[bucket2] = slot;
    }
    /* When bucket1 == bucket2: next2 stays MC_INVALID_VAL — the bug. */

    b->dt_pos += slots_needed * MC_SLOT_SIZE;
    return slot;
}

static int generate_collision_cache(const char *output_dir)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/collision.cache", output_dir);

    /* With only 4 hash buckets, we brute-force to find the collision
     * condition at generation time. */

    struct cache_builder b;
    collision_builder_init(&b, 256);

    uint8_t payload[1024];
    uint32_t plen;

    /* Find a name+uid pair where hash1(name) % 4 == hash2(uid) % 4.
     * We try known names and UIDs. With 4 buckets this is very likely. */
    const char *victim_name = NULL;
    uint32_t victim_uid = 0;
    uint32_t victim_bucket = 0;

    /* Search for a same-bucket pair */
    struct { const char *name; uint32_t uid; } candidates[] = {
        {"alice", 5001}, {"bob", 5002}, {"carol", 5003},
        {"dave", 5004}, {"eve", 5005}, {"frank", 5006},
        {"grace", 5007}, {"heidi", 5008}, {"ivan", 5009},
        {"judy", 5010}, {"mallory", 5011}, {"oscar", 5012},
    };
    int ncandidates = sizeof(candidates) / sizeof(candidates[0]);

    for (int i = 0; i < ncandidates; i++) {
        uint32_t h1 = collision_mc_hash(candidates[i].name,
                                         strlen(candidates[i].name) + 1,
                                         b.seed);
        char uidstr[11];
        snprintf(uidstr, sizeof(uidstr), "%u", candidates[i].uid);
        uint32_t h2 = collision_mc_hash(uidstr, strlen(uidstr) + 1, b.seed);
        if (h1 == h2) {
            victim_name = candidates[i].name;
            victim_uid = candidates[i].uid;
            victim_bucket = h1;
            break;
        }
    }

    if (victim_name == NULL) {
        fprintf(stderr, "Could not find same-bucket collision pair\n");
        builder_free(&b);
        return -1;
    }

    printf("  collision.cache: victim=%s uid=%u bucket=%u\n",
           victim_name, victim_uid, victim_bucket);

    /* Step 1: Insert victim record (B) — hash1 and hash2 in same bucket */
    plen = build_passwd_payload(payload, sizeof(payload),
                                victim_name, "x", victim_uid, victim_uid,
                                "Victim User", "/home/victim", "/bin/bash");
    uint32_t h1_victim = murmurhash3(victim_name,
                                      strlen(victim_name) + 1, b.seed);
    char uidstr[11];
    snprintf(uidstr, sizeof(uidstr), "%u", victim_uid);
    uint32_t h2_victim = murmurhash3(uidstr, strlen(uidstr) + 1, b.seed);
    collision_builder_add_record(&b, h1_victim, h2_victim, EXPIRE_FUTURE,
                                 payload, plen);

    /* Step 2: Find a name whose hash1 lands in the same bucket, pushing
     * the victim down the chain. This record's hash2 must be different
     * from victim's hash2 (so chain walk by hash2 won't find victim). */
    const char *pusher_name = NULL;
    uint32_t pusher_uid = 0;

    for (int i = 0; i < ncandidates; i++) {
        if (candidates[i].name == victim_name) continue;
        uint32_t h1 = collision_mc_hash(candidates[i].name,
                                         strlen(candidates[i].name) + 1,
                                         b.seed);
        if (h1 == victim_bucket) {
            /* Also ensure pusher's hash2 doesn't accidentally land
             * in victim's bucket via hash2 chain */
            char uid2[11];
            snprintf(uid2, sizeof(uid2), "%u", candidates[i].uid);
            uint32_t h2 = murmurhash3(uid2, strlen(uid2) + 1, b.seed);
            if (h2 != h2_victim) {
                pusher_name = candidates[i].name;
                pusher_uid = candidates[i].uid;
                break;
            }
        }
    }

    if (pusher_name == NULL) {
        fprintf(stderr, "Could not find pusher for collision\n");
        builder_free(&b);
        return -1;
    }

    printf("  collision.cache: pusher=%s uid=%u (pushes victim down chain)\n",
           pusher_name, pusher_uid);

    plen = build_passwd_payload(payload, sizeof(payload),
                                pusher_name, "x", pusher_uid, pusher_uid,
                                "Pusher User", "/home/pusher", "/bin/bash");
    uint32_t h1_pusher = murmurhash3(pusher_name,
                                      strlen(pusher_name) + 1, b.seed);
    snprintf(uidstr, sizeof(uidstr), "%u", pusher_uid);
    uint32_t h2_pusher = murmurhash3(uidstr, strlen(uidstr) + 1, b.seed);
    collision_builder_add_record(&b, h1_pusher, h2_pusher, EXPIRE_FUTURE,
                                 payload, plen);

    /* Write metadata file so the Rust test knows which record is the victim */
    char meta_path[4096];
    snprintf(meta_path, sizeof(meta_path), "%s/collision_meta.txt", output_dir);
    FILE *mf = fopen(meta_path, "w");
    if (mf) {
        fprintf(mf, "victim_name %s\n", victim_name);
        fprintf(mf, "victim_uid %u\n", victim_uid);
        fprintf(mf, "victim_bucket %u\n", victim_bucket);
        fprintf(mf, "pusher_name %s\n", pusher_name);
        fprintf(mf, "pusher_uid %u\n", pusher_uid);
        fprintf(mf, "ht_entries %u\n", NUM_COLLISION_HT_ENTRIES);
        fclose(mf);
    }

    int ret = builder_write_file(&b, path);
    builder_free(&b);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Hash reference values                                              */
/* ------------------------------------------------------------------ */

static int generate_hash_reference(const char *output_dir)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/hashes.txt", output_dir);

    FILE *f = fopen(path, "w");
    if (!f) {
        perror(path);
        return -1;
    }

    /* Format: key_hex seed hash
     * key_hex is the key bytes in hex (including any \0 terminator) */
    struct {
        const char *key;
        int key_len;
        uint32_t seed;
    } tests[] = {
        { "",          0,  0          },
        { "root\0",   5,  0          },
        { "root\0",   5,  0xdeadbeef },
        { "test",     4,  0          },
        { "test",     4,  42         },
        { "alice\0",  6,  123        },
        { "bob\0",    4,  123        },
        { "a",        1,  42         },
        { "ab",       2,  42         },
        { "abc",      3,  42         },
        { "abcd",     4,  42         },
        { "testuser\0", 9, 0xdeadbeef },
        { "1000\0",   5,  0xdeadbeef },
        { "0\0",      2,  0xdeadbeef },
    };
    int ntests = sizeof(tests) / sizeof(tests[0]);

    fprintf(f, "# murmurhash3 reference values\n");
    fprintf(f, "# key_hex seed_hex hash_hex\n");

    for (int i = 0; i < ntests; i++) {
        uint32_t h = murmurhash3(tests[i].key, tests[i].key_len, tests[i].seed);

        /* Print key as hex */
        for (int j = 0; j < tests[i].key_len; j++) {
            fprintf(f, "%02x", (unsigned char)tests[i].key[j]);
        }
        if (tests[i].key_len == 0) {
            fprintf(f, "(empty)");
        }
        fprintf(f, " %08x %08x\n", tests[i].seed, h);
    }

    fclose(f);
    printf("  hashes.txt: %d reference values\n", ntests);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <output_dir>\n", argv[0]);
        return 1;
    }

    const char *output_dir = argv[1];

    /* Create output directory if needed */
    mkdir(output_dir, 0755);

    printf("Generating test fixtures in %s/\n", output_dir);

    if (generate_passwd_cache(output_dir) != 0) return 1;
    if (generate_group_cache(output_dir) != 0) return 1;
    if (generate_initgroups_cache(output_dir) != 0) return 1;
    if (generate_sid_cache(output_dir) != 0) return 1;
    if (generate_collision_cache(output_dir) != 0) return 1;
    if (generate_hash_reference(output_dir) != 0) return 1;

    printf("Done.\n");
    return 0;
}
