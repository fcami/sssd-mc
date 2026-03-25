//! Integration tests that parse C-generated cache fixtures and verify contents.
//!
//! Uses CacheFile::parse_entry() — no unsafe code in tests.

use std::path::PathBuf;

use sssd_mc::entries::*;
use sssd_mc::parsers::cache::CacheFile;
use sssd_mc::types::*;

fn fixtures_dir(version: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(version)
}

// ---- passwd cache tests ----

fn open_passwd(version: &str) -> CacheFile {
    let path = fixtures_dir(version).join("passwd.cache");
    CacheFile::open(&path, CacheType::Passwd)
        .unwrap_or_else(|e| panic!("Failed to open {}: {e}. Run `just gen-fixtures {version}` first.", path.display()))
}

fn passwd_entries(version: &str) -> Vec<(u32, PasswdEntry)> {
    let cache = open_passwd(version);
    cache.iter_records()
        .filter_map(|(slot, rec)| {
            match cache.parse_entry(slot, &rec) {
                Ok(CacheEntry::Passwd(e)) => Some((slot, e)),
                _ => None,
            }
        })
        .collect()
}

#[test]
fn passwd_head_header_valid() {
    let cache = open_passwd("head");
    assert_eq!(cache.header.major_vno, 1);
    assert_eq!(cache.header.minor_vno, 1);
    assert_eq!(cache.header.status, SSS_MC_HEADER_ALIVE);
    assert_eq!(cache.header.seed, 0xdeadbeef);
}

#[test]
fn passwd_head_record_count() {
    let entries = passwd_entries("head");
    assert_eq!(entries.len(), 3, "Expected 3 passwd records");
}

#[test]
fn passwd_head_root_entry() {
    let entries = passwd_entries("head");
    let (_, ref root) = entries[0];
    assert_eq!(root.name, "root");
    assert_eq!(root.uid, 0);
    assert_eq!(root.gid, 0);
    assert_eq!(root.passwd, "x");
    assert_eq!(root.gecos, "root");
    assert_eq!(root.dir, "/root");
    assert_eq!(root.shell, "/bin/bash");
}

#[test]
fn passwd_head_testuser_entry() {
    let entries = passwd_entries("head");
    let (_, ref user) = entries[1];
    assert_eq!(user.name, "testuser");
    assert_eq!(user.uid, 1000);
    assert_eq!(user.gid, 1000);
    assert_eq!(user.gecos, "Test User");
    assert_eq!(user.dir, "/home/testuser");
}

#[test]
fn passwd_head_expired_entry() {
    let cache = open_passwd("head");
    let records: Vec<_> = cache.iter_records().collect();
    let (slot, rec) = &records[2];
    let entry = cache.parse_entry(*slot, rec).unwrap();
    if let CacheEntry::Passwd(e) = entry {
        assert_eq!(e.name, "expired");
        // expire=1000000000 (2001-09-08), definitely in the past
        assert!(e.expire < 2_000_000_000);
    } else {
        panic!("Expected passwd entry");
    }
}

#[test]
fn passwd_head_hash_chain() {
    let cache = open_passwd("head");
    let ht_entries = cache.ht_entries();
    let mut found_non_empty = 0;
    for i in 0..ht_entries {
        let slot = cache.ht_entry(i).expect("valid ht entry");
        if slot != MC_INVALID_VAL32 {
            found_non_empty += 1;
            let rec = cache.read_rec(slot).expect("valid record at hash slot");
            assert!(valid_barrier(rec.b1));
            assert_eq!(rec.b1, rec.b2);
        }
    }
    assert!(found_non_empty > 0);
}

// ---- group cache tests ----

fn open_group(version: &str) -> CacheFile {
    let path = fixtures_dir(version).join("group.cache");
    CacheFile::open(&path, CacheType::Group)
        .unwrap_or_else(|e| panic!("Failed to open {}: {e}. Run `just gen-fixtures {version}` first.", path.display()))
}

fn group_entries(version: &str) -> Vec<(u32, GroupEntry)> {
    let cache = open_group(version);
    cache.iter_records()
        .filter_map(|(slot, rec)| {
            match cache.parse_entry(slot, &rec) {
                Ok(CacheEntry::Group(e)) => Some((slot, e)),
                _ => None,
            }
        })
        .collect()
}

#[test]
fn group_head_record_count() {
    let entries = group_entries("head");
    assert_eq!(entries.len(), 3, "Expected 3 group records");
}

#[test]
fn group_head_root_entry() {
    let entries = group_entries("head");
    let (_, ref root) = entries[0];
    assert_eq!(root.name, "root");
    assert_eq!(root.gid, 0);
    assert_eq!(root.passwd, "x");
    assert!(root.members.is_empty());
}

#[test]
fn group_head_developers_with_members() {
    let entries = group_entries("head");
    let (_, ref dev) = entries[1];
    assert_eq!(dev.name, "developers");
    assert_eq!(dev.gid, 2000);
    assert_eq!(dev.members, vec!["alice", "bob"]);
}

// ---- initgroups cache tests ----

fn open_initgroups(version: &str) -> CacheFile {
    let path = fixtures_dir(version).join("initgroups.cache");
    CacheFile::open(&path, CacheType::Initgroups)
        .unwrap_or_else(|e| panic!("Failed to open {}: {e}. Run `just gen-fixtures {version}` first.", path.display()))
}

fn initgr_entries(version: &str) -> Vec<(u32, InitgrEntry)> {
    let cache = open_initgroups(version);
    cache.iter_records()
        .filter_map(|(slot, rec)| {
            match cache.parse_entry(slot, &rec) {
                Ok(CacheEntry::Initgr(e)) => Some((slot, e)),
                _ => None,
            }
        })
        .collect()
}

#[test]
fn initgr_head_record_count() {
    let entries = initgr_entries("head");
    assert_eq!(entries.len(), 3, "Expected 3 initgroups records");
}

#[test]
fn initgr_head_testuser_entry() {
    let entries = initgr_entries("head");
    let (_, ref user) = entries[0];
    assert_eq!(user.name, "testuser");
    assert_eq!(user.gids, vec![1000, 2000]);
}

#[test]
fn initgr_head_admin_three_groups() {
    let entries = initgr_entries("head");
    let (_, ref admin) = entries[1];
    assert_eq!(admin.name, "admin");
    assert_eq!(admin.gids, vec![1000, 2000, 3000]);
}

#[test]
fn initgr_head_expired_entry() {
    let entries = initgr_entries("head");
    let (_, ref old) = entries[2];
    assert!(old.expire < 2_000_000_000);
}

// ---- sid cache tests ----

fn open_sid(version: &str) -> CacheFile {
    let path = fixtures_dir(version).join("sid.cache");
    CacheFile::open(&path, CacheType::Sid)
        .unwrap_or_else(|e| panic!("Failed to open {}: {e}. Run `just gen-fixtures {version}` first.", path.display()))
}

fn sid_entries(version: &str) -> Vec<(u32, SidEntry)> {
    let cache = open_sid(version);
    cache.iter_records()
        .filter_map(|(slot, rec)| {
            match cache.parse_entry(slot, &rec) {
                Ok(CacheEntry::Sid(e)) => Some((slot, e)),
                _ => None,
            }
        })
        .collect()
}

#[test]
fn sid_head_record_count() {
    let entries = sid_entries("head");
    assert_eq!(entries.len(), 3, "Expected 3 SID records");
}

#[test]
fn sid_head_user_sid() {
    let entries = sid_entries("head");
    let (_, ref sid) = entries[0];
    assert_eq!(sid.sid, "S-1-5-21-123456789-123456789-123456789-1001");
    assert_eq!(sid.id, 1001);
    assert_eq!(sid.id_type, 1); // SSS_ID_TYPE_UID
    assert_eq!(sid.populated_by, 0); // by_id()
}

#[test]
fn sid_head_group_sid() {
    let entries = sid_entries("head");
    let (_, ref sid) = entries[1];
    assert_eq!(sid.id, 2001);
    assert_eq!(sid.id_type, 2); // SSS_ID_TYPE_GID
    assert_eq!(sid.populated_by, 1); // by_gid()
}

#[test]
fn sid_head_expired_entry() {
    let entries = sid_entries("head");
    let (_, ref sid) = entries[2];
    assert!(sid.expire < 2_000_000_000);
}

// ---- hash lookup tests ----

#[test]
fn passwd_head_hash_lookup_root() {
    let cache = open_passwd("head");
    let seed = cache.seed();
    let hash = sssd_mc::murmurhash3::murmurhash3(b"root\0", seed) % cache.ht_entries();
    let slot = cache.ht_entry(hash).expect("valid ht entry");
    assert_ne!(slot, MC_INVALID_VAL32);

    let rec = cache.read_rec(slot).expect("valid record");
    let entry = cache.parse_entry(slot, &rec).unwrap();
    if let CacheEntry::Passwd(e) = entry {
        assert_eq!(e.uid, 0, "Hash lookup for root should find uid=0");
    } else {
        panic!("Expected passwd entry");
    }
}

#[test]
fn passwd_head_hash_lookup_by_uid() {
    let cache = open_passwd("head");
    let seed = cache.seed();
    let hash = sssd_mc::murmurhash3::murmurhash3(b"1000\0", seed) % cache.ht_entries();
    let mut slot = cache.ht_entry(hash).expect("valid ht entry");

    let mut found = false;
    while slot != MC_INVALID_VAL32 {
        let rec = cache.read_rec(slot).expect("valid record");
        if rec.hash2 == hash {
            let entry = cache.parse_entry(slot, &rec).unwrap();
            if let CacheEntry::Passwd(e) = entry {
                assert_eq!(e.uid, 1000);
                found = true;
                break;
            }
        }
        if rec.hash1 == hash {
            slot = rec.next1;
        } else if rec.hash2 == hash {
            slot = rec.next2;
        } else {
            break;
        }
    }
    assert!(found, "Should find testuser via UID hash lookup");
}
