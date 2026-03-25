//! Integration tests that parse C-generated cache fixtures and verify contents.

use std::path::PathBuf;

use sssd_mc::parsers::cache::{extract_strings, CacheFile};
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
    let cache = open_passwd("head");
    let records: Vec<_> = cache.iter_records().collect();
    assert_eq!(records.len(), 3, "Expected 3 passwd records");
}

#[test]
fn passwd_head_root_entry() {
    let cache = open_passwd("head");
    let (slot, rec) = cache.iter_records().next().expect("at least one record");
    let data = cache.read_rec_data(slot, &rec).expect("valid record data");

    assert!(data.len() >= std::mem::size_of::<McPwdData>());
    let pwd: McPwdData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
    assert_eq!(pwd.uid, 0);
    assert_eq!(pwd.gid, 0);

    let strs_start = std::mem::size_of::<McPwdData>();
    let strs_end = strs_start + pwd.strs_len as usize;
    let strings = extract_strings(&data[strs_start..strs_end]);
    assert_eq!(strings.len(), 5, "passwd should have 5 strings");
    assert_eq!(strings[0], "root");
    assert_eq!(strings[1], "x");
    assert_eq!(strings[2], "root");       // gecos
    assert_eq!(strings[3], "/root");      // dir
    assert_eq!(strings[4], "/bin/bash");  // shell
}

#[test]
fn passwd_head_testuser_entry() {
    let cache = open_passwd("head");
    let records: Vec<_> = cache.iter_records().collect();
    assert!(records.len() >= 2, "Need at least 2 records");

    let (slot, rec) = &records[1];
    let data = cache.read_rec_data(*slot, rec).expect("valid record data");
    let pwd: McPwdData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
    assert_eq!(pwd.uid, 1000);
    assert_eq!(pwd.gid, 1000);

    let strs_start = std::mem::size_of::<McPwdData>();
    let strs_end = strs_start + pwd.strs_len as usize;
    let strings = extract_strings(&data[strs_start..strs_end]);
    assert_eq!(strings[0], "testuser");
    assert_eq!(strings[2], "Test User");
    assert_eq!(strings[3], "/home/testuser");
}

#[test]
fn passwd_head_expired_entry() {
    let cache = open_passwd("head");
    let records: Vec<_> = cache.iter_records().collect();
    assert!(records.len() >= 3, "Need at least 3 records");

    let (_slot, rec) = &records[2];
    // expire=1000000000 which is 2001-09-08, definitely in the past
    assert!(rec.expire < 2_000_000_000, "Third entry should have past expiry");
}

#[test]
fn passwd_head_hash_chain() {
    let cache = open_passwd("head");
    // Verify that hash table entries point to valid slots
    let ht_entries = cache.ht_entries();
    let mut found_non_empty = 0;
    for i in 0..ht_entries {
        let slot = cache.ht_entry(i).expect("valid ht entry");
        if slot != MC_INVALID_VAL32 {
            found_non_empty += 1;
            // Slot should be readable
            let rec = cache.read_rec(slot).expect("valid record at hash slot");
            assert!(valid_barrier(rec.b1), "Record at hash slot should have valid barrier");
            assert_eq!(rec.b1, rec.b2, "Record barriers should match");
        }
    }
    assert!(found_non_empty > 0, "At least one hash bucket should be non-empty");
}

// ---- group cache tests ----

fn open_group(version: &str) -> CacheFile {
    let path = fixtures_dir(version).join("group.cache");
    CacheFile::open(&path, CacheType::Group)
        .unwrap_or_else(|e| panic!("Failed to open {}: {e}. Run `just gen-fixtures {version}` first.", path.display()))
}

#[test]
fn group_head_record_count() {
    let cache = open_group("head");
    let records: Vec<_> = cache.iter_records().collect();
    assert_eq!(records.len(), 3, "Expected 3 group records");
}

#[test]
fn group_head_root_entry() {
    let cache = open_group("head");
    let (slot, rec) = cache.iter_records().next().expect("at least one record");
    let data = cache.read_rec_data(slot, &rec).expect("valid record data");

    let grp: McGrpData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
    assert_eq!(grp.gid, 0);
    assert_eq!(grp.members, 0);

    let strs_start = std::mem::size_of::<McGrpData>();
    let strs_end = strs_start + grp.strs_len as usize;
    let strings = extract_strings(&data[strs_start..strs_end]);
    assert_eq!(strings[0], "root");
    assert_eq!(strings[1], "x");
}

#[test]
fn group_head_developers_with_members() {
    let cache = open_group("head");
    let records: Vec<_> = cache.iter_records().collect();
    assert!(records.len() >= 2);

    let (slot, rec) = &records[1];
    let data = cache.read_rec_data(*slot, rec).expect("valid record data");

    let grp: McGrpData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
    assert_eq!(grp.gid, 2000);
    assert_eq!(grp.members, 2);

    let strs_start = std::mem::size_of::<McGrpData>();
    let strs_end = strs_start + grp.strs_len as usize;
    let strings = extract_strings(&data[strs_start..strs_end]);
    // name, passwd, member1, member2
    assert_eq!(strings[0], "developers");
    assert_eq!(strings[1], "x");
    assert_eq!(strings[2], "alice");
    assert_eq!(strings[3], "bob");
}

// ---- initgroups cache tests ----

fn open_initgroups(version: &str) -> CacheFile {
    let path = fixtures_dir(version).join("initgroups.cache");
    CacheFile::open(&path, CacheType::Initgroups)
        .unwrap_or_else(|e| panic!("Failed to open {}: {e}. Run `just gen-fixtures {version}` first.", path.display()))
}

#[test]
fn initgr_head_record_count() {
    let cache = open_initgroups("head");
    let records: Vec<_> = cache.iter_records().collect();
    assert_eq!(records.len(), 3, "Expected 3 initgroups records");
}

#[test]
fn initgr_head_testuser_entry() {
    let cache = open_initgroups("head");
    let (slot, rec) = cache.iter_records().next().expect("at least one record");
    let data = cache.read_rec_data(slot, &rec).expect("valid record data");

    assert!(data.len() >= std::mem::size_of::<McInitgrData>());
    let initgr: McInitgrData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
    assert_eq!(initgr.num_groups, 2);

    // Read GIDs
    let gids_start = std::mem::size_of::<McInitgrData>();
    let mut gids = Vec::new();
    for i in 0..initgr.num_groups as usize {
        let off = gids_start + i * 4;
        let gid = u32::from_ne_bytes([
            data[off], data[off + 1], data[off + 2], data[off + 3],
        ]);
        gids.push(gid);
    }
    assert_eq!(gids, vec![1000, 2000]);

    // Read name from strs offset
    let strs_offset = initgr.strs as usize;
    assert!(strs_offset < data.len());
    let strings = extract_strings(&data[strs_offset..]);
    assert!(strings.iter().any(|s| s == "testuser"), "should contain 'testuser'");
}

#[test]
fn initgr_head_admin_three_groups() {
    let cache = open_initgroups("head");
    let records: Vec<_> = cache.iter_records().collect();
    assert!(records.len() >= 2);

    let (slot, rec) = &records[1];
    let data = cache.read_rec_data(*slot, rec).expect("valid record data");
    let initgr: McInitgrData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
    assert_eq!(initgr.num_groups, 3);

    let gids_start = std::mem::size_of::<McInitgrData>();
    let mut gids = Vec::new();
    for i in 0..initgr.num_groups as usize {
        let off = gids_start + i * 4;
        let gid = u32::from_ne_bytes([
            data[off], data[off + 1], data[off + 2], data[off + 3],
        ]);
        gids.push(gid);
    }
    assert_eq!(gids, vec![1000, 2000, 3000]);
}

#[test]
fn initgr_head_expired_entry() {
    let cache = open_initgroups("head");
    let records: Vec<_> = cache.iter_records().collect();
    assert!(records.len() >= 3);
    let (_slot, rec) = &records[2];
    assert!(rec.expire < 2_000_000_000, "Third entry should be expired");
}

// ---- sid cache tests ----

fn open_sid(version: &str) -> CacheFile {
    let path = fixtures_dir(version).join("sid.cache");
    CacheFile::open(&path, CacheType::Sid)
        .unwrap_or_else(|e| panic!("Failed to open {}: {e}. Run `just gen-fixtures {version}` first.", path.display()))
}

#[test]
fn sid_head_record_count() {
    let cache = open_sid("head");
    let records: Vec<_> = cache.iter_records().collect();
    assert_eq!(records.len(), 3, "Expected 3 SID records");
}

#[test]
fn sid_head_user_sid() {
    let cache = open_sid("head");
    let (slot, rec) = cache.iter_records().next().expect("at least one record");
    let data = cache.read_rec_data(slot, &rec).expect("valid record data");

    assert!(data.len() >= std::mem::size_of::<McSidData>());
    let sid: McSidData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
    assert_eq!(sid.id, 1001);
    assert_eq!(sid.id_type, 1); // SSS_ID_TYPE_UID
    assert_eq!(sid.populated_by, 0); // by_id()

    let sid_start = std::mem::size_of::<McSidData>();
    let sid_end = sid_start + sid.sid_len as usize;
    assert!(sid_end <= data.len());
    let sid_str = std::str::from_utf8(&data[sid_start..sid_end])
        .expect("valid UTF-8 SID")
        .trim_end_matches('\0');
    assert_eq!(sid_str, "S-1-5-21-123456789-123456789-123456789-1001");
}

#[test]
fn sid_head_group_sid() {
    let cache = open_sid("head");
    let records: Vec<_> = cache.iter_records().collect();
    assert!(records.len() >= 2);

    let (slot, rec) = &records[1];
    let data = cache.read_rec_data(*slot, rec).expect("valid record data");
    let sid: McSidData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
    assert_eq!(sid.id, 2001);
    assert_eq!(sid.id_type, 2); // SSS_ID_TYPE_GID
    assert_eq!(sid.populated_by, 1); // by_gid()
}

#[test]
fn sid_head_expired_entry() {
    let cache = open_sid("head");
    let records: Vec<_> = cache.iter_records().collect();
    assert!(records.len() >= 3);
    let (_slot, rec) = &records[2];
    assert!(rec.expire < 2_000_000_000, "Third entry should be expired");
}

// ---- hash lookup tests ----

#[test]
fn passwd_head_hash_lookup_root() {
    let cache = open_passwd("head");
    let seed = cache.seed();

    // Hash "root\0" the same way SSSD does (including null terminator)
    let hash = sssd_mc::murmurhash3::murmurhash3(b"root\0", seed) % cache.ht_entries();
    let slot = cache.ht_entry(hash).expect("valid ht entry");
    assert_ne!(slot, MC_INVALID_VAL32, "root should be in hash table");

    let rec = cache.read_rec(slot).expect("valid record");
    let data = cache.read_rec_data(slot, &rec).expect("valid record data");
    let pwd: McPwdData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
    assert_eq!(pwd.uid, 0, "Hash lookup for root should find uid=0");
}
