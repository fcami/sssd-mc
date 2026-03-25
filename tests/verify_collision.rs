//! Integration test for the hash collision detection in `verify`.
//!
//! Uses the collision.cache fixture which has a record that is
//! unreachable by its secondary hash (hash2) due to SSSD's
//! same-bucket chain linking behavior.

use std::path::PathBuf;

use sssd_mc::analysis::{verify_cache, CacheProblem};
use sssd_mc::parsers::cache::CacheFile;
use sssd_mc::types::CacheType;

fn fixtures_dir(version: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(version)
}

fn read_meta(version: &str) -> std::collections::HashMap<String, String> {
    let path = fixtures_dir(version).join("collision_meta.txt");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
    content
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, ' ');
            let key = parts.next()?;
            let val = parts.next()?;
            Some((key.to_string(), val.to_string()))
        })
        .collect()
}

#[test]
fn collision_cache_detects_unreachable_record() {
    let path = fixtures_dir("head").join("collision.cache");
    let cache = CacheFile::open(&path, CacheType::Passwd)
        .unwrap_or_else(|e| panic!("Failed to open collision.cache: {e}. Run `just gen-fixtures head` first."));

    let result = verify_cache(&cache);

    // Should have exactly 2 records
    assert_eq!(result.total_records, 2, "Expected 2 records in collision fixture");

    // Should detect at least one same-bucket condition
    assert!(result.same_bucket_count > 0,
            "Should detect same-bucket hash condition");

    // Should detect the victim as unreachable by hash2
    assert!(result.unreachable_count > 0,
            "Should detect unreachable record (the SSSD hash collision bug)");

    // Verify the unreachable problem references the victim
    let unreachable: Vec<_> = result.problems.iter()
        .filter(|p| matches!(p, CacheProblem::UnreachableByHash2 { .. }))
        .collect();
    assert!(!unreachable.is_empty(),
            "Should have at least one UnreachableByHash2 problem");

    eprintln!("  Detected {} unreachable record(s)", unreachable.len());
    for p in &unreachable {
        eprintln!("  {p}");
    }
}

#[test]
fn collision_meta_matches_fixture() {
    let meta = read_meta("head");
    assert_eq!(meta.get("ht_entries").map(|s| s.as_str()), Some("4"),
               "Collision fixture should use 4 hash buckets");
    assert!(meta.contains_key("victim_name"), "Meta should have victim_name");
    assert!(meta.contains_key("pusher_name"), "Meta should have pusher_name");
}

#[test]
fn normal_passwd_cache_has_no_unreachable() {
    let path = fixtures_dir("head").join("passwd.cache");
    let cache = CacheFile::open(&path, CacheType::Passwd)
        .expect("passwd.cache should open");

    let result = verify_cache(&cache);
    assert_eq!(result.unreachable_count, 0,
               "Normal passwd cache should have no unreachable records");
}

#[test]
fn normal_group_cache_has_no_unreachable() {
    let path = fixtures_dir("head").join("group.cache");
    let cache = CacheFile::open(&path, CacheType::Group)
        .expect("group.cache should open");

    let result = verify_cache(&cache);
    assert_eq!(result.unreachable_count, 0,
               "Normal group cache should have no unreachable records");
}
