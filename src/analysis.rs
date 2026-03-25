//! Cache integrity analysis.
//!
//! Checks for structural issues in SSSD memory cache files,
//! including hash chain reachability problems that can cause
//! lookup failures.

use crate::murmurhash3::murmurhash3;
use crate::parsers::cache::CacheFile;
use crate::types::*;

/// A problem found during cache verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheProblem {
    /// Record is unreachable via its secondary hash (hash2) chain walk.
    /// This means lookups by UID/GID will fail for this record.
    UnreachableByHash2 {
        slot: u32,
        hash1: u32,
        hash2: u32,
        bucket: u32,
        /// Name of the affected entry (if parseable).
        name: Option<String>,
        /// ID (UID/GID) of the affected entry (if parseable).
        id: Option<u32>,
    },

    /// Record's hash1 and hash2 resolve to the same bucket.
    /// This is a precondition for the unreachability bug.
    SameBucketHashes {
        slot: u32,
        hash1: u32,
        hash2: u32,
        bucket: u32,
    },

    /// Record has inconsistent barriers.
    BarrierMismatch {
        slot: u32,
        b1: u32,
        b2: u32,
    },

    /// Hash chain is longer than expected, suggesting degraded performance.
    LongChain {
        bucket: u32,
        length: u32,
    },

    /// Record's stored hash doesn't match recomputed hash from its data.
    HashMismatch {
        slot: u32,
        which: &'static str,
    },
}

impl std::fmt::Display for CacheProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnreachableByHash2 { slot, hash1, hash2, bucket, name, id } => {
                write!(f, "CRITICAL: record at slot {slot}")?;
                if let Some(n) = name {
                    write!(f, " ({n}")?;
                    if let Some(i) = id {
                        write!(f, ", id={i}")?;
                    }
                    write!(f, ")")?;
                }
                write!(f, " unreachable via hash2 \
                       (hash1={hash1:#x} hash2={hash2:#x} bucket={bucket}) — \
                       UID/GID lookup will fail")
            }
            Self::SameBucketHashes { slot, hash1, hash2, bucket } => {
                write!(f, "WARNING: record at slot {slot} has hash1={hash1:#x} and \
                       hash2={hash2:#x} both mapping to bucket {bucket}")
            }
            Self::BarrierMismatch { slot, b1, b2 } => {
                write!(f, "ERROR: record at slot {slot} has barrier mismatch \
                       (b1={b1:#010x} b2={b2:#010x})")
            }
            Self::LongChain { bucket, length } => {
                write!(f, "INFO: bucket {bucket} has chain length {length}")
            }
            Self::HashMismatch { slot, which } => {
                write!(f, "ERROR: record at slot {slot} has {which} mismatch \
                       (stored hash doesn't match recomputed hash from data)")
            }
        }
    }
}

/// Result of a full cache verification.
#[derive(Debug, Default)]
pub struct VerifyResult {
    pub problems: Vec<CacheProblem>,
    pub total_records: u32,
    pub same_bucket_count: u32,
    pub unreachable_count: u32,
    pub hash_mismatch_count: u32,
    pub max_chain_length: u32,
}

const LONG_CHAIN_THRESHOLD: u32 = 10;

/// Check whether a record at `target_slot` is reachable by walking the
/// hash chain from `ht[bucket]` using the given `hash` value.
///
/// This simulates what `sss_nss_mc_next_slot_with_hash()` does on the
/// client side: at each record, if `rec->hash1 == hash` follow `next1`,
/// if `rec->hash2 == hash` follow `next2`.
fn is_reachable_by_hash(cache: &CacheFile, target_slot: u32, bucket: u32, hash: u32) -> bool {
    let mut slot = match cache.ht_entry(bucket) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let mut visited = 0u32;
    let max_visits = cache.total_slots();

    while slot != MC_INVALID_VAL32 && visited < max_visits {
        if slot == target_slot {
            return true;
        }

        let rec = match cache.read_rec(slot) {
            Ok(r) => r,
            Err(_) => return false,
        };

        // Follow the chain the same way SSSD's client does
        if rec.hash1 == hash {
            slot = rec.next1;
        } else if rec.hash2 == hash {
            slot = rec.next2;
        } else {
            // Record in chain doesn't match this hash at all —
            // chain is corrupt or we followed the wrong path
            return false;
        }

        visited += 1;
    }

    false
}

/// Measure the chain length starting from a hash table bucket,
/// following records that have `hash` as either hash1 or hash2.
fn chain_length(cache: &CacheFile, bucket: u32, hash: u32) -> u32 {
    let mut slot = match cache.ht_entry(bucket) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let mut length = 0u32;
    let max = cache.total_slots();

    while slot != MC_INVALID_VAL32 && length < max {
        length += 1;
        let rec = match cache.read_rec(slot) {
            Ok(r) => r,
            Err(_) => break,
        };

        if rec.hash1 == hash {
            slot = rec.next1;
        } else if rec.hash2 == hash {
            slot = rec.next2;
        } else {
            break;
        }
    }

    length
}

/// Check structural integrity: barriers, reachability, chain lengths.
///
/// This does not read record payloads — it only examines record headers
/// and hash table structure.
pub fn verify_structure(cache: &CacheFile) -> VerifyResult {
    let mut result = VerifyResult::default();
    let ht_entries = cache.ht_entries();

    for (slot, rec) in cache.iter_records() {
        result.total_records += 1;

        if rec.b1 != rec.b2 {
            result.problems.push(CacheProblem::BarrierMismatch {
                slot,
                b1: rec.b1,
                b2: rec.b2,
            });
            continue;
        }

        let bucket1 = rec.hash1 % ht_entries;
        let bucket2 = rec.hash2 % ht_entries;

        if bucket1 == bucket2 {
            result.same_bucket_count += 1;
            result.problems.push(CacheProblem::SameBucketHashes {
                slot,
                hash1: rec.hash1,
                hash2: rec.hash2,
                bucket: bucket1,
            });
        }

        if !is_reachable_by_hash(cache, slot, bucket2, rec.hash2) {
            result.unreachable_count += 1;

            // Try to extract name and ID for actionable output
            let (name, id) = cache.parse_entry(slot, &rec)
                .map(|entry| match entry {
                    crate::entries::CacheEntry::Passwd(e) => (Some(e.name), Some(e.uid)),
                    crate::entries::CacheEntry::Group(e) => (Some(e.name), Some(e.gid)),
                    crate::entries::CacheEntry::Initgr(e) => (Some(e.name), None),
                    crate::entries::CacheEntry::Sid(e) => (Some(e.sid), Some(e.id)),
                })
                .unwrap_or((None, None));

            result.problems.push(CacheProblem::UnreachableByHash2 {
                slot,
                hash1: rec.hash1,
                hash2: rec.hash2,
                bucket: bucket2,
                name,
                id,
            });
        }
    }

    // Check chain lengths
    let mut checked_buckets = vec![false; ht_entries as usize];
    for i in 0..ht_entries {
        if checked_buckets[i as usize] {
            continue;
        }
        let slot = match cache.ht_entry(i) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if slot == MC_INVALID_VAL32 {
            continue;
        }
        checked_buckets[i as usize] = true;

        let rec = match cache.read_rec(slot) {
            Ok(r) => r,
            Err(_) => continue,
        };

        if rec.hash1 % ht_entries == i {
            let len = chain_length(cache, i, rec.hash1);
            if len > result.max_chain_length {
                result.max_chain_length = len;
            }
            if len > LONG_CHAIN_THRESHOLD {
                result.problems.push(CacheProblem::LongChain {
                    bucket: i,
                    length: len,
                });
            }
        }
    }

    result
}

/// Check hash integrity: recompute hashes from record data and compare
/// against stored values. Only supported for passwd and group caches.
pub fn verify_hashes(cache: &CacheFile) -> VerifyResult {
    let mut result = VerifyResult::default();

    for (slot, rec) in cache.iter_records() {
        result.total_records += 1;

        if let Some((h1_ok, h2_ok)) = verify_record_hashes(cache, slot, &rec) {
            if !h1_ok {
                result.hash_mismatch_count += 1;
                result.problems.push(CacheProblem::HashMismatch {
                    slot,
                    which: "hash1 (name)",
                });
            }
            if !h2_ok {
                result.hash_mismatch_count += 1;
                result.problems.push(CacheProblem::HashMismatch {
                    slot,
                    which: "hash2 (id)",
                });
            }
        }
    }

    result
}

/// Run all verification checks (structural + hash integrity).
pub fn verify_cache(cache: &CacheFile) -> VerifyResult {
    let mut result = verify_structure(cache);
    let hash_result = verify_hashes(cache);

    result.hash_mismatch_count = hash_result.hash_mismatch_count;
    result.problems.extend(hash_result.problems);

    result
}

/// Recompute hashes for a record's data and verify they match the stored
/// hash1/hash2 values. Requires knowing the cache type and seed.
///
/// For passwd: hash1 = hash(name\0), hash2 = hash(uid_string\0)
/// For group: hash1 = hash(name\0), hash2 = hash(gid_string\0)
pub fn verify_record_hashes(
    cache: &CacheFile,
    slot: u32,
    rec: &McRec,
) -> Option<(bool, bool)> {
    let data = cache.read_rec_data(slot, rec).ok()?;
    let seed = cache.seed();
    let ht_entries = cache.ht_entries();

    match cache.cache_type {
        CacheType::Passwd => {
            if data.len() < std::mem::size_of::<McPwdData>() {
                return None;
            }
            let pwd: McPwdData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
            let strs_start = std::mem::size_of::<McPwdData>();
            let strs = &data[strs_start..];
            // Find name (first null-terminated string)
            let name_end = strs.iter().position(|&b| b == 0)?;
            let name_with_null = &strs[..=name_end];
            let uid_str = format!("{}\0", pwd.uid);

            let expected_hash1 = murmurhash3(name_with_null, seed) % ht_entries;
            let expected_hash2 = murmurhash3(uid_str.as_bytes(), seed) % ht_entries;

            let hash1_ok = rec.hash1 % ht_entries == expected_hash1;
            let hash2_ok = rec.hash2 % ht_entries == expected_hash2;
            Some((hash1_ok, hash2_ok))
        }
        CacheType::Group => {
            if data.len() < std::mem::size_of::<McGrpData>() {
                return None;
            }
            let grp: McGrpData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
            let strs_start = std::mem::size_of::<McGrpData>();
            let strs = &data[strs_start..];
            let name_end = strs.iter().position(|&b| b == 0)?;
            let name_with_null = &strs[..=name_end];
            let gid_str = format!("{}\0", grp.gid);

            let expected_hash1 = murmurhash3(name_with_null, seed) % ht_entries;
            let expected_hash2 = murmurhash3(gid_str.as_bytes(), seed) % ht_entries;

            let hash1_ok = rec.hash1 % ht_entries == expected_hash1;
            let hash2_ok = rec.hash2 % ht_entries == expected_hash2;
            Some((hash1_ok, hash2_ok))
        }
        _ => None, // TODO: initgroups, sid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problem_display() {
        let p = CacheProblem::UnreachableByHash2 {
            slot: 5, hash1: 0x10, hash2: 0x20, bucket: 3,
            name: Some("testuser".to_string()), id: Some(1000),
        };
        let msg = format!("{p}");
        assert!(msg.contains("CRITICAL"));
        assert!(msg.contains("slot 5"));
        assert!(msg.contains("UID/GID lookup will fail"));
    }

    #[test]
    fn problem_same_bucket_display() {
        let p = CacheProblem::SameBucketHashes {
            slot: 2, hash1: 0x40, hash2: 0x40, bucket: 0,
        };
        let msg = format!("{p}");
        assert!(msg.contains("WARNING"));
        assert!(msg.contains("bucket 0"));
    }
}
