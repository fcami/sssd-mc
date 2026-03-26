// SPDX-FileCopyrightText: cache.rs 2026, ["François Cami" <contribs@fcami.net>]
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parser for SSSD mmap cache files.
//!
//! Opens a cache file (or reads from a byte slice), validates the header,
//! and provides access to records via hash lookup or iteration.

use std::path::Path;

use memmap2::Mmap;

use crate::{
    entries,
    entries::CacheEntry,
    errors::{McError, McResult},
    murmurhash3::murmurhash3,
    types::{
        CacheType, MC_INVALID_VAL32, MC_SLOT_SIZE, McHeader, McRec, SSS_MC_HEADER_ALIVE,
        SSS_MC_MAJOR_VNO, SSS_MC_MINOR_VNO, valid_barrier,
    },
};

/// Validated, read-only view of an SSSD memory cache file.
#[derive(Debug)]
pub struct CacheFile {
    mmap: Mmap,
    pub header: McHeader,
    pub cache_type: CacheType,
    /// File modification time as seconds since the UNIX epoch, if available.
    pub file_mtime: Option<u64>,
}

/// Aligned header size (rounded up to 64-byte boundary).
const MC_HEADER_ALIGNED: usize = (size_of::<McHeader>() + 7) & !7;

impl CacheFile {
    /// Open and validate a cache file from disk.
    pub fn open(path: &Path, cache_type: CacheType) -> McResult<Self> {
        let file = std::fs::File::open(path).map_err(|e| McError::Open {
            path: path.to_path_buf(),
            source: e,
        })?;

        let file_mtime = file
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());

        // SAFETY: we open read-only; the file may be concurrently modified
        // by sssd_nss, but we only read and validate barriers.
        let mmap = unsafe {
            Mmap::map(&file).map_err(|e| McError::Open {
                path: path.to_path_buf(),
                source: e,
            })?
        };

        Self::from_bytes(mmap, cache_type, file_mtime)
    }

    /// Parse from an already-mapped region.
    fn from_bytes(mmap: Mmap, cache_type: CacheType, file_mtime: Option<u64>) -> McResult<Self> {
        if mmap.len() < MC_HEADER_ALIGNED {
            return Err(McError::TooSmall {
                size: mmap.len(),
                min: MC_HEADER_ALIGNED,
            });
        }

        let header = read_header(&mmap);
        validate_header(&header, mmap.len())?;

        Ok(Self {
            mmap,
            header,
            cache_type,
            file_mtime,
        })
    }

    /// Return the raw data table slice.
    #[must_use]
    pub fn data_table(&self) -> &[u8] {
        let start = self.header.data_table as usize;
        let end = start + self.header.dt_size as usize;
        &self.mmap[start..end]
    }

    /// Return the hash table as a slice of bytes.
    #[must_use]
    pub fn hash_table(&self) -> &[u8] {
        let start = self.header.hash_table as usize;
        let end = start + self.header.ht_size as usize;
        &self.mmap[start..end]
    }

    /// Number of hash table entries.
    #[must_use]
    pub fn ht_entries(&self) -> u32 {
        self.header.ht_size / size_of::<u32>() as u32
    }

    /// Read a hash table entry (slot index) at the given hash bucket.
    pub fn ht_entry(&self, bucket: u32) -> McResult<u32> {
        let ht = self.hash_table();
        let offset = (bucket as usize) * size_of::<u32>();
        if offset + 4 > ht.len() {
            return Err(McError::OutOfBounds {
                offset,
                size: ht.len(),
            });
        }
        Ok(u32::from_ne_bytes([
            ht[offset],
            ht[offset + 1],
            ht[offset + 2],
            ht[offset + 3],
        ]))
    }

    /// Read the record header at the given slot in the data table.
    pub fn read_rec(&self, slot: u32) -> McResult<McRec> {
        let dt = self.data_table();
        let offset = (slot as usize) * MC_SLOT_SIZE as usize;
        let rec_size = size_of::<McRec>();

        if offset + rec_size > dt.len() {
            return Err(McError::OutOfBounds {
                offset,
                size: dt.len(),
            });
        }

        let bytes = &dt[offset..offset + rec_size];
        let rec = McRec::from_bytes(bytes).ok_or(McError::OutOfBounds {
            offset,
            size: dt.len(),
        })?;
        Ok(rec)
    }

    /// Read the record payload (data after the `McRec` header) at the given slot.
    pub fn read_rec_data(&self, slot: u32, rec: &McRec) -> McResult<&[u8]> {
        let dt = self.data_table();
        let rec_offset = (slot as usize) * MC_SLOT_SIZE as usize;
        let data_start = rec_offset + size_of::<McRec>();
        let data_end = rec_offset + rec.len as usize;

        if data_end > dt.len() {
            return Err(McError::InvalidRecordLength {
                slot,
                len: rec.len,
                dt_size: self.header.dt_size,
            });
        }

        Ok(&dt[data_start..data_end])
    }

    /// Iterate all valid (non-empty, barrier-consistent) records in the data table.
    #[must_use]
    pub fn iter_records(&self) -> RecordIterator<'_> {
        RecordIterator {
            cache: self,
            slot: 0,
        }
    }

    /// Seed used for hash computations.
    #[must_use]
    pub fn seed(&self) -> u32 {
        self.header.seed
    }

    /// Total number of slots in the data table.
    #[must_use]
    pub fn total_slots(&self) -> u32 {
        self.header.dt_size / MC_SLOT_SIZE
    }

    /// Look up a record by key string via hash table walk.
    ///
    /// The key is hashed with the cache's seed, and the hash table chain
    /// is walked looking for a matching record. This mimics SSSD's NSS
    /// client lookup (getpwnam, getgrnam, etc).
    ///
    /// `use_hash2` controls whether to search via hash1 (name lookup)
    /// or hash2 (ID lookup).
    pub fn lookup(&self, key: &str, use_hash2: bool) -> McResult<Option<(u32, CacheEntry)>> {
        // SSSD hashes include the null terminator
        let mut key_bytes = key.as_bytes().to_vec();
        key_bytes.push(0);

        let hash = murmurhash3(&key_bytes, self.seed()) % self.ht_entries();
        let mut slot = self.ht_entry(hash)?;

        let mut visited = 0u32;
        let max = self.total_slots();

        while slot != MC_INVALID_VAL32 && visited < max {
            let rec = self.read_rec(slot)?;

            let hash_matches = if use_hash2 {
                rec.hash2 == hash
            } else {
                rec.hash1 == hash
            };

            if hash_matches && let Ok(entry) = self.parse_entry(slot, &rec) {
                // Verify the key actually matches (not just hash)
                let name_matches = match &entry {
                    CacheEntry::Passwd(e) => {
                        if use_hash2 {
                            format!("{}", e.uid) == key
                        } else {
                            e.name == key
                        }
                    }
                    CacheEntry::Group(e) => {
                        if use_hash2 {
                            format!("{}", e.gid) == key
                        } else {
                            e.name == key
                        }
                    }
                    CacheEntry::Initgr(e) => e.name == key || e.unique_name == key,
                    CacheEntry::Sid(e) => {
                        if use_hash2 {
                            format!("{}", e.id) == key
                        } else {
                            e.sid == key
                        }
                    }
                };

                if name_matches {
                    return Ok(Some((slot, entry)));
                }
            }

            // Follow chain
            if rec.hash1 == hash {
                slot = rec.next1;
            } else if rec.hash2 == hash {
                slot = rec.next2;
            } else {
                break;
            }
            visited += 1;
        }

        Ok(None)
    }

    /// Parse a record at the given slot into a typed entry.
    pub fn parse_entry(&self, slot: u32, rec: &McRec) -> McResult<CacheEntry> {
        let data = self.read_rec_data(slot, rec)?;
        match self.cache_type {
            CacheType::Passwd => entries::parse_passwd(rec, data).map(CacheEntry::Passwd),
            CacheType::Group => entries::parse_group(rec, data).map(CacheEntry::Group),
            CacheType::Initgroups => entries::parse_initgr(rec, data).map(CacheEntry::Initgr),
            CacheType::Sid => entries::parse_sid(rec, data).map(CacheEntry::Sid),
        }
    }
}

/// Iterator over all valid records in a cache file.
pub struct RecordIterator<'a> {
    cache: &'a CacheFile,
    slot: u32,
}

impl Iterator for RecordIterator<'_> {
    type Item = (u32, McRec);

    fn next(&mut self) -> Option<Self::Item> {
        let total = self.cache.total_slots();
        while self.slot < total {
            let current = self.slot;
            let Ok(rec) = self.cache.read_rec(current) else {
                self.slot += 1;
                continue;
            };

            // Skip empty/invalid slots
            if !valid_barrier(rec.b1) || rec.b1 != rec.b2 {
                self.slot += 1;
                continue;
            }

            if rec.len == MC_INVALID_VAL32 || rec.len < size_of::<McRec>() as u32 {
                self.slot += 1;
                continue;
            }

            // Advance past all slots this record occupies
            let slots_used = rec.len.div_ceil(MC_SLOT_SIZE);
            self.slot = current + slots_used;

            return Some((current, rec));
        }
        None
    }
}

// --- Internal helpers ---

fn read_header(data: &[u8]) -> McHeader {
    McHeader::from_bytes(data).expect("data too small for McHeader")
}

fn validate_header(header: &McHeader, file_size: usize) -> McResult<()> {
    if !valid_barrier(header.b1) || header.b1 != header.b2 {
        return Err(McError::HeaderBarrier {
            b1: header.b1,
            b2: header.b2,
        });
    }

    if header.major_vno != SSS_MC_MAJOR_VNO || header.minor_vno != SSS_MC_MINOR_VNO {
        return Err(McError::UnsupportedVersion {
            major: header.major_vno,
            minor: header.minor_vno,
        });
    }

    if header.status != SSS_MC_HEADER_ALIVE {
        return Err(McError::BadStatus {
            status: header.status,
        });
    }

    let check_table = |field: &'static str, offset: u32, size: u32| -> McResult<()> {
        let end = offset as usize + size as usize;
        if end > file_size {
            return Err(McError::TableOutOfBounds {
                field,
                offset,
                file_size,
            });
        }
        Ok(())
    };

    check_table("data_table", header.data_table, header.dt_size)?;
    check_table("free_table", header.free_table, header.ft_size)?;
    check_table("hash_table", header.hash_table, header.ht_size)?;

    Ok(())
}

/// Extract null-terminated strings from a string buffer.
///
/// Uses lossy UTF-8 conversion so that non-UTF-8 data (e.g. legacy
/// encodings, CJK, IDN) is preserved with replacement characters
/// rather than silently dropped.
#[must_use]
pub fn extract_strings(buf: &[u8]) -> Vec<String> {
    buf.split(|&b| b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_strings_basic() {
        let buf = b"hello\0world\0";
        let strs = extract_strings(buf);
        assert_eq!(strs, &["hello", "world"]);
    }

    #[test]
    fn extract_strings_empty() {
        let strs = extract_strings(b"");
        assert!(strs.is_empty());
    }

    #[test]
    fn extract_strings_single() {
        let strs = extract_strings(b"root\0");
        assert_eq!(strs, &["root"]);
    }

    #[test]
    fn extract_strings_passwd() {
        let buf = b"root\0x\0root\0/root\0/bin/bash\0";
        let strs = extract_strings(buf);
        assert_eq!(strs, &["root", "x", "root", "/root", "/bin/bash"]);
    }

    #[test]
    fn extract_strings_non_utf8() {
        // Latin-1 "café" where é is 0xe9 (not valid UTF-8)
        let buf = b"caf\xe9\0normal\0";
        let strs = extract_strings(buf);
        assert_eq!(strs.len(), 2);
        assert!(strs[0].contains("caf"), "should preserve prefix");
        assert!(strs[0].contains('\u{FFFD}'), "should have replacement char");
        assert_eq!(strs[1], "normal");
    }

    #[test]
    fn header_aligned_size() {
        assert!(MC_HEADER_ALIGNED >= size_of::<McHeader>());
        assert_eq!(MC_HEADER_ALIGNED % 8, 0);
    }
}
