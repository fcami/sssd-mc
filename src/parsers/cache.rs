//! Parser for SSSD mmap cache files.
//!
//! Opens a cache file (or reads from a byte slice), validates the header,
//! and provides access to records via hash lookup or iteration.

use std::mem;
use std::path::Path;

use memmap2::Mmap;

use crate::errors::{McError, McResult};
use crate::types::*;

/// Validated, read-only view of an SSSD memory cache file.
pub struct CacheFile {
    mmap: Mmap,
    pub header: McHeader,
    pub cache_type: CacheType,
}

/// Aligned header size (rounded up to 64-byte boundary).
const MC_HEADER_ALIGNED: usize = (mem::size_of::<McHeader>() + 7) & !7;

impl CacheFile {
    /// Open and validate a cache file from disk.
    pub fn open(path: &Path, cache_type: CacheType) -> McResult<Self> {
        let file = std::fs::File::open(path).map_err(|e| McError::Open {
            path: path.to_path_buf(),
            source: e,
        })?;

        // SAFETY: we open read-only; the file may be concurrently modified
        // by sssd_nss, but we only read and validate barriers.
        let mmap = unsafe {
            Mmap::map(&file).map_err(|e| McError::Open {
                path: path.to_path_buf(),
                source: e,
            })?
        };

        Self::from_bytes(mmap, cache_type)
    }

    /// Parse from an already-mapped region.
    fn from_bytes(mmap: Mmap, cache_type: CacheType) -> McResult<Self> {
        if mmap.len() < MC_HEADER_ALIGNED {
            return Err(McError::TooSmall {
                size: mmap.len(),
                min: MC_HEADER_ALIGNED,
            });
        }

        let header = read_header(&mmap)?;
        validate_header(&header, mmap.len())?;

        Ok(Self {
            mmap,
            header,
            cache_type,
        })
    }

    /// Return the raw data table slice.
    pub fn data_table(&self) -> &[u8] {
        let start = self.header.data_table as usize;
        let end = start + self.header.dt_size as usize;
        &self.mmap[start..end]
    }

    /// Return the hash table as a slice of bytes.
    pub fn hash_table(&self) -> &[u8] {
        let start = self.header.hash_table as usize;
        let end = start + self.header.ht_size as usize;
        &self.mmap[start..end]
    }

    /// Number of hash table entries.
    pub fn ht_entries(&self) -> u32 {
        self.header.ht_size / mem::size_of::<u32>() as u32
    }

    /// Read a hash table entry (slot index) at the given hash bucket.
    pub fn ht_entry(&self, bucket: u32) -> McResult<u32> {
        let ht = self.hash_table();
        let offset = (bucket as usize) * mem::size_of::<u32>();
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
        let rec_size = mem::size_of::<McRec>();

        if offset + rec_size > dt.len() {
            return Err(McError::OutOfBounds {
                offset,
                size: dt.len(),
            });
        }

        let bytes = &dt[offset..offset + rec_size];
        // SAFETY: McRec is repr(C) and we have enough bytes.
        let rec: McRec = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) };
        Ok(rec)
    }

    /// Read the record payload (data after the McRec header) at the given slot.
    pub fn read_rec_data(&self, slot: u32, rec: &McRec) -> McResult<&[u8]> {
        let dt = self.data_table();
        let rec_offset = (slot as usize) * MC_SLOT_SIZE as usize;
        let data_start = rec_offset + mem::size_of::<McRec>();
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
    pub fn iter_records(&self) -> RecordIterator<'_> {
        RecordIterator {
            cache: self,
            slot: 0,
        }
    }

    /// Seed used for hash computations.
    pub fn seed(&self) -> u32 {
        self.header.seed
    }

    /// Total number of slots in the data table.
    pub fn total_slots(&self) -> u32 {
        self.header.dt_size / MC_SLOT_SIZE
    }
}

/// Iterator over all valid records in a cache file.
pub struct RecordIterator<'a> {
    cache: &'a CacheFile,
    slot: u32,
}

impl<'a> Iterator for RecordIterator<'a> {
    type Item = (u32, McRec);

    fn next(&mut self) -> Option<Self::Item> {
        let total = self.cache.total_slots();
        while self.slot < total {
            let current = self.slot;
            let rec = match self.cache.read_rec(current) {
                Ok(r) => r,
                Err(_) => {
                    self.slot += 1;
                    continue;
                }
            };

            // Skip empty/invalid slots
            if !valid_barrier(rec.b1) || rec.b1 != rec.b2 {
                self.slot += 1;
                continue;
            }

            if rec.len == MC_INVALID_VAL32 || rec.len < mem::size_of::<McRec>() as u32 {
                self.slot += 1;
                continue;
            }

            // Advance past all slots this record occupies
            let slots_used = (rec.len + MC_SLOT_SIZE - 1) / MC_SLOT_SIZE;
            self.slot = current + slots_used;

            return Some((current, rec));
        }
        None
    }
}

// --- Internal helpers ---

fn read_header(data: &[u8]) -> McResult<McHeader> {
    let bytes = &data[..mem::size_of::<McHeader>()];
    // SAFETY: McHeader is repr(C) and we checked length above.
    let header: McHeader = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) };
    Ok(header)
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
        assert!(MC_HEADER_ALIGNED >= mem::size_of::<McHeader>());
        assert_eq!(MC_HEADER_ALIGNED % 8, 0);
    }
}
