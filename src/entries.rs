//! Parsed, safe-to-use entry types extracted from raw cache records.
//!
//! These decouple consumers from the on-disk layout and unsafe reads.

use crate::errors::{McError, McResult};
use crate::parsers::cache::extract_strings;
use crate::types::*;

/// A parsed passwd cache entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub passwd: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub dir: String,
    pub shell: String,
    pub expire: u64,
    pub expired: bool,
}

/// A parsed group cache entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub passwd: String,
    pub gid: u32,
    pub members: Vec<String>,
    pub expire: u64,
    pub expired: bool,
}

/// A parsed initgroups cache entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitgrEntry {
    pub name: String,
    pub unique_name: String,
    pub gids: Vec<u32>,
    pub expire: u64,
    pub expired: bool,
}

/// A parsed SID cache entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidEntry {
    pub sid: String,
    pub id: u32,
    pub id_type: u32,
    pub populated_by: u32,
    pub expire: u64,
    pub expired: bool,
}

/// A typed cache entry (any of the four types).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheEntry {
    Passwd(PasswdEntry),
    Group(GroupEntry),
    Initgr(InitgrEntry),
    Sid(SidEntry),
}

/// Parse a passwd entry from raw record data.
pub fn parse_passwd(rec: &McRec, data: &[u8], now: u64) -> McResult<PasswdEntry> {
    if data.len() < std::mem::size_of::<McPwdData>() {
        return Err(McError::InvalidRecordLength {
            slot: 0,
            len: data.len() as u32,
            dt_size: 0,
        });
    }
    let pwd: McPwdData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
    let strs_start = std::mem::size_of::<McPwdData>();
    let strs_end = strs_start + pwd.strs_len as usize;
    if strs_end > data.len() {
        return Err(McError::InvalidRecordLength {
            slot: 0,
            len: data.len() as u32,
            dt_size: 0,
        });
    }
    let strings = extract_strings(&data[strs_start..strs_end]);

    Ok(PasswdEntry {
        name: strings.first().cloned().unwrap_or_default(),
        passwd: strings.get(1).cloned().unwrap_or_default(),
        uid: pwd.uid,
        gid: pwd.gid,
        gecos: strings.get(2).cloned().unwrap_or_default(),
        dir: strings.get(3).cloned().unwrap_or_default(),
        shell: strings.get(4).cloned().unwrap_or_default(),
        expire: rec.expire,
        expired: rec.expire < now,
    })
}

/// Parse a group entry from raw record data.
pub fn parse_group(rec: &McRec, data: &[u8], now: u64) -> McResult<GroupEntry> {
    if data.len() < std::mem::size_of::<McGrpData>() {
        return Err(McError::InvalidRecordLength {
            slot: 0,
            len: data.len() as u32,
            dt_size: 0,
        });
    }
    let grp: McGrpData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
    let strs_start = std::mem::size_of::<McGrpData>();
    let strs_end = strs_start + grp.strs_len as usize;
    if strs_end > data.len() {
        return Err(McError::InvalidRecordLength {
            slot: 0,
            len: data.len() as u32,
            dt_size: 0,
        });
    }
    let strings = extract_strings(&data[strs_start..strs_end]);

    Ok(GroupEntry {
        name: strings.first().cloned().unwrap_or_default(),
        passwd: strings.get(1).cloned().unwrap_or_default(),
        gid: grp.gid,
        members: strings.get(2..).map(|s| s.to_vec()).unwrap_or_default(),
        expire: rec.expire,
        expired: rec.expire < now,
    })
}

/// Parse an initgroups entry from raw record data.
pub fn parse_initgr(rec: &McRec, data: &[u8], now: u64) -> McResult<InitgrEntry> {
    if data.len() < std::mem::size_of::<McInitgrData>() {
        return Err(McError::InvalidRecordLength {
            slot: 0,
            len: data.len() as u32,
            dt_size: 0,
        });
    }
    let initgr: McInitgrData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };

    let gids_start = std::mem::size_of::<McInitgrData>();
    let gids_end = gids_start + (initgr.num_groups as usize) * 4;
    let mut gids = Vec::new();
    if gids_end <= data.len() {
        for i in 0..initgr.num_groups as usize {
            let off = gids_start + i * 4;
            let gid = u32::from_ne_bytes([
                data[off], data[off + 1], data[off + 2], data[off + 3],
            ]);
            gids.push(gid);
        }
    }

    let strs_offset = initgr.strs as usize;
    let strings = if strs_offset < data.len() {
        extract_strings(&data[strs_offset..])
    } else {
        Vec::new()
    };

    Ok(InitgrEntry {
        name: strings.first().cloned().unwrap_or_default(),
        unique_name: strings.get(1).cloned().unwrap_or_default(),
        gids,
        expire: rec.expire,
        expired: rec.expire < now,
    })
}

/// Parse a SID entry from raw record data.
pub fn parse_sid(rec: &McRec, data: &[u8], now: u64) -> McResult<SidEntry> {
    if data.len() < std::mem::size_of::<McSidData>() {
        return Err(McError::InvalidRecordLength {
            slot: 0,
            len: data.len() as u32,
            dt_size: 0,
        });
    }
    let sid: McSidData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
    let sid_start = std::mem::size_of::<McSidData>();
    let sid_end = sid_start + sid.sid_len as usize;
    let sid_str = if sid_end <= data.len() {
        String::from_utf8_lossy(&data[sid_start..sid_end])
            .trim_end_matches('\0')
            .to_string()
    } else {
        String::new()
    };

    Ok(SidEntry {
        sid: sid_str,
        id: sid.id,
        id_type: sid.id_type,
        populated_by: sid.populated_by,
        expire: rec.expire,
        expired: rec.expire < now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rec(expire: u64) -> McRec {
        McRec {
            b1: 0xf000_0001, len: 80, expire,
            next1: MC_INVALID_VAL32, next2: MC_INVALID_VAL32,
            hash1: 0, hash2: 0, padding: 0, b2: 0xf000_0001,
        }
    }

    #[test]
    fn parse_passwd_basic() {
        // Build a minimal passwd payload
        let strs = b"root\0x\0root\0/root\0/bin/bash\0";
        let pwd = McPwdData {
            name: std::mem::size_of::<McPwdData>() as u32,
            uid: 0,
            gid: 0,
            strs_len: strs.len() as u32,
        };
        let mut data = vec![0u8; std::mem::size_of::<McPwdData>() + strs.len()];
        unsafe {
            std::ptr::write_unaligned(data.as_mut_ptr().cast(), pwd);
        }
        data[std::mem::size_of::<McPwdData>()..].copy_from_slice(strs);

        let rec = make_rec(u64::MAX);
        let entry = parse_passwd(&rec, &data, 1000).unwrap();
        assert_eq!(entry.name, "root");
        assert_eq!(entry.uid, 0);
        assert_eq!(entry.shell, "/bin/bash");
        assert!(!entry.expired);
    }

    #[test]
    fn parse_passwd_expired() {
        let strs = b"old\0x\0old\0/home/old\0/bin/sh\0";
        let pwd = McPwdData {
            name: std::mem::size_of::<McPwdData>() as u32,
            uid: 999, gid: 999,
            strs_len: strs.len() as u32,
        };
        let mut data = vec![0u8; std::mem::size_of::<McPwdData>() + strs.len()];
        unsafe { std::ptr::write_unaligned(data.as_mut_ptr().cast(), pwd); }
        data[std::mem::size_of::<McPwdData>()..].copy_from_slice(strs);

        let rec = make_rec(500); // expire in the past
        let entry = parse_passwd(&rec, &data, 1000).unwrap();
        assert!(entry.expired);
    }

    #[test]
    fn parse_passwd_too_short() {
        let data = vec![0u8; 4]; // way too short
        let rec = make_rec(u64::MAX);
        assert!(parse_passwd(&rec, &data, 1000).is_err());
    }
}
