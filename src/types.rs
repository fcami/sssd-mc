// SPDX-FileCopyrightText: types.rs 2026, ["François Cami" <contribs@fcami.net>]
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Core types matching SSSD's mmap cache on-disk structures.
//!
//! These mirror the `#pragma pack(1)` structs from `src/util/mmap_cache.h`
//! in the SSSD source. We use `repr(C)` here because all fields are naturally
//! aligned (all u32 except one u64 that falls on an 8-byte boundary), so
//! `repr(C)` produces the same layout as `packed` without the misaligned
//! reference UB. The `size_of` assertions in tests verify this.

use std::fmt;

// --- Constants ---

pub const MC_SLOT_SIZE: u32 = 40;
pub const MC_INVALID_VAL32: u32 = u32::MAX;

pub const SSS_MC_MAJOR_VNO: u32 = 1;
pub const SSS_MC_MINOR_VNO: u32 = 1;

pub const SSS_MC_HEADER_UNINIT: u32 = 0;
pub const SSS_MC_HEADER_ALIVE: u32 = 1;
pub const SSS_MC_HEADER_RECYCLED: u32 = 2;

// --- Header ---

/// File header, found at offset 0. 13 x u32 = 52 bytes, aligned to 64 bytes.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct McHeader {
    pub b1: u32,
    pub major_vno: u32,
    pub minor_vno: u32,
    pub status: u32,
    pub seed: u32,
    pub dt_size: u32,
    pub ft_size: u32,
    pub ht_size: u32,
    pub data_table: u32,
    pub free_table: u32,
    pub hash_table: u32,
    pub reserved: u32,
    pub b2: u32,
}

impl McHeader {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 52 {
            return None;
        }
        Some(Self {
            b1: u32::from_ne_bytes(bytes[0..4].try_into().ok()?),
            major_vno: u32::from_ne_bytes(bytes[4..8].try_into().ok()?),
            minor_vno: u32::from_ne_bytes(bytes[8..12].try_into().ok()?),
            status: u32::from_ne_bytes(bytes[12..16].try_into().ok()?),
            seed: u32::from_ne_bytes(bytes[16..20].try_into().ok()?),
            dt_size: u32::from_ne_bytes(bytes[20..24].try_into().ok()?),
            ft_size: u32::from_ne_bytes(bytes[24..28].try_into().ok()?),
            ht_size: u32::from_ne_bytes(bytes[28..32].try_into().ok()?),
            data_table: u32::from_ne_bytes(bytes[32..36].try_into().ok()?),
            free_table: u32::from_ne_bytes(bytes[36..40].try_into().ok()?),
            hash_table: u32::from_ne_bytes(bytes[40..44].try_into().ok()?),
            reserved: u32::from_ne_bytes(bytes[44..48].try_into().ok()?),
            b2: u32::from_ne_bytes(bytes[48..52].try_into().ok()?),
        })
    }
}

// --- Record header ---

/// Record header, at the start of each allocated record in the data table.
/// 40 bytes (fits exactly one slot).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct McRec {
    pub b1: u32,
    pub len: u32,
    pub expire: u64,
    pub next1: u32,
    pub next2: u32,
    pub hash1: u32,
    pub hash2: u32,
    pub padding: u32,
    pub b2: u32,
}

impl McRec {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 40 {
            return None;
        }
        Some(Self {
            b1: u32::from_ne_bytes(bytes[0..4].try_into().ok()?),
            len: u32::from_ne_bytes(bytes[4..8].try_into().ok()?),
            expire: u64::from_ne_bytes(bytes[8..16].try_into().ok()?),
            next1: u32::from_ne_bytes(bytes[16..20].try_into().ok()?),
            next2: u32::from_ne_bytes(bytes[20..24].try_into().ok()?),
            hash1: u32::from_ne_bytes(bytes[24..28].try_into().ok()?),
            hash2: u32::from_ne_bytes(bytes[28..32].try_into().ok()?),
            padding: u32::from_ne_bytes(bytes[32..36].try_into().ok()?),
            b2: u32::from_ne_bytes(bytes[36..40].try_into().ok()?),
        })
    }
}

// --- Passwd data (follows McRec) ---

/// Passwd record payload. Followed by `strs_len` bytes of null-terminated
/// strings: name, passwd, gecos, dir, shell.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct McPwdData {
    pub name: u32,
    pub uid: u32,
    pub gid: u32,
    pub strs_len: u32,
}

impl McPwdData {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        Some(Self {
            name: u32::from_ne_bytes(bytes[0..4].try_into().ok()?),
            uid: u32::from_ne_bytes(bytes[4..8].try_into().ok()?),
            gid: u32::from_ne_bytes(bytes[8..12].try_into().ok()?),
            strs_len: u32::from_ne_bytes(bytes[12..16].try_into().ok()?),
        })
    }

    #[cfg(test)]
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&self.name.to_ne_bytes());
        bytes[4..8].copy_from_slice(&self.uid.to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.gid.to_ne_bytes());
        bytes[12..16].copy_from_slice(&self.strs_len.to_ne_bytes());
        bytes
    }
}

// --- Group data (follows McRec) ---

/// Group record payload. Followed by `strs_len` bytes of null-terminated
/// strings: name, passwd, member1, member2, ...
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct McGrpData {
    pub name: u32,
    pub gid: u32,
    pub members: u32,
    pub strs_len: u32,
}

impl McGrpData {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        Some(Self {
            name: u32::from_ne_bytes(bytes[0..4].try_into().ok()?),
            gid: u32::from_ne_bytes(bytes[4..8].try_into().ok()?),
            members: u32::from_ne_bytes(bytes[8..12].try_into().ok()?),
            strs_len: u32::from_ne_bytes(bytes[12..16].try_into().ok()?),
        })
    }
}

// --- Initgroups data (follows McRec) ---

/// Initgroups record payload. Followed by `num_groups` x u32 GIDs,
/// then strings for name and `unique_name`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct McInitgrData {
    pub unique_name: u32,
    pub name: u32,
    pub strs: u32,
    pub strs_len: u32,
    pub data_len: u32,
    pub num_groups: u32,
}

impl McInitgrData {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 24 {
            return None;
        }
        Some(Self {
            unique_name: u32::from_ne_bytes(bytes[0..4].try_into().ok()?),
            name: u32::from_ne_bytes(bytes[4..8].try_into().ok()?),
            strs: u32::from_ne_bytes(bytes[8..12].try_into().ok()?),
            strs_len: u32::from_ne_bytes(bytes[12..16].try_into().ok()?),
            data_len: u32::from_ne_bytes(bytes[16..20].try_into().ok()?),
            num_groups: u32::from_ne_bytes(bytes[20..24].try_into().ok()?),
        })
    }
}

// --- SID data (follows McRec) ---

/// SID record payload. Followed by `sid_len` bytes of SID string.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct McSidData {
    pub name: u32,
    pub id_type: u32,
    pub id: u32,
    pub populated_by: u32,
    pub sid_len: u32,
}

impl McSidData {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 {
            return None;
        }
        Some(Self {
            name: u32::from_ne_bytes(bytes[0..4].try_into().ok()?),
            id_type: u32::from_ne_bytes(bytes[4..8].try_into().ok()?),
            id: u32::from_ne_bytes(bytes[8..12].try_into().ok()?),
            populated_by: u32::from_ne_bytes(bytes[12..16].try_into().ok()?),
            sid_len: u32::from_ne_bytes(bytes[16..20].try_into().ok()?),
        })
    }
}

// --- Cache type enum ---

/// The type of memcache file, determining how record payloads are interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheType {
    Passwd,
    Group,
    Initgroups,
    Sid,
}

impl fmt::Display for CacheType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passwd => write!(f, "passwd"),
            Self::Group => write!(f, "group"),
            Self::Initgroups => write!(f, "initgroups"),
            Self::Sid => write!(f, "sid"),
        }
    }
}

// --- Barrier validation ---

/// Check that a barrier value has the expected form (0xf0xxxxxx).
#[must_use]
pub fn valid_barrier(val: u32) -> bool {
    (val & 0xff00_0000) == 0xf000_0000
}

/// Check that a slot index is within the data table bounds.
#[must_use]
pub fn slot_within_bounds(slot: u32, dt_size: u32) -> bool {
    slot < (dt_size / MC_SLOT_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size() {
        assert_eq!(size_of::<McHeader>(), 52);
    }

    #[test]
    fn record_size() {
        assert_eq!(size_of::<McRec>(), 40);
    }

    #[test]
    fn pwd_data_size() {
        assert_eq!(size_of::<McPwdData>(), 16);
    }

    #[test]
    fn grp_data_size() {
        assert_eq!(size_of::<McGrpData>(), 16);
    }

    #[test]
    fn initgr_data_size() {
        assert_eq!(size_of::<McInitgrData>(), 24);
    }

    #[test]
    fn sid_data_size() {
        assert_eq!(size_of::<McSidData>(), 20);
    }

    #[test]
    fn barrier_validation() {
        assert!(valid_barrier(0xf000_0000));
        assert!(valid_barrier(0xf000_0001));
        assert!(valid_barrier(0xf0ff_ffff));
        assert!(!valid_barrier(0x0000_0000));
        assert!(!valid_barrier(0xff00_0000));
        assert!(!valid_barrier(MC_INVALID_VAL32));
    }

    #[test]
    fn slot_bounds() {
        assert!(slot_within_bounds(0, 400));
        assert!(slot_within_bounds(9, 400));
        assert!(!slot_within_bounds(10, 400));
        assert!(!slot_within_bounds(MC_INVALID_VAL32, 400));
    }
}
