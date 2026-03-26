// SPDX-FileCopyrightText: negative.rs 2026, ["François Cami" <contribs@fcami.net>]
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Negative tests: malformed cache files that should produce meaningful errors.

use std::io::Write;

use sssd_mc::{
    parsers::cache::CacheFile,
    types::{
        CacheType, MC_INVALID_VAL32, MC_SLOT_SIZE, SSS_MC_HEADER_ALIVE, SSS_MC_HEADER_RECYCLED,
        SSS_MC_HEADER_UNINIT, SSS_MC_MAJOR_VNO, SSS_MC_MINOR_VNO,
    },
};
use tempfile::NamedTempFile;

/// Helper: write bytes to a temp file and try to open as a cache.
fn try_open(data: &[u8], cache_type: CacheType) -> Result<CacheFile, sssd_mc::errors::McError> {
    let mut f = NamedTempFile::new().expect("create tempfile");
    f.write_all(data).expect("write tempfile");
    f.flush().expect("flush tempfile");
    CacheFile::open(f.path(), cache_type)
}

/// Helper: build a minimal valid header as bytes.
#[allow(clippy::too_many_arguments)]
fn make_header(
    b1: u32, major: u32, minor: u32, status: u32, seed: u32, dt_size: u32, ft_size: u32,
    ht_size: u32, data_table: u32, free_table: u32, hash_table: u32, b2: u32,
) -> Vec<u8> {
    let mut buf = Vec::new();
    for val in [
        b1, major, minor, status, seed, dt_size, ft_size, ht_size, data_table, free_table,
        hash_table, 0u32, /* reserved */
        b2,
    ] {
        buf.extend_from_slice(&val.to_ne_bytes());
    }
    buf
}

/// Helper: build a valid cache file with given parameters.
fn make_valid_cache(num_ht_entries: u32, num_dt_slots: u32) -> Vec<u8> {
    let header_size = 56_u32; // 13 * 4, rounded to 8-byte align
    let ht_size = num_ht_entries * 4;
    let ft_size = num_dt_slots.div_ceil(8);
    let ft_aligned = (ft_size + 7) & !7;
    let dt_size = num_dt_slots * MC_SLOT_SIZE;

    let ht_offset = header_size;
    let ft_offset = ht_offset + ht_size;
    let dt_offset = ft_offset + ft_aligned;
    let total = dt_offset + dt_size;

    let header = make_header(
        0xf000_0001,
        SSS_MC_MAJOR_VNO,
        SSS_MC_MINOR_VNO,
        SSS_MC_HEADER_ALIVE,
        0xDEAD_BEEF,
        dt_size,
        ft_aligned,
        ht_size,
        dt_offset,
        ft_offset,
        ht_offset,
        0xf000_0001,
    );

    let mut buf = vec![0u8; total as usize];
    buf[..header.len()].copy_from_slice(&header);

    // Fill hash table with MC_INVALID_VAL
    for i in 0..num_ht_entries {
        let offset = ht_offset as usize + (i as usize) * 4;
        buf[offset..offset + 4].copy_from_slice(&MC_INVALID_VAL32.to_ne_bytes());
    }

    buf
}

// ---- Tests ----

#[test]
fn empty_file() {
    let result = try_open(b"", CacheType::Passwd);
    assert!(result.is_err());
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("too small"),
        "Expected TooSmall error, got: {msg}"
    );
}

#[test]
fn truncated_header() {
    // 20 bytes, not enough for a full header (52 bytes)
    let data = vec![0u8; 20];
    let result = try_open(&data, CacheType::Passwd);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("too small"),
        "Expected TooSmall error, got: {msg}"
    );
}

#[test]
fn wrong_major_version() {
    let header = make_header(
        0xf000_0001,
        99,
        SSS_MC_MINOR_VNO,
        SSS_MC_HEADER_ALIVE,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0xf000_0001,
    );
    let mut buf = vec![0u8; 256];
    buf[..header.len()].copy_from_slice(&header);
    let result = try_open(&buf, CacheType::Passwd);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("version"),
        "Expected version error, got: {msg}"
    );
}

#[test]
fn wrong_minor_version() {
    let header = make_header(
        0xf000_0001,
        SSS_MC_MAJOR_VNO,
        99,
        SSS_MC_HEADER_ALIVE,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0xf000_0001,
    );
    let mut buf = vec![0u8; 256];
    buf[..header.len()].copy_from_slice(&header);
    let result = try_open(&buf, CacheType::Passwd);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("version"),
        "Expected version error, got: {msg}"
    );
}

#[test]
fn status_uninit() {
    let header = make_header(
        0xf000_0001,
        SSS_MC_MAJOR_VNO,
        SSS_MC_MINOR_VNO,
        SSS_MC_HEADER_UNINIT,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0xf000_0001,
    );
    let mut buf = vec![0u8; 256];
    buf[..header.len()].copy_from_slice(&header);
    let result = try_open(&buf, CacheType::Passwd);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("status"), "Expected status error, got: {msg}");
}

#[test]
fn status_recycled() {
    let header = make_header(
        0xf000_0001,
        SSS_MC_MAJOR_VNO,
        SSS_MC_MINOR_VNO,
        SSS_MC_HEADER_RECYCLED,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0xf000_0001,
    );
    let mut buf = vec![0u8; 256];
    buf[..header.len()].copy_from_slice(&header);
    let result = try_open(&buf, CacheType::Passwd);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("status"), "Expected status error, got: {msg}");
}

#[test]
fn barrier_mismatch() {
    let header = make_header(
        0xf000_0001,
        SSS_MC_MAJOR_VNO,
        SSS_MC_MINOR_VNO,
        SSS_MC_HEADER_ALIVE,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0xf000_0002, // b2 != b1
    );
    let mut buf = vec![0u8; 256];
    buf[..header.len()].copy_from_slice(&header);
    let result = try_open(&buf, CacheType::Passwd);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("barrier"),
        "Expected barrier error, got: {msg}"
    );
}

#[test]
fn invalid_barrier_value() {
    // b1 and b2 match but don't have the 0xf0 prefix
    let header = make_header(
        0x1234_5678,
        SSS_MC_MAJOR_VNO,
        SSS_MC_MINOR_VNO,
        SSS_MC_HEADER_ALIVE,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0x1234_5678,
    );
    let mut buf = vec![0u8; 256];
    buf[..header.len()].copy_from_slice(&header);
    let result = try_open(&buf, CacheType::Passwd);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("barrier"),
        "Expected barrier error, got: {msg}"
    );
}

#[test]
fn data_table_out_of_bounds() {
    // Valid header but data_table offset points past file end
    let header = make_header(
        0xf000_0001,
        SSS_MC_MAJOR_VNO,
        SSS_MC_MINOR_VNO,
        SSS_MC_HEADER_ALIVE,
        0,
        99999,
        0,
        0,
        99999, // data_table way past end
        0,
        0,
        0xf000_0001,
    );
    let mut buf = vec![0u8; 256];
    buf[..header.len()].copy_from_slice(&header);
    let result = try_open(&buf, CacheType::Passwd);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("bounds"),
        "Expected out of bounds error, got: {msg}"
    );
}

#[test]
fn valid_empty_cache() {
    // Valid header, hash table, free table, data table — but no records
    let buf = make_valid_cache(16, 32);
    let cache = try_open(&buf, CacheType::Passwd).expect("valid empty cache should open");
    let records: Vec<_> = cache.iter_records().collect();
    assert_eq!(records.len(), 0, "Empty cache should have no records");
}

#[test]
fn record_slot_out_of_bounds() {
    let buf = make_valid_cache(16, 4); // only 4 slots
    let cache = try_open(&buf, CacheType::Passwd).expect("valid cache should open");
    // Try to read a slot beyond the data table
    let result = cache.read_rec(100);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("bounds"), "Expected out of bounds, got: {msg}");
}

#[test]
fn nonexistent_file() {
    let result = CacheFile::open(
        std::path::Path::new("/nonexistent/path/to/cache"),
        CacheType::Passwd,
    );
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("open"), "Expected open error, got: {msg}");
}
