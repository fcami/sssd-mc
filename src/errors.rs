//! Error types for SSSD memory cache parsing.

use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum McError {
    #[error("failed to open cache file {path}: {source}")]
    Open {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("cache file too small ({size} bytes, need at least {min} for header)")]
    TooSmall { size: usize, min: usize },

    #[error("unsupported version {major}.{minor} (expected {}.{})",
            crate::types::SSS_MC_MAJOR_VNO, crate::types::SSS_MC_MINOR_VNO)]
    UnsupportedVersion { major: u32, minor: u32 },

    #[error("cache status is {status} (expected ALIVE={})", crate::types::SSS_MC_HEADER_ALIVE)]
    BadStatus { status: u32 },

    #[error("header barrier mismatch (b1={b1:#010x}, b2={b2:#010x})")]
    HeaderBarrier { b1: u32, b2: u32 },

    #[error("record barrier mismatch at slot {slot} (b1={b1:#010x}, b2={b2:#010x})")]
    RecordBarrier { slot: u32, b1: u32, b2: u32 },

    #[error("record at slot {slot} has invalid length {len} (dt_size={dt_size})")]
    InvalidRecordLength { slot: u32, len: u32, dt_size: u32 },

    #[error("offset {offset} out of bounds (table size {size})")]
    OutOfBounds { offset: usize, size: usize },

    #[error("string at offset {offset} is not null-terminated")]
    UnterminatedString { offset: usize },

    #[error("record data too short ({actual} bytes, need at least {expected})")]
    DataTooShort { expected: usize, actual: usize },

    #[error("table offset in header is out of file bounds: {field}={offset}, file_size={file_size}")]
    TableOutOfBounds {
        field: &'static str,
        offset: u32,
        file_size: usize,
    },
}

pub type McResult<T> = Result<T, McError>;
