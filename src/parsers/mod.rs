//! Parsers for SSSD memory cache files.
//!
//! Each parser reads raw bytes and returns typed data structs.
//! Parsers never produce formatted output — that's the display layer's job.

pub mod cache;
