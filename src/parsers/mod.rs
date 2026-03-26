// SPDX-FileCopyrightText: mod.rs 2026, ["François Cami" <contribs@fcami.net>]
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parsers for SSSD memory cache files.
//!
//! Each parser reads raw bytes and returns typed data structs.
//! Parsers never produce formatted output — that's the display layer's job.

pub mod cache;
