// SPDX-FileCopyrightText: display.rs 2026, ["François Cami" <contribs@fcami.net>]
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Display formatting for cache entries and headers.
//!
//! All functions write to a `&mut impl Write` so they can target
//! stdout, buffers, or test captures. Expiry is computed here
//! (display concern), not in parsed types.

use std::io::Write;

use crate::{
    entries::{GroupEntry, InitgrEntry, PasswdEntry, SidEntry},
    parsers::cache::CacheFile,
    types::{MC_INVALID_VAL32, SSS_MC_HEADER_ALIVE, SSS_MC_HEADER_RECYCLED, SSS_MC_HEADER_UNINIT},
};

fn expired_tag(expire: u64, now: u64) -> &'static str {
    if expire < now { " [EXPIRED]" } else { "" }
}

/// Format a UNIX epoch timestamp as "YYYY-MM-DD HH:MM:SS UTC".
/// Simple implementation without external crate — handles dates from
/// 1970 to 2099 correctly.
fn format_epoch(epoch: u64) -> String {
    // Days per month (non-leap)
    const MONTH_DAYS: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    let secs = epoch % 60;
    let mins = (epoch / 60) % 60;
    let hours = (epoch / 3600) % 24;
    let mut days = epoch / 86400;

    let mut year = 1970u64;
    loop {
        let days_in_year =
            if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) {
                366
            } else {
                365
            };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let is_leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let mut month = 0u64;
    for (i, &md) in MONTH_DAYS.iter().enumerate() {
        let d = if i == 1 && is_leap { md + 1 } else { md };
        if days < d {
            month = i as u64 + 1;
            break;
        }
        days -= d;
    }
    let day = days + 1;

    format!("{year:04}-{month:02}-{day:02} {hours:02}:{mins:02}:{secs:02} UTC")
}

/// Write the timestamp header lines showing file mtime, current time,
/// and which is used for expiry.
pub fn write_time_context(
    w: &mut impl Write, cache: &CacheFile, system_now: u64, now_is_file_mtime: bool,
) -> std::io::Result<()> {
    if let Some(mtime) = cache.file_mtime {
        let label = if now_is_file_mtime {
            " (used for expiry calculations)"
        } else {
            ""
        };
        writeln!(w, "File modified:  {}{label}", format_epoch(mtime))?;
    }
    let now_label = if now_is_file_mtime {
        ""
    } else {
        " (used for expiry calculations)"
    };
    writeln!(w, "Current time:   {}{now_label}", format_epoch(system_now))
}

pub fn write_header(w: &mut impl Write, cache: &CacheFile) -> std::io::Result<()> {
    let h = &cache.header;
    let status_str = match h.status {
        SSS_MC_HEADER_UNINIT => "UNINIT",
        SSS_MC_HEADER_ALIVE => "ALIVE",
        SSS_MC_HEADER_RECYCLED => "RECYCLED",
        _ => "UNKNOWN",
    };
    writeln!(w, "Cache type:     {}", cache.cache_type)?;
    writeln!(w, "Version:        {}.{}", h.major_vno, h.minor_vno)?;
    writeln!(w, "Status:         {} ({status_str})", h.status)?;
    writeln!(w, "Seed:           {:#010x}", h.seed)?;
    writeln!(
        w,
        "Data table:     offset={:#010x} size={}",
        h.data_table, h.dt_size
    )?;
    writeln!(
        w,
        "Free table:     offset={:#010x} size={}",
        h.free_table, h.ft_size
    )?;
    writeln!(
        w,
        "Hash table:     offset={:#010x} size={} ({} buckets)",
        h.hash_table,
        h.ht_size,
        cache.ht_entries()
    )?;
    writeln!(w, "Barriers:       b1={:#010x} b2={:#010x}", h.b1, h.b2)?;
    writeln!(w, "Total slots:    {}", cache.total_slots())
}

pub fn write_passwd(
    w: &mut impl Write, slot: u32, entry: &PasswdEntry, now: u64,
) -> std::io::Result<()> {
    let tag = expired_tag(entry.expire, now);
    writeln!(
        w,
        "  [slot {slot:>5}] {} uid={} gid={} expire={}{tag}",
        entry.name, entry.uid, entry.gid, entry.expire
    )?;
    writeln!(
        w,
        "              gecos={} dir={} shell={}",
        entry.gecos, entry.dir, entry.shell
    )
}

pub fn write_group(
    w: &mut impl Write, slot: u32, entry: &GroupEntry, now: u64,
) -> std::io::Result<()> {
    let tag = expired_tag(entry.expire, now);
    writeln!(
        w,
        "  [slot {slot:>5}] {} gid={} members={} expire={}{tag}",
        entry.name,
        entry.gid,
        entry.members.len(),
        entry.expire
    )?;
    if !entry.members.is_empty() {
        writeln!(w, "              members: {}", entry.members.join(", "))?;
    }
    Ok(())
}

pub fn write_initgr(
    w: &mut impl Write, slot: u32, entry: &InitgrEntry, now: u64,
) -> std::io::Result<()> {
    let tag = expired_tag(entry.expire, now);
    writeln!(
        w,
        "  [slot {slot:>5}] {} num_groups={} expire={}{tag}",
        entry.name,
        entry.gids.len(),
        entry.expire
    )?;
    if !entry.gids.is_empty() {
        let gid_strs: Vec<String> = entry.gids.iter().map(ToString::to_string).collect();
        writeln!(w, "              gids: {}", gid_strs.join(", "))?;
    }
    Ok(())
}

pub fn write_sid(w: &mut impl Write, slot: u32, entry: &SidEntry, now: u64) -> std::io::Result<()> {
    let tag = expired_tag(entry.expire, now);
    writeln!(
        w,
        "  [slot {slot:>5}] {} id={} type={} populated_by={} expire={}{tag}",
        entry.sid, entry.id, entry.id_type, entry.populated_by, entry.expire
    )
}

pub fn write_stats(
    w: &mut impl Write, cache: &CacheFile, now: u64, system_now: u64, now_is_file_mtime: bool,
) -> std::io::Result<()> {
    let mut total = 0u32;
    let mut expired = 0u32;
    let mut active = 0u32;

    for (_slot, rec) in cache.iter_records() {
        total += 1;
        if rec.expire < now {
            expired += 1;
        } else {
            active += 1;
        }
    }

    let ht_entries = cache.ht_entries();
    let mut used_buckets = 0u32;
    for i in 0..ht_entries {
        if let Ok(slot) = cache.ht_entry(i)
            && slot != MC_INVALID_VAL32
        {
            used_buckets += 1;
        }
    }

    let load = if ht_entries > 0 {
        f64::from(used_buckets) / f64::from(ht_entries) * 100.0
    } else {
        0.0
    };

    writeln!(w, "Cache type:       {}", cache.cache_type)?;
    write_time_context(w, cache, system_now, now_is_file_mtime)?;
    writeln!(w, "Total records:    {total}")?;
    writeln!(w, "Active records:   {active}")?;
    writeln!(w, "Expired records:  {expired}")?;
    writeln!(w, "Total slots:      {}", cache.total_slots())?;
    writeln!(
        w,
        "Hash buckets:     {ht_entries} ({used_buckets} used, {load:.1}% load)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_epoch_known_date() {
        // 2026-03-25 00:00:00 UTC = 1_774_396_800
        let s = format_epoch(1_774_396_800);
        assert!(s.starts_with("2026-03-25"), "got: {s}");
    }

    #[test]
    fn format_epoch_unix_zero() {
        let s = format_epoch(0);
        assert_eq!(s, "1970-01-01 00:00:00 UTC");
    }
}
