//! Display formatting for cache entries and headers.
//!
//! All functions write to a `&mut impl Write` so they can target
//! stdout, buffers, or test captures. Expiry is computed here
//! (display concern), not in parsed types.

use std::io::Write;

use crate::entries::*;
use crate::parsers::cache::CacheFile;
use crate::types::*;

fn expired_tag(expire: u64, now: u64) -> &'static str {
    if expire < now { " [EXPIRED]" } else { "" }
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
    writeln!(w, "Data table:     offset={:#010x} size={}", h.data_table, h.dt_size)?;
    writeln!(w, "Free table:     offset={:#010x} size={}", h.free_table, h.ft_size)?;
    writeln!(w, "Hash table:     offset={:#010x} size={} ({} buckets)",
             h.hash_table, h.ht_size, cache.ht_entries())?;
    writeln!(w, "Barriers:       b1={:#010x} b2={:#010x}", h.b1, h.b2)?;
    writeln!(w, "Total slots:    {}", cache.total_slots())
}

pub fn write_passwd(w: &mut impl Write, slot: u32, entry: &PasswdEntry, now: u64) -> std::io::Result<()> {
    let tag = expired_tag(entry.expire, now);
    writeln!(w, "  [slot {slot:>5}] {} uid={} gid={} expire={}{tag}",
             entry.name, entry.uid, entry.gid, entry.expire)?;
    writeln!(w, "              gecos={} dir={} shell={}",
             entry.gecos, entry.dir, entry.shell)
}

pub fn write_group(w: &mut impl Write, slot: u32, entry: &GroupEntry, now: u64) -> std::io::Result<()> {
    let tag = expired_tag(entry.expire, now);
    writeln!(w, "  [slot {slot:>5}] {} gid={} members={} expire={}{tag}",
             entry.name, entry.gid, entry.members.len(), entry.expire)?;
    if !entry.members.is_empty() {
        writeln!(w, "              members: {}", entry.members.join(", "))?;
    }
    Ok(())
}

pub fn write_initgr(w: &mut impl Write, slot: u32, entry: &InitgrEntry, now: u64) -> std::io::Result<()> {
    let tag = expired_tag(entry.expire, now);
    writeln!(w, "  [slot {slot:>5}] {} num_groups={} expire={}{tag}",
             entry.name, entry.gids.len(), entry.expire)?;
    if !entry.gids.is_empty() {
        let gid_strs: Vec<String> = entry.gids.iter().map(|g| g.to_string()).collect();
        writeln!(w, "              gids: {}", gid_strs.join(", "))?;
    }
    Ok(())
}

pub fn write_sid(w: &mut impl Write, slot: u32, entry: &SidEntry, now: u64) -> std::io::Result<()> {
    let tag = expired_tag(entry.expire, now);
    writeln!(w, "  [slot {slot:>5}] {} id={} type={} populated_by={} expire={}{tag}",
             entry.sid, entry.id, entry.id_type, entry.populated_by, entry.expire)
}

pub fn write_stats(w: &mut impl Write, cache: &CacheFile, now: u64) -> std::io::Result<()> {
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
        if let Ok(slot) = cache.ht_entry(i) {
            if slot != MC_INVALID_VAL32 {
                used_buckets += 1;
            }
        }
    }

    let load = if ht_entries > 0 {
        used_buckets as f64 / ht_entries as f64 * 100.0
    } else {
        0.0
    };

    writeln!(w, "Cache type:       {}", cache.cache_type)?;
    writeln!(w, "Total records:    {total}")?;
    writeln!(w, "Active records:   {active}")?;
    writeln!(w, "Expired records:  {expired}")?;
    writeln!(w, "Total slots:      {}", cache.total_slots())?;
    writeln!(w, "Hash buckets:     {ht_entries} ({used_buckets} used, {load:.1}% load)")
}
