//! Display formatting for cache entries and headers.
//!
//! Separated from parsing so that library consumers can use the
//! parsed types without pulling in display logic.

use crate::entries::*;
use crate::parsers::cache::CacheFile;
use crate::types::*;

pub fn print_header(cache: &CacheFile) {
    let h = &cache.header;
    let status_str = match h.status {
        SSS_MC_HEADER_UNINIT => "UNINIT",
        SSS_MC_HEADER_ALIVE => "ALIVE",
        SSS_MC_HEADER_RECYCLED => "RECYCLED",
        _ => "UNKNOWN",
    };
    println!("Cache type:     {}", cache.cache_type);
    println!("Version:        {}.{}", h.major_vno, h.minor_vno);
    println!("Status:         {} ({status_str})", h.status);
    println!("Seed:           {:#010x}", h.seed);
    println!("Data table:     offset={:#010x} size={}", h.data_table, h.dt_size);
    println!("Free table:     offset={:#010x} size={}", h.free_table, h.ft_size);
    println!("Hash table:     offset={:#010x} size={} ({} buckets)",
             h.hash_table, h.ht_size, cache.ht_entries());
    println!("Barriers:       b1={:#010x} b2={:#010x}", h.b1, h.b2);
    println!("Total slots:    {}", cache.total_slots());
}

pub fn print_passwd(slot: u32, entry: &PasswdEntry) {
    let tag = if entry.expired { " [EXPIRED]" } else { "" };
    println!("  [slot {slot:>5}] {} uid={} gid={} expire={}{tag}",
             entry.name, entry.uid, entry.gid, entry.expire);
    println!("              gecos={} dir={} shell={}",
             entry.gecos, entry.dir, entry.shell);
}

pub fn print_group(slot: u32, entry: &GroupEntry) {
    let tag = if entry.expired { " [EXPIRED]" } else { "" };
    println!("  [slot {slot:>5}] {} gid={} members={} expire={}{tag}",
             entry.name, entry.gid, entry.members.len(), entry.expire);
    if !entry.members.is_empty() {
        println!("              members: {}", entry.members.join(", "));
    }
}

pub fn print_initgr(slot: u32, entry: &InitgrEntry) {
    let tag = if entry.expired { " [EXPIRED]" } else { "" };
    println!("  [slot {slot:>5}] {} num_groups={} expire={}{tag}",
             entry.name, entry.gids.len(), entry.expire);
    if !entry.gids.is_empty() {
        let gid_strs: Vec<String> = entry.gids.iter().map(|g| g.to_string()).collect();
        println!("              gids: {}", gid_strs.join(", "));
    }
}

pub fn print_sid(slot: u32, entry: &SidEntry) {
    let tag = if entry.expired { " [EXPIRED]" } else { "" };
    println!("  [slot {slot:>5}] {} id={} type={} populated_by={} expire={}{tag}",
             entry.sid, entry.id, entry.id_type, entry.populated_by, entry.expire);
}

pub fn print_stats(cache: &CacheFile, now: u64) {
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

    println!("Cache type:       {}", cache.cache_type);
    println!("Total records:    {total}");
    println!("Active records:   {active}");
    println!("Expired records:  {expired}");
    println!("Total slots:      {}", cache.total_slots());
    println!("Hash buckets:     {ht_entries} ({used_buckets} used, {load:.1}% load)");
}
