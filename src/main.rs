use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

use sssd_mc::errors::McResult;
use sssd_mc::parsers::cache::{extract_strings, CacheFile};
use sssd_mc::types::*;

#[derive(Parser)]
#[command(name = "sssd-mc")]
#[command(about = "Read-only parser and inspector for SSSD memory cache files")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show cache file header information
    Header {
        /// Path to the cache file
        path: PathBuf,
        /// Cache type
        #[arg(short, long, value_parser = parse_cache_type)]
        r#type: CacheType,
    },
    /// Dump all records in a cache file
    Dump {
        /// Path to the cache file
        path: PathBuf,
        /// Cache type
        #[arg(short, long, value_parser = parse_cache_type)]
        r#type: CacheType,
    },
    /// Show cache file statistics
    Stats {
        /// Path to the cache file
        path: PathBuf,
        /// Cache type
        #[arg(short, long, value_parser = parse_cache_type)]
        r#type: CacheType,
    },
}

fn parse_cache_type(s: &str) -> Result<CacheType, String> {
    match s {
        "passwd" => Ok(CacheType::Passwd),
        "group" => Ok(CacheType::Group),
        "initgroups" => Ok(CacheType::Initgroups),
        "sid" => Ok(CacheType::Sid),
        _ => Err(format!("unknown cache type '{s}', expected: passwd, group, initgroups, sid")),
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn print_header(cache: &CacheFile) {
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

fn print_record(cache: &CacheFile, slot: u32, rec: &McRec) {
    let now = now_epoch();
    let expired = rec.expire < now;
    let data = match cache.read_rec_data(slot, rec) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("  [slot {slot}] error reading data: {e}");
            return;
        }
    };

    match cache.cache_type {
        CacheType::Passwd => print_passwd_record(slot, rec, data, expired),
        CacheType::Group => print_group_record(slot, rec, data, expired),
        CacheType::Initgroups => print_initgr_record(slot, rec, data, expired),
        CacheType::Sid => print_sid_record(slot, rec, data, expired),
    }
}

fn print_passwd_record(slot: u32, rec: &McRec, data: &[u8], expired: bool) {
    if data.len() < std::mem::size_of::<McPwdData>() {
        eprintln!("  [slot {slot}] passwd data too short");
        return;
    }
    let pwd: McPwdData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
    let strs_start = std::mem::size_of::<McPwdData>();
    let strs_end = strs_start + pwd.strs_len as usize;
    if strs_end > data.len() {
        eprintln!("  [slot {slot}] passwd strings out of bounds");
        return;
    }
    let strings = extract_strings(&data[strs_start..strs_end]);
    let name = strings.first().map(|s| s.as_str()).unwrap_or("<unknown>");
    let expired_tag = if expired { " [EXPIRED]" } else { "" };
    println!("  [slot {slot:>5}] {name} uid={} gid={} expire={}{expired_tag}",
             pwd.uid, pwd.gid, rec.expire);
    if strings.len() >= 5 {
        println!("              gecos={} dir={} shell={}", strings[2], strings[3], strings[4]);
    }
}

fn print_group_record(slot: u32, rec: &McRec, data: &[u8], expired: bool) {
    if data.len() < std::mem::size_of::<McGrpData>() {
        eprintln!("  [slot {slot}] group data too short");
        return;
    }
    let grp: McGrpData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
    let strs_start = std::mem::size_of::<McGrpData>();
    let strs_end = strs_start + grp.strs_len as usize;
    if strs_end > data.len() {
        eprintln!("  [slot {slot}] group strings out of bounds");
        return;
    }
    let strings = extract_strings(&data[strs_start..strs_end]);
    let name = strings.first().map(|s| s.as_str()).unwrap_or("<unknown>");
    let expired_tag = if expired { " [EXPIRED]" } else { "" };
    println!("  [slot {slot:>5}] {name} gid={} members={} expire={}{expired_tag}",
             grp.gid, grp.members, rec.expire);
    if strings.len() > 2 {
        let members: Vec<&str> = strings[2..].iter().map(|s| s.as_str()).collect();
        println!("              members: {}", members.join(", "));
    }
}

fn print_initgr_record(slot: u32, rec: &McRec, data: &[u8], expired: bool) {
    if data.len() < std::mem::size_of::<McInitgrData>() {
        eprintln!("  [slot {slot}] initgroups data too short");
        return;
    }
    let initgr: McInitgrData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
    let expired_tag = if expired { " [EXPIRED]" } else { "" };

    let gids_start = std::mem::size_of::<McInitgrData>();
    let gids_end = gids_start + (initgr.num_groups as usize) * std::mem::size_of::<u32>();
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
    let name = if strs_offset < data.len() {
        let strs = extract_strings(&data[strs_offset..]);
        strs.first().cloned().unwrap_or_else(|| "<unknown>".to_string())
    } else {
        "<unknown>".to_string()
    };

    println!("  [slot {slot:>5}] {name} num_groups={} expire={}{expired_tag}",
             initgr.num_groups, rec.expire);
    if !gids.is_empty() {
        let gid_strs: Vec<String> = gids.iter().map(|g| g.to_string()).collect();
        println!("              gids: {}", gid_strs.join(", "));
    }
}

fn print_sid_record(slot: u32, rec: &McRec, data: &[u8], expired: bool) {
    if data.len() < std::mem::size_of::<McSidData>() {
        eprintln!("  [slot {slot}] SID data too short");
        return;
    }
    let sid: McSidData = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
    let expired_tag = if expired { " [EXPIRED]" } else { "" };

    let sid_start = std::mem::size_of::<McSidData>();
    let sid_end = sid_start + sid.sid_len as usize;
    let sid_str = if sid_end <= data.len() {
        std::str::from_utf8(&data[sid_start..sid_end])
            .unwrap_or("<invalid utf8>")
            .trim_end_matches('\0')
    } else {
        "<out of bounds>"
    };

    println!("  [slot {slot:>5}] {sid_str} id={} type={} populated_by={} expire={}{expired_tag}",
             sid.id, sid.id_type, sid.populated_by, rec.expire);
}

fn print_stats(cache: &CacheFile) {
    let now = now_epoch();
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

fn run() -> McResult<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Header { path, r#type } => {
            let cache = CacheFile::open(&path, r#type)?;
            print_header(&cache);
        }
        Commands::Dump { path, r#type } => {
            let cache = CacheFile::open(&path, r#type)?;
            print_header(&cache);
            println!();
            println!("Records:");
            for (slot, rec) in cache.iter_records() {
                print_record(&cache, slot, &rec);
            }
        }
        Commands::Stats { path, r#type } => {
            let cache = CacheFile::open(&path, r#type)?;
            print_stats(&cache);
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
