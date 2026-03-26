// SPDX-FileCopyrightText: main.rs 2026, ["François Cami" <contribs@fcami.net>]
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    io::{self, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand};
use sssd_mc::{
    analysis, display, entries::CacheEntry, parsers::cache::CacheFile, types::CacheType,
};

#[derive(Parser)]
#[command(name = "sssd-mc")]
#[command(about = "Read-only parser and inspector for SSSD memory cache files")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Reference time for expiry calculations.
    /// Default: file modification time. Use "system" for current system
    /// time, or a numeric UNIX epoch timestamp.
    #[arg(long, global = true)]
    now: Option<String>,
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
        /// Output as JSON (one object per line)
        #[arg(long)]
        json: bool,
    },
    /// Show cache file statistics
    Stats {
        /// Path to the cache file
        path: PathBuf,
        /// Cache type
        #[arg(short, long, value_parser = parse_cache_type)]
        r#type: CacheType,
    },
    /// Look up a record by name, ID, or slot number
    Lookup {
        /// Path to the cache file
        path: PathBuf,
        /// Cache type
        #[arg(short, long, value_parser = parse_cache_type)]
        r#type: CacheType,
        /// Key to look up (name or numeric ID)
        key: String,
        /// Treat key as a slot number instead of a name/ID
        #[arg(long)]
        slot: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Verify cache integrity (detect hash collisions and unreachable records)
    Verify {
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
        _ => Err(format!(
            "unknown cache type '{s}', expected: passwd, group, initgroups, sid"
        )),
    }
}

fn system_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Resolve the effective "now" for expiry calculations.
/// Returns (`effective_now`, `now_is_file_mtime`).
fn resolve_now(now_arg: Option<&String>, file_mtime: Option<u64>) -> (u64, bool) {
    match now_arg.map(String::as_str) {
        Some("system") => (system_now(), false),
        Some(s) => {
            if let Ok(epoch) = s.parse::<u64>() {
                (epoch, false)
            } else {
                eprintln!("Warning: invalid --now value '{s}', using file mtime");
                (file_mtime.unwrap_or_else(system_now), file_mtime.is_some())
            }
        }
        None => {
            // Default: use file mtime if available, otherwise system time
            match file_mtime {
                Some(mtime) => (mtime, true),
                None => (system_now(), false),
            }
        }
    }
}

fn dump_records(w: &mut impl Write, cache: &CacheFile, now: u64) -> io::Result<()> {
    for (slot, rec) in cache.iter_records() {
        match cache.parse_entry(slot, &rec) {
            Ok(CacheEntry::Passwd(ref e)) => display::write_passwd(w, slot, e, now)?,
            Ok(CacheEntry::Group(ref e)) => display::write_group(w, slot, e, now)?,
            Ok(CacheEntry::Initgr(ref e)) => display::write_initgr(w, slot, e, now)?,
            Ok(CacheEntry::Sid(ref e)) => display::write_sid(w, slot, e, now)?,
            Err(e) => eprintln!("  [slot {slot}] error: {e}"),
        }
    }
    Ok(())
}

/// Returns true if critical problems were found (for exit code).
#[allow(clippy::too_many_lines)]
fn run() -> Result<bool, sssd_mc::errors::McError> {
    let cli = Cli::parse();
    let sys_now = system_now();
    let mut out = io::stdout().lock();

    match cli.command {
        Commands::Header { path, r#type } => {
            let cache = CacheFile::open(&path, r#type)?;
            display::write_header(&mut out, &cache).ok();
            let (_, now_is_mtime) = resolve_now(cli.now.as_ref(), cache.file_mtime);
            display::write_time_context(&mut out, &cache, sys_now, now_is_mtime).ok();
        }
        Commands::Dump { path, r#type, json } => {
            let cache = CacheFile::open(&path, r#type)?;
            let (now, now_is_mtime) = resolve_now(cli.now.as_ref(), cache.file_mtime);
            if json {
                for (slot, rec) in cache.iter_records() {
                    match cache.parse_entry(slot, &rec) {
                        Ok(entry) => {
                            serde_json::to_writer(&mut out, &entry).ok();
                            writeln!(out).ok();
                        }
                        Err(e) => eprintln!("  [slot {slot}] error: {e}"),
                    }
                }
            } else {
                display::write_header(&mut out, &cache).ok();
                display::write_time_context(&mut out, &cache, sys_now, now_is_mtime).ok();
                writeln!(out).ok();
                writeln!(out, "Records:").ok();
                dump_records(&mut out, &cache, now).ok();
            }
        }
        Commands::Lookup {
            path,
            r#type,
            key,
            slot: by_slot,
            json,
        } => {
            let cache = CacheFile::open(&path, r#type)?;
            let (now, _) = resolve_now(cli.now.as_ref(), cache.file_mtime);

            let result = if by_slot {
                let slot_num: u32 = key
                    .parse()
                    .map_err(|_| sssd_mc::errors::McError::OutOfBounds { offset: 0, size: 0 })?;
                let rec = cache.read_rec(slot_num)?;
                cache
                    .parse_entry(slot_num, &rec)
                    .ok()
                    .map(|e| (slot_num, e))
            } else {
                cache.lookup(&key, false)?.or(cache.lookup(&key, true)?)
            };

            if let Some((slot, entry)) = result {
                if json {
                    serde_json::to_writer_pretty(&mut out, &entry).ok();
                    writeln!(out).ok();
                } else {
                    match &entry {
                        CacheEntry::Passwd(e) => display::write_passwd(&mut out, slot, e, now).ok(),
                        CacheEntry::Group(e) => display::write_group(&mut out, slot, e, now).ok(),
                        CacheEntry::Initgr(e) => display::write_initgr(&mut out, slot, e, now).ok(),
                        CacheEntry::Sid(e) => display::write_sid(&mut out, slot, e, now).ok(),
                    };
                }
            } else {
                eprintln!("Not found: {key}");
                return Ok(true);
            }
        }
        Commands::Stats { path, r#type } => {
            let cache = CacheFile::open(&path, r#type)?;
            let (now, now_is_mtime) = resolve_now(cli.now.as_ref(), cache.file_mtime);
            display::write_stats(&mut out, &cache, now, sys_now, now_is_mtime).ok();
        }
        Commands::Verify { path, r#type } => {
            let cache = CacheFile::open(&path, r#type)?;
            let (now, now_is_mtime) = resolve_now(cli.now.as_ref(), cache.file_mtime);
            let result = analysis::verify_cache(&cache);

            writeln!(out, "Cache type:         {}", cache.cache_type).ok();
            display::write_time_context(&mut out, &cache, sys_now, now_is_mtime).ok();
            writeln!(out, "Total records:      {}", result.total_records).ok();
            writeln!(out, "Same-bucket hashes: {}", result.same_bucket_count).ok();
            writeln!(out, "Unreachable (hash2):{}", result.unreachable_count).ok();
            writeln!(out, "Hash mismatches:    {}", result.hash_mismatch_count).ok();
            writeln!(out, "Max chain length:   {}", result.max_chain_length).ok();
            writeln!(out).ok();

            if result.problems.is_empty() {
                writeln!(out, "No problems found.").ok();
            } else {
                writeln!(out, "Problems:").ok();
                for problem in &result.problems {
                    writeln!(out, "  {problem}").ok();
                }
                writeln!(out).ok();
                if result.unreachable_count > 0 {
                    writeln!(
                        out,
                        "CRITICAL: {} record(s) unreachable by UID/GID lookup.",
                        result.unreachable_count
                    )
                    .ok();
                    writeln!(out, "Affected users/groups may fail getpwuid()/getgrgid()").ok();
                    writeln!(out, "while getpwnam()/getgrnam() still works.").ok();
                    writeln!(out, "Workaround: sss_cache -E (flush all caches)").ok();
                }
            }

            let _ = now; // suppress unused warning — verify doesn't use expiry
            if result.unreachable_count > 0 || result.hash_mismatch_count > 0 {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn main() {
    match run() {
        Ok(true) => std::process::exit(2),
        Ok(false) => {}
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}
