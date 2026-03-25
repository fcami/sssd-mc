use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

use sssd_mc::analysis;
use sssd_mc::display;
use sssd_mc::entries::CacheEntry;
use sssd_mc::parsers::cache::CacheFile;
use sssd_mc::types::CacheType;

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
        _ => Err(format!("unknown cache type '{s}', expected: passwd, group, initgroups, sid")),
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
fn run() -> Result<bool, sssd_mc::errors::McError> {
    let cli = Cli::parse();
    let now = now_epoch();
    let mut out = io::stdout().lock();

    match cli.command {
        Commands::Header { path, r#type } => {
            let cache = CacheFile::open(&path, r#type)?;
            display::write_header(&mut out, &cache).ok();
        }
        Commands::Dump { path, r#type, json } => {
            let cache = CacheFile::open(&path, r#type)?;
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
                writeln!(out).ok();
                writeln!(out, "Records:").ok();
                dump_records(&mut out, &cache, now).ok();
            }
        }
        Commands::Stats { path, r#type } => {
            let cache = CacheFile::open(&path, r#type)?;
            display::write_stats(&mut out, &cache, now).ok();
        }
        Commands::Verify { path, r#type } => {
            let cache = CacheFile::open(&path, r#type)?;
            let result = analysis::verify_cache(&cache);

            writeln!(out, "Cache type:         {}", cache.cache_type).ok();
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
                    writeln!(out, "CRITICAL: {} record(s) unreachable by UID/GID lookup.",
                             result.unreachable_count).ok();
                    writeln!(out, "This is a known SSSD defect where hash1 and hash2 collide").ok();
                    writeln!(out, "into the same bucket. Affected users/groups will fail").ok();
                    writeln!(out, "getpwuid()/getgrgid() while getpwnam()/getgrnam() works.").ok();
                    writeln!(out, "Workaround: sss_cache -E (flush all caches)").ok();
                }
            }

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
