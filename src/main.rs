use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

use sssd_mc::analysis;
use sssd_mc::display;
use sssd_mc::entries::CacheEntry;
use sssd_mc::errors::McResult;
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

fn dump_records(cache: &CacheFile, now: u64) {
    for (slot, rec) in cache.iter_records() {
        match cache.parse_entry(slot, &rec) {
            Ok(CacheEntry::Passwd(ref e)) => display::print_passwd(slot, e, now),
            Ok(CacheEntry::Group(ref e)) => display::print_group(slot, e, now),
            Ok(CacheEntry::Initgr(ref e)) => display::print_initgr(slot, e, now),
            Ok(CacheEntry::Sid(ref e)) => display::print_sid(slot, e, now),
            Err(e) => eprintln!("  [slot {slot}] error: {e}"),
        }
    }
}

fn run() -> McResult<()> {
    let cli = Cli::parse();
    let now = now_epoch();

    match cli.command {
        Commands::Header { path, r#type } => {
            let cache = CacheFile::open(&path, r#type)?;
            display::print_header(&cache);
        }
        Commands::Dump { path, r#type } => {
            let cache = CacheFile::open(&path, r#type)?;
            display::print_header(&cache);
            println!();
            println!("Records:");
            dump_records(&cache, now);
        }
        Commands::Stats { path, r#type } => {
            let cache = CacheFile::open(&path, r#type)?;
            display::print_stats(&cache, now);
        }
        Commands::Verify { path, r#type } => {
            let cache = CacheFile::open(&path, r#type)?;
            let result = analysis::verify_cache(&cache);

            println!("Cache type:         {}", cache.cache_type);
            println!("Total records:      {}", result.total_records);
            println!("Same-bucket hashes: {}", result.same_bucket_count);
            println!("Unreachable (hash2):{}", result.unreachable_count);
            println!("Hash mismatches:    {}", result.hash_mismatch_count);
            println!("Max chain length:   {}", result.max_chain_length);
            println!();

            if result.problems.is_empty() {
                println!("No problems found.");
            } else {
                println!("Problems:");
                for problem in &result.problems {
                    println!("  {problem}");
                }
                println!();
                if result.unreachable_count > 0 {
                    println!("CRITICAL: {} record(s) unreachable by UID/GID lookup.",
                             result.unreachable_count);
                    println!("This is a known SSSD defect where hash1 and hash2 collide");
                    println!("into the same bucket. Affected users/groups will fail");
                    println!("getpwuid()/getgrgid() while getpwnam()/getgrnam() works.");
                    println!("Workaround: sss_cache -E (flush all caches)");
                }
            }
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
