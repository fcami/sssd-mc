use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

use sssd_mc::display;
use sssd_mc::entries;
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
        let data = match cache.read_rec_data(slot, &rec) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("  [slot {slot}] error reading data: {e}");
                continue;
            }
        };

        match cache.cache_type {
            CacheType::Passwd => match entries::parse_passwd(&rec, data, now) {
                Ok(entry) => display::print_passwd(slot, &entry),
                Err(e) => eprintln!("  [slot {slot}] parse error: {e}"),
            },
            CacheType::Group => match entries::parse_group(&rec, data, now) {
                Ok(entry) => display::print_group(slot, &entry),
                Err(e) => eprintln!("  [slot {slot}] parse error: {e}"),
            },
            CacheType::Initgroups => match entries::parse_initgr(&rec, data, now) {
                Ok(entry) => display::print_initgr(slot, &entry),
                Err(e) => eprintln!("  [slot {slot}] parse error: {e}"),
            },
            CacheType::Sid => match entries::parse_sid(&rec, data, now) {
                Ok(entry) => display::print_sid(slot, &entry),
                Err(e) => eprintln!("  [slot {slot}] parse error: {e}"),
            },
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
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
