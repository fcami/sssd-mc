//! CLI integration tests for the `verify` subcommand output.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sssd-mc"))
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("head")
}

#[test]
fn verify_normal_cache_reports_no_problems() {
    let output = Command::new(binary())
        .args(["verify", &fixtures_dir().join("passwd.cache").to_string_lossy(), "-t", "passwd"])
        .output()
        .expect("failed to run sssd-mc");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());

    assert!(stdout.contains("No problems found"),
            "Normal cache should report no problems, got:\n{stdout}");
    assert!(!stdout.contains("CRITICAL"),
            "Normal cache should not contain CRITICAL, got:\n{stdout}");
}

#[test]
fn verify_nonexistent_file_fails() {
    let output = Command::new(binary())
        .args(["verify", "/nonexistent/cache", "-t", "passwd"])
        .output()
        .expect("failed to run sssd-mc");

    assert!(!output.status.success(), "Should fail on nonexistent file");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error"), "Should print error message, got:\n{stderr}");
}
