//! End-to-end CLI tests.
//!
//! These drive the real binary, so they cover argument parsing, format dispatch, file
//! output, and exit codes together.

use assert_cmd::Command;
use predicates::str::contains;
use std::io::{Cursor, Write};
use tempfile::TempDir;
use zip::write::SimpleFileOptions;

fn bin() -> Command {
    Command::cargo_bin("binspector").expect("binary builds")
}

fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        for (name, data) in entries {
            w.start_file(*name, SimpleFileOptions::default()).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap();
    }
    buf
}

/// A minimal but valid PE, so coverage reports an executable was reached.
fn fake_pe(payload: &[u8]) -> Vec<u8> {
    let mut pe = vec![0u8; 0x200];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3C] = 0x80;
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe.extend_from_slice(payload);
    pe
}

struct Fixture {
    _dir: TempDir,
    target: std::path::PathBuf,
    out: std::path::PathBuf,
}

/// A nested bundle shaped like a real one: bundle -> msix -> PE.
fn fixture() -> Fixture {
    let dir = TempDir::new().unwrap();
    let payload =
        b"\x00strcpy\x00gets\x00atoi\x00System.Windows.Forms\x00Gets or sets the value\x00";
    let inner = zip_bytes(&[("App.exe", &fake_pe(payload))]);
    let bundle = zip_bytes(&[("app.msix", &inner)]);
    let target = dir.path().join("sample.msixbundle");
    std::fs::write(&target, bundle).unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    Fixture {
        _dir: dir,
        target,
        out,
    }
}

#[test]
fn descends_nested_containers_and_reports_provenance() {
    let f = fixture();
    bin()
        .arg(&f.target)
        .assert()
        .success()
        .stdout(contains("app.msix"))
        .stdout(contains("App.exe"))
        .stdout(contains("Container format: zip"))
        .stdout(contains("strcpy"));
}

#[test]
fn suppresses_namespace_and_prose_noise_by_default() {
    let f = fixture();
    let out = bin().arg(&f.target).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // System.Windows.Forms and "Gets or sets" must not become findings.
    assert!(
        stdout.contains("Suppressed as low confidence"),
        "stdout was:\n{}",
        stdout
    );
    // The real import-shaped symbols still appear.
    assert!(stdout.contains("strcpy"));
}

#[test]
fn include_low_confidence_reports_the_suppressed_hits() {
    let f = fixture();
    let out = bin()
        .arg(&f.target)
        .arg("--include-low-confidence")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("Suppressed as low confidence"));
    assert!(stdout.contains("prose confidence"), "stdout:\n{}", stdout);
}

#[test]
fn deprecated_ignore_case_still_works_and_warns() {
    // The exact shape of the original failing command line.
    let f = fixture();
    let report = f.out.join("r.txt");
    bin()
        .args(["-p", "PROJ-1", "-o"])
        .arg(&report)
        .arg("--ignore-case")
        .arg(&f.target)
        .assert()
        .success()
        .stderr(contains("--ignore-case is deprecated"));
    let body = std::fs::read_to_string(&report).unwrap();
    assert!(body.contains("Project: PROJ-1"));
}

#[test]
fn file_output_carries_no_ansi_escapes() {
    let f = fixture();
    let report = f.out.join("plain.txt");
    bin()
        .arg("-o")
        .arg(&report)
        .arg(&f.target)
        .assert()
        .success();
    let body = std::fs::read_to_string(&report).unwrap();
    assert!(!body.contains('\u{1b}'), "report contained ANSI escapes");
    // The match is still marked, without color.
    assert!(body.contains(">strcpy<"));
}

#[test]
fn format_all_writes_every_file() {
    let f = fixture();
    let stem = f.out.join("scan");
    bin()
        .args(["--format", "txt,json,csv,html,md,sarif,sql", "-o"])
        .arg(&stem)
        .arg(&f.target)
        .assert()
        .success();
    for ext in ["txt", "json", "csv", "html", "md", "sarif", "sql"] {
        let p = f.out.join(format!("scan.{}", ext));
        assert!(p.exists(), "missing {}", p.display());
        assert!(std::fs::metadata(&p).unwrap().len() > 0, "empty {}", ext);
    }
    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(f.out.join("scan.sarif")).unwrap()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
}

#[test]
fn json_output_is_machine_readable() {
    let f = fixture();
    let out = bin()
        .args(["--format", "json"])
        .arg(&f.target)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["tool"], "binspector");
    assert!(v["coverage"]["members_scanned"].as_u64().unwrap() >= 1);
    assert!(v["low_confidence_total"].as_u64().unwrap() > 0);
    // Coverage must show a real executable was reached.
    let formats: Vec<String> = v["coverage"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["format"].as_str().unwrap().to_string())
        .collect();
    assert!(
        formats.contains(&"pe".to_string()),
        "formats: {:?}",
        formats
    );
}

#[test]
fn fail_on_controls_the_exit_code() {
    let f = fixture();
    // strcpy is critical, so the threshold is met.
    bin()
        .args(["--fail-on", "critical"])
        .arg(&f.target)
        .assert()
        .code(1);
    // With no threshold, a finding is still a successful run.
    bin().arg(&f.target).assert().success();
}

#[test]
fn missing_file_is_an_error_not_a_clean_report() {
    bin()
        .arg("/nonexistent/definitely-not-here.bin")
        .assert()
        .code(2)
        .stderr(contains("reading"));
}

#[test]
fn rejects_contradictory_and_invalid_options() {
    let f = fixture();
    bin()
        .args(["--no-ascii", "--no-utf16"])
        .arg(&f.target)
        .assert()
        .code(2)
        .stderr(contains("disables every extraction source"));

    bin()
        .args(["--format", "yaml"])
        .arg(&f.target)
        .assert()
        .code(2)
        .stderr(contains("unknown output format"));

    bin()
        .args(["--format", "sqlite"])
        .arg(&f.target)
        .assert()
        .code(2)
        .stderr(contains("needs an output path"));
}

#[test]
fn csv_works_without_matches_only() {
    // 2.0.0 rejected this combination outright.
    let f = fixture();
    let out = bin()
        .args(["--format", "csv"])
        .arg(&f.target)
        .output()
        .unwrap();
    assert!(out.status.success());
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(body.starts_with("function,severity,category,member"));
}

#[test]
fn dump_includes_every_string() {
    let f = fixture();
    let out = bin()
        .args(["--dump", "--format", "csv"])
        .arg(&f.target)
        .output()
        .unwrap();
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(body.starts_with("member,offset,encoding,hit_count,matched,text"));
    // A string with no banned reference is present too.
    assert!(body.contains("System.Windows.Forms"));
}

#[test]
fn caps_stop_a_decompression_bomb() {
    let dir = TempDir::new().unwrap();
    // 40 MiB of zeros compresses tiny, far past the default 100x ratio.
    let bomb = zip_bytes(&[("big.bin", &vec![0u8; 40 * 1024 * 1024])]);
    let path = dir.path().join("bomb.zip");
    std::fs::write(&path, bomb).unwrap();
    bin()
        .arg(&path)
        .assert()
        .success()
        .stdout(contains("expansion ratio cap reached"));
}

#[test]
fn warns_when_no_executable_was_reached() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("plain.txt");
    std::fs::write(&path, b"\x00strcpy\x00").unwrap();
    bin()
        .arg(&path)
        .assert()
        .success()
        .stdout(contains("no executable image"));
}
