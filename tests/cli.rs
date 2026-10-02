//! End-to-end CLI tests.
//!
//! These drive the real binary, so they cover argument parsing, format dispatch, file
//! output, and exit codes together.

use assert_cmd::Command;

/// Output defaults to a timestamped file since 4.3.0, so a test that reads stdout has to
/// ask for it with `-o -`.
fn bin_stdout() -> Command {
    let mut c = Command::cargo_bin("binspector").expect("binary builds");
    c.args(["-o", "-"]);
    c
}
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

#[path = "../src/pe/pe_fixture.rs"]
mod pe_fixture;

/// A structurally real PE, so coverage reports an executable was reached and the occurrences
/// in it survive the `no-code-section` rule.
fn fake_pe(payload: &[u8]) -> Vec<u8> {
    pe_fixture::pe_with_code(payload)
}

struct Fixture {
    _dir: TempDir,
    target: std::path::PathBuf,
    out: std::path::PathBuf,
}

/// A nested bundle shaped like a real one: bundle -> msix -> PE.
fn fixture() -> Fixture {
    let dir = TempDir::new().unwrap();
    // The two historical false-positive families are kept, and since 5.7.0 they are refused
    // one layer earlier by case-exact matching rather than by the prose rule. A lowercase
    // sentence is added so the prose rule itself still has something to suppress.
    let payload = b"\x00strcpy\x00gets\x00atoi\x00System.Windows.Forms\x00\
                    Gets or sets the value\x00the system gets its value at startup\x00";
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
    bin_stdout()
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
    let out = bin_stdout().arg(&f.target).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // System.Windows.Forms and "Gets or sets" must not become findings.
    assert!(
        stdout.contains("Excluded by evidence"),
        "stdout was:\n{}",
        stdout
    );
    // The exclusion is attributed to a named rule, not just counted.
    assert!(stdout.contains("prose"), "stdout was:\n{}", stdout);
    // The real import-shaped symbols still appear.
    assert!(stdout.contains("strcpy"));
}

#[test]
fn include_excluded_reports_the_suppressed_hits() {
    let f = fixture();
    let out = bin_stdout()
        .arg(&f.target)
        .arg("--include-low-confidence")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("Suppressed as low confidence"));
    assert!(stdout.contains("prose confidence"), "stdout:\n{}", stdout);
}

#[test]
fn removed_ignore_case_flag_is_rejected() {
    // Removed in 4.0.0; it had no effect once matching became case insensitive.
    let f = fixture();
    bin()
        .arg("--ignore-case")
        .arg(&f.target)
        .assert()
        .failure()
        .stderr(contains("--ignore-case"));
}

#[test]
fn project_and_output_flags_work_together() {
    let f = fixture();
    let report = f.out.join("r.txt");
    bin()
        .args(["-p", "PROJ-1", "-o"])
        .arg(&report)
        .arg(&f.target)
        .assert()
        .success();
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
fn format_all_writes_every_available_format_and_succeeds() {
    // The regression this pins: `--format all` used to abort the whole loop when one
    // writer was unavailable, losing every format ordered after it and exiting 2. The
    // reported symptom was a missing .sql dump on a build without SQLite support.
    let f = fixture();
    let stem = f.out.join("everything");
    bin()
        .args(["--format", "all", "-o"])
        .arg(&stem)
        .arg(&f.target)
        .assert()
        .success();

    // Written whatever this build supports.
    for ext in ["txt", "json", "csv", "html", "md", "sarif", "sql"] {
        let p = f.out.join(format!("everything.{}", ext));
        assert!(p.exists(), "missing {}", p.display());
        assert!(std::fs::metadata(&p).unwrap().len() > 0, "empty {}", ext);
    }
    // The binary database is present exactly when the build can write it, and `all`
    // silently omits it otherwise rather than failing the run.
    let db = f.out.join("everything.sqlite");
    if db.exists() {
        assert!(std::fs::metadata(&db).unwrap().len() > 0, "empty sqlite");
    }
}

#[test]
fn naming_sqlite_explicitly_is_not_silently_skipped() {
    // `all` omits what this build cannot write. Asking for it by name must still say so,
    // because that request was specific.
    let f = fixture();
    let out = bin()
        .args(["--format", "sqlite", "-o"])
        .arg(f.out.join("db.sqlite"))
        .arg(&f.target)
        .output()
        .unwrap();
    if out.status.success() {
        assert!(f.out.join("db.sqlite").exists());
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("no SQLite support"), "stderr: {}", err);
    }
}

#[test]
fn several_targets_aggregate_into_one_report() {
    let dir = TempDir::new().unwrap();
    let a = dir.path().join("a.msixbundle");
    let b = dir.path().join("b.msixbundle");
    std::fs::write(&a, zip_bytes(&[("A.exe", &fake_pe(b"\x00strcpy\x00"))])).unwrap();
    std::fs::write(&b, zip_bytes(&[("B.exe", &fake_pe(b"\x00gets\x00"))])).unwrap();

    let out = bin_stdout()
        .args(["--format", "json"])
        .arg(&a)
        .arg(&b)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let targets = v["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0]["label"], "a.msixbundle");
    assert_eq!(targets[1]["label"], "b.msixbundle");
    // Provenance still roots at the target, so a finding says which one it came from.
    let members: Vec<String> = v["hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["member"].as_str().unwrap().to_string())
        .collect();
    assert!(
        members.iter().any(|m| m.starts_with("a.msixbundle ::")),
        "{:?}",
        members
    );
    assert!(
        members.iter().any(|m| m.starts_with("b.msixbundle ::")),
        "{:?}",
        members
    );
    // All three manifest digests are present, each over the same newline-joined
    // "<sha256>  <label>" manifest. They used to be cleared for a set, which read as a tool that
    // failed to hash and was reported as broken twice.
    for (key, len) in [("md5", 32), ("sha1", 40), ("sha256", 64)] {
        let got = v[key].as_str().unwrap_or_default();
        assert_eq!(got.len(), len, "{} digest: {:?}", key, got);
        assert!(got.chars().all(|c| c.is_ascii_hexdigit()), "{}", key);
    }
    // And every target carries its own real file digests, which is what a reputation lookup or a
    // hand check needs. A manifest digest cannot be looked up anywhere.
    for t in v["targets"].as_array().expect("targets") {
        for (key, len) in [("md5", 32), ("sha1", 40), ("sha256", 64)] {
            let got = t[key].as_str().unwrap_or_default();
            assert_eq!(got.len(), len, "target {} digest: {:?}", key, got);
        }
    }
}

#[test]
fn a_directory_target_is_walked_and_non_candidates_are_skipped() {
    let dir = TempDir::new().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("nested")).unwrap();
    std::fs::write(tree.join("app.exe"), fake_pe(b"\x00strcpy\x00")).unwrap();
    std::fs::write(tree.join("nested/lib.dll"), fake_pe(b"\x00gets\x00")).unwrap();
    std::fs::write(tree.join("README.md"), b"# not a binary, just prose\n").unwrap();

    let out = bin_stdout()
        .args(["--format", "json"])
        .arg(&tree)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let targets = v["targets"].as_array().unwrap();
    assert_eq!(
        targets.len(),
        2,
        "the readme is not a candidate: {:?}",
        targets
    );
    // The skip is disclosed in the report, not only at -vv.
    let warnings = v["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("skipped as non-candidates")),
        "{:?}",
        warnings
    );
}

#[test]
fn all_files_takes_what_the_filter_skipped() {
    let dir = TempDir::new().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("app.exe"), fake_pe(b"\x00strcpy\x00")).unwrap();
    std::fs::write(
        tree.join("notes.txt"),
        b"nothing executable in here at all\n",
    )
    .unwrap();

    let out = bin_stdout()
        .args(["--format", "json", "--all-files"])
        .arg(&tree)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["targets"].as_array().unwrap().len(), 2);
}

#[test]
fn a_multi_target_report_names_its_digest_instead_of_printing_empty_fields() {
    // Reported as "MD5/SHA1 isn't working but SHA2 is", twice. A digest over a set of files is a
    // manifest digest rather than a file digest, and the first fix named it as one and dropped the
    // other two algorithms. That was still wrong: two missing algorithms read as a tool that
    // failed to hash, and the label already said "manifest", so there was nothing left to be
    // ambiguous about. All three manifest digests are printed now, and the per-target file digests
    // beside them, which are what a reputation lookup or a hand check actually needs.
    let dir = TempDir::new().unwrap();
    let a = dir.path().join("a.exe");
    let b = dir.path().join("b.exe");
    std::fs::write(&a, fake_pe(b"\x00strcpy\x00")).unwrap();
    std::fs::write(&b, fake_pe(b"\x00gets\x00")).unwrap();

    let out = bin_stdout().arg(&a).arg(&b).output().unwrap();
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        body.contains("Manifest digests"),
        "a multi-target run must name the digests for what they are:\n{}",
        body
    );
    assert!(
        body.contains("not file hashes"),
        "and say they are not file hashes:\n{}",
        body
    );
    // All three, because two of them missing is what was reported as broken.
    for label in ["MD5:", "SHA1:", "SHA256:"] {
        let line = body
            .lines()
            .find(|l| l.trim_start().starts_with(label))
            .unwrap_or_else(|| panic!("{} missing:\n{}", label, body));
        let value = line.trim_start().trim_start_matches(label).trim();
        assert!(
            value.chars().all(|c| c.is_ascii_hexdigit()) && !value.is_empty(),
            "{} must carry a digest, got {:?}",
            label,
            value
        );
    }
    // And the per-file digests, so a multi-target report carries a hash somebody can look up.
    assert!(
        body.contains("Target digests"),
        "per-target file digests missing:\n{}",
        body
    );

    // One target is unchanged: all three real file digests.
    let one = bin_stdout().arg(&a).output().unwrap();
    let body = String::from_utf8_lossy(&one.stdout);
    for label in ["MD5:", "SHA1:", "SHA256:"] {
        assert!(
            body.contains(label),
            "{} missing from a single-target report",
            label
        );
    }
    assert!(
        !body.contains("Manifest SHA256"),
        "one target is not a manifest"
    );
}

#[test]
fn thread_count_changes_the_speed_and_nothing_else() {
    // The property that makes --threads worth having: a faster scan producing a different report
    // each run would be useless for diffing two builds. Results are merged in target order rather
    // than completion order, so scheduling cannot reach the output.
    let dir = TempDir::new().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    for (name, body) in [
        ("a.exe", &b"\x00strcpy\x00"[..]),
        ("b.exe", &b"\x00gets\x00"[..]),
        ("c.exe", &b"\x00system\x00"[..]),
        ("d.exe", &b"\x00memcpy\x00"[..]),
        ("e.exe", &b"\x00atoi\x00"[..]),
        ("f.exe", &b"\x00sprintf\x00"[..]),
    ] {
        std::fs::write(tree.join(name), fake_pe(body)).unwrap();
    }

    let run = |n: &str| -> String {
        let out = bin_stdout()
            .args(["--format", "json", "--threads", n])
            .arg(&tree)
            .output()
            .unwrap();
        assert!(out.status.success(), "--threads {} failed", n);
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        // The scan timestamp differs between any two runs, threaded or not.
        let mut v = v;
        v.as_object_mut().unwrap().remove("timestamp");
        serde_json::to_string(&v).unwrap()
    };

    let one = run("1");
    for n in ["2", "4", "16"] {
        assert_eq!(one, run(n), "--threads {} changed the report", n);
    }
}

#[test]
fn extract_cannot_be_talked_into_writing_outside_its_directory() {
    // Member names in an archive are attacker-controlled. Rather than filter traversal, the output
    // name is built from a content hash plus a sanitised leaf, so no component of the member's own
    // path reaches the filesystem at all and every file lands directly in the named directory.
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("extracted");
    let canary = dir.path().join("CANARY_MUST_NOT_EXIST");

    let evil = dir.path().join("evil.zip");
    let escape = format!("../../{}", canary.file_name().unwrap().to_string_lossy());
    std::fs::write(
        &evil,
        zip_bytes(&[
            (escape.as_str(), &fake_pe(b"\x00strcpy\x00")),
            ("..\\..\\win_escape.dll", &fake_pe(b"\x00gets\x00")),
            ("/absolute/escape.dll", &fake_pe(b"\x00system\x00")),
            ("CON", &fake_pe(b"\x00atoi\x00")),
            ("ordinary.dll", &fake_pe(b"\x00memcpy\x00")),
        ]),
    )
    .unwrap();

    bin_stdout()
        .args(["--extract"])
        .arg(&out)
        .arg(&evil)
        .assert()
        .success();

    assert!(
        !canary.exists(),
        "a member escaped the extraction directory"
    );
    for entry in std::fs::read_dir(&out).unwrap() {
        let p = entry.unwrap().path();
        assert_eq!(
            p.parent(),
            Some(out.as_path()),
            "{} is not directly inside the extraction directory",
            p.display()
        );
        assert!(p.is_file(), "{} is not a plain file", p.display());
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        assert!(!name.contains(".."), "{} keeps a traversal sequence", name);
        assert!(!name.starts_with('.'), "{} is hidden", name);
    }
}

#[test]
fn many_targets_write_one_combined_report_unless_split_is_asked_for() {
    // The property that must never regress: how many files appear is decided by the format list
    // and by --split, never by how many targets were scanned. A directory of four hundred images
    // must not produce four hundred reports to read through.
    //
    // This also pins the invariant that per-target parallelism has to preserve: threading changes
    // the order work happens in, not the number of outputs.
    let dir = TempDir::new().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    for (name, body) in [
        ("a.exe", &b"\x00strcpy\x00"[..]),
        ("b.exe", &b"\x00gets\x00"[..]),
        ("c.exe", &b"\x00system\x00"[..]),
        ("d.exe", &b"\x00memcpy\x00"[..]),
    ] {
        std::fs::write(tree.join(name), fake_pe(body)).unwrap();
    }
    let out_dir = dir.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();

    bin()
        .args(["--format", "txt,json", "-o"])
        .arg(out_dir.join("combined"))
        .arg(&tree)
        .assert()
        .success();

    let written: Vec<String> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(
        written.len(),
        2,
        "four targets and two formats must give two files, not eight: {:?}",
        written
    );
    assert!(
        written.contains(&"combined.txt".to_string()),
        "{:?}",
        written
    );
    assert!(
        written.contains(&"combined.json".to_string()),
        "{:?}",
        written
    );

    // And the one report genuinely covers every target rather than the last one winning.
    let body = std::fs::read_to_string(out_dir.join("combined.txt")).unwrap();
    for name in ["a.exe", "b.exe", "c.exe", "d.exe"] {
        assert!(
            body.contains(name),
            "{} missing from the combined report",
            name
        );
    }
}

#[test]
fn split_writes_one_report_per_target_with_the_documented_names() {
    let dir = TempDir::new().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.exe"), fake_pe(b"\x00strcpy\x00")).unwrap();
    std::fs::write(tree.join("b.exe"), fake_pe(b"\x00gets\x00")).unwrap();
    let out_dir = dir.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();

    bin()
        .args(["--split", "--format", "txt", "-o"])
        .arg(out_dir.join("custom"))
        .arg(&tree)
        .assert()
        .success();

    let written: Vec<String> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(written.len(), 2, "one per target: {:?}", written);
    assert!(
        written.iter().any(|n| n.starts_with("custom_a.exe-")),
        "{:?}",
        written
    );
    assert!(
        written.iter().any(|n| n.starts_with("custom_b.exe-")),
        "{:?}",
        written
    );
    // One stamp for the whole run, so the output sorts as a single invocation.
    let stamps: std::collections::BTreeSet<&str> = written
        .iter()
        .map(|n| n.rsplit_once('-').unwrap().1)
        .collect();
    assert_eq!(stamps.len(), 1, "one stamp per run: {:?}", written);
    // The seconds field survives: the stamp has dots, so the extension must be appended.
    assert!(written.iter().all(|n| n.ends_with(".txt")), "{:?}", written);
}

#[test]
fn split_and_dump_are_rejected_where_they_cannot_work() {
    let f = fixture();
    // --split writes a file per target, so it cannot share stdout.
    bin()
        .args(["--split", "-o", "-"])
        .arg(&f.target)
        .assert()
        .code(2)
        .stderr(contains("cannot share stdout"));
    // --dump across several targets is supported, with a notice about the volume.
    let dir = TempDir::new().unwrap();
    let a = dir.path().join("a.msixbundle");
    let b = dir.path().join("b.msixbundle");
    std::fs::write(&a, zip_bytes(&[("A.exe", &fake_pe(b"\x00strcpy\x00"))])).unwrap();
    std::fs::write(&b, zip_bytes(&[("B.exe", &fake_pe(b"\x00gets\x00"))])).unwrap();
    let out = bin_stdout().arg("--dump").arg(&a).arg(&b).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Both targets' strings are present, each attributable to its own target.
    assert!(
        stdout.contains("a.msixbundle ::"),
        "first target missing from the dump"
    );
    assert!(
        stdout.contains("b.msixbundle ::"),
        "second target missing from the dump"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("across 2 targets"),
        "the volume notice should be printed"
    );
}

#[test]
fn json_output_is_machine_readable() {
    let f = fixture();
    let out = bin_stdout()
        .args(["--format", "json"])
        .arg(&f.target)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["tool"], "binspector");
    assert!(v["coverage"]["members_scanned"].as_u64().unwrap() >= 1);
    assert!(v["excluded_total"].as_u64().unwrap() > 0);
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
    // `-o -` on both, because `bin()` carries no output path and the default is a timestamped
    // file written to the process working directory, which for an integration test is the crate
    // root. Two of these leaked per `make check` run and a user found a pile of them in the repo.
    // The exit code is what this test is about, so stdout is the right sink.
    bin()
        .args(["--fail-on", "critical", "-o", "-"])
        .arg(&f.target)
        .assert()
        .code(1);
    // With no threshold, a finding is still a successful run.
    bin().args(["-o", "-"]).arg(&f.target).assert().success();
}

#[test]
fn no_test_leaves_a_report_in_the_working_directory() {
    // The tripwire. `bin()` has no default output path, so any test that forgets `-o` writes
    // `binspector_output-<timestamp>.txt` into the crate root. They are gitignored, which is why
    // this went unnoticed through several releases until the pile was spotted by hand.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let strays: Vec<String> = std::fs::read_dir(root)
        .expect("crate root is readable")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("binspector_output-"))
        .collect();
    assert!(
        strays.is_empty(),
        "tests left {} report(s) in the crate root: {:?}. A test running the binary without `-o` \
         writes the default timestamped name into the working directory.",
        strays.len(),
        strays
    );
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

    // A binary database can never go to stdout. On a build without SQLite support the
    // format is refused earlier, for a different and equally correct reason.
    let out = bin()
        .args(["--format", "sqlite", "-o", "-"])
        .arg(&f.target)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("cannot go to stdout") || err.contains("no SQLite support"),
        "stderr: {}",
        err
    );
}

#[test]
fn csv_works_without_matches_only() {
    // 2.0.0 rejected this combination outright.
    let f = fixture();
    let out = bin_stdout()
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
    let out = bin_stdout()
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
    bin_stdout()
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
    bin_stdout()
        .arg(&path)
        .assert()
        .success()
        .stdout(contains("no executable image"));
}

// --- 4.1.0: single-stream and additional archive formats ---

fn gz(data: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

#[test]
fn scans_inside_a_gzip_stream() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("payload.bin.gz");
    // A PE holding a banned symbol, gzipped. Before 4.1.0 this was reported as a
    // coverage gap and its contents were never read.
    std::fs::write(&path, gz(&fake_pe(b"\x00strcpy\x00"))).unwrap();
    bin_stdout()
        .arg(&path)
        .assert()
        .success()
        .stdout(contains("strcpy"))
        .stdout(contains("payload.bin"));
}

#[test]
fn scans_a_gzip_stream_nested_inside_a_zip() {
    let dir = TempDir::new().unwrap();
    let inner = gz(&fake_pe(b"\x00gets\x00"));
    let bundle = zip_bytes(&[("App.exe.gz", &inner)]);
    let path = dir.path().join("nested.zip");
    std::fs::write(&path, bundle).unwrap();
    let out = bin_stdout().arg(&path).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("gets"), "stdout:\n{}", stdout);
    // The decompressed child keeps a useful name.
    assert!(stdout.contains("App.exe"), "stdout:\n{}", stdout);
}

#[test]
fn compressed_formats_are_no_longer_reported_as_a_coverage_gap() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("p.gz");
    std::fs::write(&path, gz(b"\x00strcpy\x00some payload here\x00")).unwrap();
    let out = bin_stdout().arg(&path).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("not unpacked"), "stdout:\n{}", stdout);
}

#[test]
fn a_gzip_bomb_is_capped() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("bomb.gz");
    // 8 MiB of zeros compresses to a few KiB.
    std::fs::write(&path, gz(&vec![0u8; 8 * 1024 * 1024])).unwrap();
    bin_stdout()
        .arg(&path)
        .args(["--max-member-bytes", "4096"])
        .assert()
        .success()
        .stdout(contains("truncated"));
}

#[test]
fn carve_flag_matches_the_build() {
    // Carving is compiled in by default since 4.4.0. A build without the feature says so
    // rather than silently reporting that nothing was embedded, so assert whichever
    // behaviour this build has.
    let f = fixture();
    let out = bin_stdout().arg("--carve").arg(&f.target).output().unwrap();
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("--features carve"), "stderr: {}", err);
    } else {
        // Built with the feature: carving ran and reported a section.
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("Carving"), "stdout:\n{}", stdout);
    }
}
