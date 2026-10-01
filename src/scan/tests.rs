//! Tests for the scan driver.
//!
//! Split out of `scan/mod.rs` when that file crossed the 1,000-line soft limit the project
//! enforces with `make loc-check`. Included with `#[path]` so it stays the same `tests` module
//! and keeps `use super::*` working unchanged.

use super::*;
use confidence::Confidence;
use std::io::{Cursor, Write};
use tempfile::NamedTempFile;
use zip::write::SimpleFileOptions;

fn temp_with(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

fn cfg_with_list(list: &str) -> (ScanConfig, NamedTempFile) {
    let lf = temp_with(list.as_bytes());
    let cfg = ScanConfig {
        banned_list: Some(lf.path().to_path_buf()),
        ..Default::default()
    };
    (cfg, lf)
}

#[test]
fn finds_real_hit_with_provenance() {
    let (cfg, _lf) = cfg_with_list("gets\n");
    // Shaped like a real import table entry: a bare, NUL-delimited symbol.
    let target = temp_with(b"\x00gets\x00other\x00");
    let out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
    assert_eq!(out.report.banned_hit_count, 1);
    assert_eq!(out.report.summary[0].function, "gets");
    assert_eq!(out.report.hits.len(), 1);
    assert_eq!(out.report.hits[0].confidence, Confidence::Exact);
}

#[test]
fn does_not_report_the_historical_false_positives() {
    let (cfg, _lf) = cfg_with_list("gets\nsystem\natoi\n");
    // Exactly the strings that produced the bogus 2.0.0 result.
    let target = temp_with(b"targetsize lightunplated_targetsize FileSystem CustomSystemFont");
    let out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
    assert_eq!(
        out.report.banned_hit_count, 0,
        "summary: {:?}",
        out.report.summary
    );
    assert!(out.report.summary.is_empty());
}

#[test]
fn descends_into_nested_zip_and_attributes_the_member() {
    let inner = {
        let mut buf = Vec::new();
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        w.start_file("App.exe", SimpleFileOptions::default())
            .unwrap();
        w.write_all(b"\x00gets\x00payload\x00").unwrap();
        w.finish().unwrap();
        buf
    };
    let bundle = {
        let mut buf = Vec::new();
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        w.start_file("app.msix", SimpleFileOptions::default())
            .unwrap();
        w.write_all(&inner).unwrap();
        w.finish().unwrap();
        buf
    };
    let (cfg, _lf) = cfg_with_list("gets\n");
    let target = temp_with(&bundle);
    let out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
    assert_eq!(out.report.banned_hit_count, 1);
    let hit = &out.report.hits[0];
    assert!(hit.member.contains("app.msix"), "member: {}", hit.member);
    assert!(hit.member.contains("App.exe"), "member: {}", hit.member);
}

#[test]
fn warns_when_no_executable_was_reached() {
    let (cfg, _lf) = cfg_with_list("gets\n");
    let target = temp_with(b"\x00gets\x00plain payload\x00");
    let out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
    assert!(out
        .report
        .warnings
        .iter()
        .any(|w| w.contains("no executable image")));
}

#[test]
fn case_sensitive_mode_is_honored() {
    // lstrcpyA carries uppercase in the list, so neither spelling is demoted as
    // prose and the only difference is the case-sensitivity setting itself.
    let lf = temp_with(b"lstrcpyA\n");
    let target = temp_with(b"\x00lstrcpyA\x00lstrcpya\x00");

    let insensitive = ScanConfig {
        banned_list: Some(lf.path().to_path_buf()),
        ..Default::default()
    };
    assert_eq!(
        run(target.path(), &insensitive, &crate::observe::Null)
            .unwrap()
            .report
            .banned_hit_count,
        2
    );

    let sensitive = ScanConfig {
        banned_list: Some(lf.path().to_path_buf()),
        case_sensitive: true,
        ..Default::default()
    };
    assert_eq!(
        run(target.path(), &sensitive, &crate::observe::Null)
            .unwrap()
            .report
            .banned_hit_count,
        1
    );
}

#[test]
fn dotnet_namespaces_and_doc_prose_are_suppressed_by_default() {
    // The two noise sources measured on the real SampleApp sample.
    let lf = temp_with(b"system\ngets\n");
    let target = temp_with(b"\x00System.Windows.Forms.dll\x00Gets or sets the BindingContext\x00");
    let cfg = ScanConfig {
        banned_list: Some(lf.path().to_path_buf()),
        ..Default::default()
    };
    let out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
    assert_eq!(
        out.report.banned_hit_count, 0,
        "summary: {:?}",
        out.report.summary
    );
    assert!(out.report.excluded_total >= 2);
    assert!(out
        .report
        .warnings
        .iter()
        .any(|w| w.contains("suppressed as low confidence")));
}

#[test]
fn include_excluded_reports_the_suppressed_hits() {
    let lf = temp_with(b"system\n");
    let target = temp_with(b"\x00System.Windows.Forms.dll\x00");
    let cfg = ScanConfig {
        banned_list: Some(lf.path().to_path_buf()),
        include_excluded: true,
        ..Default::default()
    };
    let out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
    assert_eq!(out.report.banned_hit_count, 1);
    assert_eq!(out.report.hits[0].confidence, Confidence::Prose);
    assert_eq!(out.report.excluded_total, 0);
}

#[test]
fn dump_spools_every_string() {
    let lf = temp_with(b"gets\n");
    let cfg = ScanConfig {
        banned_list: Some(lf.path().to_path_buf()),
        dump: true,
        ..Default::default()
    };
    let target = temp_with(b"aaaa\x00bbbb\x00gets\x00");
    let mut out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
    let mut n = 0;
    out.spool
        .as_mut()
        .unwrap()
        .for_each(|_| {
            n += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(n, 3);
}

/// Smallest byte sequence `container::detect` accepts as a PE, so a test can exercise the
/// executable-member path without a real binary.
fn fake_pe(payload: &[u8]) -> Vec<u8> {
    let mut pe = vec![0u8; 0x200];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3C] = 0x80;
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe.extend_from_slice(payload);
    pe
}

#[test]
fn summary_is_ordered_by_severity() {
    let lf = temp_with(b"atoi\nstrcpy\n");
    let cfg = ScanConfig {
        banned_list: Some(lf.path().to_path_buf()),
        ..Default::default()
    };
    // A PE, because since 5.0.0 a hit in a non-executable member is capped at Low and
    // the ordering would then be by count rather than by severity.
    let target = temp_with(&fake_pe(b"\x00atoi\x00atoi\x00atoi\x00strcpy\x00"));
    let out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
    // strcpy is critical, atoi is medium, so strcpy leads despite fewer hits.
    assert_eq!(out.report.summary[0].function, "strcpy");
}

#[test]
fn a_hit_in_a_non_executable_member_is_capped_at_low() {
    // The same bytes without a PE header. Nothing in a data file is a critical finding,
    // and the cap is recorded as an adjustment rather than applied silently.
    let lf = temp_with(b"strcpy\n");
    let cfg = ScanConfig {
        banned_list: Some(lf.path().to_path_buf()),
        ..Default::default()
    };
    let target = temp_with(b"\x00strcpy\x00");
    let out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
    let hit = &out.report.hits[0];
    assert_eq!(hit.severity, Severity::Low);
    assert_eq!(hit.base_severity(), Severity::Critical);
    assert_eq!(hit.adjustments[0].rule, "non-executable-member");
    assert_eq!(out.report.summary[0].severity, Severity::Low);
    assert_eq!(out.report.summary[0].base_severity(), Severity::Critical);
}

#[test]
fn window_keeps_hit_inside() {
    let long = format!("{}gets{}", "a".repeat(500), "b".repeat(500));
    let (w, s, e) = strings::window(&long, 500, 504, 120);
    assert_eq!(&w[s..e], "gets");
    assert!(w.len() <= 140);
}

#[test]
fn window_returns_whole_short_string() {
    let (w, s, e) = strings::window("xx gets yy", 3, 7, 120);
    assert_eq!(w, "xx gets yy");
    assert_eq!(&w[s..e], "gets");
}
