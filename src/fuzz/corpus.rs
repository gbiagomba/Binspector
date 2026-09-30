//! Seed corpus construction.
//!
//! A coverage-guided engine is only as good as its seeds. Binspector already unpacks
//! a sample into its constituent members, so it can emit a corpus that exercises the
//! real formats a target parses, rather than a directory of random bytes.

use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::container::{self, Format, Limits};

#[derive(Clone, Debug, Serialize)]
pub struct CorpusReport {
    pub dir: String,
    pub files_written: usize,
    pub bytes_written: u64,
    pub skipped_duplicates: usize,
    pub skipped_too_large: usize,
    /// Count of each format that made it into the corpus.
    pub formats: Vec<(String, usize)>,
}

pub struct Options {
    pub max_files: usize,
    pub max_file_bytes: u64,
    /// Keep only these formats. Empty keeps everything.
    pub only_formats: Vec<Format>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_files: 500,
            max_file_bytes: 2 * 1024 * 1024,
            only_formats: Vec::new(),
        }
    }
}

/// Unpack `sample` and write its members into `dir` as a seed corpus.
pub fn build(sample: &Path, dir: &Path, opts: &Options) -> Result<CorpusReport> {
    let data =
        std::fs::read(sample).with_context(|| format!("reading sample {}", sample.display()))?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut written = 0usize;
    let mut bytes = 0u64;
    let mut dupes = 0usize;
    let mut too_large = 0usize;
    let mut formats: std::collections::BTreeMap<String, usize> = Default::default();

    let root_name = sample
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "sample".to_string());

    container::walk_bytes(
        &data,
        root_name,
        Limits::default(),
        &crate::observe::Null,
        &mut |member| {
            if written >= opts.max_files {
                return Ok(());
            }
            if member.data.len() as u64 > opts.max_file_bytes {
                too_large += 1;
                return Ok(());
            }
            if !opts.only_formats.is_empty() && !opts.only_formats.contains(&member.format) {
                return Ok(());
            }
            // Content hash keeps the corpus free of identical seeds, which waste engine time.
            let digest = crate::hashing::digests(member.data).sha256;
            if !seen.insert(digest.clone()) {
                dupes += 1;
                return Ok(());
            }
            let name = format!("{}-{}", &digest[..16], safe_suffix(&member.chain_display()));
            let path = dir.join(name);
            std::fs::write(&path, member.data)
                .with_context(|| format!("writing {}", path.display()))?;
            written += 1;
            bytes += member.data.len() as u64;
            *formats
                .entry(member.format.as_str().to_string())
                .or_insert(0) += 1;
            Ok(())
        },
    )?;

    Ok(CorpusReport {
        dir: dir.display().to_string(),
        files_written: written,
        bytes_written: bytes,
        skipped_duplicates: dupes,
        skipped_too_large: too_large,
        formats: formats.into_iter().collect(),
    })
}

/// Reduce a provenance chain to a short, filesystem-safe suffix.
fn safe_suffix(chain: &str) -> String {
    let last = chain.rsplit(" :: ").next().unwrap_or(chain);
    let cleaned: String = last
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('_');
    let s = if trimmed.is_empty() {
        "member"
    } else {
        trimmed
    };
    s.chars().take(48).collect()
}

/// Path to the corpus directory a campaign should use by default.
pub fn default_dir(sample: &Path) -> PathBuf {
    let stem = sample
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "sample".to_string());
    PathBuf::from("fuzz").join("corpus").join(stem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
            for (n, d) in entries {
                w.start_file(*n, zip::write::SimpleFileOptions::default())
                    .unwrap();
                w.write_all(d).unwrap();
            }
            w.finish().unwrap();
        }
        std::fs::write(path, buf).unwrap();
    }

    #[test]
    fn writes_one_seed_per_member() {
        let dir = tempfile::tempdir().unwrap();
        let sample = dir.path().join("s.zip");
        write_zip(
            &sample,
            &[("a.bin", b"alpha payload"), ("b.bin", b"beta payload")],
        );
        let out = dir.path().join("corpus");
        let r = build(&sample, &out, &Options::default()).unwrap();
        assert_eq!(r.files_written, 2);
        assert!(r.bytes_written > 0);
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 2);
    }

    #[test]
    fn deduplicates_identical_members() {
        let dir = tempfile::tempdir().unwrap();
        let sample = dir.path().join("s.zip");
        write_zip(
            &sample,
            &[("a.bin", b"same bytes"), ("b.bin", b"same bytes")],
        );
        let out = dir.path().join("corpus");
        let r = build(&sample, &out, &Options::default()).unwrap();
        assert_eq!(r.files_written, 1);
        assert_eq!(r.skipped_duplicates, 1);
    }

    #[test]
    fn honors_the_size_and_count_caps() {
        let dir = tempfile::tempdir().unwrap();
        let sample = dir.path().join("s.zip");
        write_zip(
            &sample,
            &[("big.bin", &vec![7u8; 5000]), ("small.bin", b"tiny")],
        );
        let out = dir.path().join("corpus");
        let r = build(
            &sample,
            &out,
            &Options {
                max_file_bytes: 100,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(r.files_written, 1);
        assert_eq!(r.skipped_too_large, 1);

        let out2 = dir.path().join("corpus2");
        let r2 = build(
            &sample,
            &out2,
            &Options {
                max_files: 1,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(r2.files_written, 1);
    }

    #[test]
    fn records_member_formats() {
        let dir = tempfile::tempdir().unwrap();
        let sample = dir.path().join("s.zip");
        write_zip(&sample, &[("a.txt", b"plain text member")]);
        let out = dir.path().join("corpus");
        let r = build(&sample, &out, &Options::default()).unwrap();
        assert!(r.formats.iter().any(|(f, n)| f == "unknown" && *n == 1));
    }

    #[test]
    fn suffix_is_filesystem_safe_and_bounded() {
        assert_eq!(safe_suffix("bundle :: app.msix :: App.exe"), "App.exe");
        assert_eq!(
            safe_suffix("weird/name:with*chars"),
            "weird_name_with_chars"
        );
        assert!(safe_suffix(&"x".repeat(200)).len() <= 48);
        assert_eq!(safe_suffix("___"), "member");
    }

    #[test]
    fn default_dir_is_under_the_fuzz_tree() {
        let p = default_dir(Path::new("/tmp/SampleApp.msixbundle"));
        assert!(p.ends_with("fuzz/corpus/SampleApp") || p.to_string_lossy().contains("SampleApp"));
    }
}
