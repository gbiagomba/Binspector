//! Writing unpacked members to disk, on request.
//!
//! **This is the one place the tool writes anything from a scanned file, and it only runs when asked
//! with `--extract`.** The walk itself stays in memory. That distinction matters: the in-memory rule
//! is why `container::limits` can describe member-name sanitising as defence in depth rather than
//! the only guard, and the moment extraction exists that reasoning becomes load-bearing.
//!
//! **Names are flattened, never mirrored.** An archive member's path is attacker-controlled, and
//! recreating the tree means defending against `../`, absolute paths, symlinked parents, Windows
//! device names and the rest, correctly, forever. Instead every output file is
//! `<sha256[..16]>-<sanitised leaf>`, where the leaf keeps only `[A-Za-z0-9._-]` and is capped. No
//! component of the member's own path ever reaches the filesystem, so traversal is not filtered, it
//! is structurally impossible: the output is always exactly one file directly inside the directory
//! the user named.
//!
//! The content hash leads the name so two members with the same leaf cannot collide and so a
//! duplicate is written once, which matters on a bundle that ships the same runtime DLL for four
//! architectures.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};

use super::Member;

/// What an extraction run did, for the report and the console.
#[derive(Clone, Debug, Default)]
pub struct ExtractReport {
    pub written: usize,
    pub bytes: u64,
    /// Members whose bytes were identical to one already written.
    pub duplicates: usize,
    /// Members skipped because the file cap was reached.
    pub skipped: usize,
    pub dir: PathBuf,
}

/// Collects members to disk as the walk visits them.
///
/// Shared across every target in a run, and across threads, which is why the state is behind a
/// mutex rather than owned per scan. One extractor per target would report a partial count per
/// target (sixteen lines on a sixteen-target run) and would deduplicate only within a target, so the
/// same runtime DLL shipped for four architectures counted as four writes rather than one and three
/// duplicates.
///
/// Concurrent writes to the same path are safe by construction rather than by locking: the filename
/// is derived from the content hash, so two threads racing on one path are writing identical bytes
/// and any interleaving produces the same file. The mutex guards the bookkeeping, not the write.
#[derive(Debug)]
pub struct Extractor {
    dir: PathBuf,
    state: Mutex<State>,
    max_files: usize,
}

#[derive(Debug, Default)]
struct State {
    seen: BTreeSet<String>,
    report: ExtractReport,
}

/// Upper bound on files written in one run.
///
/// A cap rather than unbounded, for the same reason every other limit exists: the input decides how
/// many members there are, and a bundle of 50,000 entries should not silently become 50,000 files on
/// a machine with little space. Exceeding it is reported, never fatal.
const MAX_FILES: usize = 10_000;

impl Extractor {
    /// Create the output directory, failing before the scan starts rather than midway through.
    pub fn new(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating extraction directory {}", dir.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            state: Mutex::new(State {
                seen: BTreeSet::new(),
                report: ExtractReport {
                    dir: dir.to_path_buf(),
                    ..ExtractReport::default()
                },
            }),
            max_files: MAX_FILES,
        })
    }

    /// Write one member, unless it is a duplicate or the cap is reached.
    ///
    /// Never returns an error for a member: a file that cannot be written is counted and the scan
    /// continues, because losing the whole analysis to one unwritable name would be a worse
    /// outcome than an incomplete extraction.
    pub fn take(&self, member: &Member) {
        let digest = crate::hashing::digests(member.data).sha256;
        let path = {
            let mut st = self.state.lock().expect("extractor state");
            if st.report.written >= self.max_files {
                st.report.skipped += 1;
                return;
            }
            if !st.seen.insert(digest.clone()) {
                st.report.duplicates += 1;
                return;
            }
            self.dir.join(format!(
                "{}-{}",
                &digest[..16],
                safe_leaf(&member.chain_display())
            ))
        };
        // Written outside the lock: the bytes are large and the path is unique to this member, so
        // holding the mutex across the write would serialise every thread on disk I/O.
        let outcome = std::fs::write(&path, member.data);
        let mut st = self.state.lock().expect("extractor state");
        match outcome {
            Ok(()) => {
                st.report.written += 1;
                st.report.bytes += member.data.len() as u64;
            }
            Err(_) => st.report.skipped += 1,
        }
    }

    /// A snapshot of what has been written so far.
    pub fn report(&self) -> ExtractReport {
        self.state.lock().expect("extractor state").report.clone()
    }
}

/// The last component of a provenance chain, reduced to a filename that is safe everywhere.
///
/// Everything outside `[A-Za-z0-9._-]` becomes `_`, which removes every path separator, every
/// traversal sequence, every drive letter and every shell metacharacter in one rule rather than in a
/// list of things to remember. Leading and trailing underscores are trimmed so a name cannot start
/// with a dot and hide on Unix, and the result is capped so a hostile 4 KiB member name cannot
/// produce a path the filesystem rejects.
fn safe_leaf(chain: &str) -> String {
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
    let trimmed = cleaned.trim_matches(|c| c == '_' || c == '.');
    let s = if trimmed.is_empty() {
        "member"
    } else {
        trimmed
    };
    s.chars().take(48).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_cannot_survive_the_leaf_rule() {
        for hostile in [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/shadow",
            "C:\\Windows\\System32\\cmd.exe",
            "bundle :: ../../escape.dll",
            "....//....//x",
        ] {
            let leaf = safe_leaf(hostile);
            assert!(!leaf.contains('/'), "{} -> {}", hostile, leaf);
            assert!(!leaf.contains('\\'), "{} -> {}", hostile, leaf);
            assert!(!leaf.contains(".."), "{} -> {}", hostile, leaf);
            assert!(!leaf.starts_with('.'), "{} -> {}", hostile, leaf);
        }
    }

    #[test]
    fn a_leaf_is_never_empty_or_hidden_or_unbounded() {
        assert_eq!(safe_leaf("///"), "member");
        assert_eq!(safe_leaf(""), "member");
        assert_eq!(safe_leaf("..."), "member");
        assert!(!safe_leaf(".hidden").starts_with('.'));
        assert!(safe_leaf(&"a".repeat(4096)).chars().count() <= 48);
    }

    #[test]
    fn an_ordinary_name_survives_intact() {
        assert_eq!(safe_leaf("bundle :: app.msix :: App.exe"), "App.exe");
        assert_eq!(safe_leaf("lib-1.2.3_final.dll"), "lib-1.2.3_final.dll");
    }

    /// Windows device names are not special-cased, because the hash prefix means no output file is
    /// ever named by the member alone: `con` becomes `<16 hex>-con`, which is an ordinary filename.
    #[test]
    fn the_hash_prefix_defuses_reserved_device_names() {
        let leaf = safe_leaf("CON");
        assert_eq!(leaf, "CON");
        let full = format!("{}-{}", "0123456789abcdef", leaf);
        assert_ne!(full.to_ascii_lowercase(), "con");
    }

    #[test]
    fn writes_deduplicates_and_caps() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut e = Extractor::new(dir.path()).expect("create");
        e.max_files = 2;
        let e = e;

        let data = b"the same bytes".to_vec();
        for name in ["a.dll", "b.dll"] {
            e.take(&Member {
                data: &data,
                chain: vec![name.to_string()],
                format: crate::container::Format::Unknown,
            });
        }
        let other = b"different bytes".to_vec();
        e.take(&Member {
            data: &other,
            chain: vec!["c.dll".to_string()],
            format: crate::container::Format::Unknown,
        });
        let third = b"a third set of bytes".to_vec();
        e.take(&Member {
            data: &third,
            chain: vec!["d.dll".to_string()],
            format: crate::container::Format::Unknown,
        });

        let r = e.report();
        assert_eq!(r.written, 2, "identical bytes are written once");
        assert_eq!(r.duplicates, 1);
        assert_eq!(r.skipped, 1, "and the cap is reported, not silent");

        // Every output file is directly inside the directory, never beside or above it.
        for entry in std::fs::read_dir(dir.path()).expect("read dir") {
            let p = entry.expect("entry").path();
            assert_eq!(p.parent(), Some(dir.path()));
            assert!(p.is_file());
        }
    }
}
