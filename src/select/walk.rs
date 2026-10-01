//! Turning command-line arguments into an ordered list of files to scan.
//!
//! Safety properties, each of which is a test rather than a comment:
//!
//! - **A symlink found during recursion is never followed.** `read_dir` plus
//!   `DirEntry::file_type` is `lstat`-based and does not follow, so a loop or an escape out of
//!   the named tree is structurally impossible and needs no visited-inode bookkeeping. A path
//!   named *on the command line* is followed, which is the same trust boundary `find -H` draws:
//!   naming a path is an instruction.
//! - **Nothing but regular files and directories is opened.** A fifo would block the scan, and a
//!   device file has no meaningful contents.
//! - **Entries are sorted per directory**, so target order, labels, slugs, and the aggregate
//!   digest are identical across runs and across platforms.
//! - **Every cap degrades to a warning plus partial results**, matching `container::Budget`.
//!   A breached cap must never turn a 400-file scan into an error.

use anyhow::{bail, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use super::candidate::{self, Reason, Verdict};
use super::{Origin, Plan, SelectConfig, Target};
use crate::observe::{Event, Observer};

/// Resolve the positional arguments into the files a scan should visit.
pub fn plan(roots: &[PathBuf], cfg: &SelectConfig, observer: &dyn Observer) -> Result<Plan> {
    observer.on(&Event::Phase {
        name: "selecting targets",
    });
    let mut state = State {
        cfg,
        observer,
        targets: Vec::new(),
        warnings: Vec::new(),
        considered: 0,
        skipped: 0,
        bytes: 0,
        seen: BTreeSet::new(),
        capped: false,
    };

    for root in roots {
        // An explicitly named path IS followed, deliberately: the user named it.
        let meta = match fs::metadata(root) {
            Ok(m) => m,
            // Same wording as the single-target path used before 5.1.0, so a typo in a path
            // still reads the same and the existing test for it keeps passing.
            Err(e) => bail!("reading {}: {}", root.display(), e),
        };
        if meta.is_dir() {
            state.descend(root, root, 0)?;
            if state.targets.is_empty() {
                state.warn(format!("no candidate files under {}", root.display()));
            }
        } else {
            // A named file is always taken. Filtering an explicit argument would mean
            // second-guessing an instruction.
            state.take(root, root, meta.len(), Origin::Explicit, Reason::Explicit);
        }
    }

    if state.targets.is_empty() {
        bail!(
            "no scannable files found under {}. Every candidate was filtered out; pass \
             --all-files to scan everything.",
            roots
                .iter()
                .map(|r| r.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let State {
        mut targets,
        mut warnings,
        considered,
        skipped,
        ..
    } = state;
    super::label::assign(&mut targets);
    if skipped > 0 {
        // Surfaced in the report as well as at -vv, so the filter is auditable by someone
        // reading the output rather than only by someone watching the run.
        warnings.push(format!(
            "{} file(s) considered, {} skipped as non-candidates; pass --all-files to scan \
             everything",
            considered, skipped
        ));
    }
    Ok(Plan {
        targets,
        warnings,
        considered,
        skipped,
    })
}

struct State<'a> {
    cfg: &'a SelectConfig,
    observer: &'a dyn Observer,
    targets: Vec<Target>,
    warnings: Vec<String>,
    considered: usize,
    skipped: usize,
    bytes: u64,
    /// Canonical paths already taken, so a file named twice and also reached through a
    /// directory argument is scanned once.
    seen: BTreeSet<PathBuf>,
    capped: bool,
}

impl State<'_> {
    fn warn(&mut self, msg: String) {
        if !self.warnings.contains(&msg) {
            self.warnings.push(msg);
        }
    }

    fn skip(&mut self, path: &Path, reason: &str) {
        self.skipped += 1;
        let chain = path.display().to_string();
        self.observer.on(&Event::Skipped {
            chain: &chain,
            reason,
        });
    }

    /// True once a fleet cap is breached, after recording the warning once.
    fn at_capacity(&mut self) -> bool {
        if self.capped {
            return true;
        }
        if self.targets.len() >= self.cfg.max_targets {
            self.capped = true;
            self.warn(format!(
                "stopped after {} target(s): --max-targets reached, results are partial",
                self.cfg.max_targets
            ));
        } else if self.bytes >= self.cfg.max_input_bytes {
            self.capped = true;
            self.warn(format!(
                "stopped after {} byte(s) of input: --max-input-bytes reached, results are \
                 partial",
                self.bytes
            ));
        }
        self.capped
    }

    fn take(&mut self, path: &Path, _root: &Path, size: u64, origin: Origin, reason: Reason) {
        let key = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if !self.seen.insert(key) {
            // Named twice, or named and also reachable through a directory argument.
            return;
        }
        self.bytes = self.bytes.saturating_add(size);
        self.targets.push(Target {
            path: path.to_path_buf(),
            // Filled in by `label::assign` once the whole set is known, because a collision
            // cannot be detected one target at a time.
            label: String::new(),
            slug: String::new(),
            relative: relative_to(path, _root),
            origin,
            size,
            selected_by: reason.as_label(),
        });
    }

    fn descend(&mut self, dir: &Path, root: &Path, depth: usize) -> Result<()> {
        if depth > self.cfg.max_dir_depth {
            let chain = dir.display().to_string();
            self.observer.on(&Event::Skipped {
                chain: &chain,
                reason: "--max-dir-depth reached",
            });
            self.warn(format!(
                "stopped descending at {}: --max-dir-depth of {} reached",
                dir.display(),
                self.cfg.max_dir_depth
            ));
            return Ok(());
        }

        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                // A directory that cannot be opened is a warning, never fatal: one unreadable
                // directory must not discard the rest of the tree.
                self.warn(format!("skipped {}: {}", dir.display(), e));
                return Ok(());
            }
        };

        // Collected and sorted so the walk is deterministic across platforms.
        let mut files: Vec<PathBuf> = Vec::new();
        let mut dirs: Vec<PathBuf> = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    self.warn(format!("skipped an entry under {}: {}", dir.display(), e));
                    continue;
                }
            };
            // file_type does not follow a symlink, which is what makes a loop impossible.
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) => {
                    self.warn(format!("skipped {}: {}", entry.path().display(), e));
                    continue;
                }
            };
            let path = entry.path();
            if ft.is_symlink() {
                self.skip(&path, "symlink, not followed");
            } else if ft.is_dir() {
                dirs.push(path);
            } else if ft.is_file() {
                files.push(path);
            } else {
                self.skip(&path, "not a regular file");
            }
        }
        files.sort();
        dirs.sort();

        for path in files {
            if self.at_capacity() {
                return Ok(());
            }
            self.consider(&path, root);
        }
        for path in dirs {
            if self.at_capacity() {
                return Ok(());
            }
            self.descend(&path, root, depth + 1)?;
        }
        Ok(())
    }

    /// Read a file's head and decide whether to scan it.
    fn consider(&mut self, path: &Path, root: &Path) {
        self.considered += 1;
        let size = match fs::metadata(path) {
            Ok(m) => m.len(),
            Err(e) => {
                // Discovered, not named, so this is a warning and the walk continues.
                self.warn(format!("skipped {}: {}", path.display(), e));
                self.skipped += 1;
                return;
            }
        };
        let head = match read_head(path, self.cfg.sniff_bytes) {
            Ok(h) => h,
            Err(e) => {
                self.warn(format!("skipped {}: {}", path.display(), e));
                self.skipped += 1;
                return;
            }
        };
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        match candidate::classify(&name, &head, size, self.cfg.all_files) {
            Verdict::Take(reason) => self.take(path, root, size, Origin::Discovered, reason),
            Verdict::Skip(reason) => self.skip(path, reason),
        }
    }
}

/// First `n` bytes of a file, or fewer if it is shorter.
fn read_head(path: &Path, n: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = fs::File::open(path)?;
    let mut buf = vec![0u8; n];
    let read = f.read(&mut buf)?;
    buf.truncate(read);
    Ok(buf)
}

/// Path relative to the directory root it was found under, or the file name for a named file.
fn relative_to(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::testing::Recorder;
    use std::io::Write;

    fn write(dir: &Path, rel: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(bytes).unwrap();
        p
    }

    fn fake_pe() -> Vec<u8> {
        let mut v = vec![0u8; 0x100];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3C] = 0x40;
        v[0x40..0x44].copy_from_slice(b"PE\0\0");
        v
    }

    fn cfg() -> SelectConfig {
        SelectConfig::default()
    }

    #[test]
    fn a_directory_yields_its_candidates_and_skips_the_rest() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "app.exe", &fake_pe());
        write(d.path(), "bin/tool", &fake_pe());
        write(d.path(), "README.md", b"# just text, not a binary\n");
        write(d.path(), "icon.png", b"\x89PNG\r\n\x1a\n padding padding");

        let rec = Recorder::new(crate::observe::level::DECISIONS);
        let plan = plan(&[d.path().to_path_buf()], &cfg(), &rec).unwrap();
        let names: Vec<&str> = plan.targets.iter().map(|t| t.relative.as_str()).collect();
        assert_eq!(plan.targets.len(), 2, "got {:?}", names);
        assert!(names.contains(&"app.exe"));
        // The extensionless one, which only magic can find.
        assert!(names.iter().any(|n| n.ends_with("tool")));
        assert_eq!(plan.skipped, 2);
        assert_eq!(plan.considered, 4);
        // Every skip is reported, so the filter is auditable.
        assert_eq!(
            rec.kinds()
                .iter()
                .filter(|k| k.starts_with("skip:"))
                .count(),
            2
        );
    }

    #[test]
    fn all_files_takes_everything() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "app.exe", &fake_pe());
        write(d.path(), "README.md", b"# just text\n");
        let c = SelectConfig {
            all_files: true,
            ..cfg()
        };
        let plan = plan(&[d.path().to_path_buf()], &c, &crate::observe::Null).unwrap();
        assert_eq!(plan.targets.len(), 2);
        assert_eq!(plan.skipped, 0);
    }

    #[test]
    fn a_named_file_is_taken_even_when_it_would_be_filtered() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "notes.md", b"# naming it is an instruction\n");
        let plan = plan(std::slice::from_ref(&p), &cfg(), &crate::observe::Null).unwrap();
        assert_eq!(plan.targets.len(), 1);
        assert_eq!(plan.targets[0].origin, Origin::Explicit);
        assert_eq!(plan.targets[0].selected_by, "explicit");
    }

    #[test]
    fn several_named_files_are_all_taken_in_order() {
        let d = tempfile::tempdir().unwrap();
        let a = write(d.path(), "a.exe", &fake_pe());
        let b = write(d.path(), "b.exe", &fake_pe());
        let plan = plan(&[a, b], &cfg(), &crate::observe::Null).unwrap();
        assert_eq!(plan.targets.len(), 2);
        assert_eq!(plan.targets[0].label, "a.exe");
        assert_eq!(plan.targets[1].label, "b.exe");
    }

    #[test]
    fn a_missing_named_path_is_a_hard_error_with_the_old_wording() {
        // Pinned: a typo in a path must never be reported as a clean scan, and the message has
        // to keep saying "reading" so the existing integration test holds.
        let err = plan(
            &[PathBuf::from("/nonexistent/sample.bin")],
            &cfg(),
            &crate::observe::Null,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("reading"), "got {}", err);
    }

    #[test]
    fn a_directory_of_no_candidates_is_an_error_not_a_clean_report() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "README.md", b"# nothing scannable here\n");
        let err = plan(&[d.path().to_path_buf()], &cfg(), &crate::observe::Null)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no scannable files"), "got {}", err);
        assert!(
            err.contains("--all-files"),
            "the error must say how to override"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_never_followed_during_recursion() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "real/app.exe", &fake_pe());
        // A link back to the tree root, which would recurse forever if followed.
        std::os::unix::fs::symlink(d.path(), d.path().join("real/loop")).unwrap();
        // And a link to a candidate, which must not be scanned twice.
        std::os::unix::fs::symlink(
            d.path().join("real/app.exe"),
            d.path().join("real/alias.exe"),
        )
        .unwrap();

        let rec = Recorder::new(crate::observe::level::DECISIONS);
        let plan = plan(&[d.path().to_path_buf()], &cfg(), &rec).unwrap();
        assert_eq!(plan.targets.len(), 1, "only the real file");
        assert!(
            rec.kinds()
                .iter()
                .any(|k| k.contains("symlink, not followed")),
            "the skip must be reported: {:?}",
            rec.kinds()
        );
    }

    #[test]
    fn the_same_file_named_twice_is_scanned_once() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "app.exe", &fake_pe());
        let plan = plan(&[p.clone(), p.clone()], &cfg(), &crate::observe::Null).unwrap();
        assert_eq!(plan.targets.len(), 1);
    }

    #[test]
    fn a_file_named_and_also_inside_a_named_directory_is_scanned_once() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "app.exe", &fake_pe());
        let plan = plan(&[p, d.path().to_path_buf()], &cfg(), &crate::observe::Null).unwrap();
        assert_eq!(plan.targets.len(), 1);
    }

    #[test]
    fn directory_depth_is_capped_with_a_warning_and_partial_results() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "top.exe", &fake_pe());
        write(d.path(), "a/b/c/deep.exe", &fake_pe());
        let c = SelectConfig {
            max_dir_depth: 1,
            ..cfg()
        };
        let plan = plan(&[d.path().to_path_buf()], &c, &crate::observe::Null).unwrap();
        assert_eq!(plan.targets.len(), 1, "only the shallow one");
        assert!(
            plan.warnings.iter().any(|w| w.contains("max-dir-depth")),
            "a breached cap must warn: {:?}",
            plan.warnings
        );
    }

    #[test]
    fn the_target_cap_degrades_to_partial_results() {
        let d = tempfile::tempdir().unwrap();
        for i in 0..5 {
            write(d.path(), &format!("app{}.exe", i), &fake_pe());
        }
        let c = SelectConfig {
            max_targets: 2,
            ..cfg()
        };
        let plan = plan(&[d.path().to_path_buf()], &c, &crate::observe::Null).unwrap();
        assert_eq!(plan.targets.len(), 2);
        assert!(plan.warnings.iter().any(|w| w.contains("max-targets")));
    }

    #[test]
    fn traversal_order_is_deterministic() {
        let d = tempfile::tempdir().unwrap();
        for name in ["z.exe", "a.exe", "m/inner.exe", "b.exe"] {
            write(d.path(), name, &fake_pe());
        }
        let first = plan(&[d.path().to_path_buf()], &cfg(), &crate::observe::Null).unwrap();
        let second = plan(&[d.path().to_path_buf()], &cfg(), &crate::observe::Null).unwrap();
        let a: Vec<&str> = first.targets.iter().map(|t| t.relative.as_str()).collect();
        let b: Vec<&str> = second.targets.iter().map(|t| t.relative.as_str()).collect();
        assert_eq!(a, b);
        // Files before subdirectories, each sorted.
        assert_eq!(a[0], "a.exe");
        assert_eq!(a[1], "b.exe");
        assert_eq!(a[2], "z.exe");
    }

    #[test]
    fn an_unreadable_directory_is_a_warning_and_the_rest_still_scans() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "app.exe", &fake_pe());
        let blocked = d.path().join("locked");
        fs::create_dir_all(&blocked).unwrap();
        write(&blocked, "hidden.exe", &fake_pe());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).unwrap();
        }
        let plan = plan(&[d.path().to_path_buf()], &cfg(), &crate::observe::Null).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Restore so the tempdir can be cleaned up.
            let _ = fs::set_permissions(&blocked, fs::Permissions::from_mode(0o755));
            // Running as root defeats the permission block, so accept either outcome but
            // require that the readable file was found.
            assert!(plan.targets.iter().any(|t| t.relative == "app.exe"));
        }
        #[cfg(not(unix))]
        assert!(!plan.targets.is_empty());
    }
}
