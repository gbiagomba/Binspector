//! A persistent store for reputation verdicts.
//!
//! **Why persist at all.** A 4,281-member package holds 3,799 distinct hashes, and a free tier
//! answers 500 a day. Without a cache a second scan of the same package pays the whole quota again,
//! which makes the member sweep unusable in practice rather than merely slow.
//!
//! **TTL by verdict class, because one lifetime would be wrong in one direction.** The dangerous
//! entry to cache is `NotFound`. It does not mean the file is clean; it means nobody has submitted
//! that hash yet. Cached for a month, the tool would keep reporting "unknown" long after the file
//! became known-bad, and a reader has no way to tell a fresh unknown from a stale one. So `NotFound`
//! expires in a day while a malicious verdict, which rarely reverses, keeps a month. An `Error` is
//! not an answer and is never stored.
//!
//! **What this file is, stated rather than left implicit.** It is an index of every binary hash
//! inspected on this machine, and it crosses engagements: a hash seen while reviewing one product
//! is still here while reviewing the next. For assessment work that is investigative-sensitive in a
//! way the digests inside a single report are not. It is created mode 0600 and refused if anything
//! else can read it, using the same check the credentials file uses, and `binspector cache --purge`
//! deletes it.

use std::path::PathBuf;

use super::reputation::Verdict;

/// How long each class of answer stays usable.
///
/// Returns `None` for an answer that is not an answer, which is never written.
pub fn ttl_secs(v: &Verdict) -> Option<i64> {
    match v {
        // Rarely reverses. A month saves the most requests on the hashes that matter most.
        Verdict::Malicious { .. } => Some(30 * 24 * 3600),
        // A clean hash can become malicious when a new signature lands.
        Verdict::Clean { .. } => Some(7 * 24 * 3600),
        // The short one, on purpose. "Nobody has submitted this" is the most perishable thing a
        // service can tell you, and the one most dangerous to remember.
        Verdict::NotFound => Some(24 * 3600),
        // Not answers. Caching a transport failure would turn a blip into a day of silence.
        Verdict::Error(_) | Verdict::NotConfigured => None,
    }
}

/// Where the cache lives, unless `BINSPECTOR_CACHE` overrides it.
///
/// Beside the credentials file, since both are user-level state this tool owns. `None` when `HOME`
/// is unset, which is how a sandbox or a CI container with no home opts out by accident rather than
/// getting a file in an unexpected place.
pub fn cache_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BINSPECTOR_CACHE") {
        if !p.trim().is_empty() {
            return Some(PathBuf::from(p.trim()));
        }
    }
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".config/binspector/reputation.sqlite"))
}

/// One stored answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub sha256: String,
    pub service: String,
    pub verdict: Verdict,
    /// Unix seconds when this was written.
    pub stored_at: i64,
}

impl Entry {
    /// Whether this answer is still usable at `now`.
    ///
    /// A negative age is not fresh. `now` earlier than `stored_at` means either the clock moved
    /// backwards or the row claims a future timestamp, and neither is a basis for serving a cached
    /// answer. The first version of this compared `now.saturating_sub(stored_at) < ttl`, which is
    /// true for any negative age, so a backwards clock made every entry fresh forever: the exact
    /// opposite of what the comment beside it claimed. Erring toward a wasted request rather than
    /// toward a stale answer is the only safe direction here.
    pub fn is_fresh(&self, now: i64) -> bool {
        let Some(ttl) = ttl_secs(&self.verdict) else {
            // An unstorable verdict read back from a hand-edited file is never fresh.
            return false;
        };
        let age = now.saturating_sub(self.stored_at);
        (0..ttl).contains(&age)
    }
}

/// Seconds since the Unix epoch.
///
/// Zero before the epoch, matching `pe::now_unix`, so a misconfigured clock makes every entry look
/// ancient and therefore stale rather than making a stale entry look fresh. Erring toward a wasted
/// request rather than toward a wrong answer is the right direction for this.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Statistics for `binspector cache --show`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub total: usize,
    pub fresh: usize,
    pub expired: usize,
    /// Distinct hashes, which is what the file discloses about what has been inspected.
    pub hashes: usize,
    pub bytes: u64,
}

#[cfg(feature = "sqlite")]
pub use store::*;

#[cfg(feature = "sqlite")]
mod store {
    // Imported here rather than at module scope: everything below is feature-gated, and an import
    // used only by gated code is dead in a `--no-default-features` build. That is the same lint
    // that failed CI in 5.9.0, caught locally this time by running the command CI runs.
    use super::*;
    use anyhow::{Context, Result};
    use rusqlite::{params, Connection};
    use std::path::Path;

    const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS verdicts (
  sha256 TEXT NOT NULL, service TEXT NOT NULL, verdict TEXT NOT NULL,
  detections INTEGER, total INTEGER, stored_at INTEGER NOT NULL,
  PRIMARY KEY (sha256, service));
";

    /// The store, opened for the life of one scan.
    pub struct Cache {
        /// Visible to the sibling test module so it can plant a row this version cannot decode,
        /// which is the only way to exercise forward compatibility.
        pub(super) conn: Connection,
        path: PathBuf,
    }

    impl Cache {
        /// Open or create the cache at `path`, refusing one others can read.
        ///
        /// The permission check runs before the open, and the 0600 mode is applied at creation
        /// rather than afterwards, so there is no window in which the file exists readable.
        pub fn open(path: &Path) -> Result<Self> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            if path.exists() {
                super::super::creds::check_permissions(path).with_context(|| {
                    format!(
                        "refusing to use a cache others can read: {}",
                        path.display()
                    )
                })?;
            } else {
                create_private(path)?;
            }
            let conn = Connection::open(path)
                .with_context(|| format!("opening reputation cache {}", path.display()))?;
            conn.execute_batch(SCHEMA)?;
            Ok(Self {
                conn,
                path: path.to_path_buf(),
            })
        }

        /// A fresh answer for this hash and service, if there is one.
        pub fn get(&self, sha256: &str, service: &str, now: i64) -> Option<Verdict> {
            let row: Option<(String, Option<i64>, Option<i64>, i64)> = self
                .conn
                .query_row(
                    "SELECT verdict, detections, total, stored_at FROM verdicts \
                     WHERE sha256 = ?1 AND service = ?2",
                    params![sha256, service],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .ok();
            let (kind, detections, total, stored_at) = row?;
            let verdict = decode(&kind, detections, total)?;
            let entry = Entry {
                sha256: sha256.to_string(),
                service: service.to_string(),
                verdict,
                stored_at,
            };
            entry.is_fresh(now).then_some(entry.verdict)
        }

        /// Store an answer, replacing any previous one for the same hash and service.
        ///
        /// A verdict with no TTL is silently not stored, which is deliberate: the caller should not
        /// have to ask whether an error is cacheable before offering it.
        pub fn put(&self, sha256: &str, service: &str, v: &Verdict, now: i64) -> Result<()> {
            if ttl_secs(v).is_none() {
                return Ok(());
            }
            let (kind, detections, total) = encode(v);
            self.conn.execute(
                "INSERT INTO verdicts (sha256, service, verdict, detections, total, stored_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(sha256, service) DO UPDATE SET \
                 verdict = ?3, detections = ?4, total = ?5, stored_at = ?6",
                params![sha256, service, kind, detections, total, now],
            )?;
            Ok(())
        }

        /// Counts and size, for `--show`.
        pub fn stats(&self, now: i64) -> Result<Stats> {
            let mut st = Stats {
                bytes: std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0),
                ..Default::default()
            };
            let mut q = self.conn.prepare(
                "SELECT sha256, service, verdict, detections, total, stored_at FROM verdicts",
            )?;
            let mut hashes = std::collections::BTreeSet::new();
            let rows = q.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            })?;
            for row in rows {
                let (sha, service, kind, det, tot, at) = row?;
                st.total += 1;
                hashes.insert(sha.clone());
                let fresh = decode(&kind, det, tot).is_some_and(|verdict| {
                    Entry {
                        sha256: sha,
                        service,
                        verdict,
                        stored_at: at,
                    }
                    .is_fresh(now)
                });
                if fresh {
                    st.fresh += 1;
                } else {
                    st.expired += 1;
                }
            }
            st.hashes = hashes.len();
            Ok(st)
        }

        /// Drop expired rows, returning how many went.
        ///
        /// Done row by row against the per-class TTL rather than with one SQL predicate, because
        /// the lifetime depends on the verdict and encoding that as SQL would duplicate
        /// [`ttl_secs`] in a second place where the two could drift.
        pub fn prune(&self, now: i64) -> Result<usize> {
            let mut q = self.conn.prepare(
                "SELECT sha256, service, verdict, detections, total, stored_at FROM verdicts",
            )?;
            let doomed: Vec<(String, String)> = q
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                        r.get::<_, Option<i64>>(4)?,
                        r.get::<_, i64>(5)?,
                    ))
                })?
                .filter_map(|row| row.ok())
                .filter(|(sha, service, kind, det, tot, at)| {
                    !decode(kind, *det, *tot).is_some_and(|verdict| {
                        Entry {
                            sha256: sha.clone(),
                            service: service.clone(),
                            verdict,
                            stored_at: *at,
                        }
                        .is_fresh(now)
                    })
                })
                .map(|(sha, service, ..)| (sha, service))
                .collect();
            for (sha, service) in &doomed {
                self.conn.execute(
                    "DELETE FROM verdicts WHERE sha256 = ?1 AND service = ?2",
                    params![sha, service],
                )?;
            }
            Ok(doomed.len())
        }
    }

    /// The sweep talks to the cache through this, so it compiles without the `sqlite` feature.
    ///
    /// A write failure is swallowed rather than propagated: the answer it failed to store is still a
    /// good answer, and losing a scan over a cache hiccup would be the wrong trade.
    impl super::super::reputation::VerdictStore for Cache {
        fn lookup(&self, sha256: &str, service: &str, now: i64) -> Option<Verdict> {
            self.get(sha256, service, now)
        }

        fn remember(&self, sha256: &str, service: &str, v: &Verdict, now: i64) {
            let _ = self.put(sha256, service, v, now);
        }
    }

    /// Delete the cache file. Not a method, because there is nothing to open first.
    pub fn purge(path: &Path) -> Result<bool> {
        if !path.exists() {
            return Ok(false);
        }
        std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
        Ok(true)
    }

    /// Create the file 0600 before anything is written to it.
    #[cfg(unix)]
    fn create_private(path: &Path) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        Ok(())
    }

    #[cfg(not(unix))]
    fn create_private(path: &Path) -> Result<()> {
        // Windows inherits the directory ACL, and there is no mode to set. The file still lives
        // under the user's profile, which is the same protection the credentials file gets.
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        Ok(())
    }

    /// Flatten a verdict into the three stored columns.
    fn encode(v: &Verdict) -> (&'static str, Option<i64>, Option<i64>) {
        match v {
            Verdict::Malicious { detections, total } => (
                "malicious",
                Some(i64::from(*detections)),
                Some(i64::from(*total)),
            ),
            Verdict::Clean { total } => ("clean", None, Some(i64::from(*total))),
            Verdict::NotFound => ("notfound", None, None),
            // Never reached: `put` refuses these first. Encoded rather than panicking so a future
            // caller cannot turn a logic slip into a crash.
            Verdict::Error(_) => ("error", None, None),
            Verdict::NotConfigured => ("notconfigured", None, None),
        }
    }

    /// Rebuild a verdict, or `None` for a row this version does not understand.
    ///
    /// A hand-edited or future-written row is dropped rather than guessed at, and because
    /// `is_fresh` is false for anything undecodable, an unknown row behaves as expired and gets
    /// pruned rather than lingering.
    fn decode(kind: &str, detections: Option<i64>, total: Option<i64>) -> Option<Verdict> {
        match kind {
            "malicious" => Some(Verdict::Malicious {
                detections: u32::try_from(detections.unwrap_or(0)).ok()?,
                total: u32::try_from(total.unwrap_or(0)).ok()?,
            }),
            "clean" => Some(Verdict::Clean {
                total: u32::try_from(total.unwrap_or(0)).ok()?,
            }),
            "notfound" => Some(Verdict::NotFound),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_expires_far_sooner_than_a_detection() {
        // The security argument the whole design rests on. "Nobody has submitted this hash" is the
        // most perishable thing a service can say and the most dangerous to remember.
        let nf = ttl_secs(&Verdict::NotFound).unwrap();
        let mal = ttl_secs(&Verdict::Malicious {
            detections: 3,
            total: 70,
        })
        .unwrap();
        let clean = ttl_secs(&Verdict::Clean { total: 70 }).unwrap();
        assert_eq!(nf, 24 * 3600);
        assert!(nf < clean, "unknown must expire before clean");
        assert!(clean < mal, "clean must expire before a detection");
    }

    #[test]
    fn an_error_is_not_an_answer_and_is_never_stored() {
        assert!(ttl_secs(&Verdict::Error("timeout".into())).is_none());
        assert!(ttl_secs(&Verdict::NotConfigured).is_none());
    }

    #[test]
    fn freshness_is_measured_against_an_injected_clock_not_a_wait() {
        let e = Entry {
            sha256: "a".repeat(64),
            service: "virustotal".into(),
            verdict: Verdict::NotFound,
            stored_at: 1_000_000,
        };
        assert!(e.is_fresh(1_000_000), "just written");
        assert!(
            e.is_fresh(1_000_000 + 24 * 3600 - 1),
            "one second short of a day"
        );
        assert!(
            !e.is_fresh(1_000_000 + 24 * 3600),
            "exactly a day is expired"
        );
        assert!(!e.is_fresh(1_000_000 + 40 * 3600));

        // The same instant is still fresh for a detection, which is the point of the per-class TTL.
        let mal = Entry {
            verdict: Verdict::Malicious {
                detections: 3,
                total: 70,
            },
            ..e.clone()
        };
        assert!(mal.is_fresh(1_000_000 + 40 * 3600));
    }

    #[test]
    fn a_clock_before_the_epoch_makes_entries_stale_rather_than_eternal() {
        // `now_unix` floors at zero, so a misconfigured clock errs toward a wasted request rather
        // than toward serving a stale answer.
        let e = Entry {
            sha256: "b".repeat(64),
            service: "metadefender".into(),
            verdict: Verdict::NotFound,
            stored_at: 2_000_000,
        };
        assert!(!e.is_fresh(0));
        // And a row claiming a future timestamp, which is the same arithmetic from the other side.
        assert!(!e.is_fresh(1_999_999));
        assert!(e.is_fresh(2_000_000), "the boundary itself is fresh");
    }

    #[test]
    fn the_cache_path_is_overridable_and_sits_beside_the_credentials() {
        // The override exists so a test, a container or an operator who wants the file elsewhere is
        // not forced into `$HOME`.
        let prev = std::env::var("BINSPECTOR_CACHE").ok();
        std::env::set_var("BINSPECTOR_CACHE", "/tmp/somewhere/else.sqlite");
        assert_eq!(
            cache_path().unwrap(),
            PathBuf::from("/tmp/somewhere/else.sqlite")
        );
        std::env::remove_var("BINSPECTOR_CACHE");
        if let Ok(home) = std::env::var("HOME") {
            let p = cache_path().unwrap();
            assert!(p.starts_with(&home));
            assert!(p.ends_with(".config/binspector/reputation.sqlite"));
        }
        if let Some(v) = prev {
            std::env::set_var("BINSPECTOR_CACHE", v);
        }
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod store_tests {
    use super::*;

    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("nested").join("reputation.sqlite");
        (d, p)
    }

    #[test]
    fn a_stored_verdict_comes_back_and_an_expired_one_does_not() {
        let (_d, p) = tmp();
        let c = Cache::open(&p).unwrap();
        let h = "c".repeat(64);
        c.put(&h, "virustotal", &Verdict::NotFound, 1_000_000)
            .unwrap();
        assert_eq!(
            c.get(&h, "virustotal", 1_000_000),
            Some(Verdict::NotFound),
            "fresh"
        );
        assert_eq!(
            c.get(&h, "virustotal", 1_000_000 + 25 * 3600),
            None,
            "a day later it must be asked again"
        );
    }

    #[test]
    fn a_detection_survives_long_after_an_unknown_would_have_expired() {
        let (_d, p) = tmp();
        let c = Cache::open(&p).unwrap();
        let h = "d".repeat(64);
        let v = Verdict::Malicious {
            detections: 5,
            total: 71,
        };
        c.put(&h, "virustotal", &v, 1_000_000).unwrap();
        assert_eq!(c.get(&h, "virustotal", 1_000_000 + 25 * 3600), Some(v));
    }

    #[test]
    fn services_are_cached_independently() {
        // One service answering is not the other answering. Keying on the hash alone would serve
        // VirusTotal's verdict as MetaDefender's.
        let (_d, p) = tmp();
        let c = Cache::open(&p).unwrap();
        let h = "e".repeat(64);
        c.put(&h, "virustotal", &Verdict::Clean { total: 70 }, 100)
            .unwrap();
        assert!(c.get(&h, "metadefender", 100).is_none());
        assert!(c.get(&h, "virustotal", 100).is_some());
    }

    #[test]
    fn storing_again_replaces_rather_than_duplicating() {
        let (_d, p) = tmp();
        let c = Cache::open(&p).unwrap();
        let h = "f".repeat(64);
        c.put(&h, "virustotal", &Verdict::NotFound, 100).unwrap();
        c.put(
            &h,
            "virustotal",
            &Verdict::Malicious {
                detections: 1,
                total: 70,
            },
            200,
        )
        .unwrap();
        let st = c.stats(200).unwrap();
        assert_eq!(st.total, 1, "one row per (hash, service)");
        assert!(matches!(
            c.get(&h, "virustotal", 200),
            Some(Verdict::Malicious { .. })
        ));
    }

    #[test]
    fn an_unstorable_verdict_is_accepted_and_not_written() {
        // The caller offers whatever it got without having to ask whether it is cacheable.
        let (_d, p) = tmp();
        let c = Cache::open(&p).unwrap();
        let h = "0".repeat(64);
        c.put(&h, "virustotal", &Verdict::Error("timeout".into()), 100)
            .unwrap();
        c.put(&h, "metadefender", &Verdict::NotConfigured, 100)
            .unwrap();
        assert_eq!(c.stats(100).unwrap().total, 0);
    }

    #[test]
    fn prune_drops_only_what_expired() {
        let (_d, p) = tmp();
        let c = Cache::open(&p).unwrap();
        c.put(&"1".repeat(64), "virustotal", &Verdict::NotFound, 1_000)
            .unwrap();
        c.put(
            &"2".repeat(64),
            "virustotal",
            &Verdict::Malicious {
                detections: 2,
                total: 70,
            },
            1_000,
        )
        .unwrap();
        let later = 1_000 + 25 * 3600;
        let st = c.stats(later).unwrap();
        assert_eq!(st.total, 2);
        assert_eq!(st.expired, 1);
        assert_eq!(st.fresh, 1);
        assert_eq!(c.prune(later).unwrap(), 1);
        let st = c.stats(later).unwrap();
        assert_eq!(st.total, 1, "the detection stays");
        assert_eq!(st.hashes, 1);
    }

    #[test]
    #[cfg(unix)]
    fn a_new_cache_is_created_private_and_a_readable_one_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, p) = tmp();
        let _ = Cache::open(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "created private, not fixed up afterwards");

        // Loosen it the way a careless `chmod` would and confirm the refusal names the fix.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = match Cache::open(&p) {
            Ok(_) => panic!("a world-readable cache must be refused"),
            Err(e) => format!("{:#}", e),
        };
        assert!(err.contains("others can read"), "{}", err);
    }

    #[test]
    fn purge_removes_the_file_and_says_whether_there_was_one() {
        let (_d, p) = tmp();
        let _ = Cache::open(&p).unwrap();
        assert!(p.exists());
        assert!(purge(&p).unwrap(), "there was a file");
        assert!(!p.exists());
        assert!(!purge(&p).unwrap(), "and now there is not");
    }

    #[test]
    fn a_row_this_version_cannot_decode_behaves_as_expired() {
        // Forward compatibility in the safe direction: an unrecognised verdict is never served as
        // an answer, and prune clears it rather than leaving it forever.
        let (_d, p) = tmp();
        let c = Cache::open(&p).unwrap();
        c.conn
            .execute(
                "INSERT INTO verdicts (sha256, service, verdict, stored_at) VALUES (?1,?2,?3,?4)",
                rusqlite::params!["9".repeat(64), "virustotal", "from-the-future", 100],
            )
            .unwrap();
        assert!(c.get(&"9".repeat(64), "virustotal", 100).is_none());
        assert_eq!(c.prune(100).unwrap(), 1);
    }
}
