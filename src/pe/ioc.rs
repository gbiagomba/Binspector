//! Indicator extraction from already-extracted strings.
//!
//! Mirrors what peframe surfaces: network endpoints, filesystem and registry paths,
//! and addresses. Patterns are deliberately conservative, since a binary is full of
//! text that merely resembles a URL.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use regex::Regex;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Iocs {
    pub urls: Vec<String>,
    pub ips: Vec<String>,
    pub emails: Vec<String>,
    pub registry_keys: Vec<String>,
    pub file_paths: Vec<String>,
    /// Paths rooted in a developer's home directory, kept apart from `file_paths` and under their
    /// own cap.
    ///
    /// These are three findings in one: a username disclosed in a shipped binary, a build that did
    /// not come from CI, and often the only evidence of a statically linked dependency. They are
    /// collected separately because they must not compete for the ordinary path budget. On a real
    /// bundle the 500-path cap filled with a thousand near-identical MSVC header paths and dropped
    /// the single developer path that was the only trace of a vendored OpenCV, which an adversarial
    /// review then had to find by hand.
    #[serde(default)]
    pub build_paths: Vec<String>,
    /// The per-target cap that was in force, so the disclosure line can name it.
    #[serde(default)]
    pub cap: usize,
    /// How many of each kind were seen after the cap was reached and therefore not collected.
    ///
    /// Without this a count reads as a total when it is an artifact of scan order. The project
    /// already refuses to suppress findings silently; the same applies to indicators.
    #[serde(default)]
    pub dropped: Dropped,
}

/// Per-kind count of indicators discarded because the cap was already reached.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Dropped {
    pub urls: usize,
    pub ips: usize,
    pub emails: usize,
    pub registry_keys: usize,
    pub file_paths: usize,
}

impl Dropped {
    pub fn total(&self) -> usize {
        self.urls + self.ips + self.emails + self.registry_keys + self.file_paths
    }
}

impl Iocs {
    pub fn is_empty(&self) -> bool {
        self.urls.is_empty()
            && self.ips.is_empty()
            && self.emails.is_empty()
            && self.registry_keys.is_empty()
            && self.file_paths.is_empty()
            && self.build_paths.is_empty()
    }

    /// The cap that was in force, recovered for the report's disclosure line.
    ///
    /// Derived rather than stored: every kind stops at the same cap, so the largest collected list
    /// is it whenever anything was dropped at all.
    pub fn total(&self) -> usize {
        self.urls.len()
            + self.ips.len()
            + self.emails.len()
            + self.registry_keys.len()
            + self.file_paths.len()
            + self.build_paths.len()
    }
}

pub struct Extractor {
    url: Regex,
    ip: Regex,
    email: Regex,
    registry: Regex,
    path: Regex,
    urls: BTreeSet<String>,
    ips: BTreeSet<String>,
    emails: BTreeSet<String>,
    registry_keys: BTreeSet<String>,
    file_paths: BTreeSet<String>,
    build_paths: BTreeSet<String>,
    dropped: Dropped,
    cap: usize,
}

/// Cap on developer-home paths, separate from and far below the ordinary indicator cap.
///
/// Small on purpose: a handful names the machines and the vendored trees, and anything beyond that
/// is the same few roots repeated. Separate on purpose: these must never lose a slot to boilerplate.
const BUILD_PATH_CAP: usize = 64;

/// Paths kept per home root. Two is enough to show the shape of a tree without letting one
/// developer's deep dependency directory crowd out every other root.
const PER_ROOT_CAP: usize = 2;

impl Extractor {
    pub fn new(cap: usize) -> Self {
        Self {
            url: Regex::new(r"(?i)\b(?:https?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,}")
                .expect("static regex"),
            ip: Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
                .expect("static regex"),
            email: Regex::new(r"(?i)\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
                .expect("static regex"),
            registry: Regex::new(
                r"(?i)\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU)\\[A-Za-z0-9\\ _.\-]{3,}",
            )
            .expect("static regex"),
            path: Regex::new(r"(?i)\b[A-Za-z]:\\(?:[A-Za-z0-9 _.\-]+\\){1,}[A-Za-z0-9 _.\-]*")
                .expect("static regex"),
            urls: BTreeSet::new(),
            ips: BTreeSet::new(),
            emails: BTreeSet::new(),
            registry_keys: BTreeSet::new(),
            file_paths: BTreeSet::new(),
            build_paths: BTreeSet::new(),
            dropped: Dropped::default(),
            cap,
        }
    }

    pub fn feed(&mut self, text: &str) {
        // Cheap pre-filter: most strings contain none of these markers.
        if text.len() < 4 {
            return;
        }
        if text.contains("://") {
            for m in self.url.find_iter(text) {
                if self.urls.len() < self.cap {
                    self.urls.insert(m.as_str().to_string());
                } else {
                    self.dropped.urls += 1;
                }
            }
        }
        if text.contains('@') {
            for m in self.email.find_iter(text) {
                if self.emails.len() < self.cap {
                    self.emails.insert(m.as_str().to_string());
                } else {
                    self.dropped.emails += 1;
                }
            }
        }
        if self.registry_keys.len() < self.cap
            && (text.contains("HKEY_") || text.contains("HKLM") || text.contains("HKCU"))
        {
            for m in self.registry.find_iter(text) {
                if self.registry_keys.len() < self.cap {
                    self.registry_keys.insert(m.as_str().to_string());
                } else {
                    self.dropped.registry_keys += 1;
                }
            }
        }
        if text.contains(":\\") || text.contains('/') {
            for m in self.path.find_iter(text) {
                let p = m.as_str();
                // A developer-home path is taken whatever the ordinary budget is doing. This is the
                // whole fix: the interesting path is rare and arrives late, and the boilerplate is
                // common and arrives early, so a first-come cap keeps exactly the wrong ones.
                if is_build_path(p) {
                    // Per-root quota, not just a total. Without it one noisy tree fills the budget:
                    // nine Rust registry paths under a single CI account consumed the slots and
                    // dropped the one developer path that identified a vendored dependency, which
                    // is the same first-come failure this whole section exists to fix, one level
                    // down. The roots are what matter; two examples each are plenty.
                    let root = home_root(p);
                    let per_root = self
                        .build_paths
                        .iter()
                        .filter(|q| home_root(q) == root)
                        .count();
                    if per_root < PER_ROOT_CAP && self.build_paths.len() < BUILD_PATH_CAP {
                        self.build_paths.insert(p.to_string());
                    }
                    continue;
                }
                if self.file_paths.len() < self.cap {
                    self.file_paths.insert(p.to_string());
                } else if let Some(evictable) = self.crowded_path(p) {
                    // The cap is full, but it is full of near-duplicates. A thousand headers from
                    // one compiler install say one thing; this path may say something else. Drop a
                    // member of the largest directory family to make room, and still count it as a
                    // drop, because one indicator was lost either way.
                    self.file_paths.remove(&evictable);
                    self.file_paths.insert(p.to_string());
                    self.dropped.file_paths += 1;
                } else {
                    self.dropped.file_paths += 1;
                }
            }
        }
        if self.ips.len() < self.cap && text.contains('.') {
            for m in self.ip.find_iter(text) {
                let s = m.as_str();
                // Version strings look exactly like IPs; require a plausible first octet.
                if !is_probably_version(s) {
                    self.ips.insert(s.to_string());
                }
                if self.ips.len() >= self.cap {
                    break;
                }
            }
        }
    }

    /// A path to evict so a more distinctive one can be kept, or `None` when nothing is crowded.
    ///
    /// The cap is first-come, which is the wrong order: boilerplate is common and arrives early,
    /// while the interesting path is rare and arrives late. Rather than reorder collection, this
    /// trades a path from the most over-represented directory for the incoming one, but only when
    /// the incoming path is from a *less* represented directory than the one being evicted. That
    /// condition is what stops it thrashing: two equally common families cannot evict each other
    /// forever, and a flood of new boilerplate cannot displace an established distinct entry.
    fn crowded_path(&self, incoming: &str) -> Option<String> {
        let incoming_dir = parent_dir(incoming);
        let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
        for p in &self.file_paths {
            *counts.entry(parent_dir(p)).or_insert(0) += 1;
        }
        let incoming_count = counts.get(&incoming_dir).copied().unwrap_or(0);
        let (fullest, n) = counts.into_iter().max_by_key(|(_, n)| *n)?;
        // Only worth evicting when one family genuinely dominates and the newcomer is rarer.
        if n < 8 || incoming_count + 1 >= n {
            return None;
        }
        self.file_paths
            .iter()
            .find(|p| parent_dir(p) == fullest)
            .cloned()
    }

    pub fn finish(self) -> Iocs {
        Iocs {
            build_paths: self.build_paths.into_iter().collect(),
            dropped: self.dropped,
            cap: self.cap,
            urls: self.urls.into_iter().collect(),
            ips: self.ips.into_iter().collect(),
            emails: self.emails.into_iter().collect(),
            registry_keys: self.registry_keys.into_iter().collect(),
            file_paths: self.file_paths.into_iter().collect(),
        }
    }
}

/// `1.0.0.0` and `6.9.0.0` are version numbers, not addresses.
/// Whether a path is rooted in a developer's home directory rather than a system or install tree.
///
/// Three facts in one string, which is why these are pulled out rather than left in the general
/// path list. The username is disclosed in a shipped artifact. The build did not come from CI, so
/// it is not reproducible and the toolchain is whatever that machine had. And the directory names
/// along the way frequently identify a statically linked dependency that appears in no manifest:
/// `C:\Users\<name>\Desktop\ocv43\opencv-4.3.0\...` is the only trace of a vendored OpenCV in a
/// bundle whose component list does not mention it.
///
/// Matched on the shape rather than on a username list, so it works for any developer. The two
/// Windows system accounts are excluded because services legitimately run under them and their
/// paths say nothing about who built anything.
/// The `<drive>:\\Users\\<name>` or `/home/<name>` prefix of a path, used to spread the build-path
/// budget across people and machines rather than across directories.
fn home_root(p: &str) -> String {
    let lower = p.to_ascii_lowercase().replace('\\', "/");
    let parts: Vec<&str> = lower.split('/').filter(|s| !s.is_empty()).collect();
    for (i, part) in parts.iter().enumerate() {
        if (*part == "users" || *part == "home") && i + 1 < parts.len() {
            return format!("{}/{}", part, parts[i + 1]);
        }
    }
    lower
}

/// The directory a path sits in, used to measure how over-represented a family is.
fn parent_dir(p: &str) -> String {
    let norm = p.replace('\\', "/");
    match norm.rfind('/') {
        Some(i) => norm[..i].to_ascii_lowercase(),
        None => String::new(),
    }
}

fn is_build_path(p: &str) -> bool {
    let lower = p.to_ascii_lowercase();
    let home = ["\\users\\", "/users/", "/home/"];
    let system = [
        "\\users\\public\\",
        "\\users\\default\\",
        "\\users\\all users\\",
    ];
    if system.iter().any(|s| lower.contains(s)) {
        return false;
    }
    // Hosted CI accounts. A path under one of these is evidence the build *did* come from CI, so
    // reporting it as "built outside CI" states the opposite of the truth. The username is still
    // not a person's, so there is no disclosure to report either.
    const CI_ACCOUNTS: &[&str] = &[
        "runneradmin",
        "runner",
        "vsts",
        "vssadministrator",
        "azdevops",
        "buildbot",
        "jenkins",
        "gitlab-runner",
        "teamcity",
    ];
    let root = home_root(p);
    if let Some(user) = root.rsplit('/').next() {
        if CI_ACCOUNTS.contains(&user) {
            return false;
        }
    }
    home.iter().any(|h| lower.contains(h))
}

fn is_probably_version(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    // A trailing pair of zeroes is overwhelmingly a version, and a leading 0 is
    // never a routable first octet.
    (parts[2] == "0" && parts[3] == "0") || parts[0] == "0"
}

#[cfg(test)]
mod build_path_tests {
    use super::*;

    #[test]
    fn a_developer_home_is_a_build_path_on_either_platform() {
        for p in [
            r"C:\Users\Eric\Desktop\ocv43\opencv-4.3.0\modules\core\src\system.cpp",
            "/Users/alice/src/thing/build/x.c",
            "/home/bob/work/lib/y.c",
        ] {
            assert!(is_build_path(p), "{} should be a build path", p);
        }
    }

    #[test]
    fn install_and_system_trees_are_not() {
        for p in [
            r"C:\Program Files\Microsoft Visual Studio\2022\VC\include\atlbase.h",
            r"C:\Windows\System32\kernel32.dll",
            r"C:\Users\Public\Documents\shared.txt",
            r"C:\Users\Default\NTUSER.DAT",
            "/usr/include/stdio.h",
        ] {
            assert!(!is_build_path(p), "{} must not be a build path", p);
        }
    }

    /// The defect this exists to fix: the ordinary cap filled with boilerplate and dropped the one
    /// path that mattered, because it arrived late and the cap is first-come.
    #[test]
    fn a_developer_path_survives_a_full_indicator_budget() {
        let mut e = Extractor::new(4);
        for i in 0..50 {
            e.feed(&format!(r"C:\Program Files\Vendor\inc\header{}.h", i));
        }
        e.feed(r"C:\Users\Eric\Desktop\ocv43\opencv-4.3.0\modules\core\src\system.cpp");
        let out = e.finish();
        assert_eq!(out.file_paths.len(), 4, "the ordinary cap still holds");
        assert!(out.dropped.file_paths > 0, "and the overflow is counted");
        assert_eq!(
            out.build_paths.len(),
            1,
            "the developer path is kept regardless: {:?}",
            out.build_paths
        );
        assert!(out.build_paths[0].contains("opencv-4.3.0"));
    }

    /// The cap is first-come, which keeps exactly the wrong paths: boilerplate is common and
    /// arrives early, the interesting path is rare and arrives late.
    #[test]
    fn a_distinct_path_displaces_one_from_a_crowded_directory() {
        let mut e = Extractor::new(12);
        // One compiler install, many near-identical headers.
        for i in 0..12 {
            e.feed(&format!(r"C:\Program Files\MSVC\include\h{}.h", i));
        }
        // A path from a directory nothing else is in.
        e.feed(r"C:\build\vendor\thirdparty\interesting.c");
        let out = e.finish();
        assert_eq!(out.file_paths.len(), 12, "the cap still holds");
        assert!(
            out.file_paths.iter().any(|p| p.contains("interesting.c")),
            "the distinct path should have displaced a crowded one: {:?}",
            out.file_paths
        );
        assert!(out.dropped.file_paths > 0, "and the loss is still counted");
    }

    /// The guard against thrashing: a flood of equally common paths must not keep evicting each
    /// other, and must not displace an established distinct entry.
    #[test]
    fn more_boilerplate_cannot_displace_an_established_entry() {
        let mut e = Extractor::new(12);
        e.feed(r"C:\build\vendor\thirdparty\interesting.c");
        for i in 0..40 {
            e.feed(&format!(r"C:\Program Files\MSVC\include\h{}.h", i));
        }
        let out = e.finish();
        assert!(
            out.file_paths.iter().any(|p| p.contains("interesting.c")),
            "the distinct entry must survive a flood: {:?}",
            out.file_paths
        );
    }

    #[test]
    fn truncation_is_counted_rather_than_silent() {
        let mut e = Extractor::new(2);
        for i in 0..20 {
            e.feed(&format!("https://example.com/{}", i));
        }
        let out = e.finish();
        assert_eq!(out.urls.len(), 2);
        assert_eq!(
            out.dropped.urls, 18,
            "a count that reads as a total when it is a scan-order artifact is the defect"
        );
        assert!(out.dropped.total() >= 18);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(texts: &[&str]) -> Iocs {
        let mut e = Extractor::new(100);
        for t in texts {
            e.feed(t);
        }
        e.finish()
    }

    #[test]
    fn extracts_urls() {
        let i = extract(&[
            "see https://example.com/path?a=1 for details",
            "ftp://files.test/x",
        ]);
        assert!(i
            .urls
            .iter()
            .any(|u| u.starts_with("https://example.com/path")));
        assert!(i.urls.iter().any(|u| u.starts_with("ftp://")));
    }

    #[test]
    fn extracts_emails_and_registry_and_paths() {
        let i = extract(&[
            "contact a.dev@example.co.uk now",
            r"HKEY_LOCAL_MACHINE\Software\Vendor\Test",
            r"C:\Program Files\Vendor\app.exe",
        ]);
        assert_eq!(i.emails, vec!["a.dev@example.co.uk"]);
        assert!(i.registry_keys[0].starts_with("HKEY_LOCAL_MACHINE"));
        assert!(i.file_paths[0].starts_with(r"C:\Program Files"));
    }

    #[test]
    fn extracts_real_ips() {
        let i = extract(&["connect 192.168.1.10 then 8.8.8.8"]);
        assert!(i.ips.contains(&"192.168.1.10".to_string()));
        assert!(i.ips.contains(&"8.8.8.8".to_string()));
    }

    #[test]
    fn does_not_mistake_version_numbers_for_ips() {
        // Straight from the SampleApp sample: 6.9.0.0 is a version.
        let i = extract(&["SampleApp 1.0.0.0", "1.0.0.0", "0.1.2.3"]);
        assert!(i.ips.is_empty(), "ips: {:?}", i.ips);
    }

    #[test]
    fn rejects_out_of_range_octets() {
        let i = extract(&["999.999.999.999"]);
        assert!(i.ips.is_empty());
    }

    #[test]
    fn deduplicates_and_sorts() {
        let i = extract(&["8.8.8.8", "8.8.8.8", "1.1.1.1"]);
        assert_eq!(i.ips, vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[test]
    fn honors_the_cap() {
        let mut e = Extractor::new(2);
        for n in 1..20 {
            e.feed(&format!("10.0.0.{}", n));
        }
        assert!(e.finish().ips.len() <= 2);
    }

    #[test]
    fn empty_input_yields_nothing() {
        let i = extract(&["", "abc", "no indicators here"]);
        assert!(i.is_empty());
        assert_eq!(i.total(), 0);
    }
}
