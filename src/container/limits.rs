//! Resource caps for recursive unpacking.
//!
//! Unpacking untrusted archives is a decompression-bomb surface: a small input can
//! expand without bound. Every cap here is enforced during the walk, and a breach
//! degrades to a warning plus partial results rather than aborting the scan, so a
//! hostile sample cannot hide findings by tripping a limit.

use std::fmt;

#[derive(Clone, Debug)]
pub struct Limits {
    /// Maximum nesting depth. A `.msixbundle` holding `.msix` holding a PE is depth 2.
    pub max_depth: usize,
    /// Maximum total unpacked bytes across the whole walk.
    pub max_total_bytes: u64,
    /// Maximum bytes for any single member.
    pub max_member_bytes: u64,
    /// Maximum ratio of total unpacked bytes to the root input size.
    pub max_expansion_ratio: u64,
    /// Maximum number of members visited.
    pub max_members: usize,
    /// Scan each member for embedded file signatures. Needs the `carve` feature.
    pub carve: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 4,
            max_total_bytes: 2 * 1024 * 1024 * 1024,
            max_member_bytes: 512 * 1024 * 1024,
            max_expansion_ratio: 100,
            max_members: 50_000,
            carve: false,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Breach {
    Depth,
    TotalBytes,
    MemberBytes,
    ExpansionRatio,
    MemberCount,
}

impl fmt::Display for Breach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Breach::Depth => "maximum nesting depth reached",
            Breach::TotalBytes => "maximum total unpacked bytes reached",
            Breach::MemberBytes => "member exceeds the per-member size cap",
            Breach::ExpansionRatio => "expansion ratio cap reached (possible decompression bomb)",
            Breach::MemberCount => "maximum member count reached",
        };
        f.write_str(s)
    }
}

/// Running accounting for one walk.
#[derive(Debug)]
pub struct Budget {
    limits: Limits,
    root_size: u64,
    total_unpacked: u64,
    members_seen: usize,
    warnings: Vec<String>,
}

impl Budget {
    pub fn new(limits: Limits, root_size: u64) -> Self {
        Self {
            limits,
            root_size: root_size.max(1),
            total_unpacked: 0,
            members_seen: 0,
            warnings: Vec::new(),
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn total_unpacked(&self) -> u64 {
        self.total_unpacked
    }

    pub fn members_seen(&self) -> usize {
        self.members_seen
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn warn(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        // Repeated identical warnings add noise without adding information.
        if !self.warnings.contains(&msg) {
            self.warnings.push(msg);
        }
    }

    pub fn check_depth(&mut self, depth: usize, at: &str) -> Option<Breach> {
        if depth > self.limits.max_depth {
            self.warn(format!(
                "{}: {} (depth {} > {})",
                at,
                Breach::Depth,
                depth,
                self.limits.max_depth
            ));
            return Some(Breach::Depth);
        }
        None
    }

    /// Declare an intent to read `size` bytes for a member. Returns a breach when
    /// the read must be skipped.
    pub fn check_member(&mut self, size: u64, at: &str) -> Option<Breach> {
        if self.members_seen >= self.limits.max_members {
            self.warn(format!("{}: {}", at, Breach::MemberCount));
            return Some(Breach::MemberCount);
        }
        if size > self.limits.max_member_bytes {
            self.warn(format!(
                "{}: {} ({} bytes > {})",
                at,
                Breach::MemberBytes,
                size,
                self.limits.max_member_bytes
            ));
            return Some(Breach::MemberBytes);
        }
        if self.total_unpacked.saturating_add(size) > self.limits.max_total_bytes {
            self.warn(format!("{}: {}", at, Breach::TotalBytes));
            return Some(Breach::TotalBytes);
        }
        let projected = self.total_unpacked.saturating_add(size);
        if projected / self.root_size > self.limits.max_expansion_ratio {
            self.warn(format!(
                "{}: {} ({}x)",
                at,
                Breach::ExpansionRatio,
                projected / self.root_size
            ));
            return Some(Breach::ExpansionRatio);
        }
        None
    }

    /// Record that `size` bytes were actually consumed.
    pub fn commit(&mut self, size: u64) {
        self.total_unpacked = self.total_unpacked.saturating_add(size);
        self.members_seen += 1;
    }
}

/// Reject archive member names that could escape an extraction root.
///
/// Nothing is written to disk during a scan, so this is defence in depth rather
/// than the only guard, and it also keeps hostile names out of report output.
pub fn is_safe_member_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let p = std::path::Path::new(name);
    if p.is_absolute() || name.starts_with('/') || name.starts_with('\\') {
        return false;
    }
    // Windows drive prefix such as C:\ or C:/
    let b = name.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return false;
    }
    !name.split(['/', '\\']).any(|c| c == "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_and_absolute_names() {
        assert!(is_safe_member_name("a/b/c.exe"));
        assert!(!is_safe_member_name("../escape"));
        assert!(!is_safe_member_name("a/../../escape"));
        assert!(!is_safe_member_name("/etc/passwd"));
        assert!(!is_safe_member_name("\\windows\\system32"));
        assert!(!is_safe_member_name("C:\\windows"));
        assert!(!is_safe_member_name(""));
    }

    #[test]
    fn depth_cap_trips() {
        let mut b = Budget::new(Limits::default(), 1000);
        assert!(b.check_depth(1, "x").is_none());
        assert_eq!(b.check_depth(99, "x"), Some(Breach::Depth));
        assert!(!b.warnings().is_empty());
    }

    #[test]
    fn member_size_cap_trips() {
        let limits = Limits {
            max_member_bytes: 10,
            ..Default::default()
        };
        let mut b = Budget::new(limits, 1000);
        assert_eq!(b.check_member(11, "x"), Some(Breach::MemberBytes));
        assert!(b.check_member(5, "x").is_none());
    }

    #[test]
    fn expansion_ratio_cap_trips() {
        let limits = Limits {
            max_expansion_ratio: 2,
            ..Default::default()
        };
        let mut b = Budget::new(limits, 100);
        // 500 bytes from a 100 byte root is 5x, over the 2x cap.
        assert_eq!(b.check_member(500, "x"), Some(Breach::ExpansionRatio));
    }

    #[test]
    fn total_bytes_cap_trips() {
        let limits = Limits {
            max_total_bytes: 100,
            max_expansion_ratio: u64::MAX,
            ..Default::default()
        };
        let mut b = Budget::new(limits, 10);
        b.commit(90);
        assert_eq!(b.check_member(50, "x"), Some(Breach::TotalBytes));
    }

    #[test]
    fn warnings_are_deduplicated() {
        let mut b = Budget::new(Limits::default(), 1000);
        b.warn("same");
        b.warn("same");
        assert_eq!(b.warnings().len(), 1);
    }
}
