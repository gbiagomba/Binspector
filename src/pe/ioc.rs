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
}

impl Iocs {
    pub fn is_empty(&self) -> bool {
        self.urls.is_empty()
            && self.ips.is_empty()
            && self.emails.is_empty()
            && self.registry_keys.is_empty()
            && self.file_paths.is_empty()
    }

    pub fn total(&self) -> usize {
        self.urls.len()
            + self.ips.len()
            + self.emails.len()
            + self.registry_keys.len()
            + self.file_paths.len()
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
    cap: usize,
}

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
            cap,
        }
    }

    pub fn feed(&mut self, text: &str) {
        // Cheap pre-filter: most strings contain none of these markers.
        if text.len() < 4 {
            return;
        }
        if self.urls.len() < self.cap && (text.contains("://")) {
            for m in self.url.find_iter(text) {
                self.urls.insert(m.as_str().to_string());
                if self.urls.len() >= self.cap {
                    break;
                }
            }
        }
        if self.emails.len() < self.cap && text.contains('@') {
            for m in self.email.find_iter(text) {
                self.emails.insert(m.as_str().to_string());
                if self.emails.len() >= self.cap {
                    break;
                }
            }
        }
        if self.registry_keys.len() < self.cap
            && (text.contains("HKEY_") || text.contains("HKLM") || text.contains("HKCU"))
        {
            for m in self.registry.find_iter(text) {
                self.registry_keys.insert(m.as_str().to_string());
                if self.registry_keys.len() >= self.cap {
                    break;
                }
            }
        }
        if self.file_paths.len() < self.cap && text.contains(":\\") {
            for m in self.path.find_iter(text) {
                self.file_paths.insert(m.as_str().to_string());
                if self.file_paths.len() >= self.cap {
                    break;
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

    pub fn finish(self) -> Iocs {
        Iocs {
            urls: self.urls.into_iter().collect(),
            ips: self.ips.into_iter().collect(),
            emails: self.emails.into_iter().collect(),
            registry_keys: self.registry_keys.into_iter().collect(),
            file_paths: self.file_paths.into_iter().collect(),
        }
    }
}

/// `1.0.0.0` and `6.9.0.0` are version numbers, not addresses.
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
