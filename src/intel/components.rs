//! Component and version detection from embedded strings.
//!
//! This is the input to CVE lookup. Scope is stated plainly: cve-bin-tool ships
//! roughly 380 hand-written checkers, and this is a curated set covering libraries
//! that actually turn up in the binaries under review. Coverage is reported so a
//! silent miss is never mistaken for a clean result.

use regex::Regex;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Component {
    pub name: String,
    pub version: String,
    /// The string the detection came from, so a reviewer can check it.
    pub evidence: String,
}

/// A detector: the vendor/product name, and a regex whose first capture is the version.
struct Signature {
    name: &'static str,
    pattern: &'static str,
}

/// Curated signature set. Patterns are anchored on the banner text these libraries
/// embed, which is far more reliable than a bare version number.
const SIGNATURES: &[Signature] = &[
    Signature {
        name: "openssl",
        pattern: r"OpenSSL (\d+\.\d+\.\d+[a-z]?)",
    },
    Signature {
        name: "zlib",
        pattern: r"(?:^|\s)(?:deflate|inflate) (\d+\.\d+\.\d+) Copyright",
    },
    Signature {
        name: "libpng",
        pattern: r"libpng version (\d+\.\d+\.\d+)",
    },
    Signature {
        name: "libjpeg-turbo",
        pattern: r"libjpeg-turbo version (\d+\.\d+\.\d+)",
    },
    Signature {
        name: "libcurl",
        pattern: r"libcurl/(\d+\.\d+\.\d+)",
    },
    Signature {
        name: "sqlite",
        pattern: r"SQLite version (\d+\.\d+\.\d+)",
    },
    Signature {
        name: "expat",
        pattern: r"expat_(\d+\.\d+\.\d+)",
    },
    Signature {
        name: "libxml2",
        pattern: r"libxml2-(\d+\.\d+\.\d+)",
    },
    Signature {
        name: "freetype",
        pattern: r"FreeType (\d+\.\d+\.\d+)",
    },
    Signature {
        name: "icu",
        pattern: r"icudt(\d+)",
    },
    Signature {
        name: "bzip2",
        pattern: r"bzip2-(\d+\.\d+\.\d+)",
    },
    Signature {
        name: "libtiff",
        pattern: r"LIBTIFF, Version (\d+\.\d+\.\d+)",
    },
    Signature {
        name: "openjpeg",
        pattern: r"openjpeg (\d+\.\d+\.\d+)",
    },
    Signature {
        name: "libwebp",
        pattern: r"libwebp (\d+\.\d+\.\d+)",
    },
    Signature {
        name: "zstd",
        pattern: r"Zstandard v?(\d+\.\d+\.\d+)",
    },
    Signature {
        name: "lz4",
        pattern: r"LZ4 v?(\d+\.\d+\.\d+)",
    },
    Signature {
        name: "onnxruntime",
        pattern: r"onnxruntime[- ]v?(\d+\.\d+\.\d+)",
    },
    Signature {
        name: "dotnet",
        pattern: r"\.NET (?:Core )?(\d+\.\d+\.\d+)",
    },
    Signature {
        name: "boost",
        pattern: r"Boost (\d+\.\d+\.\d+)",
    },
    Signature {
        name: "protobuf",
        pattern: r"protobuf[- ](\d+\.\d+\.\d+)",
    },
];

pub struct Detector {
    compiled: Vec<(&'static str, Regex)>,
    found: BTreeMap<(String, String), String>,
    cap: usize,
}

impl Detector {
    pub fn new(cap: usize) -> Self {
        let compiled = SIGNATURES
            .iter()
            .filter_map(|s| Regex::new(s.pattern).ok().map(|r| (s.name, r)))
            .collect();
        Self {
            compiled,
            found: BTreeMap::new(),
            cap,
        }
    }

    /// Number of detectors in the curated set, for the coverage statement.
    pub fn signature_count(&self) -> usize {
        self.compiled.len()
    }

    pub fn feed(&mut self, text: &str) {
        if self.found.len() >= self.cap || text.len() < 5 {
            return;
        }
        for (name, re) in &self.compiled {
            if let Some(c) = re.captures(text) {
                if let Some(v) = c.get(1) {
                    let key = (name.to_string(), v.as_str().to_string());
                    self.found.entry(key).or_insert_with(|| truncate(text, 160));
                }
            }
        }
    }

    pub fn finish(self) -> Vec<Component> {
        self.found
            .into_iter()
            .map(|((name, version), evidence)| Component {
                name,
                version,
                evidence,
            })
            .collect()
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(texts: &[&str]) -> Vec<Component> {
        let mut d = Detector::new(100);
        for t in texts {
            d.feed(t);
        }
        d.finish()
    }

    #[test]
    fn detects_openssl_from_its_banner() {
        let c = detect(&["OpenSSL 1.1.1k  25 Mar 2021"]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].name, "openssl");
        assert_eq!(c[0].version, "1.1.1k");
        assert!(c[0].evidence.contains("OpenSSL"));
    }

    #[test]
    fn detects_zlib_from_the_deflate_banner() {
        let c = detect(&["deflate 1.2.11 Copyright 1995-2017 Jean-loup Gailly"]);
        assert_eq!(c[0].name, "zlib");
        assert_eq!(c[0].version, "1.2.11");
    }

    #[test]
    fn detects_several_components() {
        let c = detect(&[
            "libpng version 1.6.37",
            "libcurl/7.79.1",
            "SQLite version 3.36.0",
        ]);
        let names: Vec<&str> = c.iter().map(|x| x.name.as_str()).collect();
        assert!(names.contains(&"libpng"));
        assert!(names.contains(&"libcurl"));
        assert!(names.contains(&"sqlite"));
    }

    #[test]
    fn deduplicates_repeated_detections() {
        let c = detect(&["OpenSSL 1.1.1k", "OpenSSL 1.1.1k", "OpenSSL 1.1.1k"]);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn distinct_versions_are_kept_separately() {
        let c = detect(&["OpenSSL 1.1.1k", "OpenSSL 3.0.2"]);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn a_bare_version_number_is_not_a_detection() {
        // This is the whole point of anchoring on banner text.
        let c = detect(&["1.2.3", "6.9.0.0", "version 1.0"]);
        assert!(c.is_empty(), "{:?}", c);
    }

    #[test]
    fn honors_the_cap() {
        let mut d = Detector::new(1);
        d.feed("OpenSSL 1.1.1k");
        d.feed("libpng version 1.6.37");
        assert_eq!(d.finish().len(), 1);
    }

    #[test]
    fn evidence_is_truncated_but_char_safe() {
        let long = format!("OpenSSL 1.1.1k {}", "\u{00e9}".repeat(200));
        let c = detect(&[&long]);
        assert!(c[0].evidence.len() <= 164);
        assert!(c[0].evidence.ends_with("..."));
    }

    #[test]
    fn signature_count_is_reported_for_coverage() {
        assert_eq!(Detector::new(10).signature_count(), SIGNATURES.len());
        assert!(SIGNATURES.len() >= 20);
    }
}
