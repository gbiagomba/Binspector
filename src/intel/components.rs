//! Component and version detection from embedded strings.
//!
//! This is the input to CVE lookup. Scope is stated plainly: cve-bin-tool ships
//! roughly 380 hand-written checkers, and this is a curated set covering libraries
//! that actually turn up in the binaries under review. Coverage is reported so a
//! silent miss is never mistaken for a clean result.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
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
    /// A member filename this component must ship under for the detection to be real, with `{}`
    /// standing in for the captured version.
    ///
    /// `None` for the banner signatures, where the evidence is a copyright string the library
    /// itself compiled in and the string's presence is the fact. Filename evidence is weaker:
    /// `icudt(\d+)` matched `icudt36` in some module's leftover string table and reported ICU 36
    /// as a shipped component, when the only ICU payloads in the package were `icudt74.dll` and
    /// `icuuc74.dll`. A filename that names no member of the archive is not a component.
    confirm_file: Option<&'static str>,
}

/// Curated signature set. Patterns are anchored on the banner text these libraries
/// embed, which is far more reliable than a bare version number.
const SIGNATURES: &[Signature] = &[
    Signature {
        name: "openssl",
        pattern: r"OpenSSL (\d+\.\d+(?:\.\d+)?[a-z]?)",
        confirm_file: None,
    },
    Signature {
        name: "zlib",
        pattern: r"(?:^|\s)(?:deflate|inflate) (\d+\.\d+(?:\.\d+)?) Copyright",
        confirm_file: None,
    },
    Signature {
        name: "libpng",
        pattern: r"libpng version (\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
    Signature {
        name: "libjpeg-turbo",
        pattern: r"libjpeg-turbo version (\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
    Signature {
        name: "libcurl",
        pattern: r"libcurl/(\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
    Signature {
        name: "sqlite",
        pattern: r"SQLite version (\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
    Signature {
        name: "expat",
        pattern: r"expat_(\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
    Signature {
        name: "libxml2",
        pattern: r"libxml2-(\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
    Signature {
        name: "freetype",
        pattern: r"FreeType (\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
    Signature {
        name: "icu",
        pattern: r"icudt(\d+)",
        confirm_file: Some("icudt{}"),
    },
    Signature {
        name: "bzip2",
        pattern: r"bzip2-(\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
    Signature {
        name: "libtiff",
        pattern: r"LIBTIFF, Version (\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
    Signature {
        name: "openjpeg",
        pattern: r"openjpeg (\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
    Signature {
        name: "libwebp",
        pattern: r"libwebp (\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
    Signature {
        name: "zstd",
        pattern: r"Zstandard v?(\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
    Signature {
        name: "lz4",
        pattern: r"LZ4 v?(\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
    Signature {
        name: "onnxruntime",
        pattern: r"onnxruntime[- ]v?(\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
    Signature {
        name: "dotnet",
        // The framework moniker and the runtime package name, not prose mentioning a version.
        //
        // `\.NET (?:Core )?(\d+\.\d+)` matched the error string "Getting the contract for the
        // initialized hostpolicy is only supported for .NET Core 3.0 or a higher version." and
        // reported .NET 3.0 as a shipped component of a package that ships .NET 8. That is the
        // same defect as reporting ICU 36 from a filename no member carries: a sentence that
        // names a version is not evidence that the version is present.
        //
        // Both forms here are structured identifiers a build emits, so neither can appear in a
        // sentence: `.NETCoreApp,Version=v8.0` comes from TargetFrameworkAttribute and
        // `Microsoft.NETCore.App/8.0.11` from the runtime package reference.
        pattern: r"(?:\.NETCoreApp,Version=v|Microsoft\.NETCore\.App[/ ])(\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
    Signature {
        name: "boost",
        pattern: r"Boost (\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
    Signature {
        name: "protobuf",
        pattern: r"protobuf[- ](\d+\.\d+(?:\.\d+)?)",
        confirm_file: None,
    },
];

/// Libraries recognisable from a build-path directory name rather than from a banner string.
///
/// A statically linked library often embeds no banner at all, so the signature table above cannot
/// see it. What survives is the path the object files were compiled from, and a directory called
/// `opencv-4.3.0` names the library and its version exactly.
///
/// This is why it matters rather than being a nicety. An adversarial review of a real bundle found a
/// vendored OpenCV 4.3.0 that appeared in no manifest and in no component list, and the only trace
/// of it anywhere was a leaked build path. A dependency nothing is tracking receives no CVE
/// analysis, which is the finding.
///
/// A fixed vocabulary rather than "any `name-version` directory", because a path is full of things
/// shaped like one that are not libraries: `netstandard2.0`, `net6.0-windows`, `v14.42-x64`. Every
/// entry here is a library whose source tree is conventionally named this way.
const PATH_LIBRARIES: &[&str] = &[
    "opencv",
    "boost",
    "ffmpeg",
    "openssl",
    "zlib",
    "libpng",
    "libjpeg-turbo",
    "libjpeg",
    "freetype",
    "harfbuzz",
    "icu",
    "libxml2",
    "libwebp",
    "libtiff",
    "openjpeg",
    "protobuf",
    "sqlite",
    "lz4",
    "zstd",
    "bzip2",
    "expat",
    "curl",
    "libcurl",
    "onnxruntime",
    "eigen",
    "glew",
    "glfw",
    "sdl",
    "libsodium",
    "mbedtls",
    "wolfssl",
    "nghttp2",
    "pcre",
    "pcre2",
    "jsoncpp",
    "yaml-cpp",
    "libuv",
    "libevent",
    "openexr",
    "tbb",
    "flatbuffers",
    "snappy",
    "brotli",
];

pub struct Detector {
    compiled: Vec<(&'static str, Regex, Option<&'static str>)>,
    /// `<library>-<version>` as a path segment, the shape a vendored source tree is unpacked into.
    path_version: Regex,
    found: BTreeMap<(String, String), String>,
    /// Detections whose evidence is a filename, and the filename each one requires.
    ///
    /// Resolved in `finish`, because the member list is only complete once the scan is.
    needs_file: BTreeMap<(String, String), String>,
    cap: usize,
}

impl Detector {
    pub fn new(cap: usize) -> Self {
        let compiled = SIGNATURES
            .iter()
            .filter_map(|s| {
                Regex::new(s.pattern)
                    .ok()
                    .map(|r| (s.name, r, s.confirm_file))
            })
            .collect();
        Self {
            compiled,
            // A segment boundary on both sides, so `myopencv-1.0` and a version glued to a longer
            // token are not mistaken for the library itself.
            path_version: Regex::new(
                r"(?i)[\\/]([A-Za-z][A-Za-z0-9_+]*(?:-[A-Za-z]+)?)-(\d+\.\d+(?:\.\d+)?)(?:[\\/]|$)",
            )
            .expect("static regex"),
            found: BTreeMap::new(),
            needs_file: BTreeMap::new(),
            cap,
        }
    }

    /// Detect a component from a filesystem path, which is how a statically linked library with no
    /// banner string becomes visible.
    ///
    /// Separate from `feed` because the input is different in kind: `feed` reads every extracted
    /// string and must stay cheap, while this runs over the indicator lists once at the end.
    pub fn feed_path(&mut self, path: &str) {
        if self.found.len() >= self.cap {
            return;
        }
        for c in self.path_version.captures_iter(path) {
            let (Some(name), Some(version)) = (c.get(1), c.get(2)) else {
                continue;
            };
            let lower = name.as_str().to_ascii_lowercase();
            if !PATH_LIBRARIES.contains(&lower.as_str()) {
                continue;
            }
            self.found
                .entry((lower, version.as_str().to_string()))
                .or_insert_with(|| truncate(path, 160));
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
        for (name, re, confirm) in &self.compiled {
            if let Some(c) = re.captures(text) {
                if let Some(v) = c.get(1) {
                    let key = (name.to_string(), v.as_str().to_string());
                    if let Some(template) = confirm {
                        self.needs_file
                            .insert(key.clone(), template.replace("{}", v.as_str()));
                    }
                    self.found.entry(key).or_insert_with(|| truncate(text, 160));
                }
            }
        }
    }

    /// Resolve the detections, dropping any whose only evidence is a filename no member carries.
    ///
    /// `members` is every scanned member's leaf name, lowercased. A detection that names a file
    /// the archive does not contain is a leftover string in somebody else's string table, not a
    /// shipped component, and reporting it puts a version in an inventory that was never there.
    pub fn finish(self, members: &std::collections::BTreeSet<String>) -> Vec<Component> {
        self.found
            .into_iter()
            .filter(|(key, _)| match self.needs_file.get(key) {
                None => true,
                Some(stem) => members.iter().any(|m| m.starts_with(stem.as_str())),
            })
            .map(|((name, version), evidence)| Component {
                name,
                version,
                evidence,
            })
            .collect()
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn a_vendored_source_tree_names_its_library_and_version() {
        let mut d = Detector::new(50);
        d.feed_path(r"C:\Users\Eric\Desktop\ocv43\opencv-4.3.0\modules\core\src\system.cpp");
        let got = d.finish(&Default::default());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "opencv");
        assert_eq!(got[0].version, "4.3.0");
        assert!(
            got[0].evidence.contains("opencv-4.3.0"),
            "evidence cites the path"
        );
    }

    #[test]
    fn unix_separators_work_too() {
        let mut d = Detector::new(50);
        d.feed_path("/home/bob/src/boost-1.84.0/libs/thread/src/x.cpp");
        let got = d.finish(&Default::default());
        assert_eq!(got[0].name, "boost");
        assert_eq!(got[0].version, "1.84.0");
    }

    /// The reason this uses a vocabulary rather than any `name-version` directory: a build path is
    /// full of things shaped like one that are not libraries.
    #[test]
    fn framework_monikers_and_build_dirs_are_not_components() {
        let mut d = Detector::new(50);
        for p in [
            r"C:\proj\obj\Release\netstandard2.0\thing.pdb",
            r"C:\proj\bin\net6.0-windows\app.dll",
            "/build/toolchain-14.42/bin/cc",
            "/src/myproject-1.0.0/main.c",
        ] {
            d.feed_path(p);
        }
        assert!(
            d.finish(&Default::default()).is_empty(),
            "no library should be inferred"
        );
    }

    /// A segment boundary on both sides, so a longer token that merely ends in a library name is
    /// not credited to that library.
    #[test]
    fn a_similar_name_is_not_the_library() {
        let mut d = Detector::new(50);
        d.feed_path("/src/myopencv-1.0.0/x.c");
        assert!(d.finish(&Default::default()).is_empty());
    }

    #[test]
    fn two_versions_of_one_library_are_both_reported() {
        let mut d = Detector::new(50);
        d.feed_path(r"C:\Users\a\opencv-4.3.0\x.cpp");
        d.feed_path(r"C:\Users\b\opencv-4.10.0\y.cpp");
        let got = d.finish(&Default::default());
        assert_eq!(got.len(), 2, "{:?}", got);
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
        detect_in_package(texts, &["icudt74.dll"])
    }

    /// Detect with an explicit member list, which the filename-evidence signatures check
    /// against. The default above ships the real ICU payload so banner detections are
    /// unaffected and the ICU signature has something to confirm.
    fn detect_in_package(texts: &[&str], members: &[&str]) -> Vec<Component> {
        let mut d = Detector::new(100);
        for t in texts {
            d.feed(t);
        }
        let set: std::collections::BTreeSet<String> =
            members.iter().map(|m| m.to_string()).collect();
        d.finish(&set)
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
        assert_eq!(d.finish(&Default::default()).len(), 1);
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

    #[test]
    fn a_two_component_version_is_detected() {
        // zlib 1.3 exists and shipped in a real package. Requiring three dotted components
        // missed it entirely, so a reviewer using this field as the zlib inventory was short a
        // whole version while four others were listed.
        let got = detect(&["deflate 1.3 Copyright 1995-2023 Jean-loup Gailly and Mark Adler"]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "zlib");
        assert_eq!(got[0].version, "1.3");
    }

    #[test]
    fn a_three_component_version_still_wins_over_the_shorter_match() {
        let got = detect(&["deflate 1.2.11 Copyright 1995-2017 Jean-loup Gailly"]);
        assert_eq!(got[0].version, "1.2.11");
    }

    #[test]
    fn filename_evidence_is_dropped_when_the_file_is_not_in_the_package() {
        // `icudt36` was a leftover string in some module's string table. The only ICU payloads
        // in the real package were icudt74.dll and icuuc74.dll, so ICU 36 was an invented
        // inventory entry that a consumer would have had to disprove by hand.
        let got = detect_in_package(&["icudt36"], &["icudt74.dll", "icuuc74.dll"]);
        assert!(
            got.is_empty(),
            "a filename naming no member is not a component: {:?}",
            got
        );
    }

    #[test]
    fn filename_evidence_is_kept_when_the_file_really_ships() {
        let got = detect_in_package(&["icudt74"], &["icudt74.dll", "icuuc74.dll"]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "icu");
        assert_eq!(got[0].version, "74");
    }

    #[test]
    fn banner_evidence_needs_no_file_confirmation() {
        // The banner is a string the library compiled into itself, so its presence is the fact.
        // Requiring a matching filename would drop every statically linked component, which is
        // the case this detector exists for.
        let got = detect_in_package(
            &["deflate 1.2.13 Copyright 1995-2022 Jean-loup Gailly"],
            &[],
        );
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].version, "1.2.13");
    }

    #[test]
    fn prose_naming_a_dotnet_version_is_not_a_shipped_component() {
        // The exact string from a real scan. The loose pattern reported .NET 3.0 as a component
        // of a package that ships .NET 8, which is the `icu 36` defect in a new place: a
        // sentence that names a version is not evidence the version is present.
        let got = detect(&[
            "Getting the contract for the initialized hostpolicy is only supported for \
             .NET Core 3.0 or a higher version.",
            ".NET 6.0",
        ]);
        assert!(
            got.is_empty(),
            "prose and a bare version string are not component evidence: {:?}",
            got
        );
    }

    #[test]
    fn the_framework_moniker_and_runtime_package_are_component_evidence() {
        // Structured identifiers a build emits, which cannot occur inside a sentence.
        let got = detect(&[
            "[assembly: global::System.Runtime.Versioning.TargetFrameworkAttribute(\
             \".NETCoreApp,Version=v8.0\", FrameworkDisplayName=\"\")]",
        ]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "dotnet");
        assert_eq!(got[0].version, "8.0");

        let got = detect(&["Microsoft.NETCore.App/8.0.11"]);
        assert_eq!(got[0].version, "8.0.11");
    }
}
