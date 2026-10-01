//! Naming targets: the label that roots a provenance chain, and the slug for `--split` files.
//!
//! Both have to be assigned once the whole target set is known, because a collision cannot be
//! detected one target at a time. Both must be deterministic across runs, which the sorted
//! traversal in `walk` provides, and the tie-breakers here preserve.

use std::collections::BTreeMap;

use super::Target;

/// Longest a slug may be before it is truncated, so an output filename stays usable.
const SLUG_MAX: usize = 64;

/// Fill in `label` and `slug` for every target.
///
/// `label` becomes the root of each member chain, so it is what a reviewer reads in
/// `bundle :: app.msix :: App.exe`. It is the file name when that is unique, and the path
/// relative to the directory root when it is not, because `bin/a.exe` and `lib/a.exe`
/// disambiguate naturally and read better than `a.exe` and `a.exe-2`.
///
/// `slug` is used for `--split` output filenames, so it must be filesystem-safe and short.
pub fn assign(targets: &mut [Target]) {
    // Count file names first: a name used once needs no disambiguation.
    let mut name_counts: BTreeMap<String, usize> = BTreeMap::new();
    for t in targets.iter() {
        *name_counts.entry(file_name(t)).or_insert(0) += 1;
    }

    for t in targets.iter_mut() {
        let name = file_name(t);
        t.label = if name_counts.get(&name).copied().unwrap_or(0) > 1 {
            // Collision: the relative path distinguishes them and says where each came from.
            t.relative.clone()
        } else {
            name
        };
    }

    // A relative path can still collide when two directory roots contain the same layout, so
    // the labels are made unique as a set, in traversal order, which is deterministic.
    dedupe(targets, |t| t.label.clone(), |t, v| t.label = v);

    for t in targets.iter_mut() {
        t.slug = sanitize(&file_name(t));
    }
    dedupe(targets, |t| t.slug.clone(), |t, v| t.slug = sanitize(&v));
}

/// Make a derived field unique across the set by appending `-2`, `-3`, and so on.
///
/// Order-dependent by design: the first occurrence in traversal order keeps the bare value, so
/// a single-target scan and the first target of a directory scan agree.
fn dedupe<G, S>(targets: &mut [Target], get: G, set: S)
where
    G: Fn(&Target) -> String,
    S: Fn(&mut Target, String),
{
    let mut used: BTreeMap<String, usize> = BTreeMap::new();
    for t in targets.iter_mut() {
        let base = get(t);
        let n = used.entry(base.clone()).or_insert(0);
        *n += 1;
        if *n > 1 {
            set(t, format!("{}-{}", base, n));
        }
    }
}

fn file_name(t: &Target) -> String {
    t.path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| t.relative.clone())
}

/// Reduce a name to something safe in a filename on every platform.
///
/// Path separators become underscores rather than being stripped, so `arm64/foo.msix` reads as
/// `arm64_foo.msix` and still says where it came from.
fn sanitize(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.len() > SLUG_MAX {
        out.truncate(SLUG_MAX);
    }
    // A leading dot would make the output file hidden on Unix, and a trailing separator reads
    // as a mistake.
    let trimmed = out.trim_matches(|c| c == '.' || c == '_');
    if trimmed.is_empty() {
        "target".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::select::{Origin, Target};
    use std::path::PathBuf;

    fn target(path: &str, relative: &str) -> Target {
        Target {
            path: PathBuf::from(path),
            label: String::new(),
            slug: String::new(),
            relative: relative.to_string(),
            origin: Origin::Discovered,
            size: 1024,
            selected_by: "magic:pe".to_string(),
        }
    }

    #[test]
    fn a_unique_name_is_used_bare() {
        let mut t = vec![target("/s/app.exe", "app.exe")];
        assign(&mut t);
        assert_eq!(t[0].label, "app.exe");
        assert_eq!(t[0].slug, "app.exe");
    }

    #[test]
    fn colliding_names_fall_back_to_the_relative_path() {
        // The real case: Microsoft.WindowsAppRuntime.2.msix appears under four architecture
        // directories in one dependency tree.
        let mut t = vec![
            target("/d/arm64/Runtime.msix", "arm64/Runtime.msix"),
            target("/d/x64/Runtime.msix", "x64/Runtime.msix"),
            target("/d/x86/Runtime.msix", "x86/Runtime.msix"),
            target("/d/win32/Runtime.msix", "win32/Runtime.msix"),
        ];
        assign(&mut t);
        let labels: Vec<&str> = t.iter().map(|x| x.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "arm64/Runtime.msix",
                "x64/Runtime.msix",
                "x86/Runtime.msix",
                "win32/Runtime.msix"
            ],
            "the path says which one each finding came from"
        );
        // Slugs stay short and filesystem-safe, and are still distinct.
        let slugs: Vec<&str> = t.iter().map(|x| x.slug.as_str()).collect();
        assert_eq!(
            slugs,
            vec![
                "Runtime.msix",
                "Runtime.msix-2",
                "Runtime.msix-3",
                "Runtime.msix-4"
            ]
        );
        assert_eq!(
            slugs
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            4,
            "an output file per target needs a distinct name"
        );
    }

    #[test]
    fn a_mixed_set_only_disambiguates_what_collides() {
        let mut t = vec![
            target("/d/a/dup.exe", "a/dup.exe"),
            target("/d/b/dup.exe", "b/dup.exe"),
            target("/d/unique.exe", "unique.exe"),
        ];
        assign(&mut t);
        assert_eq!(t[0].label, "a/dup.exe");
        assert_eq!(t[1].label, "b/dup.exe");
        assert_eq!(
            t[2].label, "unique.exe",
            "untouched by someone else's collision"
        );
    }

    #[test]
    fn identical_relative_paths_still_resolve() {
        // Two directory roots with the same internal layout.
        let mut t = vec![
            target("/one/x64/app.exe", "x64/app.exe"),
            target("/two/x64/app.exe", "x64/app.exe"),
        ];
        assign(&mut t);
        assert_eq!(t[0].label, "x64/app.exe");
        assert_eq!(t[1].label, "x64/app.exe-2");
        assert_ne!(t[0].label, t[1].label, "labels must be unique as a set");
    }

    #[test]
    fn a_slug_is_filesystem_safe() {
        let mut t = vec![target(
            "/d/weird name:with*chars.exe",
            "weird name:with*chars.exe",
        )];
        assign(&mut t);
        assert_eq!(t[0].slug, "weird_name_with_chars.exe");
        assert!(!t[0].slug.contains('/'));
        assert!(!t[0].slug.contains(' '));
    }

    #[test]
    fn a_long_name_is_truncated_and_a_hidden_one_is_not_left_hidden() {
        let long = "a".repeat(200) + ".exe";
        let mut t = vec![target(&format!("/d/{}", long), &long)];
        assign(&mut t);
        assert!(t[0].slug.len() <= SLUG_MAX);

        let mut t = vec![target("/d/.hidden", ".hidden")];
        assign(&mut t);
        assert!(
            !t[0].slug.starts_with('.'),
            "an output file must not be hidden: {}",
            t[0].slug
        );
    }

    #[test]
    fn assignment_is_stable_for_the_same_input() {
        let build = || {
            vec![
                target("/d/arm64/r.msix", "arm64/r.msix"),
                target("/d/x64/r.msix", "x64/r.msix"),
            ]
        };
        let mut a = build();
        let mut b = build();
        assign(&mut a);
        assign(&mut b);
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.label, y.label);
            assert_eq!(x.slug, y.slug);
        }
    }
}
