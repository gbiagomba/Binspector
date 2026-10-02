//! Compiland provenance: which source trees were linked into each image.
//!
//! The section exists for one condition. When two trees contribute objects for the same component,
//! two copies of that component were linked and the linker chose per symbol, so the shipped
//! behaviour is neither version and no version field can describe it. Everything else here is
//! context for reading that.

use anyhow::Result;
use std::io::Write;

use super::fmt_util::{short_name, truncate};
use super::thousands;
use crate::model::Report;

/// Trees listed per image before the list is cut.
const ROOT_CAP: usize = 6;
/// Images listed before the list is cut.
const IMAGE_CAP: usize = 10;

pub fn write_text(w: &mut dyn Write, r: &Report) -> Result<()> {
    let found: Vec<(&str, &crate::pdb::Provenance)> = r
        .coverage
        .entries
        .iter()
        .filter_map(|e| e.pdb.as_ref().map(|p| (e.member.as_str(), p)))
        .collect();
    if found.is_empty() {
        return Ok(());
    }
    let parsed = found.iter().filter(|(_, p)| p.skipped.is_none()).count();
    let compilands: usize = found.iter().map(|(_, p)| p.compilands).sum();
    writeln!(
        w,
        "Build provenance from debug symbols ({} PDB(s), {} parsed, {} translation unit(s))",
        thousands(found.len() as u64),
        thousands(parsed as u64),
        thousands(compilands as u64)
    )?;

    // The finding first, because it is the only thing here that is one.
    let mixed: Vec<(&str, &crate::pdb::MixedSource)> = found
        .iter()
        .flat_map(|(m, p)| p.mixed.iter().map(move |x| (*m, x)))
        .collect();
    if !mixed.is_empty() {
        for (member, m) in &mixed {
            writeln!(
                w,
                "  !! {}: {} objects came from {} different source trees",
                short_name(member),
                m.component,
                m.roots.len()
            )?;
            for root in &m.roots {
                writeln!(w, "       {:>5} object(s)  {}", root.objects, root.root)?;
            }
        }
        writeln!(
            w,
            "  Two trees for one component means two copies were linked and the linker resolved \
             each symbol from whichever it saw first, so the shipped code is neither version and a \
             version number cannot describe it. This is the signature of a static-library update \
             that did not fully apply: check which copy supplies the security-relevant symbols."
        )?;
        writeln!(
            w,
            "  fix: link one copy. Build the dependency once and reference that artifact \
             everywhere, rather than letting two vendored trees reach the same link line."
        )?;
    }

    for (member, p) in found.iter().take(IMAGE_CAP) {
        if let Some(reason) = p.skipped.as_deref() {
            writeln!(w, "  {}: {}", short_name(member), reason)?;
            continue;
        }
        let named: Vec<String> = p
            .roots
            .iter()
            .take(ROOT_CAP)
            .map(|root| match root.component.as_deref() {
                Some(c) => format!("{} ({}, {} obj)", truncate(&root.root, 72), c, root.objects),
                None => format!("{} ({} obj)", truncate(&root.root, 72), root.objects),
            })
            .collect();
        writeln!(
            w,
            "  {}: {} tree(s), {} translation unit(s)",
            short_name(member),
            thousands(p.roots.len() as u64),
            thousands(p.compilands as u64)
        )?;
        for n in &named {
            writeln!(w, "      {}", n)?;
        }
        if p.roots.len() > ROOT_CAP {
            writeln!(w, "      ... and {} more tree(s)", p.roots.len() - ROOT_CAP)?;
        }
    }
    if found.len() > IMAGE_CAP {
        writeln!(
            w,
            "  ... and {} more PDB(s)",
            thousands((found.len() - IMAGE_CAP) as u64)
        )?;
    }
    writeln!(
        w,
        "  Compiland records are complete where string extraction is capped and heuristic, so this \
         supersedes the indicator-derived build paths wherever a PDB is present."
    )?;
    writeln!(w)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(r: &Report) -> String {
        let mut buf = Vec::new();
        write_text(&mut buf, r).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn silent_when_no_pdb_was_scanned() {
        let r = crate::report::tests_support::rich_report();
        assert!(render(&r).is_empty());
    }

    #[test]
    fn the_mixed_source_condition_leads_and_says_what_it_means() {
        let mut r = crate::report::tests_support::rich_report();
        let mut e = crate::report::tests_support::pe_entry("bundle :: EditorManagerBridge.pdb");
        e.pe = None;
        e.format = "pdb".into();
        e.pdb = Some(crate::pdb::Provenance {
            image_stem: "EditorManagerBridge".into(),
            compilands: 1717,
            roots: vec![
                crate::pdb::SourceRoot {
                    root: "d:/b/xmp/toolkit/public/libraries/windows_x64".into(),
                    objects: 8,
                    component: Some("zlib".into()),
                },
                crate::pdb::SourceRoot {
                    root: "d:/b/camera_raw/opencv/3rdparty".into(),
                    objects: 4,
                    component: Some("zlib".into()),
                },
            ],
            mixed: vec![crate::pdb::MixedSource {
                component: "zlib".into(),
                roots: vec![
                    crate::pdb::SourceRoot {
                        root: "d:/b/xmp/toolkit/public/libraries/windows_x64".into(),
                        objects: 8,
                        component: Some("zlib".into()),
                    },
                    crate::pdb::SourceRoot {
                        root: "d:/b/camera_raw/opencv/3rdparty".into(),
                        objects: 4,
                        component: Some("zlib".into()),
                    },
                ],
            }],
            skipped: None,
        });
        r.coverage.entries.push(e);
        let out = render(&r);
        assert!(out.contains("different source trees"), "{}", out);
        assert!(out.contains("zlib"), "{}", out);
        // The counts a reviewer checks against the binary.
        assert!(out.contains("8 object(s)"), "{}", out);
        assert!(out.contains("4 object(s)"), "{}", out);
        // And the interpretation, because "two trees" alone is not actionable.
        assert!(out.contains("neither version"), "{}", out);
        assert!(out.contains("did not fully apply"), "{}", out);
    }

    #[test]
    fn a_skipped_pdb_states_its_reason_instead_of_looking_clean() {
        let mut r = crate::report::tests_support::rich_report();
        let mut e = crate::report::tests_support::pe_entry("bundle :: broken.pdb");
        e.pe = None;
        e.pdb = Some(crate::pdb::Provenance::skipped(
            "broken".into(),
            "could not be read: UnexpectedEof".into(),
        ));
        r.coverage.entries.push(e);
        let out = render(&r);
        assert!(out.contains("could not be read"), "{}", out);
    }
}
