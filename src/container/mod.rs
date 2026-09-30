//! Recursive container traversal.
//!
//! The walk hands each leaf member's bytes to a visitor and drops them again, so
//! peak memory tracks the largest single member rather than the whole expanded
//! tree. Nothing is written to disk, which keeps a scan safe to run on a host with
//! little free space and removes extraction as an attack surface entirely.

pub mod detect;
pub mod limits;
pub mod zip;

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

pub use detect::Format;
pub use limits::{Budget, Limits};

/// One scannable leaf: bytes that are not themselves a container we descend into.
pub struct Member<'a> {
    /// Provenance from the root inwards, for example
    /// `["SampleApp.msixbundle", "app.msix", "App.exe"]`.
    pub chain: Vec<String>,
    pub data: &'a [u8],
    pub format: Format,
}

impl Member<'_> {
    /// Human-readable provenance, as it appears in reports.
    pub fn chain_display(&self) -> String {
        self.chain.join(" :: ")
    }
}

#[derive(Debug)]
pub struct WalkOutcome {
    pub root_format: Format,
    pub root_size: u64,
    pub members_scanned: usize,
    pub total_unpacked: u64,
    pub warnings: Vec<String>,
    /// Every leaf visited, with its detected format, for the coverage section.
    pub leaves: Vec<(String, Format, u64)>,
}

/// Walk `root`, invoking `visit` for every scannable leaf.
pub fn walk<F>(root: &Path, limits: Limits, visit: &mut F) -> Result<WalkOutcome>
where
    F: FnMut(&Member) -> Result<()>,
{
    if !root.exists() {
        bail!("Binary not found: {}", root.display());
    }
    let data = fs::read(root).with_context(|| format!("reading {}", root.display()))?;
    let root_name = root
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| root.display().to_string());
    walk_bytes(&data, root_name, limits, visit)
}

/// Walk bytes already in hand, so the caller can hash the root without a second read.
pub fn walk_bytes<F>(
    data: &[u8],
    root_name: String,
    limits: Limits,
    visit: &mut F,
) -> Result<WalkOutcome>
where
    F: FnMut(&Member) -> Result<()>,
{
    let root_size = data.len() as u64;
    let root_format = detect::detect(data);

    let mut budget = Budget::new(limits, root_size);
    let mut leaves = Vec::new();
    let mut members_scanned = 0usize;

    descend(
        data,
        vec![root_name],
        0,
        &mut budget,
        &mut leaves,
        &mut members_scanned,
        visit,
    )?;

    Ok(WalkOutcome {
        root_format,
        root_size,
        members_scanned,
        total_unpacked: budget.total_unpacked(),
        warnings: budget.warnings().to_vec(),
        leaves,
    })
}

#[allow(clippy::too_many_arguments)]
fn descend<F>(
    data: &[u8],
    chain: Vec<String>,
    depth: usize,
    budget: &mut Budget,
    leaves: &mut Vec<(String, Format, u64)>,
    members_scanned: &mut usize,
    visit: &mut F,
) -> Result<()>
where
    F: FnMut(&Member) -> Result<()>,
{
    let format = detect::detect(data);
    let at = chain.join(" :: ");

    if format.is_walkable_archive() {
        if budget.check_depth(depth + 1, &at).is_some() {
            // Too deep to open, so treat the archive itself as a leaf and say so.
            return visit_leaf(data, chain, format, leaves, members_scanned, visit);
        }
        let mut opened_any = false;
        let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
        let result = zip::for_each_entry(data, budget, &at, &mut |name, bytes| {
            entries.push((name.to_string(), bytes));
            Ok(())
        });
        match result {
            Ok(()) => {
                for (name, bytes) in entries {
                    opened_any = true;
                    let mut child = chain.clone();
                    child.push(name);
                    descend(
                        &bytes,
                        child,
                        depth + 1,
                        budget,
                        leaves,
                        members_scanned,
                        visit,
                    )?;
                }
            }
            Err(e) => {
                // A corrupt or unsupported archive still gets scanned raw, so a
                // parse failure degrades coverage instead of losing the member.
                budget.warn(format!("{}: {:#}; scanning raw bytes instead", at, e));
            }
        }
        if opened_any {
            return Ok(());
        }
        return visit_leaf(data, chain, format, leaves, members_scanned, visit);
    }

    if format.is_unsupported_archive() {
        budget.warn(format!(
            "{}: {} container is recognised but not unpacked yet, so its contents were not scanned",
            at,
            format.as_str()
        ));
    }

    visit_leaf(data, chain, format, leaves, members_scanned, visit)
}

fn visit_leaf<F>(
    data: &[u8],
    chain: Vec<String>,
    format: Format,
    leaves: &mut Vec<(String, Format, u64)>,
    members_scanned: &mut usize,
    visit: &mut F,
) -> Result<()>
where
    F: FnMut(&Member) -> Result<()>,
{
    let member = Member {
        chain,
        data,
        format,
    };
    leaves.push((member.chain_display(), format, member.data.len() as u64));
    *members_scanned += 1;
    visit(&member)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::zip::write::SimpleFileOptions;
    use std::io::{Cursor, Write};
    use tempfile::NamedTempFile;

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = ::zip::ZipWriter::new(Cursor::new(&mut buf));
            for (name, data) in entries {
                w.start_file(*name, SimpleFileOptions::default()).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        buf
    }

    fn temp_with(data: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn plain_file_is_one_leaf() {
        let f = temp_with(b"just some strings here");
        let mut seen = Vec::new();
        let out = walk(f.path(), Limits::default(), &mut |m| {
            seen.push(m.chain_display());
            Ok(())
        })
        .unwrap();
        assert_eq!(out.members_scanned, 1);
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn descends_into_zip_and_skips_container_bytes() {
        let inner = zip_bytes(&[("App.exe", b"strcpy lives here")]);
        let f = temp_with(&inner);
        let mut seen = Vec::new();
        let out = walk(f.path(), Limits::default(), &mut |m| {
            seen.push((m.chain_display(), m.data.to_vec()));
            Ok(())
        })
        .unwrap();
        assert_eq!(out.root_format, Format::Zip);
        // Only the member is scanned, never the compressed container bytes.
        assert_eq!(out.members_scanned, 1);
        assert!(seen[0].0.ends_with("App.exe"));
        assert_eq!(seen[0].1, b"strcpy lives here");
    }

    #[test]
    fn descends_into_nested_zip_like_a_msixbundle() {
        // Mirrors the real shape: bundle -> msix -> payload.
        let msix = zip_bytes(&[("App.exe", b"payload with gets")]);
        let bundle = zip_bytes(&[("app.msix", &msix)]);
        let f = temp_with(&bundle);
        let mut chains = Vec::new();
        let out = walk(f.path(), Limits::default(), &mut |m| {
            chains.push(m.chain_display());
            Ok(())
        })
        .unwrap();
        assert_eq!(out.members_scanned, 1);
        let chain = &chains[0];
        assert!(chain.contains("app.msix"), "chain was {}", chain);
        assert!(chain.contains("App.exe"), "chain was {}", chain);
    }

    #[test]
    fn depth_cap_stops_recursion_and_warns() {
        let l3 = zip_bytes(&[("deep.txt", b"deepest")]);
        let l2 = zip_bytes(&[("l3.zip", &l3)]);
        let l1 = zip_bytes(&[("l2.zip", &l2)]);
        let f = temp_with(&l1);
        let limits = Limits {
            max_depth: 1,
            ..Default::default()
        };
        let out = walk(f.path(), limits, &mut |_| Ok(())).unwrap();
        assert!(
            out.warnings.iter().any(|w| w.contains("depth")),
            "warnings: {:?}",
            out.warnings
        );
    }

    #[test]
    fn missing_file_errors() {
        let r = walk(
            Path::new("/nonexistent/xyz"),
            Limits::default(),
            &mut |_| Ok(()),
        );
        assert!(r.is_err());
    }

    #[test]
    fn corrupt_archive_falls_back_to_raw_scan() {
        // ZIP magic but truncated body.
        let f = temp_with(&[0x50, 0x4B, 0x03, 0x04, 0x00, 0x00]);
        let out = walk(f.path(), Limits::default(), &mut |_| Ok(())).unwrap();
        assert_eq!(out.members_scanned, 1);
        assert!(!out.warnings.is_empty());
    }
}
