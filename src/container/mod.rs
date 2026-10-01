//! Recursive container traversal.
//!
//! The walk hands each leaf member's bytes to a visitor and drops them again, so
//! peak memory tracks the largest single member rather than the whole expanded
//! tree. Nothing is written to disk unless `--extract` asks for it, which keeps a
//! scan safe to run on a host with little free space and keeps extraction off the
//! attack surface of an ordinary run. See `container::extract` for why the one path
//! that does write uses flattened, hashed names rather than the member's own.

pub mod archives;
pub mod carve;
pub mod compressed;
pub mod detect;
pub mod extract;
pub mod limits;
pub mod zip;

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

pub use carve::{CarveReport, CarvedItem};
pub use detect::Format;
pub use limits::{Budget, Limits};

use crate::observe::{Event, Observer};

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
    /// Embedded signatures found by carving, when the `carve` feature is enabled.
    pub carved: Vec<(String, CarveReport)>,
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
    walk_bytes(&data, root_name, limits, &crate::observe::Null, visit)
}

/// Walk bytes already in hand, so the caller can hash the root without a second read.
pub fn walk_bytes<F>(
    data: &[u8],
    root_name: String,
    limits: Limits,
    observer: &dyn Observer,
    visit: &mut F,
) -> Result<WalkOutcome>
where
    F: FnMut(&Member) -> Result<()>,
{
    let root_size = data.len() as u64;
    let root_format = detect::detect(data);

    let carve_enabled = limits.carve;
    let mut budget = Budget::new(limits, root_size);
    let mut leaves = Vec::new();
    let mut members_scanned = 0usize;
    let mut carved = Vec::new();

    let mut ctx = Ctx {
        leaves: &mut leaves,
        members_scanned: &mut members_scanned,
        carved: &mut carved,
        carve_enabled,
        observer,
    };
    descend(data, vec![root_name], 0, &mut budget, &mut ctx, visit)?;

    Ok(WalkOutcome {
        root_format,
        root_size,
        members_scanned,
        total_unpacked: budget.total_unpacked(),
        warnings: budget.warnings().to_vec(),
        leaves,
        carved,
    })
}

/// Mutable state threaded through the recursion, so `descend` keeps a short signature.
struct Ctx<'a> {
    leaves: &'a mut Vec<(String, Format, u64)>,
    members_scanned: &'a mut usize,
    carved: &'a mut Vec<(String, CarveReport)>,
    carve_enabled: bool,
    observer: &'a dyn Observer,
}

fn descend<F>(
    data: &[u8],
    chain: Vec<String>,
    depth: usize,
    budget: &mut Budget,
    ctx: &mut Ctx,
    visit: &mut F,
) -> Result<()>
where
    F: FnMut(&Member) -> Result<()>,
{
    let format = detect::detect(data);
    let at = chain.join(" :: ");

    if format.is_walkable_archive() {
        if budget.check_depth(depth + 1, &at).is_some() {
            ctx.observer.on(&Event::Skipped {
                chain: &at,
                reason: "nesting depth cap reached, scanned as a leaf instead",
            });
            return visit_leaf(data, chain, format, budget, ctx, visit);
        }
        let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
        let collect = &mut |name: &str, bytes: Vec<u8>| {
            entries.push((name.to_string(), bytes));
            Ok(())
        };
        let result = match format {
            Format::Zip => zip::for_each_entry(data, budget, &at, collect),
            Format::SevenZip => archives::for_each_7z_entry(data, budget, &at, collect),
            Format::Cab => archives::for_each_cab_entry(data, budget, &at, collect),
            _ => unreachable!("is_walkable_archive covers exactly these formats"),
        };
        match result {
            Ok(()) => {
                let opened_any = !entries.is_empty();
                ctx.observer.on(&Event::Container {
                    chain: &at,
                    format,
                    size: data.len() as u64,
                    depth,
                    members: entries.len(),
                });
                for (name, bytes) in entries {
                    let mut child = chain.clone();
                    child.push(name);
                    descend(&bytes, child, depth + 1, budget, ctx, visit)?;
                }
                if opened_any {
                    return Ok(());
                }
            }
            Err(e) => {
                // A corrupt or password-protected archive still gets scanned raw, so a
                // parse failure degrades coverage instead of losing the member.
                budget.warn(format!("{}: {:#}; scanning raw bytes instead", at, e));
                ctx.observer.on(&Event::Skipped {
                    chain: &at,
                    reason: "archive could not be opened, scanning raw bytes",
                });
            }
        }
        return visit_leaf(data, chain, format, budget, ctx, visit);
    }

    if format.is_single_stream() {
        if budget.check_depth(depth + 1, &at).is_some() {
            ctx.observer.on(&Event::Skipped {
                chain: &at,
                reason: "nesting depth cap reached, scanned compressed",
            });
            return visit_leaf(data, chain, format, budget, ctx, visit);
        }
        let limit = budget.limits().max_member_bytes;
        match compressed::decompress(data, format, limit, &at, budget) {
            Ok(payload) if !payload.is_empty() => {
                budget.commit(payload.len() as u64);
                ctx.observer.on(&Event::Container {
                    chain: &at,
                    format,
                    size: payload.len() as u64,
                    depth,
                    members: 1,
                });
                let last = chain.last().cloned().unwrap_or_default();
                let mut child = chain.clone();
                child.push(compressed::inner_name(&last, format));
                return descend(&payload, child, depth + 1, budget, ctx, visit);
            }
            Ok(_) => {
                budget.warn(format!("{}: {} stream was empty", at, format.as_str()));
            }
            Err(e) => {
                budget.warn(format!("{}: {:#}; scanning raw bytes instead", at, e));
                ctx.observer.on(&Event::Skipped {
                    chain: &at,
                    reason: "stream could not be decompressed, scanning raw bytes",
                });
            }
        }
        return visit_leaf(data, chain, format, budget, ctx, visit);
    }

    if format.is_unsupported_archive() {
        budget.warn(format!(
            "{}: {} container is recognised but not unpacked, so its contents were not scanned",
            at,
            format.as_str()
        ));
    }

    visit_leaf(data, chain, format, budget, ctx, visit)
}

fn visit_leaf<F>(
    data: &[u8],
    chain: Vec<String>,
    format: Format,
    budget: &mut Budget,
    ctx: &mut Ctx,
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
    let name = member.chain_display();
    carve_leaf(member.data, &name, budget, ctx);
    ctx.leaves
        .push((name.clone(), format, member.data.len() as u64));
    *ctx.members_scanned += 1;
    visit(&member)
}

/// Carve every leaf for embedded signatures. Run as a separate pass so carving cannot
/// change what the ordinary walk reports.
fn carve_leaf(data: &[u8], at: &str, budget: &mut Budget, ctx: &mut Ctx) {
    if !ctx.carve_enabled {
        return;
    }
    let report = carve::scan(data, at, budget, 100);
    if !report.is_empty() {
        ctx.carved.push((at.to_string(), report));
    }
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
