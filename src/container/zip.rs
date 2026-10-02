//! ZIP member enumeration.
//!
//! Covers the container family that made the original scan blind: `.msixbundle`,
//! `.msix`, `.appx`, `.jar`, `.nupkg`, and plain `.zip` are all this format.

use anyhow::{Context, Result};
use std::io::{Cursor, Read};

use super::limits::{is_safe_member_name, sanitize_member_name, Budget};

/// Call `f` once per readable file member, with its sanitized name and bytes.
///
/// Members that trip a budget cap or carry an unsafe name are skipped with a
/// warning rather than aborting, so one hostile entry cannot suppress the rest
/// of the report.
pub fn for_each_entry<F>(data: &[u8], budget: &mut Budget, at: &str, f: &mut F) -> Result<()>
where
    F: FnMut(&str, Vec<u8>) -> Result<()>,
{
    let mut archive = zip::ZipArchive::new(Cursor::new(data))
        .with_context(|| format!("opening zip container {}", at))?;

    for i in 0..archive.len() {
        let entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(e) => {
                budget.warn(format!(
                    "{}: skipping unreadable zip entry {}: {}",
                    at, i, e
                ));
                continue;
            }
        };

        if entry.is_dir() {
            continue;
        }

        // enclosed_name rejects traversal itself; the explicit check keeps hostile
        // names out of report output and covers the raw-name fallback.
        let name = match entry.enclosed_name() {
            Some(p) => p.to_string_lossy().to_string(),
            None => {
                budget.warn(format!(
                    "{}: skipping zip entry with unsafe name: {}",
                    at,
                    entry.name()
                ));
                continue;
            }
        };
        if !is_safe_member_name(&name) {
            budget.warn(format!(
                "{}: skipping zip entry with unsafe name: {}",
                at, name
            ));
            continue;
        }
        // The name is reported, rendered to a terminal and written into SQL, so control characters
        // in it are neutralised here rather than at each of those. Sanitised rather than skipped:
        // refusing the entry would let an attacker hide a member from analysis by naming it badly.
        let name = sanitize_member_name(&name);

        let declared = entry.size();
        let member_at = format!("{} :: {}", at, name);
        if budget.check_member(declared, &member_at).is_some() {
            continue;
        }

        // Read at most the declared size plus one byte. The extra byte detects a
        // member whose real content exceeds its declared size, which is how a
        // bomb tries to slip past a size check.
        let cap = declared.saturating_add(1);
        let mut buf = Vec::with_capacity(declared.min(8 * 1024 * 1024) as usize);
        match entry.take(cap).read_to_end(&mut buf) {
            Ok(_) => {}
            Err(e) => {
                budget.warn(format!("{}: failed to read zip entry: {}", member_at, e));
                continue;
            }
        }
        if buf.len() as u64 > declared {
            budget.warn(format!(
                "{}: entry content exceeds its declared size, truncated",
                member_at
            ));
            buf.truncate(declared as usize);
        }

        budget.commit(buf.len() as u64);
        f(&name, buf)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::limits::Limits;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
            for (name, data) in entries {
                w.start_file(*name, SimpleFileOptions::default()).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        buf
    }

    #[test]
    fn enumerates_members() {
        let z = build_zip(&[("a.txt", b"hello"), ("dir/b.txt", b"world")]);
        let mut budget = Budget::new(Limits::default(), z.len() as u64);
        let mut seen = Vec::new();
        for_each_entry(&z, &mut budget, "root", &mut |name, data| {
            seen.push((name.to_string(), data));
            Ok(())
        })
        .unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, "a.txt");
        assert_eq!(seen[0].1, b"hello");
        assert_eq!(budget.members_seen(), 2);
    }

    #[test]
    fn skips_members_over_the_cap() {
        let z = build_zip(&[("big.bin", &[0u8; 5000]), ("small.bin", b"ok")]);
        let limits = Limits {
            max_member_bytes: 100,
            ..Default::default()
        };
        let mut budget = Budget::new(limits, z.len() as u64);
        let mut seen = Vec::new();
        for_each_entry(&z, &mut budget, "root", &mut |name, _| {
            seen.push(name.to_string());
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, vec!["small.bin"]);
        assert!(!budget.warnings().is_empty());
    }

    #[test]
    fn rejects_non_zip_input() {
        let mut budget = Budget::new(Limits::default(), 4);
        let r = for_each_entry(b"not a zip at all", &mut budget, "root", &mut |_, _| Ok(()));
        assert!(r.is_err());
    }
}
