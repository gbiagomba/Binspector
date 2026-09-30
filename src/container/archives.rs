//! Multi-member archive formats beyond ZIP: 7z and cab.
//!
//! Both were previously detected and reported as a coverage gap. They share ZIP's
//! contract here: each readable member is handed to a callback, unsafe names and
//! oversized members are skipped with a warning rather than aborting, and nothing is
//! written to disk.

use anyhow::{Context, Result};
use std::io::{Cursor, Read};

use super::limits::{is_safe_member_name, Budget};

/// Enumerate 7z members.
pub fn for_each_7z_entry<F>(data: &[u8], budget: &mut Budget, at: &str, f: &mut F) -> Result<()>
where
    F: FnMut(&str, Vec<u8>) -> Result<()>,
{
    let mut archive =
        sevenz_rust2::ArchiveReader::new(Cursor::new(data), sevenz_rust2::Password::empty())
            .with_context(|| format!("opening 7z container {}", at))?;

    // The reader yields entries with their decompressed bytes in one pass.
    let entries: Vec<(String, u64)> = archive
        .archive()
        .files
        .iter()
        .map(|e| (e.name().to_string(), e.size()))
        .collect();

    for (name, size) in entries {
        if name.ends_with('/') {
            continue;
        }
        if !is_safe_member_name(&name) {
            budget.warn(format!(
                "{}: skipping 7z entry with unsafe name: {}",
                at, name
            ));
            continue;
        }
        let member_at = format!("{} :: {}", at, name);
        if budget.check_member(size, &member_at).is_some() {
            continue;
        }
        match archive.read_file(&name) {
            Ok(bytes) => {
                budget.commit(bytes.len() as u64);
                f(&name, bytes)?;
            }
            Err(e) => {
                budget.warn(format!("{}: failed to read 7z entry: {}", member_at, e));
            }
        }
    }
    Ok(())
}

/// Enumerate cabinet members.
pub fn for_each_cab_entry<F>(data: &[u8], budget: &mut Budget, at: &str, f: &mut F) -> Result<()>
where
    F: FnMut(&str, Vec<u8>) -> Result<()>,
{
    let mut cabinet = cab::Cabinet::new(Cursor::new(data))
        .with_context(|| format!("opening cab container {}", at))?;

    // Names are collected first because reading a member borrows the cabinet mutably.
    let mut names: Vec<(String, u32)> = Vec::new();
    for folder in cabinet.folder_entries() {
        for file in folder.file_entries() {
            names.push((file.name().to_string(), file.uncompressed_size()));
        }
    }

    for (name, size) in names {
        // Cabinet paths use backslashes, which is_safe_member_name already handles.
        if !is_safe_member_name(&name) {
            budget.warn(format!(
                "{}: skipping cab entry with unsafe name: {}",
                at, name
            ));
            continue;
        }
        let member_at = format!("{} :: {}", at, name);
        if budget.check_member(size as u64, &member_at).is_some() {
            continue;
        }
        let mut buf = Vec::with_capacity(size.min(8 * 1024 * 1024) as usize);
        match cabinet
            .read_file(&name)
            .and_then(|mut r| r.read_to_end(&mut buf))
        {
            Ok(_) => {
                budget.commit(buf.len() as u64);
                f(&name, buf)?;
            }
            Err(e) => {
                budget.warn(format!("{}: failed to read cab entry: {}", member_at, e));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::limits::Limits;

    fn budget() -> Budget {
        Budget::new(Limits::default(), 1000)
    }

    fn make_7z(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = sevenz_rust2::ArchiveWriter::new(Cursor::new(&mut buf)).unwrap();
            for (name, data) in entries {
                w.push_archive_entry(
                    sevenz_rust2::ArchiveEntry::new_file(name),
                    Some(Cursor::new(*data)),
                )
                .unwrap();
            }
            w.finish().unwrap();
        }
        buf
    }

    #[test]
    fn enumerates_7z_members() {
        let z = make_7z(&[("a.bin", b"alpha payload"), ("b.bin", b"beta payload")]);
        let mut b = budget();
        let mut seen = Vec::new();
        for_each_7z_entry(&z, &mut b, "root", &mut |name, data| {
            seen.push((name.to_string(), data));
            Ok(())
        })
        .unwrap();
        assert_eq!(seen.len(), 2, "warnings: {:?}", b.warnings());
        assert_eq!(seen[0].0, "a.bin");
        assert_eq!(seen[0].1, b"alpha payload");
    }

    #[test]
    fn skips_7z_members_over_the_cap() {
        let z = make_7z(&[("big.bin", &vec![0u8; 5000]), ("small.bin", b"ok")]);
        let mut b = Budget::new(
            Limits {
                max_member_bytes: 100,
                ..Default::default()
            },
            1000,
        );
        let mut seen = Vec::new();
        for_each_7z_entry(&z, &mut b, "root", &mut |name, _| {
            seen.push(name.to_string());
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, vec!["small.bin"]);
        assert!(!b.warnings().is_empty());
    }

    #[test]
    fn rejects_non_7z_input() {
        let mut b = budget();
        assert!(for_each_7z_entry(b"not a 7z", &mut b, "root", &mut |_, _| Ok(())).is_err());
    }

    #[test]
    fn rejects_non_cab_input() {
        let mut b = budget();
        assert!(for_each_cab_entry(b"not a cab", &mut b, "root", &mut |_, _| Ok(())).is_err());
    }
}
