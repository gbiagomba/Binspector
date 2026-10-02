//! Which source trees contributed objects to an image, read from its PDB.
//!
//! **The finding this exists for.** `EditorManagerBridge.dll` in a real package ships a zlib
//! whose compression core (`adler32`, `crc32`, `deflate`, `inffast`, `inflate`, `inftrees`,
//! `trees`, `zutil`) is 1.2.11 from one vendored tree, while its `gz*` file-I/O layer
//! (`gzclose`, `gzlib`, `gzread`, `gzwrite`) is 1.3.1 from a different one. Somebody replaced a
//! static library to patch zlib, and in that module the other tree's objects won the MSVC
//! duplicate-symbol race for every security-relevant function, so the patch shipped and did not
//! take. The version banner says 1.2.11, which is half the truth, and **no release of zlib exists
//! in that state**, so no version-based inventory can represent it.
//!
//! Recovering it by hand took reading compiland records out of a `.pdb` the scanner was already
//! opening and extracting strings from while discarding the structure. This module reads the
//! structure.
//!
//! **Why a dependency here, when goblin's Mach-O importer was reimplemented locally.** The
//! project's rule is that a parser exposed to hostile input gets rewritten rather than trusted,
//! and that rule was written after goblin was found to panic on a raw index and to allocate on an
//! attacker-chosen repeat count. The rule was applied to `pdb2` per code path rather than per
//! crate, and the path this module uses comes out materially different:
//!
//! - The whole path is `PDB::open`, `debug_information()`, `modules()`. `modules()` takes a
//!   **bounded slice** of the DBI stream, and the iterator is a streaming parse that propagates
//!   every failure with `?` and **allocates nothing**.
//! - Every `Vec::with_capacity(n)` whose `n` comes from the file lives in the crate's `symbol`,
//!   `tpi` and `omap` modules. **None of them is reachable from the DBI module list.** The
//!   allocation-bomb class that disqualified goblin is not on this path.
//! - Non-test, non-doc panic sites on the path: two `unreachable!()` in the MSF layer guarding
//!   internal state the same function just established, and one in `common.rs` already behind
//!   `cfg!(debug_assertions)`.
//!
//! That is an argument about a specific path, so it is only worth what the path boundary is worth.
//! `fuzz_pdb` exists to hold it, and the type and symbol streams are never touched.
//!
//! **Bounded.** A PDB is parsed from memory through a `Cursor`, so nothing is written to disk, and
//! an image over `MAX_PDB_BYTES` is skipped with a stated reason rather than silently.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub mod provenance;

/// Largest PDB this will parse.
///
/// The reference `.appxsym` holds 31 PDBs totalling 483 MB, the largest 199 MB. The DBI module
/// list is a small substream and the cost is proportional to it rather than to the file, so this
/// is a guard against a crafted file rather than a performance budget. A skipped PDB says so.
pub const MAX_PDB_BYTES: usize = 512 * 1024 * 1024;

/// MSF 7.0, the container every modern PDB uses.
const MSF_7: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";
/// MSF 2.0, emitted by toolchains old enough that `pdb2` will refuse them. Detected anyway, so a
/// member is reported as a PDB that could not be read rather than as an unknown blob.
const MSF_2: &[u8] = b"Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0";

/// Whether these bytes open a PDB container.
pub fn is_pdb(data: &[u8]) -> bool {
    data.starts_with(MSF_7) || data.starts_with(MSF_2)
}

/// One source tree that contributed objects to an image.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRoot {
    /// The tree, normalised to forward slashes and truncated to a sane length.
    pub root: String,
    /// Translation units linked in from it.
    pub objects: usize,
    /// The component this tree looks like it carries, when the path names one.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
}

/// A component whose objects came from more than one tree.
///
/// This is the mixed-version condition, and it is the whole point of the module. Two trees
/// contributing objects for the same component means two copies of that component were linked and
/// the linker picked per symbol, so the shipped behaviour is neither version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixedSource {
    pub component: String,
    /// The contributing trees, worst-first by object count.
    pub roots: Vec<SourceRoot>,
}

/// What a PDB says about the image it describes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// The image this PDB belongs to, by stem, so `EditorManagerBridge.pdb` names
    /// `EditorManagerBridge`.
    pub image_stem: String,
    pub compilands: usize,
    pub roots: Vec<SourceRoot>,
    /// Components linked from more than one tree.
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mixed: Vec<MixedSource>,
    /// Why nothing was read, when nothing was.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

impl Provenance {
    /// A PDB that was recognised and deliberately not read.
    pub fn skipped(image_stem: String, reason: String) -> Self {
        Self {
            image_stem,
            skipped: Some(reason),
            ..Default::default()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty() && self.skipped.is_none()
    }
}

/// Read compiland provenance out of a PDB's bytes.
///
/// `member_name` is the member's leaf name, used only for the image stem.
///
/// `Ok(None)` means the bytes are not a PDB. An `Err` means they are one and it could not be read,
/// which is a different fact and is reported as a skip rather than discarded.
#[cfg(feature = "pdb")]
pub fn read(data: &[u8], member_name: &str) -> Result<Option<Provenance>, String> {
    if !is_pdb(data) {
        return Ok(None);
    }
    let stem = image_stem(member_name);
    if data.len() > MAX_PDB_BYTES {
        return Ok(Some(Provenance::skipped(
            stem,
            format!(
                "{} bytes exceeds the {} byte PDB cap, so no compiland records were read",
                data.len(),
                MAX_PDB_BYTES
            ),
        )));
    }

    let cursor = std::io::Cursor::new(data);
    let mut pdb = pdb2::PDB::open(cursor).map_err(|e| e.to_string())?;
    let dbi = pdb.debug_information().map_err(|e| e.to_string())?;

    // The one walk. Streaming, no allocation inside the iterator, and the type and symbol streams
    // are never opened.
    let mut modules = dbi.modules().map_err(|e| e.to_string())?;
    let mut by_root: BTreeMap<String, usize> = BTreeMap::new();
    let mut compilands = 0usize;
    loop {
        let next = pdb2::FallibleIterator::next(&mut modules).map_err(|e| e.to_string());
        match next {
            Ok(Some(m)) => {
                compilands += 1;
                // The object file name is the archive for a static-library member and the object
                // itself for one passed straight to the linker, which is exactly the distinction
                // that matters: a `.lib` path names the tree the library was built in.
                let object = m.object_file_name();
                let module = m.module_name();
                if let Some(root) = provenance::source_root(&object, &module) {
                    *by_root.entry(root).or_insert(0) += 1;
                }
            }
            Ok(None) => break,
            Err(e) => {
                // A truncated or malformed module list is partial data, not nothing: the
                // compilands already read are still facts about the image.
                let mut p = finish(stem, compilands, by_root);
                p.skipped = Some(format!("module list ended early: {}", e));
                return Ok(Some(p));
            }
        }
    }
    Ok(Some(finish(stem, compilands, by_root)))
}

#[cfg(not(feature = "pdb"))]
pub fn read(data: &[u8], member_name: &str) -> Result<Option<Provenance>, String> {
    if !is_pdb(data) {
        return Ok(None);
    }
    Ok(Some(Provenance::skipped(
        image_stem(member_name),
        "built without the `pdb` feature, so no compiland records were read".to_string(),
    )))
}

/// Assemble the roots and detect the mixed-source condition.
fn finish(image_stem: String, compilands: usize, by_root: BTreeMap<String, usize>) -> Provenance {
    let mut roots: Vec<SourceRoot> = by_root
        .into_iter()
        .map(|(root, objects)| SourceRoot {
            component: provenance::component_of(&root),
            root,
            objects,
        })
        .collect();
    roots.sort_by(|a, b| b.objects.cmp(&a.objects).then(a.root.cmp(&b.root)));

    // One component, two or more trees. Grouped after sorting so each group inherits the
    // worst-first order and the report can name the dominant tree.
    let mut per_component: BTreeMap<&str, Vec<&SourceRoot>> = BTreeMap::new();
    for r in &roots {
        if let Some(c) = r.component.as_deref() {
            per_component.entry(c).or_default().push(r);
        }
    }
    let mut mixed: Vec<MixedSource> = per_component
        .into_iter()
        .filter(|(_, rs)| rs.len() > 1)
        .map(|(component, rs)| MixedSource {
            component: component.to_string(),
            roots: rs.into_iter().cloned().collect(),
        })
        .collect();
    mixed.sort_by(|a, b| a.component.cmp(&b.component));

    Provenance {
        image_stem,
        compilands,
        roots,
        mixed,
        skipped: None,
    }
}

/// `EditorManagerBridge.pdb` names the image `EditorManagerBridge`.
fn image_stem(member_name: &str) -> String {
    let leaf = member_name
        .rsplit([':', '/', '\\'])
        .next()
        .unwrap_or(member_name);
    leaf.trim()
        .strip_suffix(".pdb")
        .or_else(|| leaf.trim().strip_suffix(".PDB"))
        .unwrap_or(leaf.trim())
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_msf_signatures_are_recognised_and_nothing_else_is() {
        assert!(is_pdb(MSF_7));
        assert!(is_pdb(MSF_2));
        let mut v = MSF_7.to_vec();
        v.extend_from_slice(&[0u8; 64]);
        assert!(is_pdb(&v));
        assert!(!is_pdb(b"MZ\x90\x00"));
        assert!(!is_pdb(b"PK\x03\x04"));
        assert!(!is_pdb(b""));
        // A near miss: the right words, the wrong container.
        assert!(!is_pdb(b"Microsoft C/C++ MSF 6.00\r\n\x1aDS\0\0\0"));
    }

    #[test]
    fn the_image_stem_comes_from_the_leaf_of_the_provenance_chain() {
        assert_eq!(
            image_stem("PSExpress_6.9.0.0.appxsym :: EditorManagerBridge.pdb"),
            "EditorManagerBridge"
        );
        assert_eq!(image_stem("zlib.pdb"), "zlib");
        assert_eq!(
            image_stem("Adobe Crash Processor.pdb"),
            "Adobe Crash Processor"
        );
        // Not a PDB name at all: left alone rather than mangled.
        assert_eq!(image_stem("something.dll"), "something.dll");
    }

    #[test]
    fn non_pdb_bytes_yield_nothing_rather_than_an_error() {
        assert_eq!(read(b"MZ\x90\x00not a pdb", "app.dll").unwrap(), None);
    }

    #[test]
    fn a_pdb_that_cannot_be_read_is_distinguished_from_one_that_is_not_a_pdb() {
        // The signature is right and the rest is garbage, which is the shape of a truncated or
        // crafted file. That must not read as "no PDB here".
        let mut v = MSF_7.to_vec();
        v.extend_from_slice(&[0xffu8; 256]);
        let got = read(&v, "broken.pdb");
        match got {
            // Either an outright parse failure or a recognised-but-skipped record is correct;
            // silently returning `None` is not.
            Err(_) => {}
            Ok(Some(p)) => assert!(p.skipped.is_some() || p.compilands == 0),
            Ok(None) => panic!("a file with the MSF signature is a PDB"),
        }
    }

    #[test]
    fn the_mixed_source_condition_is_detected_per_component() {
        let mut by_root = BTreeMap::new();
        // The real shape: a zlib core from the XMP toolkit tree and a gz* layer from an OpenCV
        // tree, in one image.
        by_root.insert("c:/adobe/xmp/toolkit/third-party/zlib".to_string(), 8);
        by_root.insert(
            "c:/users/awsingh/desktop/opencv/opencv-4.10-build/build/3rdparty/zlib".to_string(),
            4,
        );
        by_root.insert("c:/adobe/ace/src".to_string(), 40);
        let p = finish("EditorManagerBridge".into(), 52, by_root);
        assert_eq!(p.mixed.len(), 1, "{:?}", p.mixed);
        assert_eq!(p.mixed[0].component, "zlib");
        assert_eq!(p.mixed[0].roots.len(), 2);
        // Worst-first, so the dominant tree is named first and a reader can see which one won.
        assert_eq!(p.mixed[0].roots[0].objects, 8);
        assert_eq!(p.mixed[0].roots[1].objects, 4);
    }

    #[test]
    fn one_tree_per_component_is_not_a_mixed_source() {
        let mut by_root = BTreeMap::new();
        by_root.insert("c:/build/zlib-1.3.1".to_string(), 12);
        by_root.insert("c:/build/libpng-1.6.40".to_string(), 20);
        let p = finish("app".into(), 32, by_root);
        assert!(p.mixed.is_empty(), "{:?}", p.mixed);
        assert_eq!(p.roots.len(), 2);
        assert_eq!(p.roots[0].objects, 20, "roots are worst-first");
    }

    #[test]
    fn a_skipped_pdb_says_why_rather_than_looking_clean() {
        let p = Provenance::skipped("huge".into(), "too big".into());
        assert!(!p.is_empty(), "a skip is not an empty result");
        assert_eq!(p.skipped.as_deref(), Some("too big"));
        assert_eq!(p.compilands, 0);
    }
}
