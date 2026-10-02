//! Reducing a compiland record to the source tree it came from.
//!
//! A PDB names two paths per translation unit. For an object passed straight to the linker both
//! are the same `.obj`; for a member of a static library the object file name is the `.lib` and the
//! module name is the object inside it. The `.lib` is the more useful of the two, because it names
//! the tree the library was built in, which is the question.
//!
//! **What a "root" is, and why not the whole directory.** The real evidence looked like this:
//!
//! ```text
//! C:\Users\awsingh\Desktop\opencv\opencv-4.10-build\build\3rdparty\zlib\zlib.dir\Release\adler32.obj
//! ```
//!
//! Grouping by the containing directory puts `Release` and `zlib.dir` in the key, so two trees that
//! differ higher up look like four roots, and the mixed-source condition is a comparison between
//! roots. Grouping by the whole path is worse: every object is its own root. So the build-output
//! tail is trimmed, which is what makes `...\3rdparty\zlib` and `...\xmp\third-party\zlib`
//! comparable as two trees carrying one component.

/// Directory names that are build output rather than source identity.
///
/// Trimmed from the tail so two trees differing further up compare as two rather than as four.
/// `.dir` is MSBuild's per-target directory and carries the target name, which is sometimes the
/// only place the component appears, so it is trimmed only after the component has been read.
const BUILD_TAIL: &[&str] = &[
    "release",
    "debug",
    "relwithdebinfo",
    "minsizerel",
    "x64",
    "x86",
    "win32",
    "arm64",
    "arm",
    "obj",
    "objs",
    "output",
    "out",
    "bin",
    "lib",
    "build",
    "intermediate",
    "temp",
];

/// Component names worth recognising in a path.
///
/// Deliberately the same vocabulary `intel::components` uses for path-derived detection, so the
/// SBOM and the provenance agree on what a component is called. A mixed-source warning naming a
/// component the component list does not know would be unactionable.
const COMPONENTS: &[&str] = &[
    "zlib",
    "libpng",
    "libjpeg-turbo",
    "libjpeg",
    "openssl",
    "libxml2",
    "expat",
    "freetype",
    "icu",
    "bzip2",
    "libtiff",
    "openjpeg",
    "libwebp",
    "zstd",
    "lz4",
    "brotli",
    "sqlite",
    "curl",
    "libcurl",
    "boost",
    "protobuf",
    "opencv",
    "pugixml",
    "harfbuzz",
    "lcms2",
    "lcms",
    "jbig2dec",
    "openexr",
    "libraw",
    "giflib",
];

/// Source file names that identify a component wherever its objects end up.
///
/// **Why this is needed and not optional.** The motivating finding is a zlib whose core came from
/// one tree and whose `gz*` layer came from another, inside one DLL. The real records are:
///
/// ```text
/// obj=...\xmp\toolkit\public\libraries\windows_x64\Release\XMPFilesStaticRelease.lib
/// mod=XMPFilesStatic.dir\Release\deflate.obj
///
/// obj=...\camera_raw\opencv\3rdparty\lib\Release\zlib.lib
/// mod=zlib.dir\Release\gzclose.obj
/// ```
///
/// The second names zlib in its archive. **The first does not name zlib anywhere**: not in the
/// archive (`XMPFilesStaticRelease.lib`), not in any path segment (`xmp`, `toolkit`, `libraries`).
/// The only thing identifying it is `deflate.obj`, which is a zlib source file. Without this table
/// that tree is attributed to no component, the two never compare, and the finding this module
/// exists for is invisible.
///
/// Only components whose source file names are distinctive enough to be safe appear here. zlib's
/// twelve are unmistakable; a table entry for a library with generic file names such as `util.c`
/// would produce false attributions, so there is none. That asymmetry is why a vendored zlib is
/// detected and another vendored library may not be, and it is a coverage limit rather than a bug.
const OBJECT_FINGERPRINTS: &[(&str, &[&str])] = &[
    (
        "zlib",
        &[
            "adler32", "crc32", "deflate", "gzclose", "gzlib", "gzread", "gzwrite", "infback",
            "inffast", "inflate", "inftrees", "trees", "zutil",
        ],
    ),
    // bzip2 is here because leaving it out caused a false finding rather than a missed one.
    // `compress.c` and `decompress.c` belong to bzip2 as well as zlib, and with only zlib in the
    // table a bzip2 archive's `compress.obj` was attributed to zlib, inventing a third zlib tree
    // in an image that has two. Naming bzip2's own files fixes the attribution; dropping the two
    // shared names from zlib's list is what fixes the collision.
    (
        "bzip2",
        &[
            "blocksort",
            "bzlib",
            "crctable",
            "huffman",
            "randtable",
            "compress",
            "decompress",
        ],
    ),
];

/// Names that appear in more than one component's file set, and so identify nothing.
///
/// Checked before the tables so a future entry cannot silently reintroduce the collision above.
/// A name here is a coverage gap, deliberately, because a wrong attribution is worse than none:
/// the whole value of this module is a reviewer trusting that two trees means two copies.
const AMBIGUOUS_OBJECTS: &[&str] = &[
    "compress",
    "decompress",
    "util",
    "common",
    "crc",
    "checksum",
];

/// The component a single compiland belongs to, from the most specific evidence available.
///
/// Three sources in descending confidence, because the real data needs all three:
///
/// 1. The archive basename. `zlib.lib` is unambiguous.
/// 2. The object basename, against [`OBJECT_FINGERPRINTS`]. This is what identifies zlib objects
///    inside somebody else's static library.
/// 3. A path segment, which catches a vendored source tree such as `3rdparty/zlib`.
///
/// Path segments come last on purpose. Taking them first attributed twelve vendored zlib objects
/// to OpenCV, because they sit under an `opencv` directory, and that hid the mixed-version zlib.
pub fn component_of_compiland(object_file_name: &str, module_name: &str) -> Option<String> {
    for name in [object_file_name, module_name] {
        if let Some(c) = component_from_file_name(name) {
            return Some(c);
        }
    }
    for name in [object_file_name, module_name] {
        if let Some(c) = component_of(&name.replace('\\', "/")) {
            return Some(c);
        }
    }
    None
}

/// Match the basename of a path against the archive and object-fingerprint tables.
fn component_from_file_name(path: &str) -> Option<String> {
    let base = path
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let stem = base.rsplit_once('.').map(|(a, _)| a).unwrap_or(&base);
    if stem.is_empty() {
        return None;
    }
    // An archive or object named for the component outright: `zlib.lib`, `libpng.lib`.
    if COMPONENTS.contains(&stem) {
        return Some(stem.to_string());
    }
    // A component's own source file inside somebody else's archive, which is the case that
    // matters. Ambiguous names are refused first: `compress.obj` belongs to zlib and to bzip2, so
    // it identifies neither.
    if AMBIGUOUS_OBJECTS.contains(&stem) {
        return None;
    }
    for (component, files) in OBJECT_FINGERPRINTS {
        if files.contains(&stem) {
            return Some((*component).to_string());
        }
    }
    None
}

/// Collapse a tree that names the component down to the component's own directory.
///
/// `.../build/boost/boost/filesystem` and `.../build/boost/boost/regex` are two libraries inside
/// one Boost checkout, not two Boost versions, and they were reported as a mixed source. When a
/// path segment names the component, the tree *is* that component's directory and everything below
/// it is internal structure, so the root truncates there.
///
/// Left alone when the component appears nowhere in the path, which is the zlib case: neither
/// `.../xmp/toolkit/public/libraries/windows_x64` nor `.../opencv/3rdparty` contains a `zlib`
/// segment, so both survive as the two distinct trees they are.
pub fn narrow_to_component(root: &str, component: &str) -> String {
    let parts: Vec<&str> = root.split('/').collect();
    match parts.iter().position(|p| p.eq_ignore_ascii_case(component)) {
        Some(i) => parts[..=i].join("/"),
        None => root.to_string(),
    }
}

/// The source tree a compiland came from.
///
/// Prefers the object file name, because for a static-library member that is the `.lib` and names
/// the tree the library was built in. Falls back to the module name when the two are the same or
/// the object name carries nothing usable.
///
/// `None` for a compiland with no path at all, which is normal: the linker synthesises records
/// such as `* Linker *` and `Import:KERNEL32.dll`, and neither names a source tree.
pub fn source_root(object_file_name: &str, module_name: &str) -> Option<String> {
    let candidate = if usable(object_file_name) {
        object_file_name
    } else if usable(module_name) {
        module_name
    } else {
        return None;
    };
    Some(trim_to_root(candidate))
}

/// Whether a compiland path names a file on a filesystem rather than a synthesised record.
fn usable(p: &str) -> bool {
    let p = p.trim();
    if p.is_empty() {
        return false;
    }
    // `* Linker *`, `* CIL *`, and the import thunks the linker invents. None is a source tree,
    // and counting them as roots would put a fictional tree in every image.
    if p.starts_with('*') || p.starts_with("Import:") {
        return false;
    }
    p.contains('\\') || p.contains('/')
}

/// Drop the file name and the build-output tail, leaving the tree.
fn trim_to_root(path: &str) -> String {
    let norm = path.replace('\\', "/");
    let mut parts: Vec<&str> = norm
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    // The file itself.
    parts.pop();
    // Then the build-output tail, bounded by the remaining depth so a path made entirely of
    // build-output names cannot empty the vector.
    while parts.len() > 1 {
        let last = parts[parts.len() - 1].to_ascii_lowercase();
        let is_tail = BUILD_TAIL.contains(&last.as_str())
            // MSBuild's `<target>.dir`, and CMake's `CMakeFiles/<target>.dir`.
            || last.ends_with(".dir")
            || last == "cmakefiles";
        if is_tail {
            parts.pop();
        } else {
            break;
        }
    }
    let mut out = parts.join("/");
    // Bounded, because a report prints these and a 400-character path helps nobody.
    const MAX: usize = 160;
    if out.len() > MAX {
        let mut cut = MAX;
        while cut > 0 && !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push_str("...");
    }
    out
}

/// The component a tree looks like it carries.
///
/// Matched on a path segment rather than a substring, so `c:/src/myzlibwrapper` is not reported as
/// zlib. A `<name>-<version>` segment counts, which is the shape a vendored source tree is
/// unpacked into.
///
/// **Segments are read innermost first, and that is load-bearing.** The real evidence is
/// `...\opencv\opencv-4.10-build\build\3rdparty\zlib`, which names two components: OpenCV is the
/// tree it was vendored into and zlib is what these objects actually are. Taking the first match
/// attributed those twelve zlib objects to OpenCV, which hid the mixed-version zlib this module
/// exists to find. The deepest segment is the most specific, so it wins.
pub fn component_of(root: &str) -> Option<String> {
    for segment in root.split('/').rev() {
        let seg = segment.to_ascii_lowercase();
        if COMPONENTS.contains(&seg.as_str()) {
            return Some(seg);
        }
        // `zlib-1.3.1`, `opencv-4.10-build`.
        if let Some((name, rest)) = seg.split_once('-') {
            if COMPONENTS.contains(&name) && rest.chars().next().is_some_and(|c| c.is_ascii_digit())
            {
                return Some(name.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_static_library_member_is_attributed_to_the_archive_tree() {
        // The object name is the `.lib`, which names the tree the library was built in. The module
        // name is the object inside the archive and says much less.
        let root = source_root(
            r"C:\Users\Eric\Desktop\ocv43\opencv-4.3.0\ocv-build\lib\Release\opencv_world430.lib",
            r"adler32.obj",
        )
        .expect("a path");
        // Case is preserved: a reviewer verifying this needs the path as it appears in the file.
        assert_eq!(root, "C:/Users/Eric/Desktop/ocv43/opencv-4.3.0/ocv-build");
    }

    #[test]
    fn the_build_output_tail_is_trimmed_so_two_trees_compare_as_two() {
        // The real evidence. Without trimming, `zlib.dir` and `Release` are part of the key and
        // one tree looks like several.
        let a = source_root(
            r"C:\Users\awsingh\Desktop\opencv\opencv-4.10-build\build\3rdparty\zlib\zlib.dir\Release\adler32.obj",
            "",
        )
        .unwrap();
        let b = source_root(
            r"C:\Users\awsingh\Desktop\opencv\opencv-4.10-build\build\3rdparty\zlib\zlib.dir\Release\gzclose.obj",
            "",
        )
        .unwrap();
        assert_eq!(a, b, "two objects from one tree are one root");
        assert!(a.ends_with("3rdparty/zlib"), "{}", a);
    }

    #[test]
    fn synthesised_linker_records_are_not_source_trees() {
        // Every image has these and none of them names a tree. Counting them would put a fictional
        // root in every single image.
        assert_eq!(source_root("* Linker *", "* Linker *"), None);
        assert_eq!(source_root("* CIL *", "* CIL *"), None);
        assert_eq!(
            source_root("Import:KERNEL32.dll", "Import:KERNEL32.dll"),
            None
        );
        assert_eq!(source_root("", ""), None);
        // A bare name with no separator is not a path either.
        assert_eq!(source_root("adler32.obj", "adler32.obj"), None);
    }

    #[test]
    fn the_module_name_is_used_when_the_object_name_carries_nothing() {
        let root = source_root("* Linker *", r"D:\B\workspace\Harmony-release\src\main.obj")
            .expect("a path");
        assert_eq!(root, "D:/B/workspace/Harmony-release/src");
    }

    #[test]
    fn a_component_is_matched_on_a_segment_not_a_substring() {
        assert_eq!(
            component_of("c:/adobe/xmp/third-party/zlib").as_deref(),
            Some("zlib")
        );
        assert_eq!(
            component_of("c:/build/zlib-1.3.1/src").as_deref(),
            Some("zlib")
        );
        assert_eq!(
            component_of("c:/build/opencv-4.10-build").as_deref(),
            Some("opencv")
        );
        // Innermost wins. This exact path is the one that mattered: taking the first match
        // attributed twelve vendored zlib objects to OpenCV and hid the mixed-version zlib.
        assert_eq!(
            component_of("C:/Users/awsingh/Desktop/opencv/opencv-4.10-build/build/3rdparty/zlib")
                .as_deref(),
            Some("zlib")
        );
        // And with no inner component present, the outer tree is still named.
        assert_eq!(
            component_of("C:/Users/Eric/Desktop/ocv43/opencv-4.3.0/ocv-build").as_deref(),
            Some("opencv")
        );
        // Not a component: a wrapper whose name merely contains one.
        assert_eq!(component_of("c:/src/myzlibwrapper"), None);
        assert_eq!(component_of("c:/src/zlibtastic"), None);
        // A hyphenated segment whose tail is not a version is not a vendored tree either.
        assert_eq!(component_of("c:/src/zlib-wrapper"), None);
        assert_eq!(component_of("d:/b/workspace/harmony-release/src"), None);
    }

    #[test]
    fn a_path_made_only_of_build_output_names_does_not_trim_to_nothing() {
        // Pathological, and the loop must leave at least one segment rather than producing "".
        let root = source_root(r"release\x64\obj\thing.obj", "").expect("a path");
        assert!(!root.is_empty(), "trimmed to nothing");
    }

    #[test]
    fn a_very_long_path_is_bounded_because_the_report_prints_it() {
        let deep = format!(r"C:\{}\thing.obj", vec!["segment"; 60].join("\\"));
        let root = source_root(&deep, "").expect("a path");
        assert!(root.len() <= 163, "{} chars", root.len());
        assert!(root.ends_with("..."));
    }

    #[test]
    fn the_real_mixed_zlib_records_resolve_to_one_component_and_two_trees() {
        // Verbatim from the reference package. This is the acceptance test for the whole module:
        // if these two do not come back as one component from two trees, the finding is invisible.
        let xmp_obj = r"D:\B\workspace\Harmony-release\ThirdParty\adobe\PSXImageCore\camera_raw\camera_raw\xmp\toolkit\public\libraries\windows_x64\Release\XMPFilesStaticRelease.lib";
        let xmp_mod = r"XMPFilesStatic.dir\Release\deflate.obj";
        let ocv_obj = r"D:\B\workspace\Harmony-release\ThirdParty\adobe\PSXImageCore\camera_raw\camera_raw\opencv\3rdparty\lib\Release\zlib.lib";
        let ocv_mod = r"zlib.dir\Release\gzclose.obj";

        // The XMP archive names zlib nowhere: not in `XMPFilesStaticRelease.lib`, not in any path
        // segment. Only `deflate.obj` identifies it.
        assert_eq!(
            component_of_compiland(xmp_obj, xmp_mod).as_deref(),
            Some("zlib")
        );
        assert_eq!(
            component_of_compiland(ocv_obj, ocv_mod).as_deref(),
            Some("zlib")
        );

        let xmp_root = source_root(xmp_obj, xmp_mod).expect("a root");
        let ocv_root = source_root(ocv_obj, ocv_mod).expect("a root");
        assert_ne!(xmp_root, ocv_root, "two trees, or there is no finding");
        assert!(xmp_root.contains("xmp/toolkit"), "{}", xmp_root);
        assert!(ocv_root.ends_with("opencv/3rdparty"), "{}", ocv_root);
    }

    #[test]
    fn an_archive_naming_the_component_wins_over_the_enclosing_tree() {
        // `...\opencv\3rdparty\lib\Release\zlib.lib` is zlib, not OpenCV. Reading the path
        // segment first attributed twelve vendored zlib objects to OpenCV.
        let obj = r"C:\src\opencv\3rdparty\lib\Release\zlib.lib";
        assert_eq!(
            component_of_compiland(obj, r"zlib.dir\Release\adler32.obj").as_deref(),
            Some("zlib")
        );
    }

    #[test]
    fn an_object_with_no_component_evidence_is_attributed_to_none() {
        // First-party code. Guessing a component here would put a fictional one in every image.
        let obj = r"D:\B\workspace\Harmony-release\PSExpress\_build\x64\Release\EditorManagerBridge\obj\EditManager.obj";
        assert_eq!(component_of_compiland(obj, obj), None);
    }

    #[test]
    fn a_generic_object_name_is_not_a_fingerprint() {
        // The fingerprint table holds only names distinctive enough to be safe. `util.obj` or
        // `compress.obj` inside an unrelated library must not become zlib on the strength of a
        // common word, so `compress` is in the table but only matches as a whole stem.
        assert_eq!(component_from_file_name("util.obj"), None);
        assert_eq!(component_from_file_name("decompressor.obj"), None);
        assert_eq!(component_from_file_name("myinflate.obj"), None);
        // And the real ones still match.
        assert_eq!(
            component_from_file_name("inflate.obj").as_deref(),
            Some("zlib")
        );
        assert_eq!(
            component_from_file_name("zlib.lib").as_deref(),
            Some("zlib")
        );
    }
}
