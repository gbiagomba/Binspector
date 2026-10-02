#![cfg(test)]
//! One report that makes every section of every writer render something.
//!
//! `tests_support::sample_report` is deliberately small: one hit, one coverage entry, no signature,
//! no carving, no intel. That is the right fixture for "does this writer emit a table" and the
//! wrong one for a refactor, because a section that stops rendering altogether still passes
//! against it. `rich_report` is the opposite trade: it populates every optional field, so a golden
//! snapshot of it changes when any section changes. Breadth over realism, but never at the cost of
//! internal consistency. The summary is derived from the hits rather than restated beside them,
//! each target's severity counts sum to its `banned_hit_count`, the per-target sizes and string
//! counts sum to the coverage totals, and every `Confidence::Import` hit names a function its
//! member actually imports.
//!
//! # Hostile text is deliberate
//!
//! Four fields carry attacker-chosen text, because in a real scan they do: an Authenticode subject
//! Common Name, a named-pipe name, a carved item's description, and a detected component's name
//! all come out of the file under analysis. Each embeds `<script>alert(1)</script>` and a `|`, and
//! the signer CN also embeds U+202E RIGHT-TO-LEFT OVERRIDE, which makes `exe.gpj` read as
//! `jpg.exe`. None of it is a mistake to tidy up: tests assert this text never reaches HTML
//! unescaped (`html_escape`), never breaks a Markdown table row (`md_cell`), never escapes a CSV
//! field (`csv_field`) or a SQL string literal (`sql_literal`), and that the override is
//! neutralised rather than passed to a terminal. Deleting it would silently retire those
//! assertions.

use crate::container::carve::Class::{Container, Embedded, Other};
use crate::container::carve::{CarvedItem, Class};
use crate::exe::posture::UnixMitigations;
use crate::exe::Source;
use crate::intel::components::Component;
use crate::intel::cve::{ComponentCves, Cve, CveReport};
use crate::intel::reputation::{Reputation, Verdict as RepVerdict};
use crate::intel::Intel;
use crate::model::{
    Adjustment, CarvedMember, Coverage, CoverageEntry, HitRecord, MatchSummary, Report, TargetInfo,
};
use crate::pe::authenticode::DigestState;
use crate::pe::chain::ChainState::{Broken, Partial, SelfSigned};
use crate::pe::chain::{Chain, ChainState};
use crate::pe::ipc::{IpcSurface, IpcVerdict};
use crate::pe::loader::{LoaderSurface, UnqualifiedModule, Verdict as LoaderVerdict};
use crate::pe::mitigations::{Mitigations, State};
use crate::pe::sections::SectionInfo;
use crate::pe::signer::Signature;
use crate::pe::{ImportRef, Iocs, PeAnalysis};
use crate::scan::banned::Severity::{Critical, High, Low, Medium};
use crate::scan::banned::{Category, Severity};
use crate::scan::confidence::Confidence;
use crate::scan::confidence::Confidence::{Exact, Import, Prose, Symbolic};
use crate::scan::strings::Encoding;

/// Markup plus a table delimiter in one token, planted in every attacker-controlled field.
const HOSTILE: &str = "<script>alert(1)</script>|x";
/// A signer CN that also carries a right-to-left override, so the escaping tests have a
/// bidirectional-control case and not only a markup case.
const HOSTILE_CN: &str = "Evil Corp <script>alert(1)</script>|CN\u{202e}gpj.exe";

/// Pipe-server and ACL import names, shared by the import list and the IPC surface built from it.
const PIPE: &[&str] = &["ConnectNamedPipe", "CreateNamedPipeW"];
const ACL: &[&str] = &["SetEntriesInAclW", "SetSecurityDescriptorDacl"];

/// Target labels. The first two elide to the same 38-column label, so the `#n` disambiguation
/// path runs; the third is long enough to need middle truncation.
const ARM: &str = "Microsoft.VCLibs.ARM.14.00.Desktop.appx";
const ARM64: &str = "Microsoft.VCLibs.ARM64.14.00.Desktop.appx";
const LONG: &str = "vendor/bundles/arm64/Microsoft.WindowsAppRuntime.Redist.1.6/Payload.msix";

/// Member paths, named once so hits, coverage, and carving cannot drift apart.
const APP: &str = "Microsoft.VCLibs.ARM.14.00.Desktop.appx :: App.exe";
const PACKED: &str = "Microsoft.VCLibs.ARM.14.00.Desktop.appx :: plugins :: Packed.dll";
const WEAK: &str = "Microsoft.VCLibs.ARM.14.00.Desktop.appx :: Weak.exe";
const BRIDGE: &str = "Microsoft.VCLibs.ARM64.14.00.Desktop.appx :: Bridge.dll";
const ELF: &str = "Payload.msix :: usr :: lib :: libthing.so";
const MACHO: &str = "Payload.msix :: Contents :: MacOS :: Helper";
/// A hit lands here on purpose and no coverage entry matches it, so the origin roll-up has to
/// take its "not a parsed image" branch.
const UNPARSED: &str = "bundle.msixbundle :: assets :: readme.txt";

/// What the function-family table says about each function used here, before evidence.
const FAMILY: &[(&str, Severity, Category)] = &[
    ("getenv", Medium, Category::Other),
    ("atoi", Medium, Category::Conversion),
    ("memcpy", High, Category::MemoryManagement),
    ("memset", High, Category::MemoryManagement),
    ("sprintf", High, Category::FormatString),
    ("ShellExecuteW", Medium, Category::ProcessCreation),
    ("LoadLibraryExW", High, Category::DllHijacking),
    ("strcpy", Critical, Category::BufferOverflow),
    ("gets", Critical, Category::BufferOverflow),
];

/// Nine occurrences as (function, adjusted severity, member, confidence, string offset), spanning
/// all four severities and all four confidence tiers.
///
/// Deliberately **not** sorted: the lowest severity is first and a critical is last, the reverse
/// of the worst-first order `Severity`'s `Ord` gives. A later commit sorts `hits`, and a golden
/// snapshot has to show that change rather than pass unchanged.
const OCCURRENCES: &[(&str, Severity, &str, Confidence, u64)] = &[
    ("getenv", Low, ELF, Prose, 0x1_2340),
    ("atoi", Medium, APP, Symbolic, 0x1_1000),
    ("memcpy", Low, PACKED, Import, 0x2_2000),
    ("sprintf", High, WEAK, Import, 0x3_1000),
    ("memset", Low, WEAK, Import, 0x3_2000),
    ("ShellExecuteW", Medium, UNPARSED, Exact, 0x40),
    ("LoadLibraryExW", High, BRIDGE, Import, 0x4_1000),
    ("strcpy", Critical, PACKED, Exact, 0x2_3000),
    ("gets", Critical, BRIDGE, Import, 0x4_2000),
];

/// A report in which every section of every writer renders non-empty.
///
/// `posture` is deliberately empty. The parent fills it with
/// `crate::scan::all_posture(&report.coverage.entries)`, so the findings come from the real rules
/// applied to these entries and the fixture cannot drift from what those rules would say. The
/// entries are built to make them fire: `Weak.exe` has ASLR, DEP, CFG, and /GS disabled,
/// `libthing.so` has NX and full RELRO disabled, and `Helper` has an executable stack and no code
/// signature.
pub(crate) fn rich_report() -> Report {
    let hits = hits();
    let entries = entries();
    Report {
        tool: "binspector".into(),
        tool_version: "5.3.0".into(),
        binary: "bundle.msixbundle".into(),
        project: Some("PROJ-4711".into()),
        timestamp: "2026-10-01T12:00:00Z".into(),
        // The scalar fields are the first target's, which is what a single-target run writes.
        file_size: 6_291_456,
        md5: digest(0x11, 32),
        sha1: digest(0x11, 40),
        sha256: digest(0x11, 64),
        min_len: 4,
        case_sensitive: false,
        banned_list_size: 197,
        strings_total: 11_200,
        banned_hit_count: hits.len(),
        summary: summary(&hits),
        hits,
        excluded_total: 144,
        excluded_top: vec![("system".into(), 96), ("getenv".into(), 30)],
        excluded_by_rule: vec![("prose".into(), 120), ("read-only-primitive".into(), 24)],
        // False so the suppression notice renders: the writers gate it on
        // `excluded_total > 0 && !include_excluded`.
        include_excluded: false,
        coverage: Coverage {
            root_format: "zip".into(),
            members_scanned: entries.len(),
            total_unpacked_bytes: 2_260_992,
            entries,
            carved: carved(),
            carve_ran: true,
        },
        posture: Vec::new(),
        // Filled by the parent from `crate::scan::all_external_imports`, the same way `posture`
        // is, so the finding comes from the real rule rather than from a hand-written record.
        external_imports: Vec::new(),
        targets: targets(),
        iocs: iocs(),
        intel: intel(),
        warnings: vec![
            format!("{}: truncated central directory, 2 member(s) skipped", ARM),
            format!("{}: no readable import table", MACHO),
        ],
    }
}

/// `n` hex characters from one seed byte: digests and fingerprints only need the right shape.
fn digest(seed: u8, n: usize) -> String {
    format!("{:02x}", seed).repeat(n.div_ceil(2))[..n].to_string()
}

fn targets() -> Vec<TargetInfo> {
    let mut arm = target(ARM, 0x11, (6_291_456, 1_835_008, 8_300), 3, [1, 1, 2, 2]);
    arm.warnings = vec!["truncated central directory, 2 member(s) skipped".into()];
    let mut long = target(LONG, 0x33, (2_097_152, 294_912, 2_000), 2, [0, 0, 0, 1]);
    long.selected_by = "all-files".into();
    long.warnings = vec!["no readable import table on 1 image".into()];
    let arm64 = target(ARM64, 0x22, (11_010_048, 131_072, 900), 1, [1, 1, 0, 0]);
    vec![arm, arm64, long]
}

/// One target. `size` is (on-disk, unpacked, strings) and `sev` is [critical, high, medium, low],
/// whose sum is this target's `banned_hit_count`.
fn target(l: &str, seed: u8, size: (u64, u64, usize), n: usize, sev: [usize; 4]) -> TargetInfo {
    TargetInfo {
        label: l.to_string(),
        path: format!("/builds/out/{}", l),
        file_size: size.0,
        md5: digest(seed, 32),
        sha1: digest(seed, 40),
        sha256: digest(seed, 64),
        root_format: "zip".into(),
        members_scanned: n,
        total_unpacked_bytes: size.1,
        strings_total: size.2,
        banned_hit_count: sev.iter().sum(),
        critical: sev[0],
        high: sev[1],
        medium: sev[2],
        low: sev[3],
        reached_executable: true,
        selected_by: "extension:appx".into(),
        warnings: Vec::new(),
    }
}

fn hits() -> Vec<HitRecord> {
    let mut out: Vec<HitRecord> = OCCURRENCES
        .iter()
        .map(|(f, s, m, c, o)| hit(f, *s, m, *c, *o))
        .collect();
    // One hit sits at a confidence a run with `include_excluded: false` would have dropped, so the
    // prose tier's own rendering is reached.
    out[0].adjustments = vec![Adjustment {
        rule: "read-only-primitive".into(),
        from: Medium,
        to: Low,
        evidence: "reads an environment variable, cannot write caller memory".into(),
    }];
    out[1].encoding = Encoding::Utf16Le;
    out[1].token_len *= 2;
    out
}

/// One occurrence, with the context window and the offsets inside it kept consistent.
fn hit(f: &str, severity: Severity, member: &str, confidence: Confidence, at: u64) -> HitRecord {
    let (_, base, category) = *FAMILY.iter().find(|r| r.0 == f).expect("f is in FAMILY");
    // Hostile text goes in a context, not only in a signer Common Name, because the occurrence list
    // is the one section every human format already renders. Planted anywhere else, the escaping
    // tests would pass vacuously until format parity lands, and a test that cannot fail is not a
    // safety net. A real context is attacker-controlled: it is bytes lifted out of the scanned file.
    let context = format!("sub_401000: {} call {}", HOSTILE, f);
    let context_start = context.len() - f.len();
    HitRecord {
        vendor: None,
        function: f.to_string(),
        severity,
        base_severity: Some(base),
        category,
        member: member.to_string(),
        offset: at + context_start as u64,
        token_len: f.len(),
        string_offset: at,
        encoding: Encoding::Ascii,
        confidence,
        context_end: context.len(),
        context,
        context_start,
        adjustments: Vec::new(),
    }
}

/// Roll the hits up. Every function in `OCCURRENCES` appears once, in one member, so each row is
/// one occurrence and `occurrences` cannot disagree with what is in `hits`.
fn summary(hits: &[HitRecord]) -> Vec<MatchSummary> {
    hits.iter()
        .map(|h| MatchSummary {
            function: h.function.clone(),
            severity: h.severity,
            base_severity: h.base_severity,
            category: h.category,
            occurrences: 1,
            members: 1,
            // The rest of `excluded_total` is `system`, suppressed outright and so without a row.
            excluded: if h.function == "getenv" { 30 } else { 0 },
        })
        .collect()
}

/// Four PE members and two non-PE members, each built to make one more section render.
fn entries() -> Vec<CoverageEntry> {
    // A managed assembly, signed, with a verified digest over a chain that stops at an
    // intermediate rather than a root. That is the normal Authenticode case, not a defect.
    let mut app = pe();
    app.is_managed = true;
    app.is_dll = false;
    app.subsystem = "windows-cui".into();
    app.imports = from_lib("mscoree.dll", &["_CorExeMain"]);
    app.libraries = vec!["mscoree.dll".into()];
    // The one image mid-migration: hardened forms beside an unbounded one, which is the
    // counterweight the hygiene roll-up exists to print.
    app.imports.extend(from_lib(
        "ucrtbase.dll",
        &["sprintf_s", "strcpy_s", "wcscpy_s", "strcpy"],
    ));
    app.hygiene = crate::pe::credited::Hygiene::from_imports(&app.imports);
    // The CLR controls code generation, so these are not properties of the shipped file.
    app.mitigations.cfg = State::Unknown;
    app.mitigations.gs = State::Unknown;
    let ch = chain(Partial, "Example Signing CA", &digest(0xa1, 64), 2, 0);
    app.signature = Some(signature(HOSTILE_CN, DigestState::Verified, ch));

    // Packer hints over a high-entropy writable-executable section, a digest that does not match
    // the shipped bytes, and a chain whose links do not verify under the issuer they name.
    let mut packed = pe();
    packed.sections.push(section(".pack", 7.93, true, true));
    packed.packer_hints = vec![
        "section .pack is both writable and executable".into(),
        "section .pack entropy 7.93 bits/byte suggests compressed content".into(),
    ];
    packed.imports = from_lib("msvcrt.dll", &["memcpy", "memmove", "atoi"]);
    let ch = chain(Broken, "Unknown Issuer", "", 0, 1);
    packed.signature = Some(signature("Plugin Vendor", DigestState::Mismatch, ch));

    // Unsigned, with four mitigations off, which is what makes the PE posture rules fire. No
    // certificate table at all, which is a different fact from an unreadable one.
    let mut weak = pe();
    weak.is_dll = false;
    weak.mitigations.aslr = State::Disabled;
    weak.mitigations.dep = State::Disabled;
    weak.mitigations.cfg = State::Disabled;
    weak.mitigations.gs = State::Disabled;
    weak.mitigations.authenticode = State::Disabled;
    weak.imports = from_lib("msvcrt.dll", &["memcpy", "memset", "sprintf"]);
    // A crypto dependency that ships nowhere in this fixture's member list and is not a Windows
    // component, on an unsigned image that restricts nothing about its search path. That is the
    // worst-case shape for the external-import rule and it is a real one: `AdobePDFL.dll` in the
    // reference package imports 25 functions from a `libcrypto` the package does not carry.
    weak.imports.extend(from_lib(
        "libcrypto-3-x64.dll",
        &["EVP_aes_256_cbc", "RAND_bytes", "EVP_sha256"],
    ));
    weak.signature = None;

    // TLS callbacks, an overlay, dynamic loading, a pipe server, and the `--first-party` match,
    // which the origin roll-up prefers over a signer name. `load_library` stays zero, so the
    // loader verdict is `Unhardened`, which is what `LoaderSurface::decide` would conclude here.
    let mut bridge = pe();
    bridge.first_party = true;
    bridge.tls_callbacks = 3;
    bridge.overlay_size = 2_097_152;
    bridge.has_debug_info = false;
    bridge.imports = from_lib("KERNEL32.dll", &["LoadLibraryExW", "GetProcAddress"]);
    bridge.imports.extend(from_lib("KERNEL32.dll", PIPE));
    bridge.imports.extend(from_lib("ADVAPI32.dll", ACL));
    bridge.imports.extend(from_lib("msvcrt.dll", &["gets"]));
    bridge.loader = LoaderSurface {
        load_library_ex: 2,
        get_proc_address: 1,
        unqualified_modules: vec![module("secur32.dll", 0x4880), module("version.dll", 0x4910)],
        verdict: LoaderVerdict::Unhardened,
        ..Default::default()
    };
    // A pipe server importing no authorization primitive, this tool's strongest import-only claim.
    // The attacker-chosen pipe name rides in the server-side name the report prints, the only pipe
    // string any writer emits. It still starts with `CreateNamedPipe`, so
    // `IpcSurface::serves_a_pipe` agrees with the verdict set here.
    let mut pipe_server: Vec<String> = strs(PIPE);
    pipe_server.push(format!("CreateNamedPipeW \\\\.\\pipe\\{}", HOSTILE));
    bridge.ipc = IpcSurface {
        pipe_server,
        pipe_client: vec!["PeekNamedPipe".into()],
        descriptor_builders: strs(ACL),
        verdict: IpcVerdict::ServerUnauthorized,
        ..Default::default()
    };
    let ch = chain(SelfSigned, "Internal Build CA", &digest(0x9f, 64), 1, 2);
    bridge.signature = Some(signature("Internal Build CA", DigestState::Verified, ch));

    // An ELF executable with an executable stack and a writable GOT, so the Unix posture rules
    // fire on something that is not a Mach-O.
    let mut elf = entry(ELF, 196_608, 1_200, None);
    elf.format = "elf".into();
    elf.imports = from_lib("", &["getenv", "memcpy", "__stack_chk_fail"]);
    elf.import_source = Source::ElfDynsym.as_str().into();
    elf.unix_executable = true;
    elf.unix = Some(UnixMitigations {
        nx: State::Disabled,
        relro: State::Disabled,
        pie: State::Enabled,
        canary: State::Enabled,
        ..Default::default()
    });

    // A Mach-O whose import table could not be read, the case where the absence of an import
    // proves nothing and the report has to say so.
    let mut macho = entry(MACHO, 98_304, 800, None);
    macho.format = "macho".into();
    macho.import_source = String::new();
    macho.unix_executable = true;
    macho.unix = Some(UnixMitigations {
        pie: State::Enabled,
        exec_stack: State::Disabled,
        code_signature: State::Disabled,
        ..Default::default()
    });

    vec![
        entry(APP, 1_048_576, 4_000, Some(app)),
        entry(PACKED, 524_288, 2_500, Some(packed)),
        entry(WEAK, 262_144, 1_800, Some(weak)),
        entry(BRIDGE, 131_072, 900, Some(bridge)),
        elf,
        macho,
    ]
}

/// Embedded signatures across every `Class`, with a low-confidence match and non-zero counted
/// markers, so the carving section prints all of its branches.
fn carved() -> Vec<CarvedMember> {
    let mut gzip = item("gzip", "original name ", Container, 0x6_8000, false);
    gzip.description.push_str(HOSTILE);
    vec![
        CarvedMember {
            member: PACKED.into(),
            items: vec![
                item("zip", "ZIP archive, 3 entries", Container, 0x4_0000, true),
                gzip,
                item("pe", "PE32+ executable", Embedded, 0x7_1000, true),
            ],
            metadata_markers: 214,
            speculative: 9,
        },
        CarvedMember {
            member: BRIDGE.into(),
            items: vec![item("riff", "unclassified", Other, 0x1_f400, false)],
            metadata_markers: 38,
            speculative: 4,
        },
    ]
}

fn item(sig: &str, desc: &str, class: Class, offset: u64, confident: bool) -> CarvedItem {
    CarvedItem {
        signature: sig.to_string(),
        description: desc.to_string(),
        offset,
        size: 262_144,
        class,
        confident,
    }
}

/// All five indicator kinds, including the build-machine source path that leaks a developer's
/// desktop layout into a shipped binary.
fn iocs() -> Iocs {
    Iocs {
        // A developer-home path, which is the shape the build-provenance section reports and the
        // one an adversarial review had to find by hand because the ordinary cap dropped it.
        build_paths: strs(&[
            r"C:\Users\Eric\Desktop\ocv43\opencv-4.3.0\modules\core\src\system.cpp",
        ]),
        cap: 500,
        dropped: crate::pe::ioc::Dropped {
            file_paths: 1_450,
            ..Default::default()
        },
        urls: vec![
            "https://update.example.com/v1/manifest.json".into(),
            "http://192.0.2.44/beacon".into(),
        ],
        ips: vec!["192.0.2.44".into(), "198.51.100.7".into()],
        emails: vec!["build@example.com".into(), "support@example.net".into()],
        registry_keys: vec![
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Example\\Agent".into(),
            "HKCU\\Software\\Example\\Run".into(),
        ],
        file_paths: vec![
            "C:\\Users\\Eric\\Desktop\\ocv43\\opencv-4.3.0\\modules\\core\\src\\system.cpp".into(),
            "C:\\Program Files\\Example\\bin\\".into(),
        ],
    }
}

/// Components, a reputation lookup, and CVEs, so every intel branch renders. One component name
/// is attacker-chosen text, because a detected name comes out of the scanned file.
fn intel() -> Intel {
    let openssl = component("openssl", "1.1.1k", "OpenSSL 1.1.1k  25 Mar 2021");
    let zlib = component("zlib", "1.2.11", "deflate 1.2.11 Copyright 1995-2017");
    Intel {
        reputation: Some(Reputation {
            sha256: digest(0x11, 64),
            virustotal: RepVerdict::Malicious {
                detections: 3,
                total: 72,
            },
            metadefender: RepVerdict::Clean { total: 34 },
            content_transmitted: false,
        }),
        cves: Some(CveReport {
            components: vec![
                ComponentCves {
                    component: openssl.clone(),
                    cves: vec![
                        cve("CVE-2021-3450", Some(7.4), "high", "CA check bypass"),
                        cve("CVE-2021-3711", None, "critical", "SM2 overflow"),
                    ],
                    error: None,
                },
                ComponentCves {
                    component: zlib.clone(),
                    cves: Vec::new(),
                    error: Some("NVD rate limit reached, retry after 30s".into()),
                },
            ],
            signature_count: 24,
            coverage_note: "24 detectors ran; silence is not an absence of risk".into(),
        }),
        components: vec![openssl, zlib, component(HOSTILE, "0.0.1", "banner string")],
    }
}

fn component(name: &str, version: &str, evidence: &str) -> Component {
    Component {
        name: name.to_string(),
        version: version.to_string(),
        evidence: evidence.to_string(),
    }
}

fn cve(id: &str, cvss: Option<f64>, severity: &str, description: &str) -> Cve {
    Cve {
        id: id.to_string(),
        cvss,
        severity: severity.to_string(),
        description: description.to_string(),
        url: format!("https://nvd.nist.gov/vuln/detail/{}", id),
    }
}

/// A fully hardened 64-bit native DLL with one code section. Every PE member starts here and
/// changes only what its own section of the report is about.
fn pe() -> PeAnalysis {
    PeAnalysis {
        machine: "x86_64".into(),
        is_dll: true,
        is_64: true,
        subsystem: "windows-gui".into(),
        timestamp: 0x6612_3456,
        entry_point: 0x1000,
        image_base: 0x1_4000_0000,
        is_managed: false,
        sections: vec![section(".text", 6.1, false, true)],
        imports: Vec::new(),
        libraries: vec!["KERNEL32.dll".into()],
        export_count: 12,
        tls_callbacks: 0,
        has_debug_info: true,
        mitigations: hardened(),
        loader: LoaderSurface::default(),
        ipc: IpcSurface::default(),
        signature: None,
        first_party: false,
        hygiene: Default::default(),
        exports: Vec::new(),
        packer_hints: Vec::new(),
        overlay_size: 0,
    }
}

/// Every mitigation on. `Mitigations` does not derive `Default`, so all twelve are named.
#[rustfmt::skip]
fn hardened() -> Mitigations {
    let on = State::Enabled;
    Mitigations { aslr: on, high_entropy_va: on, dep: on, cfg: on, seh: on, force_integrity: on,
        appcontainer: on, authenticode: on, relocations: on, gs: on, safe_seh: on, cet: on }
}

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}

fn section(name: &str, entropy: f64, writable: bool, executable: bool) -> SectionInfo {
    SectionInfo {
        name: name.to_string(),
        virtual_size: 0x2000,
        raw_size: 0x1e00,
        entropy,
        readable: true,
        writable,
        executable,
        contains_code: executable,
    }
}

fn signature(signer: &str, digest: DigestState, chain: Chain) -> Signature {
    Signature {
        signer: Some(signer.to_string()),
        chain_len: 3,
        well_formed: true,
        digest,
        chain,
    }
}

fn chain(state: ChainState, anchor: &str, fp: &str, links: usize, expired: usize) -> Chain {
    Chain {
        state,
        anchor: Some(anchor.to_string()),
        anchor_fingerprint: fp.to_string(),
        verified_links: links,
        expired,
    }
}

fn module(name: &str, offset: u64) -> UnqualifiedModule {
    UnqualifiedModule {
        name: name.to_string(),
        offset,
    }
}

/// Imports from one library. ELF passes an empty library, which is what a flat namespace means.
fn from_lib(library: &str, names: &[&str]) -> Vec<ImportRef> {
    names
        .iter()
        .map(|name| ImportRef {
            library: library.to_string(),
            name: (*name).to_string(),
        })
        .collect()
}

/// A PE coverage entry named `m`, for a sibling module's tests to populate.
pub(crate) fn pe_entry(m: &str) -> CoverageEntry {
    entry(m, 64 * 1024, 100, Some(pe()))
}

/// One coverage entry, defaulting to a PE whose imports are carried up the way the scan does.
fn entry(m: &str, size: u64, strings: usize, pe: Option<PeAnalysis>) -> CoverageEntry {
    let (imports, import_source) = match &pe {
        Some(a) => (a.imports.clone(), "pe-directory".to_string()),
        None => (Vec::new(), String::new()),
    };
    CoverageEntry {
        vendor: None,
        member: m.to_string(),
        format: "pe".to_string(),
        size,
        strings,
        imports,
        import_source,
        unix: None,
        unix_executable: false,
        pe,
    }
}
