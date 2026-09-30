# Changelog

All notable changes to this project will be documented in this file.

## [4.0.0] - 2026-09-30

Delivers the three phases the 3.0.0 roadmap listed as 3.1.0, 3.2.0, and 3.3.0. They
land together in one MAJOR release because `--ignore-case` is removed, which is a
breaking change, and shipping them behind it would have meant three tags in a row that
each broke the same thing.

### Breaking
- **`--ignore-case` is removed.** It has had no effect since matching became case
  insensitive by default in 3.0.0, and it now fails as an unknown argument rather than
  being silently accepted. Use `--case-sensitive` for the opposite behavior.
- The positional target is now optional, because `binspector fuzz ...` takes no target.
  A bare `binspector` with no argument and no subcommand is an error that points at
  `binspector fuzz --help`.

### Added: PE analysis (the peframe mirror)
- New `src/pe/`, built on `goblin`: headers, per-section Shannon entropy, imports and
  exports, TLS callbacks, overlay detection, packer heuristics, indicator extraction
  (URLs, IPs, emails, registry keys, file paths), and **exploit mitigation state**
  (ASLR, high-entropy VA, DEP, Control Flow Guard, SafeSEH, Authenticode, relocations).
- **Findings are now confirmed from the import table.** A string match is
  circumstantial: the name could be documentation, a namespace, or dead data. An entry
  in the import directory is a linker-recorded dependency, so it is direct evidence the
  binary calls the function. A new `import` confidence tier outranks `exact`, and a
  string match is skipped when an import already proved the same function.
- Mitigation analysis surfaces findings a string scan cannot reach. On the reference
  sample: ASLR missing on `render.dll`, `renderutils.dll`, and `fontengine.dll`, and
  Authenticode missing on 179 of 441 images.
- `--no-pe` skips PE parsing, `--ioc-cap` bounds indicator collection.

### Added: reputation and CVE enrichment
- `--reputation` queries VirusTotal and MetaDefender **by hash only**. No file content
  is ever transmitted. An unknown hash is reported as "not known to the service, which
  is not evidence that it is safe".
- `--cve` detects third-party components from strings and resolves them against NVD
  2.0. The report states its own coverage: 20 curated signatures, and a component with
  no detector produces no CVEs, which is not the same as having none.
- Credentials come from the environment or `~/.config/binspector/credentials`, never
  from a command line argument, since arguments are visible through `ps` and recorded
  in shell history. A credentials file readable by group or others is refused with a
  `chmod` hint. Keys also stay out of the argument list at request time, because HTTP
  runs through curl with headers supplied on its stdin.

### Added: fuzzing, in three modes
- **Self-fuzzing.** A separate `fuzz/` crate with AFL, honggfuzz, and plain harnesses
  for the string extractor, the container walker, and the PE parser, using `arbitrary`
  so the option space is explored alongside the byte space. Each target asserts a real
  invariant rather than only looking for crashes.
- **Parser-differential.** `binspector fuzz --differential <FILE>` mutates a sample and
  feeds the mutants to Binspector's own parsers, reporting panics and hangs with a
  reproducing artifact. Deterministic from the seed, works on any host, and never
  executes the sample. This replaces the legacy `zzuf ... objdump -x` approach.
- **External engine orchestration.** `binspector fuzz --engine afl++|honggfuzz|libfuzzer|winafl`
  prepares and drives an engine against a harness you supply, seeded by
  `--corpus-from`, and parses the crash directory afterwards. The boundary is stated
  plainly in both the code and the help text: these engines drive an instrumented
  harness, so none of them can blackbox-fuzz an arbitrary bundle with no harness and no
  entry point, and WinAFL additionally needs a Windows host with DynamoRIO.
- CI now builds the harnesses and runs a short fixed-seed differential campaign, so a
  parser regression fails the build.

### Fixed
- Packer heuristics no longer fire on ordinary structure. Managed .NET assemblies are
  exempt from import-table heuristics (383 of 441 images on the reference sample are
  managed, and the CLR resolves their dependencies), resource-only DLLs are exempt too,
  and `.rsrc` is exempt from the high-entropy check because it holds already-compressed
  icons and images. Code and data sections are still checked.
- The curl config path escapes control characters using curl's own escapes. Wrapping a
  value in quotes is not sufficient on its own: curl parses its config line by line, so
  a literal newline would have ended the value and the remainder would have been read
  as a fresh directive.

### Verified on `SampleApp_1.0.0_x64.msixbundle`
- 441 PE images parsed, 11,870 imports read, 210 of 301 reported occurrences carrying
  import-table evidence rather than inference.
- 8 third-party components detected offline, including four bundled zlib versions
  (1.2.11, 1.2.12, 1.2.13, 1.3.1).
- NVD lookup verified live for OpenSSL 1.1.1k:
  [CVE-2021-3450](https://nvd.nist.gov/vuln/detail/CVE-2021-3450) (CVSS 7.4) and
  [CVE-2021-3449](https://nvd.nist.gov/vuln/detail/CVE-2021-3449), ranked by severity
  with citable URLs.
- 300 differential iterations against the full 256 MiB sample: no panics, no hangs.
- All three harnesses run clean over 40 real corpus members.

## [3.0.1] - 2026-09-30

Release engineering only. No change to scanning behavior or output; the binary is
functionally identical to 3.0.0. This exists because two long-standing CI faults meant
v3.0.0 published only 4 of the 6 platform assets the README advertises.

### Fixed
- **aarch64 Linux never built.** The cross-compile step wrote its linker config with
  `echo "[target...]\nlinker = ..."`, relying on `\n` being interpreted. `/bin/sh` does
  not do that, so a literal backslash-n landed in `~/.cargo/config.toml` and cargo failed
  to parse it. This job had failed on every run since it was introduced in `3a787aa`
  (2025-10-01). The linker, `CC`, and `AR` are now exported through `GITHUB_ENV`, which
  removes the quoting problem entirely.
- **The x86_64 macOS asset was never published.** The matrix used the deprecated
  `macos-13` runner for that architecture and its queue never started. Both macOS targets
  are now cross-compiled from one Apple silicon runner with an explicit `--target`,
  matching the Linux and Windows jobs.
- **macOS archives were missing `README.md` and `LICENSE`.** The packaging command ran
  `tar -C $(dirname "$BIN")`, changing into `target/release` where neither file exists, so
  its `||` fallback chain silently produced an archive containing only the binary.
  Packaging now stages the files first.

### Documentation
- `rsc/README.md` corrected: it listed `sdl_banned_funct.old`, which was deleted in
  `b2c2f21`, and described `sql_extended.list` as "extra SQL-related strings" when the
  file contains no SQL at all (0 matches for select/insert/drop/union/xp_/sp_/exec). It is
  another banned function list. Measured line counts and the overlap between lists were
  added, along with why they are kept separate rather than merged.
- `.version-tracking.md` records what was deferred from 3.0.0 (binwalk carving, and
  gzip/bzip2/xz/7z/cab unpacking) rather than leaving it implicit.

## [3.0.0] - 2026-09-30

Correctness release. 2.0.0 reported findings that were all false and missed everything
real; this release fixes both causes and adds the output surface around them. See
`.version-tracking.md` for the measured before and after.

### Fixed
- **Token-accurate matching.** Matching used `String::contains`, so any substring
  counted: `gets` matched `targetsize`, and `system` matched `System`, `FileSystem`,
  and `CustomSystemFont`. Matches are now verified against identifier boundaries.
  Compiler decoration on the left is still accepted (`_strcpy`, `__imp__strcpy`,
  `strcpy@8`), because those are real references, while a trailing identifier byte
  rejects the match so `strcpy_s` is never reported as `strcpy`.
- **Containers are opened.** A `.msixbundle` is a ZIP of `.msix` files holding the
  real PE binaries, so the previous scan only saw compressed bytes and found nothing.
  ZIP family archives (`.msixbundle`, `.msix`, `.appx`, `.jar`, `.nupkg`, `.zip`) are
  now unpacked recursively in memory, and every finding carries its full provenance
  chain.
- **Scan performance.** The pattern-by-string nested loop was replaced with a single
  Aho-Corasick pass. The previous approach was roughly 611M substring searches on the
  sample that exposed the bug.
- **Offsets are useful.** A reported offset now points at the matched token, with the
  UTF-16LE two-bytes-per-character stride applied, so seeking to it lands on the token.

### Added
- **Confidence scoring.** Some noise is a genuine whole token: `System.Windows.Forms`
  contains `System`, and `"Gets or sets the..."` contains `Gets`. Hits are scored
  `exact`, `symbolic`, or `prose`, and prose is excluded by default with a full
  accounting of what was suppressed. On the real sample this cut 24,511 reported
  occurrences to 306. Use `--include-low-confidence` to see them.
- **Output formats:** `text`/`txt`, `json`, `csv`, `html`, `markdown`/`md`, `sarif`,
  `sqlite`/`db`, `sql`, and `all`. Several may be given comma separated, with `-o`
  used as a filename stem. SARIF 2.1.0 locates results by byte offset rather than
  inventing line numbers. The `sqlite` format needs `--features sqlite`; `sql`
  produces an equivalent loadable dump with no extra dependency.
- **Color and accessibility:** `--color auto|always|never` and
  `--palette default|colorblind`. The colorblind palette uses Okabe-Ito colors with no
  red-green pairing. Color is never the only channel: every hit also carries a text
  marker and bold weight, so output stays readable when piped, in monochrome, and in
  a screen reader. ANSI is suppressed for file output unless `--color always`.
- **Full dump:** `--dump` reports every extracted string with banned references
  highlighted, streamed through a temporary spool so memory does not scale with the
  sample.
- **Decompression bomb protection:** `--max-depth`, `--max-unpacked-bytes`,
  `--max-member-bytes`, `--max-expansion-ratio`, and `--max-members`. A breach warns
  and continues with partial results rather than aborting, and archive member names
  that are absolute or contain `..` are rejected. Nothing is written to disk during a
  scan.
- **Coverage reporting.** The report states what was actually opened, and warns
  explicitly when no executable image was reached, so a clean result on an unopened
  container is never mistaken for a clean binary.
- **Severity and category** per banned function (`critical`, `high`, `medium`), derived
  from the function family so a custom `--banned-list` is tiered too.
- `--fail-on critical|high|medium` for pipeline use.
- `make loc-check` plus a CI quality gate enforcing formatting, clippy, the per-file
  line budget, and tests on every push.

### Changed
- Matching is case insensitive by default; `--case-sensitive` selects the opposite.
- CSV output no longer requires `--matches-only`.
- Default output is a summary; the full dump is opt-in via `--dump`.
- `src/main.rs` was split into `cli`, `container`, `report`, and `scan` modules, with
  no file over 1500 lines.

### Breaking
- **Matching is case insensitive by default.** 2.0.0 matched case sensitively, so an
  existing invocation can now return different results. Pass `--case-sensitive` for the
  previous behavior.
- **The no-op `fuzz` subcommand placeholder was removed.** It did nothing in 2.0.0.
  `binspector fuzz` is now interpreted as a request to scan a file named `fuzz`. Real
  fuzzing is planned for 3.3.0.
- Results change substantially even where flags did not, because 2.0.0 reported false
  positives and missed real findings. Re-baseline any stored output.

### Deprecated
- `--ignore-case` is now the default and warns when passed.
- `--json` is superseded by `--format json`.

## [2.0.0] - 2025-10-01
- Major: Complete overhaul from shell to Rust CLI.
- Port to Rust CLI: ASCII and UTF-16LE string extraction, banned function scanning.
- Add hashing (MD5/SHA1/SHA256) and JSON output for full report.
- Add custom banned list via `--banned-list`.
- Add matches-only export with `--matches-only` and `--format {text,json,csv}`.
- Warn/limit: CSV format is only supported with `--matches-only`.
- Add toggles `--no-ascii` and `--no-utf16` to control extraction sources.
- Add `--ignore-case` for case-insensitive matching.
- Add `--banned-filter REGEX` to filter the banned function names considered.
- Sanitize banned list entries (strip zero-width/format/control chars; split tokens on whitespace).
- Validate flags: error if both `--no-ascii` and `--no-utf16` are set.
- Add Makefile, Dockerfile, and GitHub Actions CI for Linux/macOS/Windows (x64/arm64).
- Update README and add .gitignore.
