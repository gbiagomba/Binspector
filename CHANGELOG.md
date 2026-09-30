# Changelog

All notable changes to this project will be documented in this file.

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
