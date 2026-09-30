# Binspector

Binspector is a fast, cross-platform Rust CLI that scans binaries for banned and
dangerous C/C++ functions by extracting embedded strings (ASCII and UTF-16LE).

Two properties make its output trustworthy:

**It opens containers.** A `.msixbundle` is a ZIP of `.msix` files holding the real PE
binaries. A scanner that reads the outer file byte by byte sees only compressed data and
finds nothing. Binspector unpacks ZIP family archives recursively in memory, and every
finding carries the full path to the file it came from.

**It matches whole tokens, then scores confidence.** A raw substring search reports
`gets` inside `targetsize` and `system` inside `FileSystem`. Binspector verifies
identifier boundaries, then scores what survives: an import-table symbol is not the same
evidence as the word `Gets` in an XML doc comment, and the two are reported differently.

On a 256 MiB Windows application bundle this is the difference between 3 findings that
were all false, and 39 real ones traceable to a named DLL and a byte offset.

## Install

Via script (builds from source):

```bash
# Unix/macOS
./scripts/install.sh

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

See `scripts/README.md` for options and troubleshooting.

From source (requires Rust):

```bash
git clone https://github.com/gbiagomba/Binspector
cd Binspector
cargo build --release
./target/release/binspector --help
```

With binary SQLite output (optional, lengthens the build):

```bash
cargo build --release --features sqlite
```

Via Docker:

```bash
docker build -t binspector .
docker run --rm -v "$PWD:/work" binspector /work/path/to/binary
```

From Releases: download the asset matching your OS and architecture, extract, and place
the binary on your `PATH`.

- Linux: `binspector-x86_64-unknown-linux-gnu-<tag>.tar.gz`, `binspector-aarch64-unknown-linux-gnu-<tag>.tar.gz`
- macOS: `binspector-x86_64-apple-darwin-<tag>.tar.gz`, `binspector-aarch64-apple-darwin-<tag>.tar.gz`
- Windows: `binspector-x86_64-pc-windows-msvc-<tag>.zip`, `binspector-aarch64-pc-windows-msvc-<tag>.zip`

## Usage

```
binspector <BINARY> [OPTIONS]
```

A bare run prints a summary: metadata, coverage, findings, and occurrences. The full
per-string dump is opt-in, because a large sample yields millions of strings.

```bash
# Scan, summary to the terminal
binspector ./app.exe

# Scan a Windows app bundle, writing a report
binspector -p "PROJ-123" -o report.txt ./SampleApp_1.0.0_x64.msixbundle

# Every format at once, using the path as a filename stem
binspector --format all -o out/scan ./app.exe

# SARIF for a code-scanning pipeline, failing the build on critical findings
binspector --format sarif -o scan.sarif --fail-on critical ./app.exe

# Full annotated dump, colorblind palette, forced color
binspector --dump --palette colorblind --color always ./app.exe | less -R

# See what confidence filtering removed
binspector --include-low-confidence ./app.exe
```

### Options

| Option | Description |
|---|---|
| `-p, --project <NAME>` | Project name for output labeling |
| `-l, --min-len <N>` | Minimum string length (default 4) |
| `-o, --output <FILE>` | Write to a file; a filename stem when several formats are given |
| `--format <FORMAT>` | `text`/`txt`, `json`, `csv`, `html`, `markdown`/`md`, `sarif`, `sqlite`/`db`, `sql`, `all`. Comma separated for several |
| `--banned-list <FILE>` | Custom list, one function name per line |
| `--matches-only` | Report only the matches, omitting metadata and coverage |
| `--dump` | Include every extracted string with matches highlighted |
| `--case-sensitive` | Match case sensitively (matching is case insensitive by default) |
| `--banned-filter <REGEX>` | Consider only banned names matching this regex |
| `--include-low-confidence` | Also report namespace and prose matches |
| `--color <WHEN>` | `auto` (default), `always`, `never` |
| `--palette <NAME>` | `default`, or `colorblind` for Okabe-Ito colors |
| `--no-ascii`, `--no-utf16` | Disable an extraction source (not both) |
| `--fail-on <SEVERITY>` | Exit 1 when a match at or above `critical`, `high`, or `medium` is found |
| `--max-depth <N>` | Container nesting depth (default 4) |
| `--max-unpacked-bytes <N>` | Total unpacked byte cap (default 2 GiB) |
| `--max-member-bytes <N>` | Per-member byte cap (default 512 MiB) |
| `--max-expansion-ratio <N>` | Bomb protection ratio (default 100) |
| `--max-members <N>` | Member count cap (default 50,000) |
| `--max-hits <N>` | Cap on individually recorded occurrences (default 100,000) |
| `--context <N>` | Characters of context kept per occurrence (default 120) |

Exit codes: `0` success, `1` a `--fail-on` threshold was met, `2` an error occurred.

## How findings are classified

**Severity** comes from the function family, so a custom `--banned-list` is tiered too.

| Severity | Meaning | Examples |
|---|---|---|
| `critical` | Unbounded write, no caller-supplied length | `gets`, `strcpy`, `strcat`, `sprintf`, `alloca` |
| `high` | Bounded but routinely misused, or a weak primitive | `memcpy`, `snprintf`, `getenv`, `IsBadWritePtr` |
| `medium` | Weak error handling or predictability | `atoi`, `strtok`, `rand` |

**Confidence** comes from how the token sits in its string. This is what separates a
real import from text that merely contains the word.

| Confidence | Meaning | Example | Reported by default |
|---|---|---|---|
| `exact` | The whole string is the name, allowing compiler decoration | `strcpy`, `__imp__strcpy`, `strcpy@8` | yes |
| `symbolic` | A symbol or path, no whitespace | `?sprintf@WRStrSafe@@SAHPEAD_KPEBDZZ` | yes |
| `prose` | Natural language, or a case mismatch on a lowercase name | `System.Windows.Forms`, `"Gets or sets the..."` | no |

Suppressed counts are always disclosed in the report, with the largest contributors
named, so filtering stays auditable. `--include-low-confidence` reports them.

## Safety

Binspector is built to be pointed at untrusted samples.

- **Nothing is written to disk during a scan.** Archives are unpacked in memory, so
  there is no extraction step to escape from and no disk usage to manage.
- **The sample is never executed.** Binspector only reads bytes.
- **Decompression bombs are capped** on depth, total bytes, per-member size, expansion
  ratio, and member count. A breach warns and continues with partial results, so one
  hostile member cannot suppress the rest of the report.
- **Hostile member names are rejected** when absolute or containing `..`.
- **Report output is escaped** per format, so a string inside a binary cannot inject
  markup into an HTML report or statements into a SQL dump.

## Coverage is reported, not assumed

A clean result only means something if the scan reached real code. Every report states
the container format, how many members were opened, how many bytes were unpacked, and
which files were seen. When no executable image (PE, ELF, or Mach-O) was reached,
the report says so explicitly and calls the result inconclusive.

## Supported containers

ZIP family, unpacked recursively: `.zip`, `.msixbundle`, `.msix`, `.appx`, `.jar`,
`.nupkg`, and any other ZIP-based format, detected by magic bytes rather than extension.

Recognised but not yet unpacked, and reported as a coverage gap: gzip, bzip2, xz, 7z,
and cab. Executables (PE, ELF, Mach-O) are identified and scanned directly.

## Project structure

- `src/cli/`: command line surface, format resolution, color and palette handling
- `src/container/`: magic detection, ZIP recursion, resource caps
- `src/scan/`: string extraction, Aho-Corasick matching, banned list, confidence scoring
- `src/report/`: one module per output format
- `rsc/`: banned function lists and references. `rsc/sdl_banned_funct.list` is compiled
  in by default and overridable with `--banned-list`
- `scripts/`: installers and utilities, see `scripts/README.md`
- `legacy/`: the original Bash implementation, kept for reference

No `.rs` file exceeds 1500 lines; `make loc-check` enforces it and CI runs it.

## Development

```bash
make check        # fmt-check + clippy + loc-check + tests
make test-all     # tests with every feature enabled
make help         # all targets
```

## Roadmap

- **3.1.0** peframe capability mirror: PE headers, sections and entropy, imports and
  exports, TLS callbacks, resources, Authenticode, packer heuristics, IoC extraction
- **3.2.0** Reputation lookups (VirusTotal, MetaDefender) by hash only, never uploading
  file content, plus CVE enrichment via NVD
- **3.3.0** Fuzzing: self-fuzzing harnesses for Binspector's own parsers,
  parser-differential mode against a review sample, and external engine orchestration
  (AFL++, honggfuzz, WinAFL)

## References

1. https://learn.microsoft.com/en-us/previous-versions/bb288454(v=msdn.10)
2. https://github.com/intel/safestringlib/wiki/SDL-List-of-Banned-Functions
3. https://github.com/microsoft/ChakraCore/blob/master/lib/Common/Banned.h
4. https://security.web.cern.ch/security/recommendations/en/codetools/c.shtml
5. https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

## Legacy shell version (v1)

The original Bash implementation lives under `legacy/`. It shelled out to peframe,
binwalk, the VirusTotal CLI, MetaDefender, cve-bin-tool, valgrind, and zzuf. The Rust
port does its scanning without external dependencies. Two legacy behaviors are
deliberately not carried forward: `vt scan` uploaded the sample to a third party, and
`valgrind ./$bin` executed it.

## License

MIT. See `LICENSE`.
