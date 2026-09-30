# Binspector

Binspector is a fast, cross-platform Rust CLI for reviewing binaries. It finds banned and
dangerous C/C++ functions, reads PE headers and exploit mitigations, detects third-party
components and their known CVEs, and fuzzes its own parsers.

Three properties make its output trustworthy:

**It opens containers.** A `.msixbundle` is a ZIP of `.msix` files holding the real PE
binaries. A scanner that reads the outer file byte by byte sees only compressed data and
finds nothing. Binspector unpacks ZIP family archives recursively in memory, and every
finding carries the full path to the file it came from.

**It matches whole tokens, then scores confidence.** A raw substring search reports
`gets` inside `targetsize` and `system` inside `FileSystem`. Binspector verifies
identifier boundaries, then scores what survives: an import-table symbol is not the same
evidence as the word `Gets` in an XML doc comment, and the two are reported differently.

**It prefers evidence over inference.** When a member parses as a PE, the import
directory is read directly. An import is a linker-recorded dependency, so it is proof the
binary calls the function, unlike a name that merely appears in its bytes.

On a 256 MiB Windows application bundle this is the difference between 3 findings that
were all false, and 39 real ones traceable to a named DLL and a byte offset, 210 of them
backed by an import table entry.

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

Optional features:

```bash
cargo build --release --features sqlite   # binary --format sqlite output
cargo build --release --features carve    # embedded signature carving via binwalk
cargo build --release --all-features

# Coverage-guided instrumentation for the fuzz harnesses
cargo afl build --release --bin fuzz_pe
cargo hfuzz build --bin fuzz_pe
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
| `--reputation` | Look the hash up with VirusTotal and MetaDefender. Sends only the SHA-256 |
| `--cve` | Resolve detected components against NVD for known CVEs |
| `--no-components` | Skip third-party component detection (offline, on by default) |
| `--cve-limit <N>` | Maximum CVEs per component (default 10) |
| `--no-pe` | Skip PE parsing (headers, sections, imports, mitigations) |
| `--ioc-cap <N>` | Maximum indicators of each kind to collect (default 500) |
| `--carve` | Scan every member for embedded file signatures (needs `--features carve`) |
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
| `import` | Present in the PE import directory, so the binary demonstrably calls it | an entry in `msvcrt.dll` | yes |
| `exact` | The whole string is the name, allowing compiler decoration | `strcpy`, `__imp__strcpy`, `strcpy@8` | yes |
| `symbolic` | A symbol or path, no whitespace | `?sprintf@WRStrSafe@@SAHPEAD_KPEBDZZ` | yes |
| `prose` | Natural language, or a case mismatch on a lowercase name | `System.Windows.Forms`, `"Gets or sets the..."` | no |

Suppressed counts are always disclosed in the report, with the largest contributors
named, so filtering stays auditable. `--include-low-confidence` reports them.

## Executable analysis

When a member is a PE, Binspector reads it rather than guessing from strings. This is
what mirrors peframe, and it surfaces problems a string scan cannot see at all.

| Area | Reported |
|---|---|
| Mitigations | ASLR, high-entropy VA, DEP, Control Flow Guard, SafeSEH, Authenticode, relocations |
| Sections | Name, virtual and raw size, per-section Shannon entropy, `rwx` permissions |
| Imports | Every imported function and its DLL, cross-referenced against the banned list |
| Structure | Exports, TLS callbacks, overlay size, managed (.NET) detection, debug info |
| Packers | UPX, ASPack, Themida, VMProtect, Enigma, MPRESS, and generic entropy and layout signals |
| Indicators | URLs, IPs, emails, registry keys, file paths |

Heuristics are tuned against real applications rather than against ideal ones. Managed
.NET assemblies and resource-only DLLs are exempt from import-table heuristics, because
neither legitimately has a native import directory, and `.rsrc` is exempt from the
entropy check because icons and images are already compressed. Without those exemptions
the reference sample produced hundreds of hints describing ordinary structure.

## Reputation and CVEs

Both are opt-in. Binspector is offline by default.

```bash
export VT_API_KEY=...        # or MD_API_KEY, or ~/.config/binspector/credentials
binspector --reputation ./app.exe

export NVD_API_KEY=...       # optional, raises the rate limit
binspector --cve ./app.exe
```

**No file content is ever transmitted.** Reputation is looked up by the SHA-256 the scan
already computed, and CVE lookup sends only a detected component name and version. The
legacy shell implementation ran `vt scan $bin`, which uploads the sample and publishes it
to a third party permanently; on an unreleased binary that is a disclosure event, so it
is deliberately not reproduced. An unknown hash reports that it is unknown, never that it
is clean.

API keys are never accepted as command line arguments, because arguments are visible
through `ps` and recorded in shell history. A credentials file that group or others can
read is refused. Keys also stay out of the argument list at request time.

Component detection uses 20 curated signatures anchored on library banner text, not bare
version numbers. It is not cve-bin-tool's roughly 380 checkers, and the report says so:
a component with no detector produces no CVEs, which is not the same as having none.

## Fuzzing

Three modes, because they solve different problems.

```bash
# Mutate a sample and feed the mutants to Binspector's own parsers.
# Deterministic from the seed, runs anywhere, never executes the sample.
binspector fuzz --differential ./sample.msixbundle --iterations 20000 --seed 1

# Unpack a sample into a seed corpus of its real members.
binspector fuzz --corpus-from ./sample.msixbundle

# Drive an external engine against a harness you supply.
binspector fuzz --engine afl++ --harness ./target/release/fuzz_pe \
  --corpus fuzz/corpus/sample --run-secs 3600

# Coverage-guided self-fuzzing (needs cargo-afl or cargo-hfuzz).
make fuzz-afl TARGET=fuzz_pe
```

**What these engines can and cannot do.** AFL++, honggfuzz, and libFuzzer drive an
instrumented *harness*: a program that reads an input and feeds it to the code under
test. WinAFL instead instruments a Windows binary through DynamoRIO and needs a target
module plus a function offset. None of them can blackbox-fuzz an arbitrary
`.msixbundle` with no harness and no entry point. Binspector prepares and drives the
campaign, builds the corpus, and parses the crash directory; running it still needs the
engine installed, and WinAFL needs a Windows host. The differential mode is the one that
works everywhere with no setup.

The self-fuzzing harnesses live in `src/bin/fuzz_*.rs` and use `arbitrary`, so the option
space is explored alongside the byte space. They are binaries of this crate rather than a
separate one, so a plain `cargo build` compiles them and a change to a library type cannot
break them unnoticed.

Each harness reads one file, which is what AFL's `@@` and honggfuzz's `___FILE___`
substitute. They deliberately do not use the engines' persistent-mode macros: those need
the engine's runtime symbols at link time, so an ordinary `cargo build` could not link the
binary at all. Instrument the same binary with `cargo afl build --bin fuzz_pe` for a
coverage-guided run. Each asserts a real invariant rather than only waiting
for a crash: offsets stay inside the input, provenance chains are never empty, and
section entropy stays within 0 to 8.

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

Detected by magic bytes rather than extension, and unpacked recursively.

| Kind | Formats |
|---|---|
| ZIP family | `.zip`, `.msixbundle`, `.msix`, `.appx`, `.jar`, `.nupkg`, and any other ZIP-based format |
| Other archives | 7z, cab |
| Single stream | gzip, bzip2, xz, zstd |
| Executables | PE (parsed in full), ELF, Mach-O |

A single-stream format wraps one payload, so it decompresses to a single child that keeps
a useful name: `App.exe.gz` becomes `App.exe`, and `src.tgz` becomes `src.tar`.

Nothing Binspector detects is left unopened. For data that no directory declares, such as
a payload appended to an executable, see carving below.

## Carving

```bash
cargo build --release --features carve
binspector --carve ./app.exe
```

Carving scans for file signatures anywhere in a blob, which finds embedded data that no
container declares. It is off by default because it costs time and produces leads rather
than facts.

**Raw signature output is not usable, so it is filtered.** Run against a real 256 MiB
application bundle, binwalk reported **2,348 signatures**, almost all `copyright` strings
and `pkcs_der_hash` markers that say nothing about anything being embedded. Binspector
classifies them: embedded archives and filesystems lead the report, embedded executables
and media follow, unrecognised signatures are still listed so a new format is never
silently dropped, and checksums, certificates, and text markers are counted rather than
listed. That turns 2,348 signatures into 8 candidate containers.

Short magic values are also verified rather than trusted. `PK\x03\x04` is four bytes and
collides readily: on that same sample it matched inside a 36 MB DLL where the header
fields were actually text, claiming version 0, a zero-length member name, and a 22,635
byte extra field. ZIP matches are validated against the local file header before being
reported as an archive.

A signature match is still a lead. Extract with `binwalk -e` to confirm and scan the
contents.

## Project structure

- `src/cli/`: command line surface, format resolution, color and palette handling
- `src/container/`: magic detection, ZIP and 7z and cab recursion, single-stream
  decompression, carving, resource caps
- `src/scan/`: string extraction, Aho-Corasick matching, banned list, confidence scoring
- `src/pe/`: PE headers, sections and entropy, imports, mitigations, packers, indicators
- `src/intel/`: reputation, CVE enrichment, component detection, credentials
- `src/fuzz/`: differential fuzzer, mutation engine, corpus builder, engine orchestration
- `src/report/`: one module per output format
- `src/bin/fuzz_*.rs`: the self-fuzzing harnesses, built as binaries of this crate
- `rsc/`: banned function lists and references. `rsc/sdl_banned_funct.list` is compiled
  in by default and overridable with `--banned-list`
- `scripts/`: installers and utilities, see `scripts/README.md`
- `legacy/`: the original Bash implementation, kept for reference

No `.rs` file exceeds 1500 lines; `make loc-check` enforces it and CI runs it.

## Development

```bash
make check        # fmt-check + clippy + loc-check + tests
make test-all     # tests with every feature enabled
make fuzz-build   # build the plain fuzz harnesses
make help         # all targets
```

CI runs the same gate, plus a short fixed-seed differential campaign, so a parser
regression fails the build.

## Roadmap

No committed work outstanding. The container coverage gap is closed, so future work is
driven by what real samples turn up.

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
