# Binspector usage

Full reference. See [README.md](README.md) for the overview and quick start.

## Contents

- [Invocation](#invocation)
- [Options](#options)
- [Exit codes](#exit-codes)
- [Output formats](#output-formats)
- [How findings are classified](#how-findings-are-classified)
- [Containers](#containers)
- [Executable analysis](#executable-analysis)
- [Reputation and CVEs](#reputation-and-cves)
- [Carving](#carving)
- [Fuzzing](#fuzzing)
- [Safety properties](#safety-properties)
- [Reading a report](#reading-a-report)
- [Build features](#build-features)
- [Development](#development)

## Invocation

```
binspector <BINARY> [OPTIONS]
binspector fuzz [OPTIONS]
```

A bare run prints a summary: metadata, coverage, findings, and occurrences. The full
per-string dump is opt-in, because a large sample yields millions of strings.

```bash
# Summary to the terminal
binspector ./app.exe

# A Windows app bundle, writing a report
binspector -p "PROJ-123" -o report.txt ./SampleApp_1.0.0_x64.msixbundle

# Every format at once, using the path as a filename stem
binspector --format all -o out/scan ./app.exe

# SARIF for a code-scanning pipeline, failing the build on critical findings
binspector --format sarif -o scan.sarif --fail-on critical ./app.exe

# Full annotated dump, colorblind palette, forced color
binspector --dump --palette colorblind --color always ./app.exe | less -R

# See what confidence filtering removed
binspector --include-low-confidence ./app.exe

# Case-sensitive matching (the default is case insensitive)
binspector --case-sensitive ./app.exe

# Only banned names matching a pattern
binspector --banned-filter '^str' ./app.exe
```

## Options

### Input and matching

| Option | Description |
|---|---|
| `-p, --project <NAME>` | Project name for output labeling |
| `-l, --min-len <N>` | Minimum string length (default 4) |
| `--banned-list <FILE>` | Custom list, one function name per line |
| `--banned-filter <REGEX>` | Consider only banned names matching this regex |
| `--case-sensitive` | Match case sensitively (default is case insensitive) |
| `--no-ascii`, `--no-utf16` | Disable an extraction source (not both) |
| `--include-low-confidence` | Also report namespace and prose matches |

### Output

| Option | Description |
|---|---|
| `-o, --output <FILE>` | Write to a file, or a filename stem when several formats are given |
| `--format <FORMAT>` | See [Output formats](#output-formats). Comma separated for several |
| `--matches-only` | Report only the matches, omitting metadata and coverage |
| `--dump` | Include every extracted string with matches highlighted |
| `--color <WHEN>` | `auto` (default), `always`, `never` |
| `--palette <NAME>` | `default`, or `colorblind` for Okabe-Ito colors |
| `--context <N>` | Characters of context kept per occurrence (default 120) |
| `--max-hits <N>` | Cap on individually recorded occurrences (default 100,000) |

### Analysis

| Option | Description |
|---|---|
| `--no-pe` | Skip PE parsing (headers, sections, imports, mitigations) |
| `--carve` | Scan every member for embedded file signatures (needs `--features carve`) |
| `--ioc-cap <N>` | Maximum indicators of each kind to collect (default 500) |
| `--reputation` | Look the hash up with VirusTotal and MetaDefender |
| `--cve` | Resolve detected components against NVD for known CVEs |
| `--no-components` | Skip third-party component detection (offline, on by default) |
| `--cve-limit <N>` | Maximum CVEs per component (default 10) |

### Resource caps

Every cap degrades to a warning plus partial results rather than aborting, so a hostile
sample cannot hide findings by tripping a limit.

| Option | Default | Purpose |
|---|---|---|
| `--max-depth <N>` | 4 | Container nesting depth |
| `--max-unpacked-bytes <N>` | 2 GiB | Total unpacked byte cap |
| `--max-member-bytes <N>` | 512 MiB | Per-member byte cap |
| `--max-expansion-ratio <N>` | 100 | Bomb protection ratio |
| `--max-members <N>` | 50,000 | Member count cap |

### Pipeline

| Option | Description |
|---|---|
| `--fail-on <SEVERITY>` | Exit 1 when a match at or above `critical`, `high`, or `medium` is found |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | A `--fail-on` threshold was met, or `fuzz --fail-on-finding` found something |
| `2` | An error occurred |

## Output formats

`--format` accepts these, comma separated for several. With more than one, `-o` is used as
a filename stem.

| Value | Aliases | Notes |
|---|---|---|
| `text` | `txt` | Default. Human-facing summary |
| `json` | | The whole report model |
| `csv` | | One row per occurrence, or per string with `--dump` |
| `html` | `htm` | Self-contained, light and dark, no external assets |
| `markdown` | `md` | For pasting into a ticket or wiki page |
| `sarif` | | SARIF 2.1.0, located by byte offset rather than invented line numbers |
| `sqlite` | `db` | Binary database. Needs `--features sqlite` and an output path |
| `sql` | | Portable INSERT script. No feature needed, loadable with `.read` |
| `all` | | Every format above |

`--dump` applies to `text`, `markdown`, `html`, `csv`, `sql`, and `sqlite`. For `json` and
`sarif` it prints a notice and is ignored, since those are findings formats.

ANSI escapes are suppressed for file output unless `--color always` is given, because
escape sequences in a saved report are noise.

## How findings are classified

### Severity

Derived from the function family, so a custom `--banned-list` is tiered too. Unrecognised
names default to `high` rather than being dropped.

| Severity | Meaning | Examples |
|---|---|---|
| `critical` | Unbounded write, no caller-supplied length | `gets`, `strcpy`, `strcat`, `sprintf`, `alloca` |
| `high` | Bounded but routinely misused, or a weak primitive | `memcpy`, `snprintf`, `getenv`, `IsBadWritePtr` |
| `medium` | Weak error handling or predictability | `atoi`, `strtok`, `rand` |

### Confidence

How the token sits in its string. This is what separates a real reference from text that
merely contains the word.

| Confidence | Meaning | Example | Reported by default |
|---|---|---|---|
| `import` | Present in the PE import directory, so the binary demonstrably calls it | an entry in `msvcrt.dll` | yes |
| `exact` | The whole string is the name, allowing compiler decoration | `strcpy`, `__imp__strcpy`, `strcpy@8` | yes |
| `symbolic` | A symbol or path, no whitespace | `?sprintf@WRStrSafe@@SAHPEAD_KPEBDZZ` | yes |
| `prose` | Natural language, or a case mismatch on a lowercase name | `System.Windows.Forms`, `"Gets or sets the..."` | no |

Suppressed counts are always disclosed, with the largest contributors named, so filtering
stays auditable. `--include-low-confidence` reports them.

### Why boundaries and confidence both exist

Boundary verification removes a substring match: `gets` inside `targetsize`, or `system`
inside `FileSystem`. It cannot remove everything, because some noise is a genuine whole
token. `.` is a valid boundary, so `System.Windows.Forms` contains `System` as a real
token, and `"Gets or sets the BindingContext"` contains `Gets`. Neither is a call.

Compiler decoration on the left is accepted, because `_strcpy`, `__imp_strcpy`, and
`strcpy@8` are real references in a PE. A trailing identifier byte rejects the match, so
`strcpy_s`, the safe replacement, is never reported as `strcpy`.

## Containers

Detected by magic bytes rather than extension, and unpacked recursively in memory.

| Kind | Formats |
|---|---|
| ZIP family | `.zip`, `.msixbundle`, `.msix`, `.appx`, `.jar`, `.nupkg`, and any other ZIP-based format |
| Other archives | 7z, cab |
| Single stream | gzip, bzip2, xz, zstd |
| Executables | PE (parsed in full), ELF, Mach-O |

A single-stream format wraps one payload, so it decompresses to a single child that keeps a
useful name: `App.exe.gz` becomes `App.exe`, and `src.tgz` becomes `src.tar`.

Every finding carries its full provenance chain, for example
`SampleApp.msixbundle :: SampleApp.msix :: App.exe`, plus a byte offset into that member, so
a reviewer can seek to it and confirm.

Nothing Binspector detects is left unopened. For data that no directory declares, see
[Carving](#carving).

## Executable analysis

When a member is a PE, Binspector reads it rather than guessing from strings.

| Area | Reported |
|---|---|
| Mitigations | ASLR, high-entropy VA, DEP, Control Flow Guard, SafeSEH, Authenticode, relocations |
| Sections | Name, virtual and raw size, per-section Shannon entropy, `rwx` permissions |
| Imports | Every imported function and its DLL, cross-referenced against the banned list |
| Structure | Exports, TLS callbacks, overlay size, managed (.NET) detection, debug info |
| Packers | UPX, ASPack, Themida, VMProtect, Enigma, MPRESS, plus entropy and layout signals |
| Indicators | URLs, IPs, emails, registry keys, file paths |

Mitigation state is often the most actionable part. A banned function in a binary with
ASLR, DEP, and CFG enabled is a materially smaller problem than the same function with none
of them, and no string scan can tell you which you are looking at.

Heuristics are tuned against real applications rather than ideal ones:

- **Managed .NET assemblies** are exempt from import-table heuristics. The CLR resolves
  their dependencies, so "no import table" is normal rather than suspicious.
- **Resource-only DLLs** are exempt too: an image with no code section legitimately imports
  nothing.
- **`.rsrc`** is exempt from the high-entropy check, because it holds icons and images that
  are already compressed. Code and data sections are still checked.

Without those exemptions, a real 441-image application bundle produced hundreds of hints
describing ordinary structure.

`--no-pe` skips this entirely.

## Reputation and CVEs

Both are opt-in. Binspector is offline by default.

```bash
export VT_API_KEY=...        # or MD_API_KEY
binspector --reputation ./app.exe

export NVD_API_KEY=...       # optional, raises the rate limit
binspector --cve ./app.exe
```

### No file content is ever transmitted

Reputation is looked up by the `SHA-256` the scan already computed. CVE lookup sends only a
detected component name and version.

The legacy shell implementation ran `vt scan $bin`, which uploads the sample and publishes
it to a third party permanently. On an unreleased binary that is a disclosure event, so it
is deliberately not reproduced. An unknown hash reports that it is unknown, never that it
is clean.

### Credentials

API keys are never accepted as command line arguments, because arguments are visible
through `ps` and recorded in shell history. They come from, in order:

1. Environment: `VT_API_KEY` (or `VIRUSTOTAL_API_KEY`), `MD_API_KEY` (or
   `METADEFENDER_API_KEY`), `NVD_API_KEY`
2. `~/.config/binspector/credentials`, or the path in `BINSPECTOR_CREDENTIALS`

```
# ~/.config/binspector/credentials  (chmod 600)
virustotal = ...
metadefender = ...
nvd = ...
```

A credentials file that group or others can read is refused with a `chmod` hint. Keys also
stay out of the argument list at request time: HTTP runs through `curl` with headers
supplied on its stdin, never as `-H` arguments.

`curl` must be on `PATH` for these lookups. It is used in place of a Rust HTTP client
deliberately: rustls, ring, and webpki would add a large dependency tree and roughly a
gigabyte of build output for a feature that is off by default and issues a handful of
requests.

### Component detection coverage

Detection uses 20 curated signatures anchored on library banner text, not bare version
numbers, so `1.2.3` alone is never a detection. It is not cve-bin-tool's roughly 380
checkers, and the report says so: a component with no detector produces no CVEs, which is
not the same as having none.

## Carving

```bash
cargo build --release --features carve
binspector --carve ./app.exe
```

Carving scans for file signatures anywhere in a blob, which finds embedded data that no
container declares, such as a payload appended to an executable or buried in a resource.
Off by default: it costs time and produces leads rather than facts. Asking for `--carve`
from a build without the feature is an error naming the flag to rebuild with, rather than
silently reporting that nothing was found.

### Raw signature output is not usable, so it is filtered

Against a real 256 MiB application bundle, binwalk reported **2,348 signatures**, almost
all `copyright` strings and `pkcs_der_hash` markers that say nothing about anything being
embedded. Signatures are classified:

| Class | Meaning | Reported |
|---|---|---|
| Container | An archive or filesystem. The reason carving exists | leads the report |
| Embedded | An executable or media file | after containers |
| Other | Unclassified, so a format added to binwalk later is never silently dropped | listed |
| Metadata | Checksums, certificates, key material, text | counted, not listed |

That turned 2,348 signatures into **8 candidate containers** plus 138 other signatures,
with 176 markers excluded.

### Short magic values are verified, not trusted

`PK\x03\x04` is four bytes and collides readily. On that same sample it matched at offset
`0x1d6c924` inside a 36 MB DLL, where the header fields were actually text:

| Field | Value | Why it is impossible |
|---|---|---|
| Version needed | 0 | Real writers emit 10 to 63 |
| Member name length | 0 | A ZIP member must have a name |
| Extra field length | 22,635 | Absurd for a local header |
| Uncompressed size | 0 | Against a compressed size of 25,968 |

ZIP matches are validated against the local file header and demoted to speculative when the
fields are not plausible.

A signature match is still a lead. Extract with `binwalk -e` to confirm and scan the
contents.

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
```

### Fuzz options

| Option | Description |
|---|---|
| `--differential <FILE>` | Mutate this sample against Binspector's parsers |
| `--target <NAME>` | `strings`, `container`, `pe`, or `all` (default) |
| `--iterations <N>` | Iterations in differential mode (default 10,000) |
| `--seed <N>` | Mutation seed. The same seed reproduces the same campaign |
| `--hang-secs <N>` | An execution slower than this counts as a hang (default 5) |
| `--corpus-from <FILE>` | Build a seed corpus from this sample |
| `--corpus <DIR>` | Corpus directory (default `fuzz/corpus/<stem>`) |
| `--engine <NAME>` | `afl++`, `honggfuzz`, `libfuzzer`, `winafl` |
| `--harness <PATH>` | Instrumented harness the engine should drive |
| `--output <DIR>` | Engine output directory (default `fuzz/out`) |
| `--run-secs <N>` | Stop the engine after this many seconds |
| `--target-module`, `--target-offset` | WinAFL: module and function offset |
| `--dry-run` | Print the engine command without running it |
| `--artifact-dir <DIR>` | Reproducing inputs from differential mode |
| `--json` | Emit the campaign result as JSON |
| `--fail-on-finding` | Exit 1 when the campaign finds anything |

### What these engines can and cannot do

AFL++, honggfuzz, and libFuzzer drive an instrumented *harness*: a program that reads an
input and feeds it to the code under test. WinAFL instead instruments a Windows binary
through DynamoRIO and needs a target module plus a function offset.

**None of them can blackbox-fuzz an arbitrary `.msixbundle` with no harness and no entry
point.** Binspector prepares and drives the campaign, builds the corpus, and parses the
crash directory. Running it still needs the engine installed, and WinAFL needs a Windows
host. On other hosts the WinAFL plan prints with a note saying exactly that.

The differential mode is the one that works everywhere with no setup, and the only one that
never executes the sample.

### The harnesses

`src/bin/fuzz_strings.rs`, `fuzz_container.rs`, and `fuzz_pe.rs` are binaries of this crate,
so a plain `cargo build` compiles them and a change to a library type cannot break them
unnoticed. They use `arbitrary`, so the option space is explored alongside the byte space,
and each asserts a real invariant rather than only waiting for a crash: offsets stay inside
the input, provenance chains are never empty, section entropy stays within 0 to 8.

Each reads one file, which is what AFL's `@@` and honggfuzz's `___FILE___` substitute. They
deliberately do not use the engines' persistent-mode macros: those need the engine's runtime
symbols at link time, so an ordinary `cargo build` could not link the binary.

```bash
make fuzz-afl TARGET=fuzz_pe     # cargo afl build --release --bin fuzz_pe
make fuzz-hfuzz TARGET=fuzz_pe   # cargo hfuzz build --bin fuzz_pe
```

## Safety properties

Binspector is built to be pointed at untrusted samples.

- **Nothing is written to disk during a scan.** Archives are unpacked in memory, so there is
  no extraction step to escape from and no disk usage to manage.
- **The sample is never executed.** Binspector only reads bytes. The legacy implementation
  ran `valgrind ./$bin`, which executed the target; that is not carried forward.
- **Decompression bombs are capped** on depth, total bytes, per-member size, expansion
  ratio, and member count. A breach warns and continues with partial results, so one hostile
  member cannot suppress the rest of the report.
- **Hostile member names are rejected** when absolute or containing `..`.
- **Report output is escaped** per format, so a string inside a binary cannot inject markup
  into an HTML report or statements into a SQL dump.
- **No file content leaves the machine.** Reputation and CVE lookups send a hash and a
  component name respectively, and only when explicitly asked.

## Reading a report

### Coverage is reported, not assumed

A clean result only means something if the scan reached real code. Every report states the
container format, how many members were opened, how many bytes were unpacked, and which
files were seen. When no executable image (PE, ELF, or Mach-O) was reached, the report says
so explicitly and calls the result inconclusive.

That matters because the failure this tool was rebuilt to fix looked exactly like a clean
result: a scan that opened nothing and therefore found nothing.

### Offsets

An occurrence reports the byte offset of the matched token within its member, plus the
offset of the containing string. Seek to the first to land on the token. UTF-16LE offsets
account for the two-bytes-per-character stride, so they are directly usable.

## Build features

Both are off by default.

```bash
cargo build --release                      # default
cargo build --release --features sqlite    # binary --format sqlite output
cargo build --release --features carve     # embedded signature carving via binwalk
cargo build --release --all-features
```

| Feature | Adds | Cost |
|---|---|---|
| `sqlite` | `--format sqlite` | Bundles SQLite; noticeable build time and disk. The `sql` format is equivalent and needs no feature |
| `carve` | `--carve` | Pulls the binwalk library |

## Development

```bash
make check        # fmt-check + clippy + loc-check + tests + fuzz-build
make test-all     # tests with every feature enabled
make fuzz-build   # build all binaries including the harnesses
make help         # all targets
```

CI runs the same gate plus a short fixed-seed differential campaign, so a parser regression
fails the build. No `.rs` file exceeds 1500 lines; `make loc-check` enforces it.

### Project structure

| Path | Contents |
|---|---|
| `src/cli/` | Command line surface, format resolution, color and palette |
| `src/container/` | Magic detection, ZIP, 7z, cab, single-stream decompression, carving, caps |
| `src/scan/` | String extraction, Aho-Corasick matching, banned list, confidence scoring |
| `src/pe/` | PE headers, sections and entropy, imports, mitigations, packers, indicators |
| `src/intel/` | Reputation, CVE enrichment, component detection, credentials |
| `src/fuzz/` | Differential fuzzer, mutation engine, corpus builder, engine orchestration |
| `src/report/` | One module per output format |
| `src/bin/fuzz_*.rs` | The self-fuzzing harnesses |
| `rsc/` | Banned function lists and references. See [rsc/README.md](rsc/README.md) |
| `scripts/` | Installers and utilities. See [scripts/README.md](scripts/README.md) |
| `legacy/` | The original Bash implementation, kept for reference |
