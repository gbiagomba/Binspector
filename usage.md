# Binspector usage

Full reference. See [README.md](README.md) for the overview and quick start.

## Contents

- [Invocation](#invocation)
- [Options](#options)
- [Several targets and directories](#several-targets-and-directories)
- [Verbose output](#verbose-output)
- [Exit codes](#exit-codes)
- [Output formats](#output-formats)
- [How findings are classified](#how-findings-are-classified)
- [Containers](#containers)
- [Executable analysis](#executable-analysis)
- [Dynamic loading](#dynamic-loading)
- [Exploit mitigation findings](#exploit-mitigation-findings)
- [Origin attribution](#origin-attribution)
- [Reputation and CVEs](#reputation-and-cves)
- [Carving](#carving)
- [Fuzzing](#fuzzing)
- [Safety properties](#safety-properties)
- [Reading a report](#reading-a-report)
- [Browsing a report](#browsing-a-report)
- [Build features](#build-features)
- [Development](#development)

## Invocation

```
binspector <TARGET>... [OPTIONS]
binspector fuzz [OPTIONS]
binspector repl <REPORT>
```

A target is a file or a directory. Several may be given, and a directory is walked for
executables and archives, so `binspector ./app.msixbundle ./app.appxsym ./Dependencies/` is a
single report covering all of them.

A bare run prints a summary: metadata, coverage, findings, and occurrences. The full
per-string dump is opt-in, because a large sample yields millions of strings.

With no `-o`, output is written to `binspector_output-<YYYY.MM.DD-HH.MM.SS>.<ext>` in the
current directory, matching the naming the original shell implementation used so output from
either version sorts together. `-o` overrides it, and `-o -` writes to stdout.

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
| `--include-excluded` | Also report occurrences the evidence rules removed, each tagged with its rule. `--include-low-confidence` is an alias |
| `--split` | Write one report per target instead of one combined report |
| `--all-files` | Scan every file found, not only executables and archives |
| `--first-party <REGEX>` | Mark images whose file name or Authenticode signer matches as first-party |

### Output

| Option | Description |
|---|---|
| `-o, --output <FILE>` | Write to a file, or a filename stem when several formats are given. `-` means stdout. Defaults to a timestamped file |
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
| `--no-exe` | Skip executable parsing for all three formats (headers, sections, imports, mitigations) |
| `--no-pe` | Alias for `--no-exe`, kept because it was the name before 5.2.0 |
| `--carve` | Scan every member for embedded file signatures. Opt-in at runtime, not a build gate |
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
| `--max-dir-depth <N>` | 16 | Directory nesting depth when walking a directory target. Deliberately not `--max-depth`, which is container nesting |
| `--max-targets <N>` | 10,000 | Targets in one run |
| `--max-input-bytes <N>` | 64 GiB | Total bytes read from disk across all targets |

### Pipeline

| Option | Description |
|---|---|
| `--fail-on <SEVERITY>` | Exit 1 when a match at or above `critical`, `high`, or `medium` is found |

### Diagnostics

| Option | Description |
|---|---|
| `-v, --verbose` | Report what the scan is doing, to stderr. Repeatable, see [Verbose output](#verbose-output) |
| `--no-banner` | Do not print the banner |

The banner is written to stderr, and only when stderr is a terminal, so it never reaches a
report, a pipe, or a log file. `--no-banner` suppresses it in an interactive session too.

## Several targets and directories

```bash
binspector ./app.msixbundle ./app.appxsym ./Dependencies/
```

Targets are scanned in the order given, directories last-in-order by path, and each is read,
scanned, and dropped before the next, so peak memory stays near the largest single target rather
than their sum.

**What a directory yields.** Content decides: a file is taken when its magic says executable image
(PE, ELF, Mach-O), walkable archive, or single-stream wrapper. An extension allowlist is only a
backstop for installers whose magic the tool cannot parse (`dmg`, `msi`, `pkg`, `deb`, `rpm`,
`appimage` and similar), so those become reported coverage gaps rather than silent omissions. An
extensionless Unix executable is found by magic alone, and a PE named `.txt` is still a PE.
`--all-files` disables the filter. Every skip is counted, disclosed in the report, and named
individually at `-vv`.

**A file named on the command line is always scanned**, filter or not. Naming a path is an
instruction.

**Safety.** A symlink found while walking is never followed, which makes a recursion loop or an
escape from the named tree structurally impossible rather than merely guarded. A path named
explicitly *is* followed, the same boundary `find -H` draws. Nothing but regular files and
directories is opened. Directory entries are sorted, so two runs over one tree produce identical
output. A file named twice, or named and also reachable through a directory argument, is scanned
once.

**Caps** degrade to a warning plus partial results, never an error: `--max-dir-depth` (16),
`--max-targets` (10,000), `--max-input-bytes` (64 GiB). The per-target caps in
[Resource caps](#resource-caps) stay per target, because `--max-expansion-ratio` is defined
against one root size and a shared byte budget would let the first target consume the last one's
coverage.

**Errors.** A named path that does not exist is a hard error, because a typo must never be
reported as a clean scan. A discovered file that cannot be read is a warning and the run
continues. A directory yielding no candidates is an error naming `--all-files`.

### Labels

Each target roots its own provenance chain, so a finding reads `label :: inner.msix :: App.exe`.
A unique file name is used bare; a colliding one falls back to its path relative to the directory
root, so `bin/a.exe` and `lib/a.exe` disambiguate by saying where they came from. This matters in
practice: a dependency tree can hold the same runtime `.msix` under four architecture directories.

### One report or many

Combined is the default. `--split` writes one report per target:

| Invocation | Output |
|---|---|
| combined, no `-o` | `binspector_output-<stamp>.<ext>` |
| combined, `-o name` | `name.<ext>` |
| split, no `-o` | `binspector_<slug>-<stamp>.<ext>` |
| split, `-o name` | `name_<slug>-<stamp>.<ext>` |

The stamp is computed **once per invocation**, so every file from one run carries the same one and
sorts together. A slug is the target's file name, sanitised for a filename, with `-2`, `-3` added
on collision. `--split` cannot share stdout, and `--fail-on` in split mode trips if *any* report
trips.

`--dump` works across several targets: the per-target dumps are concatenated and every record
names its member, which is rooted at its target, so a combined dump stays attributable. It is
simply large, since one target can already yield millions of strings, so a notice says so. To
watch what a run is doing rather than read every string, use `-v` or `-vv`, which are unaffected
by target count.

### Multi-target metadata

`Report.targets` carries one entry per target, including for a single-target scan, so nothing has
to special-case arity. The top-level scalars describe the set: `binary` names it, and `sha256` is a
**manifest digest** over the newline-joined `"<sha256>  <label>"` lines in target order, which is
exactly what `sha256sum` produces and so is reproducible by hand. `md5` and `sha1` are empty for a
multi-target run rather than carrying something that looks like a file hash and is not.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | A `--fail-on` threshold was met, by a banned-function finding **or a missing exploit mitigation**, or `fuzz --fail-on-finding` found something |
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
| `sqlite` | `db` | Binary database. Needs an output path, and a build with the `sqlite` feature, which is the default |
| `sql` | | Portable INSERT script. No feature needed, loadable with `.read` |
| `all` | | Every format above |

`--dump` applies to `text`, `markdown`, `html`, `csv`, `sql`, and `sqlite`. For `json` and
`sarif` it prints a notice and is ignored, since those are findings formats.

ANSI escapes are suppressed for file output unless `--color always` is given, because
escape sequences in a saved report are noise.

## Verbose output

`-v` is repeatable, and everything it emits goes to stderr. Stdout stays byte-identical to a
non-verbose run, so `-vv --format json -o -` still pipes cleanly into `jq`.

| Level | Emits |
|---|---|
| `-v` | Phases, each archive opened with its member count, PE parse totals, per-phase timing, final counts |
| `-vv` | Every member with format, size, depth, and string count. Every skip and cap breach with its reason. Every occurrence, and every suppression naming the rule that fired |
| `-vvv` | A per-string trace, including strings that matched nothing |

The purpose is auditability rather than debugging. A scan of a large bundle reports tens of
thousands of suppressed occurrences, and `-vv` is what lets a reviewer count them instead of
trusting the total:

```bash
binspector -vv -o /dev/null ./bundle.msixbundle 2> verbose.log
grep -c '^     drop' verbose.log     # equals low_confidence_total in the JSON report
```

`-vvv` on a large sample would emit millions of lines, so the trace stops after 100,000 and
says so once. It does not silently truncate, and the count it reports is still complete.
Narrow the scan with `--banned-filter` or a larger `--min-len` before reaching for it.

## How findings are classified

### Severity

Derived from the function family, so a custom `--banned-list` is tiered too. Unrecognised
names default to `high` rather than being dropped.

| Severity | Meaning | Examples |
|---|---|---|
| `critical` | Unbounded write, no caller-supplied length | `gets`, `strcpy`, `strcat`, `sprintf`, `alloca` |
| `high` | Bounded but routinely misused, or a weak primitive | `memcpy`, `snprintf`, `getenv`, `IsBadWritePtr` |
| `medium` | Weak error handling or predictability | `atoi`, `strtok`, `rand` |

Since 4.4.0 the list also covers dynamic loading and process creation, which is where
Windows DLL search-order hijacking lives:

| Category | Severity | Names | Why |
|---|---|---|---|
| `dll-hijacking` | `high` | `SearchPath*` | Microsoft's guidance names it outright as the wrong way to locate a module |
| `dll-hijacking` | `medium` | `SetDllDirectory*`, `dlopen`, `dlmopen`, `dlsym`, `NSAddImage`, `_dyld_*` | Dangerous only when the module is named without a qualified path |
| `process-creation` | `high` | `WinExec`, `LoadModule`, `ShellExecute*`, `system`, `popen` | Legacy launchers with no way to qualify the image path; the shell or the working directory resolves the name |
| `process-creation` | `medium` | `CreateProcess*` | Safe with a quoted, fully qualified path; the classic bug is an unquoted or relative one |

`LoadLibrary`, `LoadLibraryEx`, and `GetProcAddress` are deliberately **not** findings.
`LoadLibrary` with a qualified path is correct code, the argument is not recorded in an
import table, and 78 of the 441 images in the reference bundle import the family. Calling
those defective on the strength of a name would be inference presented as evidence. See
[Dynamic loading](#dynamic-loading) for what is reported instead.

### Evidence gating

Since 5.0.0 severity is a property of the **observation**, not of the function name. The family
table still assigns a base severity, and the evidence next to the match then adjudicates it. Both
values are kept: `base_severity` is what the table said, `severity` is what the evidence
supports, and `adjustments` lists every rule that moved it. Nothing is silent.

**Exclusions.** The occurrence is removed, counted against its rule, and disclosed in the report.

| Rule | Condition |
|---|---|
| `prose` | Namespace text or documentation, the long-standing confidence filter |
| `symbol-definition` | The token is the name component of a C++ mangled or qualified symbol, so it *defines* a method of that name rather than calling the CRT function. `?sprintf@WRStrSafe@@` is a safe wrapper taking an explicit capacity; MSVC, Itanium, and `::`-qualified forms are all recognised |
| `ambiguous-name-no-import` | The name is also an ordinary English word (`system`, `gets`, `free`, `rand`, `random`). A symbolic match is excluded outright, because the token sits inside a larger token such as `h-system`. An exact match is excluded only when a usable import table was read and does not contain the name |
| `managed-no-native-call` | A managed .NET assembly has no native call site, and the match is not import-backed |

**Demotions.** The occurrence is reported at a lower severity, with the reason attached.

| Rule | New severity | Why |
|---|---|---|
| `read-only-primitive` | `low` | `strlen`, `wcslen`, `memcmp` take no destination pointer and cannot overflow a buffer |
| `deprecated-pointer-validation` | `medium` | `IsBad*Ptr` is not harmless: it suppresses the guard page that would otherwise turn a bad pointer into a clean crash |
| `allocator-entry-point` | `medium` | `malloc`, `free`, and friends take no destination buffer |
| `bounded-memory-primitive` | `medium` | `memcpy`, `memset`, `memmove` take an explicit size; the bug is a wrong size, not the call |
| `non-executable-member` | capped at `low` | A hit in a data file is data. Capped rather than excluded, because a shell script inside a bundle is a legitimate place to find `system` |

**An import is never excluded**, only demoted. An entry in the import directory is a
linker-recorded fact, and no amount of surrounding text retracts it.

**Absence of an import is only evidence when a table was read.** `import` confidence is currently
only derivable from a PE import directory, and a packed or resource-only PE has no import
directory at all, so a rule that requires import backing is skipped for an ELF, a Mach-O, or an
importless PE. Without that, a real `system()` call in a Linux binary would be dropped.

`--include-excluded` reports everything the rules removed, each tagged with the rule, so the
filter can be audited rather than trusted.

**`--dump` colours by `base_severity`, not by the adjusted value.** A dump is a raw listing of
every extracted string, and the only claim it makes about a highlighted token is that it is a
banned name; it has no specific occurrence to judge.

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

### ELF and Mach-O

Read since 5.2.0, and the reason is a gap rather than a feature. `Confidence::Import` is the
strongest evidence the tool has, because an import-table entry is a linker-recorded dependency
rather than a name that happens to appear in the bytes. Until 5.2.0 that tier was derivable only
from a PE import directory, so **`import-backed occurrences` was structurally zero for every ELF
and Mach-O binary scanned**, and the tool was quietly much weaker on Linux and macOS than on
Windows without saying so.

| Format | Imports read from | Library attribution |
|---|---|---|
| ELF | `.dynsym` entries with `SHN_UNDEF` | No. ELF has a flat namespace, so the library is left empty rather than guessed |
| Mach-O | `LC_DYLD_INFO` bind opcodes, walked locally | Yes, per symbol |
| Mach-O | `LC_DYLD_CHAINED_FIXUPS` import table | Yes, by dylib ordinal |
| Mach-O | `LC_SYMTAB` undefined externals | No. The ordinal is in `n_desc`, which is not exposed |

The report names which mechanism answered for each image, because they differ in what they can
claim. An image where none of them answered is the case where the **absence** of an import is not
evidence, and the report says how many of those there were.

A universal binary's slices are unioned and deduplicated: for a banned-function scan the finding
matters even if only one architecture has it. A fat static library's `ar` slices are skipped, and a
header claiming more than 16 architectures is not treated as one.

The bind opcodes are walked in `src/exe/binds.rs` rather than through goblin, which panics on an
out-of-range library ordinal and multiplies its output by an attacker-chosen repeat count. The local
walk agrees with goblin name-for-name on 46 real system binaries, which is a platform-gated test, and
discards the repeat count because `count` repetitions bind the same symbol at successive addresses
and so say nothing an import list needs.

`--no-exe` skips this entirely, for all three formats.

## Dynamic loading

Reported per PE image whenever it imports the loader family. A surface, not a set of
findings, and the distinction is the point.

`LoadLibrary("version.dll")` is a DLL preloading vulnerability. `LoadLibrary("C:\\Windows\\
System32\\version.dll")` is correct code. The difference is the argument, and an import table
records only that the function is called, never with what. There is no disassembler here, so
three things that *are* knowable are reported instead:

| Signal | What it means |
|---|---|
| Hardening imports | `SetDefaultDllDirectories`, `AddDllDirectory`, or `RemoveDllDirectory`. Importing any of them means the search path was deliberately restricted |
| Plain `LoadLibrary` versus `LoadLibraryEx` | The plain call has no parameter that can constrain the search, so a qualified path is its only defence. `LoadLibraryEx` accepts `LOAD_LIBRARY_SEARCH_*` flags and so can be called safely |
| Bare module-name strings | A string such as `version.dll` with no path, drive, or environment prefix, in an image that loads dynamically, is a module named without a location. Reported with its byte offset, so it is checkable by hand |

Those combine into one of three verdicts, shown in the report and in the REPL's
`mitigations` matrix as the `dll-search` column:

| Verdict | Rule |
|---|---|
| `hardened` | A hardening API is imported |
| `unqualified` | Plain `LoadLibrary`, no hardening import, and at least one bare module-name string |
| `unhardened` | Loads dynamically, but neither of the above applies |

Filter to the images worth reading with `mitigations --missing dll-search` in the browser.

**The bare-name evidence excludes what the loader already resolves.** Every PE carries the
names of the DLLs it statically imports as strings, because they sit in the import directory,
so `KERNEL32.dll` appears in nearly every image. Those, the `api-ms-win-*` and `ext-ms-*` API
sets, and an image naming itself are all excluded. Without that filter the section flagged 27
of 41 images and said nothing; with it, what remains is modules an image names but does not
statically import, which is what a runtime load looks like.

**The stated limit.** This cannot prove a call site is wrong, and `hardened` does not mean
every load in the image is safe. It narrows 78 images to the handful worth reading, and every
claim it makes carries an offset you can verify.

## Exploit mitigation findings

A missing mitigation is a finding, not prose, since 5.0.0. It is confirmable from image metadata
alone, needs no call site or source access, and is fixed by a build flag, which makes it the most
actionable thing the tool reports.

One finding per mitigation, listing the affected images rather than one finding per image: 179
unsigned images is a single statement about a build, not 179 findings.

| id | Condition | Severity |
|---|---|---|
| `aslr` | `DYNAMIC_BASE` absent | high |
| `dep` | `NX_COMPAT` absent | high |
| `gs` | Load config present with no usable `SecurityCookie` | medium |
| `cfg` | Guard flags present without `CF_INSTRUMENTED` | medium |
| `safe-seh` | 32-bit image registering no exception handlers | medium |
| `authenticode` | No certificate table | medium |
| `cet` | `CET_COMPAT` absent from the extended DLL characteristics | low |

ELF and Mach-O carry their own set, added in 5.2.0. The ids are new strings rather than overloads
of the PE ones: `aslr` names a specific optional-header bit, and making it also mean "ELF PIE"
would silently change what an existing `--filter aslr` selects.

| id | Format | Condition | Severity |
|---|---|---|---|
| `nx` | ELF | `PT_GNU_STACK` present and executable | high |
| `exec-stack` | Mach-O | `MH_ALLOW_STACK_EXECUTION` set | high |
| `pie` | both | ELF `ET_EXEC`, or a Mach-O executable without `MH_PIE` | high |
| `relro` | ELF | No `PT_GNU_RELRO`, or a segment without `BIND_NOW` | medium |
| `canary` | both | No `__stack_chk_fail` among the undefined symbols | medium |
| `fortify` | ELF | No `__*_chk` helper among the undefined symbols | medium |
| `exec-heap` | Mach-O | 32-bit x86 image without `MH_NO_HEAP_EXECUTION` | medium |
| `macho-code-signature` | Mach-O | No `LC_CODE_SIGNATURE` | medium |

Three of those are scoped to a main executable image, because the kernel reads `MH_PIE`,
`MH_ALLOW_STACK_EXECUTION`, and `MH_NO_HEAP_EXECUTION` from the main executable's header only, and
`ld` rejects `-allow_stack_execute` for anything else. ELF `nx` is deliberately **not** scoped that
way: the loader ORs `PT_GNU_STACK` across every object it maps, so one shared library with an
executable stack makes the whole process's stack executable.

`exec-heap` will almost never fire, and that is correct. `MH_NO_HEAP_EXECUTION` affects the i386
ABI; on x86_64 and every arm64 variant the heap is non-executable regardless and no current
toolchain sets the bit, so reading its absence as a defect would file "executable heap" against
every signed Apple system binary.

Each finding carries the flag or directory it was read from and the remediation, so the claim is
checkable against the file.

**`Unknown` is never a finding.** A managed assembly has no load config directory, so reporting
"/GS off" for one would be a false claim. For the same reason `/GS`, CFG, SafeSEH, and CET are not
evaluated for managed assemblies at all: the CLR controls their code generation. ASLR, DEP, and
signing are still properties of the shipped file.

**These participate in `--fail-on`**, which is the breaking change most likely to affect a
pipeline.

## Origin attribution

A reviewer cannot patch someone else's binary, so the report says whose code a finding is in.

The signer comes from the Authenticode certificate's subject Common Name. `--first-party <REGEX>`
overrides it, matched against the image's **file name** and the signer name. Not the provenance
chain: a chain always begins with the scanned file's own name, so matching it would attribute
every member of `MyProduct.msixbundle` to first-party.

```
Findings by origin
  first-party (--first-party)      131
  unsigned                          84
  signed by .NET                    13
  signed by Microsoft Corpora~       5
```

**A signer is an identity claim, not a verified one.** Nothing validates the certificate chain,
checks revocation, or compares the Authenticode hash against the image, so a hostile binary can
self-sign as anyone. Use it to deprioritise a vendor's code, never to trust a file. For the same
reason, a signature that cannot be parsed is reported as signed-but-unreadable rather than
silently treated as unsigned.

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
gigabyte of build output for a feature that issues a handful of requests.

### Component detection coverage

Detection uses 20 curated signatures anchored on library banner text, not bare version
numbers, so `1.2.3` alone is never a detection. It is not cve-bin-tool's roughly 380
checkers, and the report says so: a component with no detector produces no CVEs, which is
not the same as having none.

## Carving

```bash
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

## Browsing a report

Loads a report an earlier scan produced and answers questions about it:

```bash
binspector --format json,sqlite -o scan ./bundle.msixbundle
binspector repl scan.json
binspector repl scan.sqlite
```

The input is detected by content rather than extension, so a misnamed file still loads. A
`--matches-only` report is a bare array rather than the full model and cannot be loaded; the
error says so.

```
  summary                          findings by severity, with suppression totals
  coverage                         what was opened, and the import-backed total
  hits [fn] [--severity s]         occurrences, filterable
       [--confidence c]            one of import, exact, symbolic, prose
  member <fragment>                full detail for matching members, including PE analysis
  mitigations [--missing k]        the mitigation matrix; k is aslr, dep, cfg, seh,
                                   authenticode, dll-search, or any
  components                       third-party libraries detected
  cves                             CVEs resolved against NVD, if --cve was used
  iocs                             URLs, IPs, emails, registry keys, file paths
  carved                           embedded signatures, if --carve was used
  warnings                         coverage warnings from the scan
  sql <query>                      raw query, SQLite reports only
  export <format> <path>           re-render through the normal writers
  help                             this list
  quit                             leave
```

Two deliberate limits:

- **It never scans.** It is a viewer over a finished report, which is what keeps it from ever
  disagreeing with what the scan said. To change what is in the report, rerun the scan.
- **`export` calls the same writers the scan calls**, so a file exported here is identical to
  the same format written directly, timestamp aside. There is no second rendering path to
  drift.

`sql` needs a SQLite report, since a JSON report has no queryable schema. `mitigations
--missing aslr` is the case that justifies the whole feature: it is one line here and an
awkward `jq` expression otherwise.

## Build features

All three are **on by default** since 4.4.0, so a released binary can do everything the
documentation describes. They remain separable for a minimal build.

```bash
cargo build --release                        # sqlite, carve, and repl included
cargo build --release --no-default-features  # none of them
cargo build --release --no-default-features --features repl
```

| Feature | Adds | Cost of including it |
|---|---|---|
| `sqlite` | `--format sqlite`, and `sqlite` inside `--format all` | Bundles the SQLite C amalgamation, which needs a C compiler and is most of a cold build. The `sql` format is equivalent and needs no feature, so dropping this loses no information |
| `carve` | The `--carve` flag. Carving still has to be asked for at runtime | Pulls the binwalk library |
| `repl` | `binspector repl` | Pulls a line editor. Everything it shows is already in the report |

Without the `sqlite` feature, `--format all` writes the other eight formats and says why
`sqlite` was left out; naming `--format sqlite` explicitly is still an error.

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
