# Binspector

<p align="center">
  <img src="img/binspector-logo.png" alt="Binspector" width="620">
</p>

> Binspector was built by **Gilles Biagomba** and is licensed under
**[GPLv3 or later](LICENSE)**. It reviews compiled artifacts you did not build.
>
> Vendor deliverables, dependency bundles, firmware payloads, container images and release
archives all arrive as opaque blobs, and the usual answer is `strings` piped into `grep`: blind
to anything compressed, unable to tell a real call from a word in a help message, and silent on
whether the thing was hardened or signed at all. Binspector unpacks nested containers in memory,
matches banned C/C++ functions with boundary verification, grades every finding by the evidence
behind it, reads exploit mitigations and verifies signature integrity across PE, ELF and Mach-O,
and reports what it could not reach. It never executes the sample and never transmits its
contents.

---

## 🧬 Background / Lore

The name is the job: it inspects binaries. A binary you did not build is not a document to read,
it is a sealed thing you open carefully, from the outside, without letting it run.

It began as a Bash script that orchestrated other people's tools, and inherited two habits that
disqualify a tool for this job: it uploaded the sample to a third party, and it executed it. You
cannot examine something you do not trust by running it, and you cannot keep an unreleased artifact
confidential by uploading it. [The legacy section](#-legacy-shell-version) has the details.

The Rust port does the work in-process. The guiding principle is that a scanner must be honest
about what it did not do, which is why coverage gaps, suppressed findings, unread import tables and
unverified signatures are all first-class output rather than silence.

The legacy shell version is still in the tree under [legacy/](legacy/), kept for reference.

---

## 🎯 Why This Matters

- **Evidence, not detection:** finding the string `strcpy` in a binary is trivial and nearly worthless. The question is whether it is a resolved call, a C++ method that merely shares the name, or a word inside a documentation blob. Binspector grades every occurrence by what backs it, so an import-table entry and an incidental substring are never rated alike, and the rule that demoted a finding is printed next to it.
- **A clean result must be falsifiable:** most scanners report what they found and stop. This one reports what it could not reach: members it failed to open, images with no readable import table, occurrences it suppressed and under which rule, indicators it stopped collecting. A clean result from a tool that silently skipped half the bundle is worse than no result at all, because somebody will act on it.
- **Containers are the blind spot:** a `.msixbundle`, `.jar`, `.nupkg` or `.zst` is compressed, so a byte scan of the outer file finds nothing and reports success. Binspector descends through nested containers in memory, bounded by caps on depth, expansion ratio and member count, and never writes a member to disk.
- **Hardening beats any string match:** a missing ASLR, DEP, RELRO, PIE or stack-canary flag is confirmable from headers alone, needs no source access, and is fixed by a build flag. Those are findings here, with the field they were read from and the remediation, not prose at the bottom of a report.
- **What it is not:** static only. It does not execute the sample, disassemble it, or prove reachability, so a finding is a place to look rather than a demonstrated exploit. It is not a malware verdict, and it is not a trust decision: it verifies that a signature matches the bytes and that a chain is internally sound, then prints the anchor fingerprint for you to compare against a published thumbprint, because no code-signing root store exists to anchor against in pure Rust.
- **Honesty note:** where an upstream parser was unsafe on crafted input, the walk was reimplemented locally and checked for agreement with the original on real binaries rather than asserted. One such comparison is a committed test (`src/exe/binds.rs`, macOS only); the Authenticode one was a local run over 441 images and is recorded in that module as not committed. Capabilities that are scoped out say so and say why.

**Peer map:** Binspector = compiled-artifact review · source SAST = a peer tool · runtime and DAST = a peer tool.

---

## 📚 Table of Contents

- [Background / Lore](#-background--lore)
- [Why This Matters](#-why-this-matters)
- [Features](#-features)
- [Installation](#-installation)
  - [Using GitHub Releases](#-using-github-releases)
  - [Using Cargo](#-using-cargo)
  - [Compiling From Source](#-compiling-from-source)
- [Flags](#-flags)
- [Usage](#-usage)
  - [Quick Start](#quick-start)
  - [Running Tests](#-running-tests)
  - [Using Docker](#-using-docker)
  - [Using the Makefile](#-using-the-makefile)
  - [Exit Codes](#exit-codes)
- [Limitations](#-limitations)
- [Safety](#-safety)
- [Inspired By](#-inspired-by)
- [Legacy Shell Version](#-legacy-shell-version)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🚀 Features

- ✅ **Banned function detection**, boundary-verified so `targetsize` is never reported as `gets`, tiered `critical`/`high`/`medium`/`low` by evidence rather than by name
- ✅ **Evidence-gated severity**: `import`, `exact`, `symbolic` or `prose`. An import-table entry proves a call site exists; a string in a resource does not, and the two are not rated alike
- ✅ **Exploit mitigations as findings**, with evidence and remediation: ASLR, DEP, CFG, SafeSEH, /GS, CET, Authenticode and a digest-mismatch rule on PE; NX, RELRO, PIE, stack canary and FORTIFY on ELF; PIE, stack canary, executable stack and heap, and code-signature presence on Mach-O
- ✅ **Signature verification**, not just signer attribution. The Authenticode digest is compared against the shipped bytes, and each certificate is checked against its issuer's public key where the algorithm is RSA PKCS#1 v1.5 or ECDSA P-256/P-384. Authenticode usually omits the root, so the normal result is a verified partial chain plus the anchor's fingerprint
- ✅ **Nested containers unpacked in memory**, detected by magic rather than extension: `.msixbundle`, `.msix`, `.appx`, `.jar`, `.nupkg`, `.zip`, `.7z`, `.cab`, and the single-stream wrappers `.gz`, `.bz2`, `.xz`, `.zst`. `.tar` members are not enumerated, so a `.tar.gz` is scanned as one decompressed blob
- ✅ **Many targets or a whole directory in one report**, or `--split` for one report per target
- ✅ **Eight output formats**: `text`, `json`, `csv`, `html`, `markdown`, `sarif`, `sql`, `sqlite`, plus `--format all` to write every one a build supports
- ✅ **Third-party components and CVEs**, detected offline and resolved against NVD on request
- ✅ **Hash-only reputation** via VirusTotal and MetaDefender. File content is never transmitted
- ✅ **Fuzzes its own parsers** differentially and in-process, and prepares and drives an AFL++, honggfuzz, libFuzzer or WinAFL campaign against an instrumented harness you build
- ✅ **Six platform targets**: Linux, macOS and Windows, on x64 and ARM64
- ✅ **Remediation on every finding**, not just the mitigations: what to replace a banned call with, and why the obvious replacement is wrong for the handful whose failure mode is not their family's
- ✅ **Build provenance**: developer-home paths in a shipped artifact, which disclose a username, show the build did not come from CI, and often name a statically linked dependency absent from any manifest
- ✅ **It tells you what it did not do**: coverage gaps, suppressed findings and the rule that suppressed them, indicators dropped at the cap, and analysis that was available and did not run
- ✅ **Parallel across targets**, defaulting to your core count, with output byte-identical to a single-threaded run because results merge in target order rather than completion order
- ✅ **Docker support**

---

## 🛠 Installation

### 📦 Using GitHub Releases

Download precompiled binaries from the [releases page](https://github.com/gbiagomba/Binspector/releases).
Each release ships a bare binary and an archive for every target.

| Platform | Architecture | Binary |
|----------|-------------|--------|
| Linux | x64 | `binspector-x86_64-unknown-linux-gnu-v5.4.0` |
| Linux | ARM64 | `binspector-aarch64-unknown-linux-gnu-v5.4.0` |
| macOS | x64 | `binspector-x86_64-apple-darwin-v5.4.0` |
| macOS | ARM64 | `binspector-aarch64-apple-darwin-v5.4.0` |
| Windows | x64 | `binspector-x86_64-pc-windows-msvc-v5.4.0.exe` |
| Windows | ARM64 | `binspector-aarch64-pc-windows-msvc-v5.4.0.exe` |

**Install (Linux/macOS):**

```bash
chmod +x binspector-*
sudo mv binspector-* /usr/local/bin/binspector
```

**Install (Windows PowerShell):**

```powershell
# A per-user location on PATH, rather than a Windows-owned directory
$dir = "$env:LOCALAPPDATA\Programs\binspector"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Move-Item .\binspector-x86_64-pc-windows-msvc-v5.4.0.exe "$dir\binspector.exe"
```

---

### 📚 Using Cargo

```bash
cargo install --git https://github.com/gbiagomba/Binspector --locked --bin binspector
```

`--locked` builds against the committed `Cargo.lock`, which is what you want for a tool that
parses hostile input. `--bin binspector` skips the four fuzz harnesses, which are also `[[bin]]`
targets and are not useful on their own.

---

### 🧱 Compiling From Source

```bash
git clone https://github.com/gbiagomba/Binspector
cd Binspector
cargo build --release
# Binary: target/release/binspector
```

SQLite output, carving and the REPL are on by default. A minimal build drops all three:

```bash
cargo build --release --no-default-features
```

---

## 🔧 Flags

```
-h, --help                        Print help
-V, --version                     Print version
-v, --verbose...                  Report what the scan is doing, to stderr. Repeat for more
-p, --project <PROJECT>           Project name for output labeling
-l, --min-len <N>                 Minimum string length to consider [default: 4]
-o, --output <FILE>               Output file, a stem when several formats are given, or a
                                  directory when it ends in a separator. `-` means stdout
    --format <FORMAT>             text, json, csv, html, md, sarif, sqlite, sql, all
    --split                       One report per target instead of one combined report
    --fail-on <SEVERITY>          Exit 1 at or above critical, high or medium
    --banned-list <FILE>          Custom banned list, one function name per line
    --banned-filter <REGEX>       Consider only banned names matching this regex
    --first-party <REGEX>         Mark images matching this name or signer as first-party
    --include-excluded            Also report occurrences the evidence rules excluded
    --matches-only                Report only the matches, omitting metadata and coverage
    --dump                        Include every extracted string, matches highlighted
    --carve                       Scan members for embedded file signatures
    --extract <DIR>               Write every unpacked member into DIR, flat and hash-named
    --threads <N>                 Targets to scan at once. Defaults to CPU cores
    --no-exe                      Skip PE, ELF and Mach-O parsing
    --reputation                  VirusTotal and MetaDefender lookup (hash only)
    --cve                         Resolve detected components against NVD
    --all-files                   Scan every file found, not only executables and archives
    --color <WHEN>                auto, always, never
    --palette <NAME>              default, colorblind
```

Extraction and output also take `--no-ascii`, `--no-utf16`, `--case-sensitive` (matching is
case-insensitive by default), `--no-components` and `--no-banner`. Note `--dump` has no effect on
`json` or `sarif`, which carry matches only.

Resource caps all have safe defaults, and for a tool pointed at hostile input the defaults are
part of the safety story rather than a footnote:

| Cap | Default | Guards against |
|---|---|---|
| `--max-depth` | 4 | Container nesting, a zip inside a zip inside a zip |
| `--max-expansion-ratio` | 100 | A decompression bomb, measured against the input size |
| `--max-unpacked-bytes` | 2 GiB | Total expansion across the whole walk |
| `--max-members` | 50,000 | An archive with a million tiny entries |
| `--max-hits` | 100,000 | A report that cannot be opened |
| `--ioc-cap` | 500 | Indicator collection per kind, per target |

Exceeding a cap degrades to a warning and partial results, never to an abort. Run `binspector -h`
for the complete list.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | The scan completed. Findings may still be present; without `--fail-on` they do not change the exit code |
| `1` | `--fail-on` was given and a finding at or above that severity exists, including a missing exploit mitigation |
| `2` | The run failed: an unreadable target, an invalid option, or an output path that could not be written |

A clean scan and a scan that found nothing because it could not open the target are both `0`, so
in a pipeline read the coverage section or the JSON `warnings` array rather than the exit code
alone.

---

## 📈 Usage

### Quick Start

```bash
# Scan anything: a PE, an ELF, a Mach-O, or an archive full of them
binspector ./app.exe
binspector /usr/bin/curl
binspector ./release-bundle.zip

# Several targets, or a whole vendor drop, in one report
binspector ./app.msixbundle ./libs/ ./firmware.bin

# One report per target instead
binspector --split ./vendor-deliverables/

# Write a report, labeled with a project name
binspector -p "PROJ-123" -o report.txt ./release-1.0.0.zip

# Write every format into a directory, with a timestamped name
binspector --format all -o out/ ./app.exe

# SARIF for a pipeline, failing the build on critical findings
binspector --format sarif -o scan.sarif --fail-on critical ./app.exe

# Full annotated dump, colorblind palette
binspector --dump --palette colorblind ./app.exe | less -R

# Executable analysis is automatic. Add reputation and CVE lookups (opt-in, hash only)
export VT_API_KEY=... NVD_API_KEY=...
binspector --reputation --cve ./app.exe

# Fuzz Binspector's own parsers against a sample. Never executes the sample
binspector fuzz --differential ./app.exe --iterations 20000

# Watch the scan decide. Verbose goes to stderr, so the report stays clean
binspector -vv ./app.exe 2> decisions.log

# Browse a finished report instead of grepping it
binspector --format json -o scan.json ./app.exe
binspector repl scan.json
```

With no `-o`, output goes to `binspector_output-<timestamp>.<ext>` in the current directory.

**[usage.md](usage.md) is the full reference**: every option, the severity and confidence
tiers, container support, executable analysis, signature verification, reputation and CVE
details, carving, fuzzing, the safety properties, and how to read a report.

---

### 🧪 Running Tests

```bash
# Via Make
make test

# Via Cargo
cargo test --all

# The full gate CI runs: format, lint, file-size check, tests, fuzz harness build
make check

# Minimal build, no optional features
cargo test --all --no-default-features
```

---

### 🐳 Using Docker

**Build image:**

```bash
docker build -t binspector .
```

**Run:**

```bash
docker run --rm binspector --help
docker run --rm -v "$PWD:/work" binspector /work/app.exe
```

---

### 🛠 Using the Makefile

```bash
# Debug build
make build

# Release build
make release

# Scan a binary through cargo
make run BIN=./app.exe

# Run the full gate (fmt-check + clippy + loc-check + test + fuzz-build)
make check

# Differential fuzzing against a sample
make fuzz-diff BIN=./app.exe

# Clean build artifacts
make clean
```

---

## 🚧 Limitations

Stated plainly, because a reader who cannot find this section assumes it was hidden:

- **Static only.** No execution, no disassembly, no reachability analysis. A banned-function
  finding means the name is in the import table or the bytes, not that the call is reachable with
  attacker-controlled input. It is a place to look.
- **Not a malware verdict.** There is no behavioural analysis and no signature database. The
  reputation lookup is an opt-in hash query against third-party services.
- **Verified is not trusted.** A signature check proves the bytes match and the chain is
  internally consistent. No code-signing root store is consulted and revocation is never checked.
- **`.tar` members are not enumerated.** A `.tar.gz` is decompressed and scanned as one blob, so
  executables inside it get string matching but no header, mitigation or signature analysis.
- **Managed assemblies are exempt from most native checks**, deliberately: the CLR controls code
  generation, so `/GS`, CFG, SafeSEH and CET are not properties of the shipped file.
- **A stripped binary yields less.** Mitigation and canary detection lean on symbols and imports;
  where a table cannot be read the result is `Unknown`, which is reported and never counted as a
  finding.
- **Component detection is a curated set**, not the ~380 checkers cve-bin-tool ships. Coverage is
  stated in the report so a miss is not mistaken for a clean result.

## 🛡 Safety

Binspector is pointed at files that may be hostile, so these are properties, not aspirations:

- **The sample is never executed.** There is no execution path: the only subprocesses the tool ever spawns are `curl`, for the two opt-in network lookups, and an external fuzzing engine you asked for.
- **File content is never transmitted.** Reputation sends the SHA-256 in a GET path and nothing else, which matters because an unreleased binary uploaded to a third party is a disclosure event.
- **No container member is written to disk unless you ask:** containers are unpacked in memory, so extraction is off the attack surface of an ordinary run. The only files a scan creates are the report you asked for with `-o`, a temporary string spool under `--dump` that is deleted when the scan ends, and the members `--extract` writes. Those are named from a content hash plus a sanitised leaf, never from the member's own path, so an archive entry called `../../etc/passwd` cannot write outside the directory you named.
- **Parsers are bounds-checked and fuzzed:** four harnesses cover the string, container, PE and ELF/Mach-O readers. Where an upstream parser raw-indexed attacker-controlled header fields or honoured an attacker-chosen repeat count, the walk was reimplemented locally with checked arithmetic and checked for agreement with the original on real system binaries. Carving runs third-party code and is not covered by the container harness.
- **Resource caps on everything**: nesting depth, unpacked bytes, expansion ratio, member count, recorded hits. A decompression bomb degrades to a warning and partial results, never to an abort.
- **Revocation is deliberately not checked:** OCSP and CRL fetch a URL taken from the certificate under examination, which is attacker-controlled outbound traffic from the scanning host.

---

## 🙏 Inspired By

The Rust port does the work in-process, but the ideas and the reference data come from these
projects, and it is worth naming them.

| Project | What Binspector takes from it |
|---|---|
| [peframe](https://github.com/guelfoweb/peframe) | The shape of a PE report: headers, sections, imports, packer hints, and indicator extraction in one pass. `src/pe/` is a deliberate mirror of its capabilities |
| [binwalk](https://github.com/ReFirmLabs/binwalk) | Signature-based carving of embedded data. Used as a library behind `--carve`, not shelled out to |
| [cve-bin-tool](https://github.com/intel/cve-bin-tool) | Detecting third-party components from strings and resolving them to CVEs. Binspector implements a curated subset and says so |
| [AFL++](https://github.com/AFLplusplus/AFLplusplus), [honggfuzz](https://github.com/google/honggfuzz), [WinAFL](https://github.com/googleprojectzero/winafl) | The fuzzing engines `binspector fuzz --engine` prepares and drives |
| [arbitrary](https://github.com/rust-fuzz/arbitrary) | Structured fuzz input, so the option space is explored alongside the byte space |
| [zzuf](https://github.com/samhocevar/zzuf) | The parser-differential idea. The legacy script fuzzed `objdump` with it; `fuzz --differential` does the same to Binspector's own parsers |
| [VirusTotal](https://www.virustotal.com) and [OPSWAT MetaDefender](https://www.opswat.com/products/metadefender) | Hash reputation. Binspector queries by hash only and never uploads |
| [NVD](https://nvd.nist.gov) | The CVE data `--cve` resolves against |
| [goblin](https://github.com/m4b/goblin) | PE, ELF, and Mach-O parsing |
| [SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) | The interchange format for code-scanning pipelines |
| `strings`, from [GNU binutils](https://www.gnu.org/software/binutils/) | The original idea, and the thing whose blind spot on compressed containers motivated the rewrite |

The banned function lists come from:

- [Microsoft SDL banned function calls](https://learn.microsoft.com/en-us/previous-versions/bb288454(v=msdn.10))
- [Intel safestringlib: SDL list of banned functions](https://github.com/intel/safestringlib/wiki/SDL-List-of-Banned-Functions)
- [ChakraCore `Banned.h`](https://github.com/microsoft/ChakraCore/blob/master/lib/Common/Banned.h)
- [CERN secure coding recommendations for C](https://security.web.cern.ch/security/recommendations/en/codetools/c.shtml)

See [rsc/README.md](rsc/README.md) for how those lists are organised.

---

## 🐚 Legacy Shell Version

The original Bash implementation lives under [legacy/](legacy/), kept for historical
reference. It is not used by the Rust build or runtime.

| File | What it was |
|---|---|
| [legacy/binspector.sh](legacy/binspector.sh) | The v1 scanner. Shelled out to peframe, binwalk, the VirusTotal and MetaDefender CLIs, cve-bin-tool, valgrind and zzuf |
| [legacy/install.sh](legacy/install.sh) | Linux install helper for the shell version |
| [legacy/mac_install.sh](legacy/mac_install.sh) | macOS install helper |

It expected `sdl_banned_funct.list` at an install path such as `/opt/Binspector/`. The Rust
CLI embeds [rsc/sdl_banned_funct.list](rsc/sdl_banned_funct.list) and needs none of it.

**Two of its behaviours are deliberately not carried forward.** `vt scan` uploaded the sample
to a third party, and `valgrind ./$bin` executed it. Both are disqualifying for a tool whose
job is to examine something you do not trust.

---

## 🤝 Contributing

Pull requests are welcome.

**Before submitting:**

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run the gate (`make check`)
4. Commit changes (`git commit -m 'feat: add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a pull request

`make check` runs format, clippy with warnings denied, the file-size check (no `.rs` over
1,500 lines), the test suite, and a build of the fuzz harnesses. CI runs that gate on Linux,
then cross-builds and packages all six targets, before any release is tagged. The macOS and
Windows jobs build and package only, so a platform-gated test such as the Mach-O one in
`src/exe/binds.rs` runs locally and not in CI.

---

## 📜 License

This project is licensed under **GPLv3 or later**.
See [LICENSE](LICENSE) for details.

---

**⚡ Built with Rust · 🛡️ Static-only, evidence-graded, never executes the sample**
