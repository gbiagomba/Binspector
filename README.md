# Binspector

<p align="center">
  <img src="img/binspector-logo.png" alt="Binspector" width="620">
</p>

> **VERSION:** 5.3.0
> **DESCRIPTION:** Binspector reviews compiled artifacts you did not build. Vendor deliverables, dependency bundles, firmware payloads, container images and release archives all arrive as opaque blobs, and the usual answer is `strings` piped into `grep`: blind to anything compressed, unable to tell a real call from a word in a help message, and silent on whether the thing was hardened or signed at all. Binspector unpacks nested containers in memory, matches banned C/C++ functions with boundary verification, grades every finding by the evidence behind it, reads exploit mitigations and verifies signature integrity across PE, ELF and Mach-O, and reports what it could not reach. It never executes the sample and never transmits its contents.
> **AUTHOR:** Gilles Biagomba
> **LICENSE:** [GPLv3 or later](LICENSE)

---

## Why this matters

- **The problem is evidence, not detection.** Finding the string `strcpy` in a binary is trivial and nearly worthless. The question is whether it is a resolved call, a C++ method that merely shares the name, or a word inside a documentation blob. Binspector grades every occurrence by what backs it, so an import-table entry and an incidental substring are never rated alike, and the rule that demoted a finding is printed next to it.
- **A clean result has to be falsifiable.** Most scanners report what they found and stop. This one reports what it could not reach: members it failed to open, images with no readable import table, occurrences it suppressed and under which rule, indicators it stopped collecting. A clean result from a tool that silently skipped half the bundle is worse than no result at all, because somebody will act on it.
- **Containers are the blind spot.** A `.msixbundle`, `.jar`, `.nupkg` or `.zst` is compressed, so a byte scan of the outer file finds nothing and reports success. Binspector descends through nested containers in memory, bounded by caps on depth, expansion ratio and member count, and never writes a member to disk.
- **Hardening is more actionable than any string match.** A missing ASLR, DEP, RELRO, PIE or stack-canary flag is confirmable from headers alone, needs no source access, and is fixed by a build flag. Those are findings here, with the field they were read from and the remediation, not prose at the bottom of a report.
- **What it is NOT.** Static only. It does not execute the sample, disassemble it, or prove reachability, so a finding is a place to look rather than a demonstrated exploit. It is not a malware verdict, and it is not a trust decision: it verifies that a signature matches the bytes and that a chain is internally sound, then prints the anchor fingerprint for you to compare against a published thumbprint, because no code-signing root store exists to anchor against in pure Rust.
- **Honesty note.** Where an upstream parser was unsafe on crafted input, the walk was reimplemented locally and proved equivalent by differential against the original over hundreds of real images, rather than asserted. Numbers in this README come from measured runs. Capabilities that are scoped out say so and say why.

**Peer map:** Binspector = compiled-artifact review · source SAST = a peer tool · runtime and DAST = a peer tool.

---

## 🧬 Background / Lore

The name is the job: it inspects binaries. The logo is an armored aperture, because that is the
posture the tool takes toward its input. A binary you did not build is not a document to read, it
is a sealed thing you open carefully, from the outside, without letting it run.

It began as a Bash script that orchestrated other people's tools: peframe, binwalk, the VirusTotal
CLI, cve-bin-tool, valgrind, zzuf. That worked, but it was only as strong as the weakest assumption
in the chain, and two of its habits were disqualifying for the job: `vt scan` uploaded the sample
to a third party, and `valgrind ./$bin` executed it. You cannot examine something you do not trust
by running it, and you cannot keep an unreleased artifact confidential by uploading it.

The Rust port does the work in-process. The guiding principle is that a scanner must be honest
about what it did not do, which is why coverage gaps, suppressed findings, unread import tables and
unverified signatures are all first-class output rather than silence.

The legacy shell version is still in the tree under [legacy/](legacy/), kept for reference.

---

## 📚 Table of Contents

- [Why This Matters](#why-this-matters)
- [Background / Lore](#-background--lore)
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
- [Safety](#-safety)
- [Inspired By](#-inspired-by)
- [Legacy Shell Version](#-legacy-shell-version)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🚀 Features

- ✅ **Banned function detection**, boundary-verified so `targetsize` is never reported as `gets`, tiered `critical`/`high`/`medium`/`low` by evidence rather than by name
- ✅ **Evidence-gated severity**: `import`, `exact`, `symbolic` or `prose`. An import-table entry proves a call site exists; a string in a resource does not, and the two are not rated alike
- ✅ **Exploit mitigations as findings**, with evidence and remediation: ASLR, DEP, CFG, SafeSEH, /GS, CET and Authenticode on PE; NX, RELRO, PIE, stack canary, FORTIFY, executable stack and heap, and code signing on ELF and Mach-O
- ✅ **Signature verification**, not just signer attribution. The Authenticode digest is compared against the shipped bytes, and every certificate chain is verified cryptographically under RSA and ECDSA
- ✅ **Nested containers unpacked in memory**: `.msixbundle`, `.msix`, `.appx`, `.jar`, `.nupkg`, `.zip`, `.gz`, `.bz2`, `.xz`, `.zst`, `.7z`, `.cab`. Nothing is written to disk
- ✅ **Many targets or a whole directory in one report**, or `--split` for one report per target
- ✅ **Nine output formats**: `text`, `json`, `csv`, `html`, `markdown`, `sarif`, `sqlite`, `sql`, `all`
- ✅ **Third-party components and CVEs**, detected offline and resolved against NVD on request
- ✅ **Hash-only reputation** via VirusTotal and MetaDefender. File content is never transmitted
- ✅ **Fuzzes its own parsers**, differentially or through AFL++, honggfuzz, libFuzzer or WinAFL
- ✅ **Six platform targets**: Linux, macOS and Windows, on x64 and ARM64
- ✅ **Docker support**

---

## 🛠 Installation

### 📦 Using GitHub Releases

Download precompiled binaries from the [releases page](https://github.com/gbiagomba/Binspector/releases).
Each release ships a bare binary and an archive for every target.

| Platform | Architecture | Binary |
|----------|-------------|--------|
| Linux | x64 | `binspector-x86_64-unknown-linux-gnu-v5.3.0` |
| Linux | ARM64 | `binspector-aarch64-unknown-linux-gnu-v5.3.0` |
| macOS | x64 | `binspector-x86_64-apple-darwin-v5.3.0` |
| macOS | ARM64 | `binspector-aarch64-apple-darwin-v5.3.0` |
| Windows | x64 | `binspector-x86_64-pc-windows-msvc-v5.3.0.exe` |
| Windows | ARM64 | `binspector-aarch64-pc-windows-msvc-v5.3.0.exe` |

**Install (Linux/macOS):**

```bash
chmod +x binspector-*
sudo mv binspector-* /usr/local/bin/binspector
```

**Install (Windows PowerShell):**

```powershell
Move-Item binspector-*.exe C:\Windows\System32\binspector.exe
```

---

### 📚 Using Cargo

```bash
cargo install --git https://github.com/gbiagomba/Binspector
```

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
    --no-exe                      Skip PE, ELF and Mach-O parsing
    --reputation                  VirusTotal and MetaDefender lookup (hash only)
    --cve                         Resolve detected components against NVD
    --all-files                   Scan every file found, not only executables and archives
    --color <WHEN>                auto, always, never
    --palette <NAME>              default, colorblind
```

Resource caps (`--max-depth`, `--max-unpacked-bytes`, `--max-expansion-ratio`, `--max-members`,
`--max-hits`, `--ioc-cap`, `--max-targets` and others) all have safe defaults. Run
`binspector -h` for the complete list with their values.

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
binspector -p "PROJ-123" -o report.txt ./release-1.0.0.tar.gz

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
# Build release binary
make build

# Run with arguments
make run ARGS="--help"

# Run the full gate (fmt-check + clippy + loc-check + test + fuzz-build)
make check

# Differential fuzzing against a sample
make fuzz-diff BIN=./app.exe

# Clean build artifacts
make clean
```

---

## 🛡 Safety

Binspector is pointed at files that may be hostile, so these are properties, not aspirations:

- **The sample is never executed.** The legacy script ran `valgrind ./$bin`; that is not carried forward.
- **File content is never transmitted.** Reputation sends the hash only. The legacy `vt scan` uploaded the sample, which for an unreleased binary is a disclosure event.
- **Nothing is written to disk during a scan.** Containers are unpacked in memory, which removes extraction as an attack surface.
- **Every parser is bounds-checked and fuzzed.** Where an upstream parser raw-indexed attacker-controlled header fields, the walk was reimplemented locally with checked arithmetic and verified byte-for-byte against the original.
- **Resource caps on everything**: nesting depth, unpacked bytes, expansion ratio, member count, recorded hits. A decompression bomb degrades to a warning and partial results, never to an abort.
- **Revocation is deliberately not checked.** OCSP and CRL fetch a URL taken from the certificate under examination, which is attacker-controlled outbound traffic from the scanning host.

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
1,500 lines), the test suite, and a build of the fuzz harnesses. CI runs the same gate on
Linux, macOS and Windows before any release is tagged.

---

## 📜 License

This project is licensed under **GPLv3 or later**.
See [LICENSE](LICENSE) for details.

---

**⚡ Built with Rust | 🛡️ Secured by Design | 🚀 Production Ready**
