# Binspector

Binspector is a fast, cross-platform Rust CLI for reviewing binaries. It finds banned and
dangerous C/C++ functions, reads PE headers and exploit mitigations, detects third-party
components and their known CVEs, and fuzzes its own parsers.

Three properties make its output trustworthy:

**It opens containers.** A `.msixbundle` is a ZIP of `.msix` files holding the real PE
binaries. A scanner that reads the outer file byte by byte sees only compressed data and
finds nothing. Binspector unpacks nested archives in memory, and every finding carries the
full path to the file it came from.

**It matches whole tokens, then scores confidence.** A raw substring search reports `gets`
inside `targetsize` and `system` inside `FileSystem`. Binspector verifies identifier
boundaries, then scores what survives: an import-table symbol is not the same evidence as
the word `Gets` in an XML doc comment, and the two are reported differently.

**It prefers evidence over inference, and severity follows the evidence.** When a member parses
as a PE, the import directory is read directly: an import is a linker-recorded dependency, so it
is proof the binary calls the function. Since 5.0.0 that evidence sets the severity, rather than
a table keyed on the function name. A mangled C++ wrapper that *defines* a method called
`sprintf` is not a call to `sprintf`; a `strcpy` in a managed .NET assembly has no native call
site; `strlen` cannot overflow a buffer. Each of those is excluded or demoted by a named rule,
and every adjustment is recorded alongside what the name alone would have said.

On a 256 MiB Windows application bundle this is the difference between 3 findings that were all
false and a report a reviewer can act on: 244 occurrences, of which 68 are critical or high, every
critical one backed by an import table entry, with 87 occurrences excluded by named rules that the
report discloses individually. An adversarial three-agent review of the previous output refuted or
disputed 239 of 301 findings; the rules in 5.0.0 reproduce that partition without any rule that
says "only imports count".

## Install

```bash
# Unix/macOS
./scripts/install.sh

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

From source, which needs Rust:

```bash
git clone https://github.com/gbiagomba/Binspector
cd Binspector
cargo build --release
./target/release/binspector --help
```

Prebuilt binaries for Linux, macOS, and Windows on x86_64 and arm64 are attached to each
[release](https://github.com/gbiagomba/Binspector/releases), in two forms:

- `binspector-<target>-<tag>.tar.gz` or `.zip`, containing the binary plus `LICENSE` and
  `README.md`. Preferred: the archive preserves the executable bit, so it runs after
  extraction with no `chmod`.
- `binspector-<target>-<tag>` or `.exe`, a bare binary for scripted installs. Needs
  `chmod +x` on Unix, and carries no license text.

`LICENSE`, `README.md`, and `usage.md` are also attached standalone, so they can be linked
or fetched without downloading a platform archive.

Every feature is compiled into a default build, so a released binary writes all nine
formats, browses a report, and can carve. For a smaller build:

```bash
cargo build --release --no-default-features   # drops sqlite, carve, and repl
```

Via Docker:

```bash
docker build -t binspector .
docker run --rm -v "$PWD:/work" binspector /work/path/to/binary
```

See [scripts/README.md](scripts/README.md) for installer options.

## Quick start

```bash
# Scan a binary or bundle. Prints a summary
binspector ./app.exe

# Several targets, or a whole directory, in one report
binspector ./app.msixbundle ./app.appxsym ./Dependencies/

# One report per target instead
binspector --split ./Dependencies/

# Write a report, labeled with a project name
binspector -p "PROJ-123" -o report.txt ./SampleApp_1.0.0_x64.msixbundle

# SARIF for a pipeline, failing the build on critical findings
binspector --format sarif -o scan.sarif --fail-on critical ./app.exe

# Full annotated dump, colorblind palette
binspector --dump --palette colorblind ./app.exe | less -R

# PE analysis is automatic. Add reputation and CVE lookups (opt-in, hash only)
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

Nine output formats: `text`, `json`, `csv`, `html`, `markdown`, `sarif`, `sqlite`, `sql`,
and `all`. With no `-o`, output goes to `binspector_output-<timestamp>.<ext>` in the current
directory. Run `binspector -h` for every flag.

**[usage.md](usage.md) is the full reference**: every option, the severity and confidence
tiers, container support, PE analysis, reputation and CVE details, carving, fuzzing, the
safety properties, and how to read a report.

## What it reports

| | |
|---|---|
| **Banned functions** | Boundary-verified matches, tiered `critical`/`high`/`medium`, each with a member path and byte offset |
| **Confidence** | `import`, `exact`, `symbolic`, or `prose`. Namespace and documentation noise is excluded by default and disclosed |
| **Exploit mitigations** | ASLR, DEP, Control Flow Guard, SafeSEH, Authenticode, relocations, per PE image |
| **Exploit mitigation findings** | Missing ASLR, DEP, /GS, CFG, SafeSEH, CET, or Authenticode, as findings with evidence and remediation, not prose. Confirmable from metadata alone, which makes them the most actionable output |
| **Origin** | The Authenticode signer, plus `--first-party` to override it, so a finding in a vendor's binary is not in your queue. An identity claim, never a trust decision |
| **Dynamic loading** | Which loader APIs each image imports, whether it restricts its search path, and which modules it names without one. Reported as a surface, because an import table does not record what `LoadLibrary` was called with |
| **PE structure** | Sections with entropy and permissions, imports and exports, TLS callbacks, overlay, packer signals |
| **Components and CVEs** | Third-party libraries detected offline, resolved against NVD on request |
| **Reputation** | VirusTotal and MetaDefender, by hash only |
| **Coverage** | What was actually opened, and an explicit warning when no executable image was reached |

Two surfaces exist for checking the tool rather than the sample. `-v` reports what the scan
is doing, up to `-vv` which names the rule behind every suppressed occurrence, so a
suppression total can be counted instead of trusted. `binspector repl <report>` browses a
finished report read-only, which is worth it for the cross-cutting questions `jq` handles
worst, such as which images lack ASLR. Both are described in
[usage.md](usage.md#verbose-output).

## Safety

Binspector is built to be pointed at untrusted samples.

- **Nothing is written to disk during a scan.** Archives are unpacked in memory.
- **The sample is never executed.** Binspector only reads bytes.
- **Decompression bombs are capped** on depth, total bytes, member size, expansion ratio,
  and member count, and a breach degrades to a warning with partial results.
- **No file content leaves the machine.** Reputation sends a hash, CVE lookup sends a
  component name, and only when asked.
- **API keys never appear in a command line**, because arguments are visible through `ps`.

Details in [usage.md](usage.md#safety-properties).

## Inspired by

Binspector began as a shell script that orchestrated other people's tools. The Rust port
does the work in-process, but the ideas and the reference data come from these projects, and
it is worth naming them.

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

## Legacy shell version

The original Bash implementation lives under [legacy/](legacy/). It shelled out to peframe,
binwalk, the VirusTotal CLI, MetaDefender, cve-bin-tool, valgrind, and zzuf. Two of its
behaviors are deliberately not carried forward: `vt scan` uploaded the sample to a third
party, and `valgrind ./$bin` executed it.

## Development

```bash
make check    # fmt-check + clippy + loc-check + tests + fuzz-build
make help     # all targets
```

No `.rs` file exceeds 1500 lines, enforced by `make loc-check` in CI. See
[usage.md](usage.md#development) for the project layout.

## License

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).

Binspector links the binwalk library under the `carve` feature and several MIT and
Apache-2.0 crates; those licenses are compatible with distributing this work under the
GPL.
