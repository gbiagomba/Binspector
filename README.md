# Binspector
Binspector is now a fast, cross‑platform Rust CLI that scans an executable binary for nearly 200 banned and dangerous C functions by extracting embedded strings (ASCII and UTF‑16LE). It also reports file hashes to support downstream checks. A future release will re‑introduce optional fuzzing as a subcommand.

## Install (v2)

- From source (requires Rust):
```
git clone https://github.com/gbiagomba/Binspector
cd Binspector
cargo build --release
./target/release/binspector --help
```

- Via Docker:
```
docker build -t binspector .
docker run --rm -v "$PWD:/work" binspector /work/path/to/binary
```

## Usage
```
binspector <path-to-binary> \
  [--project <name>] [--min-len 4] [--json] [--banned-list FILE] \
  [--matches-only] [--format text|json|csv] [--output FILE] \
  [--no-ascii] [--no-utf16] [--ignore-case] [--banned-filter REGEX]
```

Examples:
- Basic scan: `binspector ./a.out`
- JSON output: `binspector ./a.out --json > report.json`
- Longer string threshold: `binspector ./a.out --min-len 6`
- Custom banned list: `binspector ./a.out --banned-list ./my_banned.txt`
- Matches-only CSV file: `binspector ./a.out --matches-only --format csv --output matches.csv`
- Matches-only JSON file: `binspector ./a.out --matches-only --format json --output matches.json`
 - Disable ASCII extraction: `binspector ./a.out --no-ascii`
 - Disable UTF-16LE extraction: `binspector ./a.out --no-utf16`
 - Case-insensitive matching: `binspector ./a.out --ignore-case`
 - Filter banned names via regex: `binspector ./a.out --banned-filter '^str.*'`

Notes:
- `--format` overrides `--json`.
- Warning: CSV format is only supported with `--matches-only`.
- Banned list sanitization: zero-width/format/control characters are stripped, and whitespace splits multiple tokens on a line (to handle legacy list quirks).
 - Validation: Setting both `--no-ascii` and `--no-utf16` errors; enable at least one.

## TODO
- [ ] Fuzzing subcommand (valgrind/zzuf integration)
- [ ] Optional external tools integration (VirusTotal, MetaDefender, binwalk, cve-bin-tool)
- [ ] Rich report formats and structured outputs

## References
1. https://docs.microsoft.com/en-us/previous-versions/bb288454(v=msdn.10)?redirectedfrom=MSDN
2. https://github.com/intel/safestringlib/wiki/SDL-List-of-Banned-Functions
3. https://github.com/microsoft/ChakraCore/blob/master/lib/Common/Banned.h
4. https://security.web.cern.ch/security/recommendations/en/codetools/c.shtml

## Legacy Shell Version (v1)
The original Bash implementation lives under `legacy/`. It relied on external tools (peframe, binwalk, VirusTotal CLI, MetaDefender, cve-bin-tool, valgrind, zzuf). The Rust port focuses on first‑class, cross‑platform scanning without external dependencies.
