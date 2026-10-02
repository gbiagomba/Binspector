# Binspector report

**Project:** PROJ-4711

| Field | Value |
|---|---|
| Binary | `bundle.msixbundle` |
| Scanned | 2026-10-01T12:00:00Z |
| Size | 6.0 MiB (6,291,456 bytes) |
| Manifest SHA256 | `afafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafaf` (over 3 target digests, not a file hash) |
| Matching | case insensitive |
| Min string length | 4 |
| Banned names | 197 |

## Findings

9 distinct functions, 9 occurrences. Critical 2, high 2, medium 2, low 3.

| | Function | Severity | Category | Occurrences | Members |
|---|---|---|---|---:|---:|
| - | `getenv` | low | other | 1 | 1 |
| ! | `atoi` | medium | conversion | 1 | 1 |
| - | `memcpy` | low | memory-management | 1 | 1 |
| !! | `sprintf` | high | format-string | 1 | 1 |
| - | `memset` | low | memory-management | 1 | 1 |
| ! | `ShellExecuteW` | medium | process-creation | 1 | 1 |
| !! | `LoadLibraryExW` | high | dll-hijacking | 1 | 1 |
| !!! | `strcpy` | critical | buffer-overflow | 1 | 1 |
| !!! | `gets` | critical | buffer-overflow | 1 | 1 |

### Suppressed as low confidence

144 occurrences were whole-token matches inside namespace text or documentation prose, such as `System.Windows.Forms` or "Gets or sets", rather than function references. Re-run with `--include-low-confidence` to report them.

| Function | Suppressed |
|---|---:|
| `system` | 96 |
| `getenv` | 30 |

## Coverage

Container format `zip`, 7 members, 2.2 MiB unpacked, 11,200 strings.

| Member | Format | Size | Strings |
|---|---|---:|---:|
| `Microsoft.VCLibs.ARM.14.00.Desktop.appx :: App.exe` | pe | 1.0 MiB | 4,000 |
| `Microsoft.VCLibs.ARM.14.00.Desktop.appx :: plugins :: Packed.dll` | pe | 512.0 KiB | 2,500 |
| `Microsoft.VCLibs.ARM.14.00.Desktop.appx :: Weak.exe` | pe | 256.0 KiB | 1,800 |
| `Payload.msix :: usr :: lib :: libthing.so` | elf | 192.0 KiB | 1,200 |
| `Microsoft.VCLibs.ARM64.14.00.Desktop.appx :: Bridge.dll` | pe | 128.0 KiB | 900 |
| `Payload.msix :: Contents :: MacOS :: Helper` | macho | 96.0 KiB | 800 |
| `bundle :: '); DROP TABLE hits;-- :: 'quoted' OR 1=1 --.dll` | pe | 4.0 KiB | 12 |

## Remediation

```text
  - getenv
      review the call site: confirm the destination size is known and enforced, and that every input is validated after canonicalisation
  ! atoi
      use a conversion that reports failure (`strtol` with `errno`, `strtonum`, Rust's `parse`) rather than one that returns zero for both a valid zero and an error
  - memcpy
      the call itself is ordinary; the defect is always the length. Confirm the length is derived from the *destination* size rather than the source, and that it cannot be influenced by input
  !! sprintf
      never pass caller-influenced data as the format argument. Use a literal format and pass the data as a parameter, and prefer the `_s` or `n` variant that takes the destination size
  - memset
      check the allocation result, and compute the size with a checked multiply so an integer overflow cannot produce an undersized buffer
  ! ShellExecuteW
      pass a fully qualified, quoted application path rather than a bare name, so the executable cannot be resolved out of a directory an attacker can write to
  !! LoadLibraryExW
      load by a fully qualified path, and call `SetDefaultDllDirectories` with `LOAD_LIBRARY_SEARCH_SYSTEM32` at startup so an attacker-writable directory is never searched
  !!! strcpy
      replace with a bounded variant that takes the destination size and guarantees termination (`strcpy_s`, `strlcpy`, `snprintf`), or use a type that owns its buffer. A length check beside the call is not equivalent: it has to be right at every call site
  !!! gets
      `gets` cannot be used safely and was removed from C in C11. Use `fgets` with an explicit size, or `gets_s`
```

## Targets (3, 9 occurrence(s), 6 member(s) scanned, 3 of 3 reached an executable image)

```text
  a target is a file named on the command line or found by walking a directory; a member is anything unpacked out of one, nested archives included
  occurrences count every banned-name match that survived the evidence rules, so one function in one file can contribute several
  every target yielded at least one PE, ELF or Mach-O image, so no row is clean merely for want of something to analyse
  !! 2 target(s) carry their own scan warnings: Microsoft.VCLibs.ARM.14.00.Desktop.appx, vendor/bundles/arm64/Microsoft.WindowsAppRuntime.Redist.1.6/Payload.msix
     target                                 format       size members     c/h/m/l  selected by
  !! Microsoft.VCLibs.A~4.00.Desktop.appx#1 zip       6.0 MiB       3     1/1/2/2  extension:appx
     !! 1 warning(s): truncated central directory, 2 member(s) skipped
     Microsoft.VCLibs.A~4.00.Desktop.appx#2 zip      10.5 MiB       1     1/1/0/0  extension:appx
  !! vendor/bundles/arm6~t.1.6/Payload.msix zip       2.0 MiB       2     0/0/0/1  all-files
     !! 1 warning(s): no readable import table on 1 image
  Worst first, not scan order: critical, then high, then total occurrences.
  Each row counts only its own target; the totals above are their sum.
  Per-target paths and hashes (MD5, SHA1, SHA256) are in --format json.
```

## Exploit mitigations: 10 finding(s)

```text
  !!! critical [authenticode-digest] 1 image(s)
      Authenticode digest mismatch: the image does not match its own signature
      evidence: the SpcIndirectDataContent digest differs from the digest of the shipped bytes over the Authenticode range
      fix: do not trust the signer name on this image. Re-sign from a known-good build, and establish where the modification came from
      images: Packed.dll
  !! high [aslr] 1 image(s)
      ASLR disabled: the image loads at a predictable address
      evidence: IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE absent from the optional header
      fix: link with /DYNAMICBASE, which is the default in current toolchains
      images: Weak.exe
  !! high [dep] 1 image(s)
      DEP disabled: data pages remain executable
      evidence: IMAGE_DLLCHARACTERISTICS_NX_COMPAT absent from the optional header
      fix: link with /NXCOMPAT
      images: Weak.exe
  !! high [exec-stack] 1 image(s)
      Executable stack allowed: the image opts out of stack NX
      evidence: MH_ALLOW_STACK_EXECUTION set in the Mach-O header flags
      fix: drop -Wl,-allow_stack_execute from the link
      images: Helper
  !! high [nx] 1 image(s)
      Executable stack: stack data can be run as code
      evidence: PT_GNU_STACK program header carries PF_X
      fix: link with -Wl,-z,noexecstack, and give every hand-written assembly file a .note.GNU-stack marker so it stops forcing the flag on
      images: libthing.so
  ! medium [authenticode] 1 image(s)
      No Authenticode signature: the file's origin cannot be verified
      evidence: no certificate table in the image
      fix: sign the shipped binaries, including third-party ones you rebuild
      images: Weak.exe
  ! medium [cfg] 1 image(s)
      Control Flow Guard not instrumented: indirect calls are unchecked
      evidence: load config guard flags present without IMAGE_GUARD_CF_INSTRUMENTED
      fix: compile and link with /guard:cf
      images: Weak.exe
  ! medium [gs] 1 image(s)
      No stack cookie: a stack overflow is not detected on return
      evidence: load config directory present with no usable SecurityCookie
      fix: compile with /GS
      images: Weak.exe
  ! medium [macho-code-signature] 1 image(s)
      No code signature: the file's origin cannot be verified
      evidence: no LC_CODE_SIGNATURE load command in the image
      fix: codesign the shipped binaries, including third-party ones you rebuild
      images: Helper
  ! medium [relro] 1 image(s)
      RELRO not full: the GOT stays writable after relocation
      evidence: PT_GNU_RELRO absent, or present without BIND_NOW (no DF_BIND_NOW, DF_1_NOW, or DT_BIND_NOW in the dynamic section)
      fix: link with -Wl,-z,relro,-z,now
      images: libthing.so
```

## Executable analysis (4 PE images)

```text
  !! ASLR missing on 1 of 4 image(s): Weak.exe
  !! DEP missing on 1 of 4 image(s): Weak.exe
  !! CFG missing on 1 of 4 image(s): Weak.exe
  !! /GS missing on 1 of 4 image(s): Weak.exe
  !! Authenticode missing on 1 of 4 image(s): Weak.exe
  1 managed .NET assembly (their embedded text is metadata, not native code)
  !! Packed.dll: section .pack is both writable and executable
  !! Packed.dll: section .pack entropy 7.93 bits/byte suggests compressed content
  !! Bridge.dll: 3 TLS callback(s) run before the entry point
  Section entropy above 7.20 of 8.00 (1 section(s)); compressed, encrypted or packed
     7.93     7.5 KiB  Packed.dll `.pack`
  Findings by origin
    first-party (--first-party)        2
    unsigned                          1
    signed by Evil Corp <script~      1
    signed by Plugin Vendor           1
    not a parsed image                2
    Who signed each file, not who wrote the code in it: a third-party library compiled into a vendor-signed image is attributed to that vendor.
    Authenticode digest: 2 verified, 1 mismatched, 0 not compared.
    !! A mismatch means the shipped bytes are not the bytes that were signed, so the signer name on those images is worth nothing.
    Certificate chain: 1 broken, 1 partial, 1 self-signed.
    !! 1 chain(s) did not verify under the issuer they name: Packed.dll
    A partial chain means every embedded certificate verified and the root is not in the file, which is how Authenticode normally ships.
    3 certificate(s) are outside their validity window, which is not a defect: Authenticode is not expiry-sensitive when countersigned.
      anchor Example Signing CA                          1  sha256:a1a1a1a1a1a1a1a1
      anchor Internal Build CA                           1  sha256:9f9f9f9f9f9f9f9f
      anchor Unknown Issuer                              1  sha256:
    Verified is not trusted: no code-signing root store is consulted, because none exists in pure Rust. Compare an anchor fingerprint against its published thumbprint. Revocation is never checked.
  Bounded memory primitives: 2 import(s) across 2 of 4 image(s) (memcpy 1, memset 1)
    1 of those image(s) also import hardened _s variants
    A link-graph fact, not 2 findings: every native image calls these, and the defect would be a wrong size an import table cannot show. Omitted from the occurrence list below; complete in --format json, csv, sql, sqlite, and sarif.
  Named-pipe servers: 1 image(s), 1 importing no authorization primitive
    !! Bridge.dll: serves ConnectNamedPipe, CreateNamedPipeW, CreateNamedPipeW \\.\pipe\<script>alert(1)</script>|x
       builds its own security descriptor: SetEntriesInAclW, SetSecurityDescriptorDacl
       imports none of ImpersonateNamedPipeClient, OpenThreadToken, GetTokenInformation, CheckTokenMembership, AccessCheck
    Narrowing, not reachability: an unauthorized verdict means no authorization primitive is linked, not that a finding here is reachable. Absence is only evidence where the import table was readable.
  String hygiene: 3 hardened slot(s) across 1 image(s) against 1 unbounded across 1, 3.0 to 1
    1 image(s) import both forms, 0 only hardened, 0 only unbounded
    App.exe                                  1 unbounded, 3 hardened
    Slots are distinct import names per image, not call sites, so the same module built for four instruction sets counts four times: that is four files to change.
  Imports parsed: 21
  5 occurrence(s) confirmed by the import table rather than inferred from text
```

## Indicators (11 total)

```text
  URLs (2)
    https://update.example.com/v1/manifest.json
    http://192.0.2.44/beacon
  IPs (2)
    192.0.2.44
    198.51.100.7
  Emails (2)
    build@example.com
    support@example.net
  Registry keys (2)
    HKEY_LOCAL_MACHINE\SOFTWARE\Example\Agent
    HKCU\Software\Example\Run
  File paths (2)
    C:\Users\Eric\Desktop\ocv43\opencv-4.3.0\modules\core\src\system.cpp
    C:\Program Files\Example\bin\
  1,450 further indicator(s) were seen after --ioc-cap (500) was reached and not collected: 0 URL(s), 0 IP(s), 0 email(s), 0 registry key(s), 1450 path(s)
```

## Build provenance (1 developer path(s) in shipped binaries)

```text
  !! C:\Users\Eric\Desktop\ocv43\opencv-4.3.0\modules\core\src\system.cpp
  Each of these discloses a username, shows the artifact was built outside CI rather than reproducibly, and names directories that frequently identify a statically linked dependency absent from any manifest.
  fix: build in CI, and strip or remap source paths (`-fdebug-prefix-map`, `/PATHMAP`).
```

## DLL search order

```text
  1 occurrence(s) in category dll-hijacking, listed with the other findings
  1 occurrence(s) in category process-creation, listed with the other findings
  1 of 4 image(s) load modules at runtime: 0 hardened, 1 unhardened, 0 naming a module with no path
  !! no image restricts its own search path: none import SetDefaultDllDirectories or AddDllDirectory
  A surface, not a defect: the module argument is not recoverable without disassembly. Seek to the offsets above to confirm, and note that names already resolved from the import table, the api-ms-win-* API sets, and self-references are excluded.
```

## Imported modules not in the package (1 module(s) across 1 image(s))

```text
  !! Weak.exe: libcrypto-3-x64.dll (3 import(s))
       unsigned, so a substitute cannot be told from the vendor's copy, and imports no search-path hardening API
  Absent from the package is not absent at runtime: a system DLL, a side-by-side assembly or a separately installed redistributable all resolve without shipping here. What this says is that the search order decides what satisfies the import, not the build.
  fix: ship the dependency inside the package, and call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` early in process start so a module dropped beside the executable cannot win.
```

## Native analysis (2 ELF/Mach-O image(s))

```text
  !! NX (non-executable stack) missing on 1 of 2 image(s): libthing.so
  !! Full RELRO missing on 1 of 2 image(s): libthing.so
  !! Non-executable stack (Mach-O) missing on 1 of 2 image(s): Helper
  !! Code signature missing on 1 of 2 image(s): Helper
  Imports read: 1 via elf-dynsym
  1 of 2 image(s) had no readable import table, so for those the absence of an import is not evidence
```

## Carving (2 candidate embedded archive(s) or filesystem(s), 2 other signature(s))

```text
  252 checksum, certificate, and text marker(s) excluded as not being embedded files.
  A signature match is a lead, not proof. Extract with `binwalk -e` to confirm.
  Packed.dll
    [archive] zip at offset 0x40000 (262144 bytes)  ZIP archive, 3 entries
    [archive] gzip at offset 0x68000 (262144 bytes) [low confidence]  original name <script>alert(1)</script>|x
    [embedded] pe at offset 0x71000 (262144 bytes)  PE32+ executable
    plus 9 speculative match(es) not listed
  Bridge.dll
    [other] riff at offset 0x1f400 (262144 bytes) [low confidence]  unclassified
    plus 4 speculative match(es) not listed
```

## Third-party components (3)

```text
  openssl 1.1.1k
  zlib 1.2.11
  <script>alert(1)</script>|x 0.0.1
```

## Reputation (2 hash lookup(s), no file content transmitted)

```text
  bundle.msixbundle
    SHA256:       1111111111111111111111111111111111111111111111111111111111111111
    VirusTotal:   3 of 72 engines flagged this hash
    MetaDefender: no detections across 34 engines
    !!! At least one service flagged this hash.
  Microsoft.VCLibs.ARM.14.00.Desktop.appx
    SHA256:       2222222222222222222222222222222222222222222222222222222222222222
    VirusTotal:   hash not known to the service, which is not evidence that it is safe
    MetaDefender: no API key configured
```

## Known CVEs (2 across 2 component(s))

```text
  Highest CVSS: 7.4
  openssl 1.1.1k
    CVE-2021-3450 CVSS 7.4 (high)  https://nvd.nist.gov/vuln/detail/CVE-2021-3450
    CVE-2021-3711 CVSS n/a (critical)  https://nvd.nist.gov/vuln/detail/CVE-2021-3711
  zlib 1.2.11: lookup failed: NVD rate limit reached, retry after 30s
  24 detectors ran; silence is not an absence of risk
```

## Warnings

- Microsoft.VCLibs.ARM.14.00.Desktop.appx: truncated central directory, 2 member(s) skipped
- Payload.msix :: Contents :: MacOS :: Helper: no readable import table

## Occurrences

| Function | Severity | Member | Offset | Encoding | Context |
|---|---|---|---|---|---|
| `getenv` | low | `Payload.msix :: usr :: lib :: libthing.so` | 0x1236d | ascii | `sub_401000: &lt;script&gt;alert(1)&lt;/script&gt;\|x call getenv` |
| `atoi` | medium | `Microsoft.VCLibs.ARM.14.00.Desktop.appx :: App.exe` | 0x1102d | utf16le | `sub_401000: &lt;script&gt;alert(1)&lt;/script&gt;\|x call atoi` |
| `sprintf` | high | `Microsoft.VCLibs.ARM.14.00.Desktop.appx :: Weak.exe` | 0x3102d | ascii | `sub_401000: &lt;script&gt;alert(1)&lt;/script&gt;\|x call sprintf` |
| `ShellExecuteW` | medium | `bundle.msixbundle :: assets :: readme.txt` | 0x6d | ascii | `sub_401000: &lt;script&gt;alert(1)&lt;/script&gt;\|x call ShellExecuteW` |
| `LoadLibraryExW` | high | `Microsoft.VCLibs.ARM64.14.00.Desktop.appx :: Bridge.dll` | 0x4102d | ascii | `sub_401000: &lt;script&gt;alert(1)&lt;/script&gt;\|x call LoadLibraryExW` |
| `strcpy` | critical | `Microsoft.VCLibs.ARM.14.00.Desktop.appx :: plugins :: Packed.dll` | 0x2302d | ascii | `sub_401000: &lt;script&gt;alert(1)&lt;/script&gt;\|x call strcpy` |
| `gets` | critical | `Microsoft.VCLibs.ARM64.14.00.Desktop.appx :: Bridge.dll` | 0x4202d | ascii | `sub_401000: &lt;script&gt;alert(1)&lt;/script&gt;\|x call gets` |

