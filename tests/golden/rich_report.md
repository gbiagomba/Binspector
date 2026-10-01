# Binspector report

**Project:** PROJ-4711

| Field | Value |
|---|---|
| Binary | `bundle.msixbundle` |
| Scanned | 2026-10-01T12:00:00Z |
| Size | 6.0 MiB (6,291,456 bytes) |
| Manifest SHA256 | `1111111111111111111111111111111111111111111111111111111111111111` (over 3 target digests, not a file hash) |
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

Container format `zip`, 6 members, 2.2 MiB unpacked, 11,200 strings.

| Member | Format | Size | Strings |
|---|---|---:|---:|
| `Microsoft.VCLibs.ARM.14.00.Desktop.appx :: App.exe` | pe | 1.0 MiB | 4,000 |
| `Microsoft.VCLibs.ARM.14.00.Desktop.appx :: plugins :: Packed.dll` | pe | 512.0 KiB | 2,500 |
| `Microsoft.VCLibs.ARM.14.00.Desktop.appx :: Weak.exe` | pe | 256.0 KiB | 1,800 |
| `Payload.msix :: usr :: lib :: libthing.so` | elf | 192.0 KiB | 1,200 |
| `Microsoft.VCLibs.ARM64.14.00.Desktop.appx :: Bridge.dll` | pe | 128.0 KiB | 900 |
| `Payload.msix :: Contents :: MacOS :: Helper` | macho | 96.0 KiB | 800 |

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

