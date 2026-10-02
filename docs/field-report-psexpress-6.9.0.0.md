# Field report: binspector 4.2.1 through 5.5.0 against Photoshop Express 6.9.0.0

**Reporter:** Gilles Biagomba
**Date:** 2026-10-02
**Target:** `PSExpress_6.9.0.0_x64.msixbundle` plus 9 sibling targets, 553,547,392 bytes, `sha256 52e12135daf677bc80c2513025fc7408b5adc4d12d76f664102f595c07016ae1`
**Runs compared:** 4.2.1 (301 hits, 1 target), 5.3.0, 5.4.0, 5.5.0 (1,355 hits, 10 targets)
**Context:** three adversarial adjudication passes over the full hit set, no sampling. Every claim below was verified against the artifacts rather than taken from the report.

This is written as a tool-improvement report, not a bug list. Where the tool is right and useful I say so, because the signal-to-noise argument cuts both ways and the parts that work are the reason the rest is worth fixing.

---

## 1. What 5.x gets right

Worth stating first, because the 4.2.1 to 5.3.0 jump was a large improvement and the exclusion machinery is the reason.

- **All 57 criticals are import-table confirmed.** In 4.2.1 the critical set included four Adobe safe-string wrappers and a C++ member function. In 5.3.0 onward every critical is backed by an IAT entry. That single change is what made the output adjudicable.
- **The exclusion rules fire and are correctly reasoned.** 33,334 occurrences suppressed: `prose` 32,594, `ambiguous-name-no-import` 532, `symbol-definition` 185, `managed-no-native-call` 23. All four verified present and firing.
- **The three demotion rules are sound and self-documenting.** `non-executable-member` (694 applications), `read-only-primitive` (255), `bounded-memory-primitive` (352). Each carries a `rule`, `from`, `to` and human-readable `evidence` string on the hit record. Being able to read why a severity moved is the single most useful thing in the schema.
- **`posture.aslr` is the highest-value output in the whole report.** Three modules lacking `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`, independently reproduced twice by parsing the optional header directly, matching the tool exactly. This became a filed finding. Nothing else in the report produced one on its own.
- **`iocs.cap` and `iocs.dropped` in 5.5.0 are a real improvement.** 5.3.0 and 5.4.0 truncated IOCs silently. Disclosing that 40,223 file paths were discarded is the correct behaviour even though it makes the output look worse.

---

## 2. Defects that change a reviewer's conclusion

Ordered by how badly each one misleads.

### 2.1 Case-insensitive matching produces 304 false criticals from one identifier

`scan.case_sensitive` is `False` by default. The banned pattern `SearchPath` matched the camelCase identifier `searchPath`, a local or member variable name recovered from a PDB symbol stream. `SELECT DISTINCT context` over those 304 hits returns exactly one row: `searchPath`.

**That is 22% of the entire 1,355-hit report refuted by one query.** Base severity for all 304 was `high`; only `non-executable-member` saved them from being reported as such.

Suggested fix: default `case_sensitive` to true for Win32 API names. The API surface is case-exact. An opt-in `--case-insensitive` for codebases with inconsistent naming would preserve the current behaviour for anyone relying on it.

### 2.2 The severity model credits bounded memory primitives but not bounded string primitives

`bounded-memory-primitive` demotes `memcpy`, `memset`, `memmove` and `wmemcpy` from high to medium, with the stated evidence *"memcpy takes an explicit size argument"*. Verified application counts: `memset` 130, `memcpy` 114, `memmove` 97, `wmemcpy` 11.

The same rule never applies to `strncpy`, `wcsncpy`, `strncat`, `wcsncat`, `lstrcpynA` or `lstrcpynW`, all of which also take an explicit count. Result: **24 of 57 criticals (42%) are counted primitives rated identically to `strcpy`.** Zero of them carry the adjustment.

`strncpy` is the single largest critical function in the report at 15 criticals. Its real failure mode is non-termination, [CWE-170](https://cwe.mitre.org/data/definitions/170.html), not unbounded overflow [CWE-787](https://cwe.mitre.org/data/definitions/787.html). Rating it identically to `strcpy` is the reason the critical count is not defensible as filed.

Suggested fix: extend `bounded-memory-primitive` to the counted string family, demote to medium, and map them to CWE-170 rather than the overflow CWEs.

### 2.3 Safe-variant blindness inverts the hygiene signal

The 226-pattern banned list contains no `_s` entries and no StrSafe entries. An independent parse of all 564 PE members with an import table found:

- **313 safe counted or `_s` string-handling import slots across 175 members**
- **55 unsafe slots across 31 members**

That is a 5.7-to-1 ratio in favour of the safe forms, and the report shows **zero** of the 313. 21 of the 31 flagged members import both forms, which is the signature of a codebase mid-migration rather than one that never started. 154 members import only safe variants and receive no credit at all.

Concretely: `AdobePDFL.dll` carries 12 of the 57 criticals and also imports `lstrcpynA`, `lstrcpynW`, `wcscat_s`, `wcscpy_s`, `wcsncat_s` and `wcsncpy_s`. `EditorManagerBridge.dll` carries 3 criticals and imports `strcpy_s`, `strcat_s` and `gets_s`.

This is the defect most likely to cost the tool credibility with a product team, because the team knows it has been migrating and the report says nothing about it.

Suggested fix: add the `_s` and StrSafe families as a `credited` category, and emit a per-member safe-to-unsafe ratio. A module that imports only safe variants should be visibly distinguished from one that was never scanned.

### 2.4 The UCRT formatting backends are absent from the list, so "no criticals" is unsound

Modern MSVC does not emit a call to `sprintf`. It emits `__stdio_common_vsprintf`. The banned list contains none of `__stdio_common_vsprintf`, `__stdio_common_vswprintf`, `__stdio_common_vfprintf` or `__stdio_common_vfwprintf`.

**41 members of the inner package import at least one unbounded backend.** The tool reports zero of them.

This cuts both ways, which is why it matters. It deflates the 5 `printf` high hits, which are bare strings with no matching import (`D3DCompiler_47_cor3.dll` imports no printf-family function at all, so that hit is a plain false positive). And it means a clean critical count for an MSVC-built module is not evidence of safe formatting. Any gating decision made on this output is unsound for MSVC targets in both directions.

Suggested fix: add the UCRT backends, and distinguish the `_s` suffixed forms (`__stdio_common_vsprintf_s`, `__stdio_common_vsnprintf_s`) as credited rather than banned.

### 2.5 Confidence tiering misses leading-underscore CRT names

`AdobePDFL.dll` genuinely imports `api-ms-win-crt-stdio-l1-1-0.dll!_mktemp`, confirmed by direct import-table parse. `_mktemp_s` is not imported. The tool reports this hit at `confidence: exact`, its tier for a bare string match with no import backing.

This under-rates a real [CWE-377](https://cwe.mitre.org/data/definitions/377.html) finding, and it is a class defect rather than a one-off: the confidence resolver does not appear to normalise the leading-underscore MSVC CRT naming convention, so an entire family of real imports is systematically downgraded to string matches.

My own first pass repeated the tool's error by trusting the `confidence` field, which is worth mentioning because the field is trusted by default and should be trustworthy.

Suggested fix: normalise `_name` against `name` when resolving imports against the banned list.

### 2.6 `safe-seh` gates on bitness rather than architecture

The stated gate is *"a 32-bit image whose load config registers no exception handlers"*. SafeSEH is an x86-32 `/SAFESEH` feature. ARM, ARM64 and x64 use table-driven unwind in `.pdata` and `.xdata` and have no overwritable SEH chain.

The tool's own member list proves the error by naming `Microsoft.VCLibs.ARM.14.00.Desktop.appx :: concrt140.dll`, an `armnt` image. ARM is 32-bit and has no SEH.

Machine-type census across the 879 PE images: `amd64` 241, `i386` 537, `armnt` 22, `arm64` 79. Of those 537 `i386` images, **435 are managed .NET assemblies** (MSIL marked `i386` with a CLR directory) with no native SEH at all. Native `i386`: 102. Of those 102, only 14 actually lack a handler table, and all 14 are resource-only satellite DLLs with no code and therefore no handlers to register.

The finding also disagrees with itself: the posture block says 66 images, the executable-analysis block in the same report says 68.

Suggested fix: gate on `machine == IMAGE_FILE_MACHINE_I386` **and** absence of a CLR directory. Reconcile the two counts.

### 2.7 Data-only members produce physically impossible findings

`icudt74.dll` is ICU 74's locale data packaged as a resource DLL. Independent PE parse: **one section (`.rdata`, 36,502,952 bytes), `IMAGE_SCN_MEM_EXECUTE` absent, `IMAGE_SCN_CNT_CODE` false, no import directory, no IAT.** Data directories present are export and debug only.

It receives **5 HIGH-severity `system` findings**. A module with no code section and no import table cannot call `system()`. The matched strings are CLDR numbering-system and calendar-system keys.

Same class: `Resources/ModelsData/DIM_640_0727_he_patch3.data`, a machine-learning weight file, gets an `atoi` hit at `symbolic` confidence on the byte fragment `(atoi`.

Suggested fix: a `no-code-section` exclusion rule, keyed on absence of an executable section or an import directory, in the same family as the existing `non-executable-member` rule.

### 2.8 The C runtime is flagged for defining the primitives it exports

`vcruntime140_cor3.dll` is reported for `memcpy` (medium), `memmove` (medium), `memset` (medium) and `memcmp` (low), all at `confidence: exact`, none at `import`. `coreclr.dll` for `wcslen`.

The CRT is the definition site. The matched strings are export-table names, not call sites. Flagging the runtime for providing `memcpy` inverts the direction of the finding.

Suggested fix: when a matched name appears in a member's **export** table and not its import table, suppress or reclassify. This is the existing `symbol-definition` rule, which appears not to consult the export directory.

### 2.9 Mangled C++ names match the mitigation rather than the defect

Two instances, both of which cost real credibility because they charge a team for having done the right thing:

- `?sprintf@WRStrSafe@@SAHPEAD_KPEBDZZ` and siblings, matched as `sprintf`. `WRStrSafe` is Adobe's own bounded safe-string wrapper (`g11n-libraries/wrservices`), and every method takes an explicit destination capacity. In 4.2.1 four of the criticals were this.
- `??$sprintf@...@StringUtils@internal@ngl@adobe@@...` returning `std::basic_string`, which is the safe allocating wrapper idiom. Three hits in 5.x.
- `cv::FileStorage::Impl::gets` matched as C `gets`, which was removed in C11 and which the UCRT does not export.

Suggested fix: when `confidence` is `symbolic` and the context matches a mangled-name pattern (`?name@Class@@`, or a namespace-qualified `ns::Class::method`), suppress. The mangled name carries the class and the return type, both of which are decisive.

---

## 3. Defects introduced or still open in 5.5.0

### 3.1 `iocs.build_paths` under-reports by roughly two orders of magnitude

`build_paths` returns **10 entries**. Across the PDBs and shipped members examined locally I counted **over 1,200 distinct `C:\Users\` build paths**. In the shipped retail DLLs alone there are 65 distinct `C:\Users\Eric\...` paths in `EditorManagerBridge.dll` and 62 in `PSXNativeCommonUtility.dll`, against the 4 reported.

The heuristic also appears keyed on `C:\Users\`, so it surfaced **none of the three build roots that carry the actual provenance story**:

```
D:\B\workspace\Harmony-release\...              <- the governed CI root
C:\A\ATE\ate\dist\gearinch_cli_nolilo\...       <- Adobe shared technology
C:\jenkins\workspace\CR-CLIENT-12.0.0\...       <- Crash Reporter CI
```

`build_paths` is the field most likely to be read as an inventory, and it cannot support that reading. There is also no `build_paths` entry in `iocs.dropped`, so it is unclear whether the 500 cap applies to it or whether a separate undocumented sampling step is responsible for 10 of 1,200.

### 3.2 The path regex truncates at `~` and `{`, manufacturing phantom entries

Two of the ten `build_paths` entries are not paths:

| Reported | Actual string in the binary |
| --- | --- |
| `C:\Users\ADMINI` | `C:\Users\ADMINI~1\AppData\Local\Temp\lnk{E16D7DA7-3EF6-4F0D-B161-E565EFAD704E}.tmp` |
| `C:\Users\crbldr\AppData\Local\Temp\lnk` | `C:\Users\crbldr\AppData\Local\Temp\lnk{CA319B19-4DF1-4C33-B3C5-BBCB3F58B4A7}.tmp` |

Both are MSVC `link.exe` temporary files, which carry no provenance meaning at all. The first is worse than useless: `ADMINI~1` is a Windows 8.3 short name, and truncating at the tilde produces a phantom account name that a reader will take for a real identity. It cost me a verification cycle.

Suggested fix: include `~` and `{` in the path character class, and add an exclusion for `AppData\Local\Temp\lnk*.tmp` since linker temporaries are never provenance.

### 3.3 `build_paths` is a regression against 5.3.0 for at least one dependency

5.3.0's `iocs.file_paths` contained **all three** NAudio paths (`NAudio.Core.pdb`, `NAudio.Wasapi.pdb`, `NAudio.pdb`) plus the truncated `crbldr` string. In 5.5.0 those moved out of `file_paths` into `build_paths`, and `build_paths` reports **two** of the three.

5.5.0 therefore reports strictly less about that component than its predecessor did. Whatever the promotion logic is, it is dropping entries rather than reclassifying them.

### 3.4 `intel.components` misses a shipped component and invents one that is not there

**Misses:** `AdobeGrowthSDK.dll` ships zlib 1.3, verbatim `deflate 1.3 Copyright 1995-2023 Jean-loup Gailly and Mark Adler`. `intel.components` lists zlib at 1.2.11, 1.2.12, 1.2.13 and 1.3.1 only. A reviewer using this field as the zlib inventory will miss a whole version.

**Invents:** `intel.components` reports `icu` version `36` on the evidence string `icudt36.dll`. **No member named `icudt36.dll` exists** among the 4,281 scanned. The only ICU payloads are `icudt74.dll` and `icuuc74.dll`. ICU 36 is a stale filename string embedded in some other module, reported as a shipped component.

Suggested fix: for the filename-evidence class of component detection, cross-check against the member list before emitting. A component whose only evidence is a filename that does not exist in the archive should be suppressed or flagged as unconfirmed.

### 3.5 `coverage.carve_ran` is `False` with no stated reason

The carve surface shipped in 5.5.0 but did not run: `carve_ran: False`, `carved: []`. No warning explains why. A reviewer cannot tell whether carving was skipped by configuration, skipped because no candidate was found, or failed. All three mean different things for coverage.

---

## 4. Export and presentation issues

These do not change a verdict but they cause a reviewer to miss things.

- **All four posture findings exist only in `binspector.json`.** The SQLite export has no `posture` table; the markdown export has no posture section in 5.3.0. A reviewer working from the recommended database silently misses `posture.aslr`, which is the highest-value finding the tool produces. 5.5.0 added `indicators` and `indicators_dropped` tables to SQLite, which is the right direction, and posture should follow.
- **Posture member lists are truncated at 50** with no indication in the record. `authenticode` shows 50 of 179, `safe-seh` 50 of 66, `cet` 50 of 69. Because the stored 50 are in scan order, the first 50 for `authenticode` were all from one vendor, which invites exactly the wrong inference. I made that inference and had to retract it. An explicit `members_truncated: true` plus a count would prevent it.
- **The `targets[]` rollup disagrees with the `hits` table by one.** For the msixbundle, `targets[]` reports medium 104 and low 72; the hit rows yield medium 103 and low 73. One hit's severity differs between the rollup and the row data. Totals still reconcile to 1,355.
- **`excluded_by_rule` is populated in JSON and empty in SQLite.** A consumer working from the database cannot see that 33,334 occurrences were suppressed, which is the context that makes the remaining count meaningful.
- **Top-level `warnings` aggregates per-target warnings without naming the target.** The warning *"no executable image (PE, ELF, or Mach-O) was reached"* is **correct** and applies only to the `PSExpress_6.9.0.0.appxsym` target, which has `reached_executable: false`. At the top level it reads as a claim about the whole scan, and two independent reviewers in my sessions concluded the warning was stale. It is not. The scan parsed 1,567 PE images against 2,714 `unknown` members. Attaching the target label to each aggregated warning would fix this.
- **No deduplication, in two dimensions.** 1,355 hits collapse to 754 distinct `(member, function, severity)` triples. Across architectures, 207 of the 314 Microsoft-redistributable hits are the same module recompiled for another instruction set, and 9 of those are not even recompilations: `win32/Microsoft.WindowsAppRuntime.2.msix` and `x86/Microsoft.WindowsAppRuntime.2.msix` are byte-identical (`sha256 93427a9b3ff71d613d10b90cad35b8b8c1cfe34851720d84d1dca52c7ffd124a`), so those hits are the same file scanned twice. A `logical_findings` count alongside the raw count would make the headline number defensible.
- **No vendor or authorship attribution.** Of the 244 hits labelled by root archive as the Adobe product, only 194 are against Adobe-authored code. The rest are Microsoft's bundled .NET and WinUI runtime (28), third-party OSS (16) and data-only members (6). Adobe-authored criticals are 27 of 57, not 31. I got this wrong initially by trusting the root-archive grouping. An `owner` or `vendor` field, even heuristic, would prevent every consumer from re-deriving it.

---

## 5. The gap that mattered most: no object or compiland provenance

The single most consequential finding of this entire engagement was invisible to binspector at every version, and I want to describe it precisely because it suggests a feature rather than a bug fix.

`EditorManagerBridge.dll` ships a **mixed-version zlib**: the compression and decompression core (`adler32`, `crc32`, `deflate`, `inffast`, `inflate`, `inftrees`, `trees`, `zutil`) is zlib 1.2.11 from one vendored tree, while the `gz*` file-I/O layer (`gzclose`, `gzlib`, `gzread`, `gzwrite`) is zlib 1.3.1 from a different tree. Someone attempted a zlib security update by swapping a static library, and in this module the other tree's objects won the MSVC duplicate-symbol race for every security-relevant function. The patch shipped and did not take.

binspector reports this module as `zlib 1.2.11`, which is what the version banner says and is half the truth. No version-based tool can represent this state, because no zlib release exists in it.

Recovering it required reading the **compiland records in the PDB**, which name the source object path for every translation unit in the image. That data was sitting in a target binspector already scans (`PSExpress_6.9.0.0.appxsym`), and the tool extracted strings from it while discarding the structure that made it useful.

**Suggested feature.** When a PDB is present for a scanned PE, parse the compiland and library records and emit, per member, the set of source trees that contributed objects. Two concrete outputs would have surfaced this immediately:

1. A `provenance` block per member listing distinct source roots and the object count from each.
2. A warning when one member receives objects for the **same component** from more than one source tree, which is the mixed-version condition.

This would also fix `build_paths` properly, because compiland records are structured and complete where string extraction is capped and heuristic. The 12 zlib objects I needed were all in the PDB; `build_paths` surfaced 2 of them.

---

## 6. Priority, if it helps

| Priority | Item | Why |
| --- | --- | --- |
| 1 | §2.1 case sensitivity | One flag change removes 22% of the report as false |
| 2 | §2.3 safe-variant credit | Biggest credibility cost with product teams |
| 3 | §2.2 bounded string primitives | Makes the critical count defensible |
| 4 | §2.4 UCRT backends | Current output cannot support a build gate on MSVC targets |
| 5 | §4 posture in SQLite and markdown | Highest-value finding is invisible in two of three exports |
| 6 | §3.1 and §3.2 build_paths | Field is actively misleading as an inventory |
| 7 | §5 compiland provenance | New capability, highest analytical value |
| 8 | §2.7 no-code-section rule | Removes physically impossible findings |
| 9 | §2.5 leading-underscore CRT names | Under-rates real findings |
| 10 | §2.6 safe-seh architecture gate | Whole finding is invalid for most of its population |

---

## 7. Follow-up: 5.7.0 closes eight of the ten

**Added 2026-10-02 after re-running the same corpus against 5.7.0** (`binspector_output-2026.10.02-13.27.29.json`). Same 10 targets, same `sha256 52e12135daf677bc80c2513025fc7408b5adc4d12d76f664102f595c07016ae1`. A 5.6.0 run also exists and is byte-identical to 5.5.0; 5.7.0 is the first version since 5.3.0 whose hit set changes.

Headline numbers: hits 1,355 to 1,300, **criticals 57 to 33**, `case_sensitive` now `True`, `banned_list_size` 226 to 232, `excluded_total` 33,334 to 1,773, `safe-seh` affected 66 to 54.

The `excluded_total` collapse is the nicest result in here. `prose` suppressions fell from 32,594 to 1,001, because case-sensitive matching eliminates the noise at the match stage instead of filtering it afterwards. The exclusion ledger got smaller because the matcher got better, which is the right direction.

| Priority in §6 | Item | 5.7.0 |
| --- | --- | --- |
| 1 | §2.1 case sensitivity | ✅ **Fixed.** `SearchPath` 304 hits to 0; the pattern no longer fires at all |
| 2 | §2.3 safe-variant credit | ❌ **Open.** Zero `_s` or StrSafe entries in `summary` |
| 3 | §2.2 bounded string primitives | ✅ **Fixed.** New `bounded-string-primitive` rule, 37 applications; all six counted functions now medium |
| 4 | §2.4 UCRT backends | ✅ **Fixed.** All four `__stdio_common_v*printf` fire; 281 hits, 231 import-confirmed |
| 5 | §4 posture in SQLite and markdown | ✅ **Fixed.** New `posture` and `posture_members` tables; markdown carries the ASLR finding |
| 6 | §3.1, §3.2 build_paths | ⬜ **Not re-examined** in this pass. Unverified either way |
| 7 | §5 compiland provenance | ⬜ **Not implemented** |
| 8 | §2.7 no-code-section rule | ✅ **Fixed.** New `no-code-section` exclusion, 5 suppressed. `icudt74.dll` 6 hits to 0, eliminating the five physically impossible HIGH `system` findings |
| 9 | §2.5 leading-underscore CRT names | ✅ **Fixed.** `_mktemp` now `confidence: import`, severity `high` |
| 10 | §2.6 safe-seh architecture gate | ✅ **Fixed.** 66 to 54 affected, zero ARM-rooted images among stored members |

Two fixes I had not ranked, both landed:

- **§2.8 CRT flagged for its own exports** is closed by a new `export-definition-site` exclusion rule, 24 suppressed.
- **§4 rollup disagreement** is closed. `targets[]` and the `hits` table now reconcile exactly at 13 critical / 99 high / 118 medium / 72 low.

### The one partial, stated precisely

`posture_members` is the right mechanism and I am glad it exists, but it is **still capped at 50 rows per finding**: `authenticode` 50 of 179, `safe-seh` 50 of 54, `cet` 50 of 69. The table was the request; the cap was the complaint, and it carried over. `aslr` is complete only because 3 falls under the cap.

The reason this matters is in §4: because the stored members are in scan order, the first 50 for `authenticode` all came from one vendor, which invites a wrong inference about ownership. I made that inference from the JSON and had to retract it publicly. A table that reproduces the cap reproduces the trap. Either lift it for `posture_members` specifically, since it is a two-column table and cheap, or emit `members_truncated` with the true count.

### What the critical count looks like now

33 criticals, all genuinely unbounded: `lstrcpyA`, `lstrcpyW`, `lstrcatA`, `lstrcatW`, `strcpy`, `strcat`, `wcscpy`, `wcscat`, `wsprintfW`. No counted primitive remains critical.

By authorship: Microsoft redistributable 20, **Adobe 12**, third-party bundled 1 (`icuuc74.dll`). The Adobe 12 are `AdobePDFL.dll` 7, `ACE.dll` 2, `EditorManagerBridge.dll` 2, `SVGRE.dll` 1.

Worth reporting back because it is the real validation: **that is exactly the set three adversarial adjudication passes had already sustained by hand**, after withdrawing the 24 bounded primitives 5.3.0 rated critical. 5.7.0 converged on the same 12 independently. This is the first run on this target whose unadjudicated critical count could be filed without correction, which is the whole point of the severity-model work.

### The new UCRT family behaves well, with one caveat

231 of the 281 hits are import-confirmed, which is the right tier, and 50 land in the symbol package at `exact` where they belong. 49 are Adobe-authored across 27 distinct modules.

The caveat is interpretive rather than a defect: `__stdio_common_vsprintf` also backs bounded callers in some code paths, so the import is weaker evidence than a direct `sprintf` import. A consumer will read `high` severity across 231 hits as 231 defects. Consider either a distinct category for "unbounded backend, caller bound unknown" or a note in the remediation text, so the tier reflects that this is linkage to a shared backend rather than a definite unbounded call.

### Still open, in priority order

1. **Safe-variant credit (§2.3).** Now the highest-value remaining item. 313 safe counted or `_s` import slots across 175 members against 55 unsafe across 31, and the report still shows zero of the 313. 21 of the 31 flagged members import both forms. A product team reading this report still cannot see that its own migration is 5.7-to-1 ahead.
2. **Posture member cap (§4, partial above).**
3. **Compiland provenance (§5).** Unimplemented, and still the capability that produced the single most consequential finding of this engagement: a module shipping a zlib 1.2.11 core with a 1.3.1 `gz*` layer because a static-library patch lost the duplicate-symbol race. No version-based output can represent that state, and nothing in 5.7.0 would surface it.
4. **`iocs.build_paths` (§3.1, §3.2).** Not re-examined against 5.7.0.

Eight of ten in one release cycle is a fast turnaround and the two highest-impact matcher changes, case sensitivity and the bounded-string rule, are exactly the ones that moved the output from unfileable to fileable. Thank you for that.

---

## 8. Method note

Every number here was re-derived from the artifacts rather than read out of the report, using independently written PE import-table, optional-header and certificate-directory parsers plus PDB compiland extraction. Where my own earlier conclusions were wrong they are noted as such in this document, because two of them came from trusting report fields (`confidence` on `_mktemp`, and the truncated `posture.authenticode` member list) that a reader is entitled to trust.

One environment note that cost time and may be worth a line in the docs: **macOS `strings` has no `-e` flag**, so a UTF-16LE search cannot be expressed as `strings -e l` and fails with `unknown flag: -e` rather than returning nothing. A UTF-16LE-only literal in this package was missed on a first pass for exactly that reason. If binspector documents a manual verification recipe anywhere, it should either use a byte scan or call out the GNU-versus-BSD `strings` difference.
