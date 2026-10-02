# Changelog

All notable changes to this project will be documented in this file.

## [5.7.0] - 2026-10-02

Prompted by a field report comparing four versions against one 553 MB Windows
application across three adversarial adjudication passes, in which every number was
re-derived from the artifacts rather than read out of the tool's own output. The report is
in `docs/field-report-psexpress-6.9.0.0.md`. Two of its claims did not survive checking and
are noted below; the rest did.

### Changed

- **Matching is case-exact, and there is no flag for the other mode.** The banned pattern
  `SearchPath` was matching the camelCase local `searchPath` recovered from a PDB symbol stream:
  304 occurrences, 22% of a 1,355-occurrence report, all restatements of one variable name. All
  226 list entries were verified to carry correct API casing, so nothing real is lost.
  `--ignore-case` was removed in 4.0.0 and a `--case-insensitive` would be that flag renamed, so
  the only thing the insensitive mode does is reproduce this defect. `--case-sensitive` is still
  accepted and now asks for the default.

- **Counted string primitives are no longer rated as unbounded writes.** `strncpy`, `wcsncpy`,
  `strncat`, `lstrcpyn` and family take an explicit count, so the defect is a wrong count or a
  destination left unterminated ([CWE-170](https://cwe.mitre.org/data/definitions/170.html)),
  not the unbounded overflow of [CWE-787](https://cwe.mitre.org/data/definitions/787.html). 24
  of 57 criticals were counted primitives rated identically to `strcpy`, 15 of them `strncpy`
  alone. `snprintf` is deliberately excluded: it terminates, so crediting it here would claim a
  property it does not have.

- **SafeSEH gates on architecture, not bitness.** `/SAFESEH` validates entries in the x86-32
  stack-based exception chain; ARM, ARM64 and x64 use table-driven unwind through `.pdata` and
  `.xdata` and have nothing for it to protect. The old `!is_64` gate reported `concrt140.dll`
  from the ARM VCLibs package as a finding, an `armnt` image.

- **The indicator cap was collecting 5%.** The default of 500 per kind kept 618 URLs and 1,902
  paths while discarding 45,273 indicators, so the list was a sample of scan order presenting
  itself as a result. The default is 10,000 per kind; the printed lists are unchanged, because
  collection and display are separate concerns.

### Added

- **The UCRT formatting backends are on the list.** MSVC does not emit a call to `sprintf`; it
  emits `__stdio_common_vsprintf`. 41 members of the real package imported at least one backend
  and the tool reported none, so a clean critical count was not evidence of safe formatting.
  They are tiered **High, not Critical**: each takes a `_BufferCount` the front end supplies, so
  the import proves formatted output into a buffer and cannot distinguish `sprintf` from
  `snprintf`. Rating them Critical would repeat the counted-primitive error above in a new
  place, and did, briefly, at 268 criticals before being corrected to 39.

- **A `no-code-section` exclusion rule.** `icudt74.dll` is one 34 MiB `.rdata` section of CLDR
  locale data with no import directory, and it drew five HIGH `system` findings on
  numbering-system keys. The rule requires positive evidence of no code, so a member that never
  parsed as a PE is untouched: a packed image is where a hidden `system` matters most.

- **An `export-definition-site` exclusion rule.** `vcruntime140_cor3.dll` was reported for
  `memcpy`, `memmove`, `memset` and `memcmp`: the C runtime flagged for supplying the primitives
  it exists to supply, matching its own export-directory name entries.

- **`posture` and `posture_members` tables in the SQL and SQLite exports**, plus the
  `excluded_by_rule` table that was created and never filled. A reviewer working from the
  database, which is what the documentation recommends, silently missed `posture.aslr`: the
  highest-value output the tool produces, and could not see that 33,334 occurrences had been
  suppressed.

- **A logical findings count beside the raw one.** 1,300 occurrences on the real target set hold
  515 distinct (module, function, severity) triples; most of the remainder are one module
  recompiled for another instruction set, and some are the same bytes scanned twice because two
  architecture `.msix` members share a sha256.

- **Copy buttons on the HTML code blocks.** One fixed script, the only script in the document,
  loading nothing, so the report stays a self-contained file that works from a `file://` URL. It
  copies `textContent`, so no report data reaches a script context.

- **The targets header explains itself**, in all three human formats, after a user reported it
  as the line in the report they understood least.

### Fixed

- **Import lookup tolerates the MSVC leading underscore.** The UCRT exports `_mktemp`, never
  `mktemp`, so an exact compare missed a whole family of real imports and reported them at the
  tier used for text with no import backing, under-rating a genuine
  [CWE-377](https://cwe.mitre.org/data/definitions/377.html) finding.

- **Template instantiations are recognised as definitions.** The MSVC mangling sigil is `?`, `??`
  or `??$`, and requiring the token at index 1 let every template through, so
  `??$sprintf@...@StringUtils@internal@ngl@`, an allocating wrapper returning
  `std::basic_string`, survived as three findings.

- **The two mitigation rollups disagreed in public.** The exec-analysis block said SafeSEH was
  missing on 68 images while the posture finding in the same report said 66. The posture module
  was right: it exempts a managed assembly from the checks the CLR controls. A test now asserts
  the identity rather than the numbers.

- **The target rollup was one off the hit table**, medium 104 and low 72 against 103 and 73,
  because a summary row carries one severity for a whole function while the evidence rules decide
  each occurrence separately.

- **Paths no longer truncate at `~` or `{`.**
  `C:\Users\ADMINI~1\AppData\Local\Temp\lnk{GUID}.tmp` was reported as `C:\Users\ADMINI`, and
  because `ADMINI~1` is a Windows 8.3 short name the truncation invented an account name a
  reader takes for a real identity. MSVC `link.exe` temporaries are now excluded from build
  provenance outright.

- **A developer path stays in the indicator list as well as the provenance section.** Promoting
  it used to remove it, so 5.5.0 reported strictly less about one dependency than 5.3.0 had.
  Build-path drops are counted now, and the per-root quota rises from 2 to 48 with the cap from
  64 to 512: the real target set goes from 10 reported developer paths to 111.

- **Prose running into a scheme is no longer a URL.** String extraction concatenates adjacent
  literals, so `http://according` and `http://familiar` were among 618 reported URLs, pushing
  real ones past the display limit.

- **Component versions can have two parts**, so `deflate 1.3` is detected. A reviewer using the
  field as the zlib inventory was short a whole version while four others were listed.

- **Filename evidence is confirmed against the member list.** `icudt(\d+)` matched `icudt36` in
  some module's leftover string table and reported ICU 36 as shipped, when the only ICU payloads
  present were `icudt74.dll` and `icuuc74.dll`.

- **Posture member lists say when they are a sample.** The stored list is capped at 50 in scan
  order, and a reviewer read 50 of 179 as representative, concluded the finding belonged to one
  vendor, and had to retract it.

- **Warnings name their target.** The merge labelled the incoming side of the fold and never the
  accumulator, so `no executable image (PE, ELF, or Mach-O) was reached`, which is correct and
  applies to exactly one `.appxsym`, read at the top level as a claim about the whole scan. Two
  independent reviewers concluded it was stale.

- **Repeated anomaly and entropy lines are collapsed**, with a count. The same module ships for
  several instruction sets, so `Microsoft.UI.Xaml.Controls.dll: 2 TLS callback(s)` appeared three
  times and added no evidence while pushing distinct anomalies past the display limit.

### Two field-report claims that did not survive checking

Recorded because the report was right about everything else, and a fix built on a false premise
is worse than no fix.

- **"The report shows zero of the 313 safe variants."** It does not. The exec-analysis section
  prints `String hygiene: 838 hardened CRT import(s) across 209 of 1567 image(s)` and
  cross-references them against the bounded-primitive roll-up. The claim came from reading the
  `hits` table, which is about findings. A per-member safe-to-unsafe ratio is still worth adding
  and is not in this release.

- **"`coverage.carve_ran` is False with no stated reason."** 5.6.0 already names every analysis
  that was available and did not run, in an `Analysis not run` section. When `--carve` is passed
  the report carries a full `Carving` section.

## [5.6.0] - 2026-10-02

### Added
- **A versioned library directory is now a component signature.** `opencv-4.3.0` in a build path is
  evidence of a statically linked dependency that the 21 banner-text signatures cannot see, because
  a static link leaves no version banner to match. `feed_path` reads
  `[\\/]<name>-<major.minor[.patch]>[\\/]` out of collected indicator paths and adds the component
  with the path itself as the citation. On the real bundle this took detected components from 8 to 9,
  recovering `opencv 4.3.0` cited to
  `C:\Users\Eric\Desktop\ocv43\opencv-4.3.0\modules\core\src\algorithm.cpp`.

  This closes the half of the Jedi Council's Family E that said the vendored OpenSSL and OpenCV were
  invisible to the SBOM, and it closes it without touching the evidence rules. Loosening those rules
  would have re-introduced the exact false positives the Council credited 5.0.0 with removing.

- **Section entropy is printed, not just the conclusion drawn from it.** The exec-analysis section
  carries the per-section value so a reviewer can disagree with the packer verdict. A derived
  sentence with no number behind it is not reviewable.

### Changed
- **Indicator collection evicts a crowded path before dropping a distinctive one.** At the
  `--ioc-cap` boundary, a path sharing a long prefix with many others yields to an incoming path
  from a sparse root. 1,950 near-identical MSVC header paths were crowding out the one
  developer-desktop path that carried the OpenCV evidence. The eviction refuses to run when it
  would thrash (`n < 8 || incoming_count + 1 >= n`), so two equally crowded roots do not trade
  places on every insert.

- **Build-path provenance excludes CI service accounts.** `runneradmin`, `runner`, `vsts`,
  `vssadministrator`, `azdevops`, `buildbot`, `jenkins`, `gitlab-runner` and `teamcity` under a home
  root are a CI worker, not a developer workstation, and reporting them as "built outside CI" said
  the opposite of the truth. A per-root quota of 2 keeps nine CI registry paths from filling the
  64-slot build-path budget and hiding the one path that matters.

### Fixed
- **The CVE coverage note described one kind of silence when there are two.** A component with no
  detector is never looked up. A *detected* component can also return nothing, because NVD
  `keywordSearch` matches literal terms against the advisory description and an advisory phrased
  "4.3.0 and earlier", or carrying only CPE data, never matches the query. Found by testing: the
  synthetic OpenSSL 1.0.2k banner resolved CVE-2017-3731 and CVE-2017-3732, while the newly
  recovered `opencv 4.3.0` returned zero CVEs with no error. Zero now reads as a reason to check
  the vendor advisories rather than as a clean result.

  A `virtualMatchString` CPE query is the accurate fix and needs a vendor-to-product map the
  detector does not have, since the two names diverge often enough to matter: `icu` is
  `icu-project:international_components_for_unicode`. That map is the work, not the query.

  The note moved into one `coverage_note()` function because the test had pasted a second copy of
  the string, so the assertion could pass while the report said something else.

## [5.5.0] - 2026-10-01

### Added
- **`--threads <N>`, defaulting to the core count.** Targets are scanned in parallel, and the output
  is byte-identical to a single-threaded run because results are merged in target order rather than
  completion order. A faster scan that produced a different report each run would be useless for
  diffing two builds. Measured on a 553 MB ten-target set: 17.5s to 6.7s.

  Across targets, never within one. Every cap in the limit set is per target, so a shared budget
  would let the first target consume the last one's coverage. The trade is that the observer is not
  shareable across threads, so the per-member `-vv` stream is unavailable above one thread.
- **`--extract <DIR>` writes unpacked members to disk**, which is the only part of a scan that
  writes bytes from the target. Names are flattened rather than mirrored: each file is a content-hash
  prefix plus a sanitised leaf, so no component of a member's own path reaches the filesystem and an
  entry named `../../etc/passwd` cannot write outside the directory. Traversal is not filtered, it is
  structurally impossible. Verified against a hostile archive carrying traversal, absolute paths and
  a reserved device name.

### Changed
- The in-memory claims in four places said nothing is written to disk. True before `--extract`, and
  now qualified rather than quietly falsified. `container::limits` mattered most: it described
  member-name sanitising as defence in depth *because* nothing was written, and that reasoning is
  load-bearing once extraction exists.

## [5.4.0] - 2026-10-01

### Added
- **Markdown and HTML carry every analysis section.** They rendered Findings, Coverage, Warnings and
  Occurrences only, so a reader of the `.md` saw no mitigations, no certificates, no DLL search
  order and no indicators, and reasonably concluded the tool had not looked. Six sections were
  text-only for three releases because nothing tested it.
- **Remediation for banned-function findings**, in the report and in SARIF `help`. One entry per
  category, plus overrides for the functions whose failure mode is not their family's: `strncpy`
  does not NUL-terminate, `strncat` bounds the source rather than the destination, `PathCombineW`
  documents a `MAX_PATH` destination with no parameter to enforce it.
- **A build-provenance section.** Developer-home paths in a shipped artifact disclose a username,
  show the build did not come from CI, and frequently name a statically linked dependency that
  appears in no manifest. On the reference bundle this recovers the exact path an adversarial review
  had to find by hand, plus a second vendored OpenCV at another version that the review missed.
- **Indicator truncation is disclosed.** Each kind counts what it saw after `--ioc-cap` and the
  report says so. On the reference bundle that is 11,147 indicators previously discarded in silence.
- **Analysis that did not run is named.** A default run lists `--carve`, `--reputation` and `--cve`
  and states that their absence is not a finding about the target.

### Changed
- **Occurrences are ordered worst-first**, then by confidence. They were in scan order, so on a
  ten-target run the first 812 of 1,355 rows were low-severity matches inside a symbol package and
  the first critical sat at index 812.
- Certificate and chain reporting no longer depends on banned-function findings existing.

### Fixed
- **`-o` naming a directory wrote the files beside it.** `format::destination` derives a stem
  through `Path::file_stem()`, which discards a trailing separator, and nothing on the output path
  called `is_dir()`. A value ending in a separator, or naming an existing directory, now resolves to
  the timestamped default stem inside it, and the directory is created if absent.
- **A multi-target report printed empty `MD5` and `SHA1` fields.** Those are cleared on purpose,
  because a digest over a set of files is a manifest digest rather than a file hash, but the writers
  printed the labels anyway. All three human formats now print one honest line naming the manifest
  digest, and no empty field.
- Trailing whitespace on excluded-by-rule rows when a rule had no prose reason.

### Security
- **Markdown cells were not inert.** `md_cell` escaped the pipe and the newline but not the
  backtick, and most untrusted cells are backtick-wrapped by the writer, so one backtick in an
  attacker-controlled value breaks out of the code span and the rest of the cell renders as live
  markup. Two cells are not wrapped at all. Backticks are now neutralised and angle brackets escaped.
- **`html_escape` passed bidirectional overrides through**, because it replaced a character only
  when `char::is_control()`, which is Unicode category Cc, and U+202E is Cf. Signer names were
  filtered elsewhere, but carved descriptions, loader module names, IPC strings, section names and
  component names were not, and they reach HTML under the format-parity work.

- **Certificate reporting was gated on findings.** `write_signature_caveat` and `write_chain_text`
  were tail calls of the findings-by-origin block, which returns early when no occurrence is
  attributable to a parsed PE, so a clean scan of 441 verified signatures printed nothing about any
  of them.
- **The indicator cap dropped the one path that mattered.** It stops collecting in scan order, so a
  thousand near-identical compiler header paths reached it before the single developer path that was
  the only trace of a vendored dependency. An adversarial review attributed this to the 5.0.0
  evidence rules; comparing both scans showed the path was never in the indicator list in either
  version, so the fix is here rather than in the filtering, which would have reintroduced the false
  positives that review credited 5.0.0 for removing.
- README restructured, with six false claims corrected after an adversarial fact-check against the
  source. `pe::authenticode` also claimed a differential test that does not exist; it now states
  that the comparison was a one-off local run and is not committed.
- Retroactive tags for 5.1.1 and 5.2.0, which were released as commits only, and a CI change so
  GitHub picks the latest release by version rather than by publish order.

## [5.3.0] - 2026-10-01

### Added
- **Authenticode digest verification: whether the shipped bytes are the bytes that were signed.**
  5.0.0 printed a certificate's subject Common Name and said plainly that nothing was verified. That
  was honest and it was a floor: a hostile binary could self-sign as "Microsoft Corporation" and the
  report printed it. The image is now hashed over the Authenticode range and compared against the
  digest inside its own signature. SHA-1, SHA-256, SHA-384, and SHA-512.

  Measured on a real 441-image bundle: 179 unsigned, **262 verified, 0 mismatched**. Flipping one
  byte inside a section turns that image to `mismatch`. Flipping one byte inside the certificate
  table leaves it `verified`, which is the test that the exclusion ranges are right rather than
  merely that hashing works.
- **A critical `authenticode-digest` posture finding**, which is the only thing the tool reports that
  says the shipped file is not the file somebody vouched for, and the first posture finding able to
  trip `--fail-on critical`. `Unchecked` emits nothing, so an unsigned image, a signature that would
  not decode, and an unrecognised digest algorithm stay "we could not tell" rather than becoming a
  claim.
- **Certificate chain verification, cryptographic and not just by name.** Each certificate's
  signature is verified under its issuer's public key over the child's `TBSCertificate`, with
  RSA-PKCS#1 under SHA-1, SHA-256, SHA-384, and SHA-512, and ECDSA on P-256 and P-384. That is what
  separates a forged chain whose issuer and subject names line up from one that was actually issued,
  and it is what makes "self-signed" a verified fact rather than a name coincidence.

  SHA-1 is verified on purpose. It is cryptographically broken for collisions and still present on
  legitimate older Microsoft components, so refusing it would report a real chain as unverifiable,
  indistinguishably from a forged one. Verifying what an issuer signed is not an endorsement of the
  algorithm.
- **A `partial` chain state, because `unverified` would have been a lie.** 260 of the bundle's 262
  signed images embed a leaf and an intermediate and no root, which is how Authenticode normally
  ships: Windows has the root already. Every one of those 260 had its leaf-to-intermediate signature
  cryptographically verified. Reporting that as "unverified" would read as "nothing was checked",
  which is the opposite of what happened.
- **Anchor fingerprints in the report.** Expiry is reported and never treated as broken, because
  Authenticode is deliberately not expiry-sensitive when countersigned; 11 certificates in the bundle
  are outside their window and none of them is a finding.

### Security
- **The Authenticode hash range walk is computed locally**, because goblin's
  `authenticode_ranges()` raw-indexes attacker-controlled header fields with no bounds check and no
  `checked_sub`: `size_of_headers`, `pointer_to_raw_data + size_of_raw_data`, and a certificate-table
  subtraction that underflows on a crafted size. Each is a reachable abort in a scan, which is the
  same class of defect `exe::binds` exists to avoid on the Mach-O side. Every range here is computed
  with checked arithmetic and clamped through `data.get()`, and a header the walk will not trust
  yields `Unchecked` rather than a panic or a guess.

  **Faithful rather than merely safe**, established by differential: the plan agrees with goblin's own
  iterator byte-for-byte on all 441 real images, with zero panics and zero declines.
- 160,000 mutations of a real signed PE across four seeds find no panic and no hang in the new ASN.1,
  including the paths that feed attacker-supplied DER to an RSA and an ECDSA verifier and the
  certificate-ordering walk, which has to terminate on a planted cycle rather than follow it.

### Changed
- **The hardcoded report line "no chain or hash is checked" is gone**, because it became false. The
  signature footer now names the digest counts and the chain states across the images actually
  scanned. What replaces it is still a limit and still the one that matters: **verified is not
  trusted**. No code-signing root store is consulted, because none exists in pure Rust.
- `--first-party` deliberately does **not** start depending on verification state. It is an explicit
  user assertion about which code is theirs, not a trust decision.

### Deliberately out of scope
- **Revocation.** OCSP and CRL both fetch a URL taken from the certificate under examination, which is
  attacker-controlled outbound traffic: an SSRF-shaped channel and a scan-detection beacon at once.
  That is categorically worse than `--reputation`, which sends a hash to an endpoint the user chose,
  and it fails the same test the AI component failed in 3.0.0.
- **A trust verdict.** `webpki-roots` is Mozilla's TLS list, not a code-signing one, and Microsoft's
  anchors live in a separate Certificate Trust List with no crates.io mirror. `rustls-webpki` needs
  `ring` or `aws-lc-rs`, which is C plus CMake and would wreck the six-target cross-compile, and it
  omits RSA-SHA-1. `codesign-verify` wraps the real operating-system APIs but validates a file on disk
  by path, contradicting "nothing is written to disk during a scan", and is host-dependent, so the
  same binary would get different verdicts on different scanners. That is the worst possible property
  for something feeding `--fail-on`.
- **The secondary signature of a dual-signed image**, which lives in an unsigned attribute of the
  first. The primary signature is verified, which is the one Windows prefers.

## [5.2.0] - 2026-10-01

### Added
- **ELF and Mach-O imports, which closes a structural gap rather than adding a feature.**
  `Confidence::Import` is the strongest evidence the tool has, because an import-table entry is a
  linker-recorded dependency rather than a name that happens to appear in the bytes. That tier was
  derivable only from a PE import directory, so `import-backed occurrences` was **zero by
  construction** for every ELF and Mach-O binary scanned, and the tool was quietly much weaker on
  Linux and macOS than on Windows without saying so. Verified on `/bin/ls`: 97 imports and 5
  import-backed occurrences including a critical `strcpy` from `libSystem.B.dylib`, where the count
  had been zero.
- **Mach-O `LC_DYLD_CHAINED_FIXUPS` import table.** goblin recognises the load command and never
  interprets it, so on anything built by a current toolchain `MachO::imports()` returns empty,
  which is indistinguishable from "this image imports nothing". The table is now read directly,
  with its dylib ordinals. Measured on eight system binaries: the same 1,055 imports went from
  **zero attributed to a library to all 1,055 attributed**, which is what lets a report say which
  library a call comes from instead of naming a bare symbol.
- **Exploit-mitigation findings for ELF and Mach-O**: `nx`, `relro`, `pie`, `canary`, `fortify`,
  `exec-stack`, `exec-heap`, and `macho-code-signature`, each with the header field it was read
  from and a build-flag remediation. New id strings rather than overloads of the PE ones, because
  the ids are a documented filter surface and making `aslr` also mean "ELF PIE" would silently
  change what an existing `--filter aslr` selects. These participate in `--fail-on`.
- **A `Native analysis` report section**, listing which mitigations are missing across the ELF and
  Mach-O images, which mechanism supplied each image's imports, and how many images had no readable
  import table at all. That last number matters: for those images the **absence** of an import is
  not evidence, and the evidence rules depend on knowing the difference.
- **CRT surface roll-up.** `memcpy`, `memset`, and `memmove` were 81 of 244 occurrences on the
  reference bundle, one per function per member, which is a link-graph fact rather than 81
  findings. The human text, markdown, and HTML occurrence lists now carry a surface summary with a
  denominator instead. JSON, CSV, SQL, SQLite, and SARIF stay complete, and `banned_hit_count`,
  `severity_counts`, and `--fail-on` are unchanged.
- **Posture findings in SARIF**, as a `missing-mitigation/<id>` rule family with one result per
  finding and one location per affected member. `region` is omitted rather than invented, because
  there is no byte offset to anchor a header fact to.
- **Named-pipe trust-boundary narrowing.** Which images are pipe servers, which build their own
  security descriptors, and which call no authorization primitive at all. The last of those is
  gated on a readable import table, because "imports nothing from the token family" manufactured
  out of a parse failure would be the tool's strongest claim built on nothing.

### Changed
- **`--no-pe` is now `--no-exe`**, since it gates three formats rather than one. `--no-pe` remains
  as a visible alias.
- `--dump` works across several targets, rather than being refused for a multi-target run.

### Security
- **A reachable panic and a reachable allocation bomb in the Mach-O import path, both found by
  fuzzing a real system binary, both now unreachable.** `MachO::imports()` is not safe to call on a
  file the tool was pointed at. It raw-indexes two attacker-controlled fields with no bounds check
  (`segments[seg_index]` and `libs[symbol_library_ordinal]`), so four bytes of edit to any signed
  binary aborted the scan: 8,000 mutations of `/bin/ls` produced it twenty times over, the first at
  iteration 63. And `BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB` carries a ULEB repeat count whose
  every repetition pushes another entry, so a 120-byte opcode stream could ask for billions; one
  mutated input spent 1.8 seconds in there and returned nothing.

  Neither is fixable from the outside, because a `catch_unwind` cannot bound an allocation and a size
  cap cannot help when 120 bytes is already enough. The opcode walk is now local, in
  `src/exe/binds.rs`, with checked arithmetic throughout. What makes it bounded is the question it
  asks: `count` repetitions bind the *same symbol from the same library* at successive addresses, so
  for an import list the count carries no information, and it is read and discarded. There is no
  address arithmetic in the module at all. **Verified faithful, not merely safe:** the walk agrees
  with goblin's name-for-name on 46 real system binaries with zero disagreements, which is now a
  platform-gated test. 80,000 further mutations across four seeds find nothing, and the slowest
  execution went from 3,866 ms to 0 ms.
- **A universal binary could claim 7,710 architecture slices**, each costing a full `MachO::parse`
  in both the import reader and the posture reader, because goblin bounds `nfat_arch` only by the
  file length over 20 bytes. Capped at the same 16 that detection already used to tell a fat header
  from a Java class file, which is well above anything Apple ships.
- **A chained-fixups header could claim four billion imports** in a blob with room for twelve, each
  claimed entry costing a scan of the string pool. The count is now clamped to what the blob holds,
  which is a structural check rather than a heuristic: an entry past the end of the blob is not an
  entry.

### Fixed
- **The bind-opcode walk read only the first lazy import.** In the lazy stream dyld writes one
  `BIND_OPCODE_DONE` after each binding rather than one at the end, so treating it as end-of-stream
  found 8 imports on `/bin/ls` where there are 91. Caught by the differential against goblin, which
  is exactly the class of defect a passing unit test would have hidden.
- **Fat-binary linkedit offsets are relative to the architecture slice, not to the file.** goblin
  slices a universal binary down to one architecture before parsing, so its offsets look absolute
  and are not. Reading them against the whole file lands in machine code and yields zero imports.
  The slice offset is now carried explicitly and pinned by an assertion, because a set comparison
  alone would have reported this as "ours is empty" rather than as an addressing error.
- Mach-O symbol names were normalised differently on the bind path and the symbol-table path, so a
  universal binary reported the same symbol twice as `___stack_chk_fail` and `__stack_chk_fail`.
  Both paths now strip exactly one assembler underscore and dedup prefers the entry that carries
  library attribution: 181 entries collapse to 97, each attributed. Found by probing a real
  universal binary, not by a test.

## [5.1.1] - 2026-10-01

### Fixed
- **A Java class file detected as a Mach-O image.** `0xCAFEBABE` is both the Mach-O universal
  binary magic and the Java class-file magic, so every `.class` inside a scanned JAR was typed
  `macho`. The discriminator is the next field: a fat header's `nfat_arch` counts architectures
  and is small, while a class file's bytes 4..8 are its minor and major version pair, and every
  real class file has a major version of at least 45. A count outside 1 to 16 is therefore not a
  fat binary. Pre-existing, not introduced by 5.1.0.
- **`FAT_CIGAM` (`0xBEBAFECA`) was absent**, so a byte-swapped universal binary was invisible to
  detection. A truncated fat header now returns `Unknown` instead of reading past the end.

### Changed
- **`--dump` works across several targets** instead of being refused. The per-target spools are
  concatenated into one, and because every record names its member and a member chain is rooted
  at its target, a combined dump stays attributable with no extra field. The concatenation is
  linear in the total rather than quadratic in the target count. A notice reports the volume,
  since one target can already yield millions of strings, and points at `-v` and `-vv` for
  watching a run rather than reading every string.

  The previous refusal was the wrong call: a spool-per-target limitation is something to fix, not
  a reason to reject the flag.

## [5.1.0] - 2026-10-01

Several targets, or a directory, in one run.

### Added
- **Any number of positional targets**, and a **directory target is walked** for executables and
  archives. `binspector ./app.msixbundle ./app.appxsym ./Dependencies/` is one report.
- **Selection is content-first.** `container::detect` reads magic and never looks at a filename,
  so an extensionless Unix executable is found and a PE named `.txt` is still a PE. An extension
  allowlist is a backstop with one job: catching installers whose magic the tool cannot parse
  (`dmg`, `msi`, `pkg`, `deb`, `rpm` and similar) so they become reported coverage gaps rather
  than silent omissions. Formats already covered by magic are deliberately absent from that list,
  and a test keeps them absent. `--all-files` scans everything.
- **`--split`** writes one report per target, scanning and dropping one at a time so N reports
  never coexist. Naming is `<stem>_<slug>-<stamp>`, defaulting to `binspector_<slug>-<stamp>`,
  with **one stamp per invocation** so a 400-target run still sorts as one run.
- **`--max-dir-depth`** (16), **`--max-targets`** (10,000), and **`--max-input-bytes`** (64 GiB).
  Deliberately not `--max-depth`, which means container nesting and defaults to 4: vendored and
  staged trees routinely exceed four directories, so reusing it would silently truncate the walk.
- **`Report.targets`**, one entry per target and present even for a single-target scan, so no
  consumer special-cases arity. A per-target table appears in the text report when there is more
  than one, and is silent otherwise, so single-target output is unchanged.
- `Event::Target` at `-v`, naming each target as it starts.

### Safety properties, each a test
- **A symlink found during recursion is never followed.** `read_dir` plus `DirEntry::file_type`
  is `lstat`-based, so a loop or an escape from the named tree is structurally impossible and
  needs no visited-inode bookkeeping. A path named *on the command line* is followed, the same
  boundary `find -H` draws: naming a path is an instruction.
- Nothing but regular files and directories is opened, so a fifo cannot block a scan.
- Entries are sorted per directory, so target order, labels, slugs, and the manifest digest are
  identical across runs and platforms.
- Every cap degrades to a warning plus partial results, never an error.
- A file named twice, or named and also reachable through a directory argument, is scanned once.
- Peak memory stays near the largest single target rather than their sum.

### Error semantics
A named path that does not exist is a hard error, keeping the exact `reading {}: {}` wording, so
a typo is never reported as a clean scan. A discovered file or directory that cannot be read is a
warning and the walk continues. A directory yielding zero candidates is an error that names
`--all-files`, because a clean report over zero files is the failure this tool exists to prevent.
`--fail-on` in split mode ORs across every report: a gate that passes because 399 of 400 targets
were clean is not a gate.

`--dump` with several targets is rejected rather than silently dumping only the last: the spool
holds one target's strings and one target already yields millions.

### Multi-target scalars
`binary` names the set. `sha256` is a **manifest digest** over the newline-joined
`"<sha256>  <label>"` lines in target order, which is what `sha256sum` produces and so is
reproducible and checkable by hand; `md5` and `sha1` are cleared rather than filled with something
that looks like a file hash and is not.

### Verified
On the real case this was built for: two named files plus a 9-file dependency tree, 10 targets in
17 seconds. All 57 criticals across all 10 targets are import-backed, and a 120 MiB `.appxsym`
symbol container's 797 occurrences are every one capped to `low`, 693 of them by
`non-executable-member`, so it contributes nothing to the critical queue. The tree holds four
copies of the same runtime `.msix` under different architecture directories, which exercises the
label and slug collision rules: labels fall back to the relative path, slugs gain `-2`, `-3`, `-4`.

### Fixed
Three defects found by running it on a real tree rather than by tests:
- Every table row was flagged `!!`, because the routine low-confidence disclosure counted as a
  per-target warning. It already has its own report section, and flagging all ten rows drained the
  marker of meaning.
- Tail truncation made rows ambiguous: `~64/Microsoft.WindowsAppRuntime.2.msix` is
  indistinguishable from `x64/...`. Truncation now elides the middle and keeps both ends, since
  `bin/tool` versus `lib/tool` is the reverse case.
- Two rows could still render identically where labels differ only in a middle segment (VCLibs ARM
  versus ARM64). A duplicate row in a security report is a defect, so colliding display labels now
  take a `#n` suffix and the table guarantees row identity.
- `--split` without `-o` stamped the filename twice, because the output had already been defaulted
  to a timestamped stem.

## [5.0.0] - 2026-10-01

Severity is now a property of the observation rather than of the function name. Two breaking
changes, both of which can alter a pipeline's exit code, so read these first.

### Breaking
- **Severity values change, and occurrence counts drop.** Evidence rules adjudicate each
  occurrence from the confidence, the member's format, whether the member is a managed
  assembly, and whether a usable import table was read. On the reference bundle, occurrences
  fall from 331 to 244 and critical+high from 306 to 68. Nothing is hidden: `HitRecord` carries
  `base_severity` and the list of `adjustments` that moved it, and `excluded_by_rule` tallies
  every removal by rule.
- **`--fail-on` now also trips on a missing exploit mitigation**, and reads the adjusted
  severity. A bundle whose images load at a predictable address fails `--fail-on high` where
  before it passed, because the mitigation was prose in the text report and invisible to the
  gate. It also stops tripping on a namespace string in .NET metadata that happened to match a
  critical function name.
- `low_confidence_total`, `low_confidence_top`, and `MatchSummary.low_confidence` are renamed
  `excluded_total`, `excluded_top`, and `excluded`, because four rules can now remove an
  occurrence and the old names described a subset. The SQL tables follow.
  `--include-low-confidence` remains as a visible alias for `--include-excluded`.
- `Severity` gains `Low`, and `Report::severity_counts()` returns a 4-tuple.

### Added
- **`src/scan/evidence.rs`.** Three exclusion rules and five demotions, each recording what it
  did. Four assertions hold on the reference bundle: no critical or high occurrence is anything
  but `import` or `exact`; every critical is import-backed; the five known false criticals are
  gone by name (four `?...@WRStrSafe@@` wrappers, which were the *countermeasure* rated
  critical, and `cv::FileStorage::Impl::gets`); and the non-prose exclusions sum to the drop in
  occurrences, so nothing vanished without a named reason.

  Three of the rules came out of review rather than design, and each closes a real hole. A
  usable import table is required before absence of an import counts as evidence, because
  `Confidence::Import` is only derivable from a PE import directory and the rule would
  otherwise have dropped every `system()` in a native ELF or Mach-O binary, and because a
  packed or resource-only image has no import directory at all. The ordinary-word rule splits
  on confidence: a symbolic match means the token sits inside a larger token, `h-system` in an
  ICU locale table being the case found on the bundle, and that is never a call whatever the
  member is. And Itanium mangling is handled, because `_ZN2cv11FileStorage4Impl4getsEv` puts a
  length digit before the token rather than `::` or `?`, so the OpenCV false positive this
  release fixes on a Windows build would have returned from a Linux build of the same code.

- **Exploit mitigations are findings** (`src/pe/posture.rs`), one per mitigation listing its
  images rather than one per image. On the bundle: ASLR disabled on `BIB.dll`, `BIBUtils.dll`,
  and `CoolType.dll`, which an adversarial review called the most actionable item in the entire
  scan and which the tool previously reported only as prose; and 179 images with no Authenticode
  signature. Each finding carries its evidence and its fix. `Unknown` is never a finding, and
  code-generation rules do not apply to managed assemblies.

- **`/GS`, SafeSEH, and CET**, all free from goblin with no new dependency. `/GS` from the load
  config `SecurityCookie`, SafeSEH from `SEHandlerTable` and 32-bit only, CET from the extended
  DLL characteristics that goblin already parses. SafeSEH is `Unknown` on 64-bit, where SEH is
  table-based and SafeSEH does not apply.

- **Signer attribution** (`src/pe/signer.rs`), walking the Authenticode PKCS#7 blob to the
  signing certificate's subject Common Name, plus `--first-party <REGEX>` to override it. On the
  bundle this separates 131 first-party occurrences from 28 in Microsoft and .NET code, which is
  the difference between a queue a team can act on and one they cannot. Adds `cms`, `x509-cert`,
  and `der` from RustCrypto, nine crates; `cms` 0.3 is a pre-release and is pinned exactly.

  **A signer is an identity claim, not a verified one.** No chain is validated, no revocation
  checked, and no Authenticode hash compared against the image, so a hostile binary can
  self-sign as anyone. The report says so. BER is deliberately refused, because `der`'s
  indefinite-length scanner recurses per nested length and a crafted blob would abort the
  process rather than raise a catchable error.

- **Hardened CRT imports are credited.** An image can import 23 `strcpy_s` beside 5 `strcpy`,
  and naming only the five inverts the signal. 250 hardened imports across 44 of 441 images on
  the bundle.

- `dll-search`, `gs`, and `cet` columns in the REPL mitigation matrix, with matching
  `--missing` selectors.

### Fixed
- `repl` `parse_severity` ended `_ => High`, so an unrecognised severity loaded from a SQLite
  report silently became `High`. With a fourth level that would turn a `low` row into a `high`
  one, misrepresenting a report the browser only views.
- The `--dump` highlight joined a spooled token back to the summary by function name, which
  stops being well defined once one name can carry several adjusted severities. It now uses
  `base_severity` deliberately, since a dump's only claim about a token is that it is a banned
  name, and its floor moved from `Medium` to `Low`.
- The aggregate mitigation loop matched a label string to a field with a `_` arm falling through
  to Authenticode, so adding a label without adding an arm would have reported one mitigation's
  state under another's name.

## [4.4.0] - 2026-09-30

Windows DLL search-order coverage, every optional feature in a default build, and a
`--format all` fix. Additive, apart from one category rename noted below.

### Fixed
- **`--format all` wrote six files, printed an error, and exited 2.** Reported from a real
  run. `OutputFormat::all()` listed `sqlite` unconditionally, `render_to_path` bails for it
  without the cargo feature, and the output loop propagated that with `?`, so the `.sql`
  dump ordered after it was never written.

  Three parts to the fix. `all` now means every format this build can write. `Sql` is
  ordered before `Sqlite`, because the text dump is the documented fallback for a build
  without SQLite and must never be the casualty of the binary writer failing. And with
  several formats requested, a failing writer no longer aborts the loop: failures are
  collected, everything writable is written, each failure is reported, and the run still
  exits 2. That last part also covers a disk filling up on file five of eight.

  Naming `--format sqlite` explicitly is still an error, because that request was specific.

  The bug was untested. `format_all_writes_every_file` listed seven formats by hand and
  never passed `all`. There is now a test that does.

### Changed
- **`sqlite`, `carve`, and `repl` are compiled into a default build.** CI release-builds
  with plain `cargo build --release`, so these were absent from every published binary and
  the documentation described formats the shipped tool could not produce. The `--carve` flag
  stays opt-in at runtime; only the build gate is gone. `--no-default-features` remains a
  full escape hatch and is covered by the test suite.

  Cost: a default build now compiles the bundled SQLite C amalgamation and the binwalk
  library. All six release targets were confirmed green before anything was built on top of
  this, including `aarch64-pc-windows-msvc`, which had not cross-compiled C at this scale
  before.
- **`system` moves from category `other` to `process-creation`.** Same severity, so exit
  codes are unaffected, but the category string in output differs. It accounts for 67 of the
  97 occurrences now in the new categories on the reference bundle.

### Added
- **Dynamic loading and process creation in the default banned list.** Two new categories,
  `dll-hijacking` and `process-creation`, and 29 names, following Microsoft's
  dynamic-link-library-security guidance. `SearchPath*` is high because that guidance names
  it outright as the wrong way to locate a module; `WinExec`, `LoadModule`, `ShellExecute*`,
  `system`, and `popen` are high because they have no way to qualify the image path;
  `SetDllDirectory*`, `CreateProcess*`, `dlopen`, `dlsym`, `NSAddImage`, and `_dyld_*` are
  medium because each can be called correctly.

  Measured on the reference bundle: occurrences 301 to 331, distinct functions 39 to 46.
  No explosion, which was the risk.

- **`LoadLibrary`, `LoadLibraryEx`, and `GetProcAddress` are deliberately not findings**, and
  a test pins that. `LoadLibrary` with a fully qualified path is correct code, the argument
  is not recorded in an import table, and 78 of the 441 images in the reference bundle import
  the family. Reporting those as defective would be inference presented as evidence, which is
  the mistake 3.0.0 existed to correct.

- **A per-image dynamic loading surface instead** (`src/pe/loader.rs`), reporting what is
  actually knowable without a disassembler: whether the image imports a search-path hardening
  API, whether it uses plain `LoadLibrary` (which cannot constrain the search at all) or
  `LoadLibraryEx` (which can take `LOAD_LIBRARY_SEARCH_*` flags), and which modules it names
  with no path at all, each with a byte offset so it is checkable by hand. Those combine into
  a `hardened`, `unhardened`, or `unqualified` verdict.

  The bare-name evidence excludes what the loader already resolves: an image's own statically
  imported DLLs, the `api-ms-win-*` and `ext-ms-*` API sets, and the image naming itself.
  Without that filter the section flagged 27 of 41 images with `KERNEL32.dll` and friends and
  said nothing useful; with it, what remains is modules an image names but does not statically
  import, which is what a runtime load looks like. On the reference bundle: 41 of 441 images
  load dynamically, 1 is hardened, 24 name a module with no path.

  Stated limit, in the report itself and in usage.md: this cannot prove a call site is wrong,
  and `hardened` does not mean every load is safe. It narrows 78 images to the handful worth
  reading.

- **A `dll-search` column in the REPL mitigation matrix**, plus
  `mitigations --missing dll-search`, alongside the existing ASLR, DEP, CFG, SafeSEH, and
  Authenticode columns. The verdict lives on the loader surface rather than in `Mitigations`,
  because it is derived from imports and strings while `Mitigations::from_pe` sees only
  headers; duplicating it would mean two sources of truth.

## [4.3.0] - 2026-09-30

Two additive surfaces for inspecting the tool rather than the sample, plus a default output
name. No change to existing scanning behavior or output content.

### Added
- **Verbose mode, `-v` and repeatable.** `-v` reports phases, archives opened with their
  member counts, PE parse totals, and per-phase timing. `-vv` adds every member, every skip
  and cap breach with its reason, and every suppression naming the rule that fired. `-vvv`
  adds a per-string trace.

  The point is auditability, not debugging. A large bundle reports tens of thousands of
  suppressed occurrences, and before this the only options were to trust the total or rebuild
  with prints added. `grep -c '^     drop'` on `-vv` output now equals `low_confidence_total`
  in the JSON report, which was verified against a 249.6 MiB bundle: 24,196 drop lines to
  24,196 reported.

  Implemented as an observer rather than prints inside the scan, because the library does not
  print: every `println!` lives in `src/main.rs` and the scan returns its warnings in
  `Report.warnings`. `src/observe.rs` defines the events, `Null` keeps the non-verbose path
  unchanged, and `Stderr` is wired from the flag count. Verbose output goes to stderr, so
  stdout at `-vv` is byte-identical to a quiet run and `--format json -o -` still pipes into
  `jq`.

  `-vvv` would emit millions of lines on a large sample, so the trace stops after 100,000 and
  says so once, naming the count and suggesting `--banned-filter` or a larger `--min-len`. It
  does not truncate silently, and the reported totals stay complete.

- **Interactive report browser, `binspector repl <report>`**, behind the `repl` feature.
  Deliberately read-only: it loads a JSON or SQLite report an earlier scan produced and never
  scans, which is what keeps it from ever disagreeing with the scan. Commands cover the
  summary, coverage, filterable occurrences, per-member detail, the mitigation matrix,
  components, CVEs, indicators, carved signatures, warnings, raw `sql` against a SQLite
  report, and `export`.

  `jq` and the `sqlite3` shell already cover most of this. The case that justifies the
  feature is the cross-cutting one: `mitigations --missing aslr` is one line here and an
  awkward expression otherwise. `export` calls the same writers the scan calls, so an exported
  file is identical to the same format written directly and there is no second rendering path
  to drift.

  The input is detected by content rather than extension, matching how the scanner treats
  input, so a misnamed report still loads.

- **The banner from the legacy shell implementation**, printed to stderr and only when stderr
  is a terminal, so it never reaches a report, a pipe, or a log. `--no-banner` suppresses it.

- **A default output name.** With no `-o`, output is written to
  `binspector_output-<YYYY.MM.DD-HH.MM.SS>.<ext>` in the current directory, matching the
  naming the original shell implementation used so output from either version sorts together.
  `-o` overrides it and `-o -` writes to stdout. Built from `time` component accessors rather
  than a format description, so it adds no dependency and cannot fail to format.

  Consequence worth stating: `--format sqlite` and multi-format runs no longer require an
  explicit `-o`, because the default supplies a path. Sending either to stdout is still
  rejected.

### Changed
- `Report.tool` and `Report.tool_version` are now `String` rather than `&'static str`, and
  skip-serialized fields carry `#[serde(default)]`, so a report round-trips through JSON.
  Required by the browser, and correct regardless.

### Decided against
- **An AI component.** The infrastructure was already there, so it would have been cheap, but
  sending findings from an internal binary to a hosted model is the same class of disclosure
  as the `vt scan` upload removed in 3.0.0. The marginal value over pasting a Markdown report
  into a chat window does not justify weakening "no file content leaves the machine", which is
  currently an unqualified claim.

## [4.2.2] - 2026-09-30

Release packaging. No change to scanning behavior or output.

### Fixed
- **Four of six release archives shipped without `LICENSE` or `README.md`.** Both Windows
  zips and both Linux tarballs contained the binary alone. The Linux job assembled its
  archive with `tar -C target/<target>/release`, where neither file exists, so its `||`
  fallback chain silently produced a binary-only archive; the Windows job handed
  `Compress-Archive` just the executable. Only macOS was correct, because that job was
  rewritten separately in 4.1.0.

  This matters beyond tidiness: the crate is GPL-3.0, so the license text should travel
  with the binary. All three jobs now stage the files first, and all six archives carry
  the binary, `LICENSE`, and `README.md`.

### Added
- **Bare binaries** attached alongside each archive, for scripted installs that would
  rather not unpack: `binspector-<target>-<tag>` on Unix and `...-<tag>.exe` on Windows.
  The archives remain the primary format, because a bare download loses the executable
  bit and carries no license.
- **Standalone `LICENSE`, `README.md`, and `usage.md`** attached to each release, so they
  can be linked or fetched without downloading a platform archive.

A tagged build now produces 15 assets: 6 archives, 6 bare binaries, and 3 documents.

### Verified
Both packaging paths were exercised locally before tagging rather than discovered in CI:
the Unix path by running the staging and `tar` commands, and the Windows path by running
the PowerShell block under `pwsh`. Both produce archives containing all three files plus a
bare executable.

## [4.2.1] - 2026-09-30

Licensing metadata correction and a documentation scrub. No change to scanning behavior or
output.

### Fixed
- **The declared license was wrong.** `LICENSE` has always contained the GNU GPL v3 text,
  byte-identical to gnu.org's `gpl-3.0.txt`, but `Cargo.toml` declared `MIT` and the README
  repeated it. Both now read `GPL-3.0-or-later`. This corrects the metadata to match the
  license that was always shipped; it is not a relicensing.

### Changed
- **The reference sample is now generic.** This repository is public, so vendor-identifying
  detail from the sample used during development has been replaced throughout the docs, the
  test fixtures, and the git history: the sample filename and its inner members, the DLL
  names quoted as evidence, a registry path and a program-files path in an indicator test,
  one compound font-name string in a matcher regression test, and an internal ticket
  reference.
- The sample's MD5, SHA-1, and SHA-256 in the report test fixtures are now obvious
  placeholders, and its exact byte size is a round 268,435,456. A digest fingerprints a
  specific file as precisely as its name does, so leaving those in place would have defeated
  the rename. The size change is paired with the expectation strings, since 268,435,456
  bytes is exactly 256.0 MiB.
- Git history was rewritten across 14 commits to scrub the same references from commit
  messages, file contents, and annotated tag messages. Tags v1.0.0 through v2.0.0 predate
  any of it and are unchanged; v3.0.0 onward now point at rewritten commits.

All measurements describing the tool's behavior are unchanged: the member counts, string
counts, finding counts, and the false positives the regression tests pin are all real, and
only the names and fingerprints differ.

## [4.2.0] - 2026-09-30

Documentation split, a concise `--help`, and dependency updates. The 4.1.x line was never
published: v4.1.0 and v4.1.1 shipped with no assets and their releases have been removed,
and 4.1.2 was held unreleased. This is the first release since v4.0.0.

### Changed
- **`--help` is concise again.** clap routes `--help` to its long renderer, which puts each
  option in its own block separated by blank lines. Every option's help is now a single
  line, and both `-h` and `--help` print the short form, with the depth living in
  `usage.md`. A 130-line wall of text became a 45-line table.
- **`usage.md` is the full reference** and the README is the overview. The README went from
  371 lines to 170: it keeps the rationale, install, a quick start, safety, and the new
  attribution section, and links to `usage.md` for every option, the severity and confidence
  tiers, container support, PE analysis, reputation and CVE detail, carving, fuzzing, and how
  to read a report.

### Added
- **An "Inspired by" section in the README**, naming peframe, binwalk, cve-bin-tool, AFL++,
  honggfuzz, WinAFL, arbitrary, zzuf, VirusTotal, MetaDefender, NVD, goblin, SARIF, and
  `strings`, with what Binspector takes from each, plus the four sources of the banned
  function lists.

### Fixed
- Upgraded `md-5`, `sha1`, and `sha2` from 0.10 to 0.11, which also pulls a current
  `generic-array`. Digest output was verified unchanged: the known-answer tests still pass
  and all three hashes match `md5`, `shasum -a 1`, and `shasum -a 256` byte for byte on a
  256 MiB sample. This matters because reputation lookups key on the hash.
- Fixed a rustdoc warning: `<sample stem>` in a doc comment was parsed as an unclosed HTML
  tag.
- Removed two stray feature entries left by dependency edits: `ureq`, whose dependency no
  longer exists, and `binwalk-ng`, which duplicated `carve`.

## [4.1.2] - 2026-09-30

Second attempt at the 4.1.x build fix. v4.1.0 and v4.1.1 both published **no release
assets**; this is the release to use. No change to scanning behavior or output.

### Fixed
- **The fuzz harnesses could not be linked by an ordinary build.** 4.1.1 moved them into
  this crate behind `afl-target` and `hfuzz-target` features, which used the engines'
  persistent-mode macros. Those macros reference runtime symbols the engine provides only
  through `cargo afl build`, so `cargo test --all --all-features` failed to link with
  `undefined symbol: __afl_persistent_loop`. It passed on macOS and failed on Linux,
  which is why the local gate missed it a second time.

  The features and the `afl` and `honggfuzz` dependencies are gone. Each harness is now a
  plain program that reads one file, which is exactly what AFL's `@@` and honggfuzz's
  `___FILE___` substitute, and what `binspector fuzz --engine` already emits. Persistent
  mode was an optimization, not a requirement, and it was the only thing coupling the
  build to an engine runtime. Instrument the same binary with `cargo afl build --bin
  fuzz_pe` for a coverage-guided run.
- Removed two stray feature entries left behind by dependency edits: `ureq`, whose
  dependency no longer exists, and `binwalk-ng`, which duplicated `carve`.

### Process
Every step of the CI quality gate is now run locally before tagging, and a tag is cut only
after CI reports green on `dev`. Both empty releases came from tagging on the strength of
`make check` alone, while the failing step was one `make check` did not cover.

## [4.1.1] - 2026-09-30

Fixes a build break that made v4.1.0 publish no release assets, and moves the fuzz
harnesses into the main crate so the same class of break cannot recur. No change to
scanning behavior or output.

### Fixed
- **The fuzz harnesses did not compile.** 4.1.0 added a `carve` field to
  `container::Limits` and updated every constructor inside the crate, but the harnesses
  lived in a separate `fuzz/` crate with its own `[workspace]`, so `cargo test` and
  `make check` at the repository root never built them. CI caught it, the quality gate
  failed, and because the platform build jobs declare `needs: quality`, v4.1.0 shipped
  with zero assets.
- **`--all-features` defined two `main` functions.** Enabling `afl-target` and
  `hfuzz-target` together, which `--all-features` does, matched both engine `main`
  gates. The gates are now mutually exclusive, with AFL taking precedence, then
  honggfuzz, then the plain file-reading harness.

### Changed
- **The fuzz harnesses moved from `fuzz/fuzz_targets/` to `src/bin/`.** They are now
  binaries of this crate, so an ordinary `cargo build` compiles them and a change to a
  library type cannot break them unnoticed. The separate crate and its `Cargo.toml` are
  gone. `src/fuzz/` keeps the library side (mutation engine, differential runner, corpus
  builder, engine orchestration) and gains `input.rs` for the `arbitrary` input shaping
  the harnesses share.
- `make check` now runs `fuzz-build`, which is what would have caught this locally.
- `make fuzz-afl` and `make fuzz-hfuzz` no longer change directory, and the harness path
  in the README is `./target/release/fuzz_pe`.

## [4.1.0] - 2026-09-30

Closes the container coverage gap that 3.0.0 opened and 4.0.0 carried. Every format
Binspector detects is now either unpacked or carved, so nothing is named in a report
without its contents being reachable.

### Added
- **Single-stream decompression:** gzip, bzip2, xz, and zstd. These wrap one payload, so
  each decompresses to a single child that the walk treats like any other member. A
  `.exe.gz` inside a bundle is now scanned rather than only named, and the child keeps a
  useful name (`App.exe.gz` becomes `App.exe`, `src.tgz` becomes `src.tar`).
- **7z and cab archives**, enumerated member by member like ZIP, with the same rules:
  unsafe names and oversized members are skipped with a warning rather than aborting.
- **zstd detection** by frame magic.
- **`--carve`**, behind the `carve` cargo feature, scanning every member for embedded
  file signatures via the binwalk library. Carving answers a different question from
  unpacking: it finds a payload appended to an executable or buried in a resource, where
  no directory declares it.

### Carving is filtered, because raw output is not usable
Run against the reference sample, binwalk reported **2,348 signatures**, almost all of
them `copyright` strings and `pkcs_der_hash` markers, which say nothing about anything
being embedded. Signatures are now classified:

- **Container** (archives and filesystems) leads the report, because that is the finding
  worth acting on.
- **Embedded** (executables and media) follows.
- **Other** is still listed, so a format added to binwalk later is never silently dropped.
- Checksums, certificates, key material, and text markers are counted, not listed.

That turned 2,348 raw signatures into **8 candidate containers** plus 138 other
signatures, with 176 markers excluded.

### Fixed
- **A ZIP magic collision that carving reported as a real archive.** `PK\x03\x04` is only
  four bytes and collides readily inside a large binary. On the reference sample it
  matched at offset 0x1d6c924 inside a 36 MB DLL, where the header fields were actually
  text: version 0, a zero-length member name, an extra field of 22,635 bytes, and an
  uncompressed size of 0 against a compressed size of 25,968. ZIP matches are now
  validated against the local file header and demoted to speculative when the fields are
  not plausible.
- Compressed and archive formats no longer report themselves as an unhandled coverage gap,
  because they are handled.

### Notes
- Carving is off by default. Signature scanning costs time (about 10 s against 7 s on the
  reference sample) and produces leads rather than facts, so it is opt-in, and asking for
  `--carve` from a build without the feature is an error that names the flag to rebuild
  with rather than silently reporting nothing.
- `flate2`, `bzip2`, `zstd`, and `lzma-rust2` were already in the dependency tree via
  `zip`, so the single-stream formats cost almost nothing to add.

## [4.0.0] - 2026-09-30

Delivers the three phases the 3.0.0 roadmap listed as 3.1.0, 3.2.0, and 3.3.0. They
land together in one MAJOR release because `--ignore-case` is removed, which is a
breaking change, and shipping them behind it would have meant three tags in a row that
each broke the same thing.

### Breaking
- **`--ignore-case` is removed.** It has had no effect since matching became case
  insensitive by default in 3.0.0, and it now fails as an unknown argument rather than
  being silently accepted. Use `--case-sensitive` for the opposite behavior.
- The positional target is now optional, because `binspector fuzz ...` takes no target.
  A bare `binspector` with no argument and no subcommand is an error that points at
  `binspector fuzz --help`.

### Added: PE analysis (the peframe mirror)
- New `src/pe/`, built on `goblin`: headers, per-section Shannon entropy, imports and
  exports, TLS callbacks, overlay detection, packer heuristics, indicator extraction
  (URLs, IPs, emails, registry keys, file paths), and **exploit mitigation state**
  (ASLR, high-entropy VA, DEP, Control Flow Guard, SafeSEH, Authenticode, relocations).
- **Findings are now confirmed from the import table.** A string match is
  circumstantial: the name could be documentation, a namespace, or dead data. An entry
  in the import directory is a linker-recorded dependency, so it is direct evidence the
  binary calls the function. A new `import` confidence tier outranks `exact`, and a
  string match is skipped when an import already proved the same function.
- Mitigation analysis surfaces findings a string scan cannot reach. On the reference
  sample: ASLR missing on `render.dll`, `renderutils.dll`, and `fontengine.dll`, and
  Authenticode missing on 179 of 441 images.
- `--no-pe` skips PE parsing, `--ioc-cap` bounds indicator collection.

### Added: reputation and CVE enrichment
- `--reputation` queries VirusTotal and MetaDefender **by hash only**. No file content
  is ever transmitted. An unknown hash is reported as "not known to the service, which
  is not evidence that it is safe".
- `--cve` detects third-party components from strings and resolves them against NVD
  2.0. The report states its own coverage: 20 curated signatures, and a component with
  no detector produces no CVEs, which is not the same as having none.
- Credentials come from the environment or `~/.config/binspector/credentials`, never
  from a command line argument, since arguments are visible through `ps` and recorded
  in shell history. A credentials file readable by group or others is refused with a
  `chmod` hint. Keys also stay out of the argument list at request time, because HTTP
  runs through curl with headers supplied on its stdin.

### Added: fuzzing, in three modes
- **Self-fuzzing.** A separate `fuzz/` crate with AFL, honggfuzz, and plain harnesses
  for the string extractor, the container walker, and the PE parser, using `arbitrary`
  so the option space is explored alongside the byte space. Each target asserts a real
  invariant rather than only looking for crashes.
- **Parser-differential.** `binspector fuzz --differential <FILE>` mutates a sample and
  feeds the mutants to Binspector's own parsers, reporting panics and hangs with a
  reproducing artifact. Deterministic from the seed, works on any host, and never
  executes the sample. This replaces the legacy `zzuf ... objdump -x` approach.
- **External engine orchestration.** `binspector fuzz --engine afl++|honggfuzz|libfuzzer|winafl`
  prepares and drives an engine against a harness you supply, seeded by
  `--corpus-from`, and parses the crash directory afterwards. The boundary is stated
  plainly in both the code and the help text: these engines drive an instrumented
  harness, so none of them can blackbox-fuzz an arbitrary bundle with no harness and no
  entry point, and WinAFL additionally needs a Windows host with DynamoRIO.
- CI now builds the harnesses and runs a short fixed-seed differential campaign, so a
  parser regression fails the build.

### Fixed
- Packer heuristics no longer fire on ordinary structure. Managed .NET assemblies are
  exempt from import-table heuristics (383 of 441 images on the reference sample are
  managed, and the CLR resolves their dependencies), resource-only DLLs are exempt too,
  and `.rsrc` is exempt from the high-entropy check because it holds already-compressed
  icons and images. Code and data sections are still checked.
- The curl config path escapes control characters using curl's own escapes. Wrapping a
  value in quotes is not sufficient on its own: curl parses its config line by line, so
  a literal newline would have ended the value and the remainder would have been read
  as a fresh directive.

### Verified on `SampleApp_1.0.0_x64.msixbundle`
- 441 PE images parsed, 11,870 imports read, 210 of 301 reported occurrences carrying
  import-table evidence rather than inference.
- 8 third-party components detected offline, including four bundled zlib versions
  (1.2.11, 1.2.12, 1.2.13, 1.3.1).
- NVD lookup verified live for OpenSSL 1.1.1k:
  [CVE-2021-3450](https://nvd.nist.gov/vuln/detail/CVE-2021-3450) (CVSS 7.4) and
  [CVE-2021-3449](https://nvd.nist.gov/vuln/detail/CVE-2021-3449), ranked by severity
  with citable URLs.
- 300 differential iterations against the full 256 MiB sample: no panics, no hangs.
- All three harnesses run clean over 40 real corpus members.

## [3.0.1] - 2026-09-30

Release engineering only. No change to scanning behavior or output; the binary is
functionally identical to 3.0.0. This exists because two long-standing CI faults meant
v3.0.0 published only 4 of the 6 platform assets the README advertises.

### Fixed
- **aarch64 Linux never built.** The cross-compile step wrote its linker config with
  `echo "[target...]\nlinker = ..."`, relying on `\n` being interpreted. `/bin/sh` does
  not do that, so a literal backslash-n landed in `~/.cargo/config.toml` and cargo failed
  to parse it. This job had failed on every run since it was introduced in `3a787aa`
  (2025-10-01). The linker, `CC`, and `AR` are now exported through `GITHUB_ENV`, which
  removes the quoting problem entirely.
- **The x86_64 macOS asset was never published.** The matrix used the deprecated
  `macos-13` runner for that architecture and its queue never started. Both macOS targets
  are now cross-compiled from one Apple silicon runner with an explicit `--target`,
  matching the Linux and Windows jobs.
- **macOS archives were missing `README.md` and `LICENSE`.** The packaging command ran
  `tar -C $(dirname "$BIN")`, changing into `target/release` where neither file exists, so
  its `||` fallback chain silently produced an archive containing only the binary.
  Packaging now stages the files first.

### Documentation
- `rsc/README.md` corrected: it listed `sdl_banned_funct.old`, which was deleted in
  `b2c2f21`, and described `sql_extended.list` as "extra SQL-related strings" when the
  file contains no SQL at all (0 matches for select/insert/drop/union/xp_/sp_/exec). It is
  another banned function list. Measured line counts and the overlap between lists were
  added, along with why they are kept separate rather than merged.
- `.version-tracking.md` records what was deferred from 3.0.0 (binwalk carving, and
  gzip/bzip2/xz/7z/cab unpacking) rather than leaving it implicit.

## [3.0.0] - 2026-09-30

Correctness release. 2.0.0 reported findings that were all false and missed everything
real; this release fixes both causes and adds the output surface around them. See
`.version-tracking.md` for the measured before and after.

### Fixed
- **Token-accurate matching.** Matching used `String::contains`, so any substring
  counted: `gets` matched `targetsize`, and `system` matched `System`, `FileSystem`,
  and `CustomSystemFont`. Matches are now verified against identifier boundaries.
  Compiler decoration on the left is still accepted (`_strcpy`, `__imp__strcpy`,
  `strcpy@8`), because those are real references, while a trailing identifier byte
  rejects the match so `strcpy_s` is never reported as `strcpy`.
- **Containers are opened.** A `.msixbundle` is a ZIP of `.msix` files holding the
  real PE binaries, so the previous scan only saw compressed bytes and found nothing.
  ZIP family archives (`.msixbundle`, `.msix`, `.appx`, `.jar`, `.nupkg`, `.zip`) are
  now unpacked recursively in memory, and every finding carries its full provenance
  chain.
- **Scan performance.** The pattern-by-string nested loop was replaced with a single
  Aho-Corasick pass. The previous approach was roughly 611M substring searches on the
  sample that exposed the bug.
- **Offsets are useful.** A reported offset now points at the matched token, with the
  UTF-16LE two-bytes-per-character stride applied, so seeking to it lands on the token.

### Added
- **Confidence scoring.** Some noise is a genuine whole token: `System.Windows.Forms`
  contains `System`, and `"Gets or sets the..."` contains `Gets`. Hits are scored
  `exact`, `symbolic`, or `prose`, and prose is excluded by default with a full
  accounting of what was suppressed. On the real sample this cut 24,511 reported
  occurrences to 306. Use `--include-low-confidence` to see them.
- **Output formats:** `text`/`txt`, `json`, `csv`, `html`, `markdown`/`md`, `sarif`,
  `sqlite`/`db`, `sql`, and `all`. Several may be given comma separated, with `-o`
  used as a filename stem. SARIF 2.1.0 locates results by byte offset rather than
  inventing line numbers. The `sqlite` format needs `--features sqlite`; `sql`
  produces an equivalent loadable dump with no extra dependency.
- **Color and accessibility:** `--color auto|always|never` and
  `--palette default|colorblind`. The colorblind palette uses Okabe-Ito colors with no
  red-green pairing. Color is never the only channel: every hit also carries a text
  marker and bold weight, so output stays readable when piped, in monochrome, and in
  a screen reader. ANSI is suppressed for file output unless `--color always`.
- **Full dump:** `--dump` reports every extracted string with banned references
  highlighted, streamed through a temporary spool so memory does not scale with the
  sample.
- **Decompression bomb protection:** `--max-depth`, `--max-unpacked-bytes`,
  `--max-member-bytes`, `--max-expansion-ratio`, and `--max-members`. A breach warns
  and continues with partial results rather than aborting, and archive member names
  that are absolute or contain `..` are rejected. Nothing is written to disk during a
  scan.
- **Coverage reporting.** The report states what was actually opened, and warns
  explicitly when no executable image was reached, so a clean result on an unopened
  container is never mistaken for a clean binary.
- **Severity and category** per banned function (`critical`, `high`, `medium`), derived
  from the function family so a custom `--banned-list` is tiered too.
- `--fail-on critical|high|medium` for pipeline use.
- `make loc-check` plus a CI quality gate enforcing formatting, clippy, the per-file
  line budget, and tests on every push.

### Changed
- Matching is case insensitive by default; `--case-sensitive` selects the opposite.
- CSV output no longer requires `--matches-only`.
- Default output is a summary; the full dump is opt-in via `--dump`.
- `src/main.rs` was split into `cli`, `container`, `report`, and `scan` modules, with
  no file over 1500 lines.

### Breaking
- **Matching is case insensitive by default.** 2.0.0 matched case sensitively, so an
  existing invocation can now return different results. Pass `--case-sensitive` for the
  previous behavior.
- **The no-op `fuzz` subcommand placeholder was removed.** It did nothing in 2.0.0.
  `binspector fuzz` is now interpreted as a request to scan a file named `fuzz`. Real
  fuzzing is planned for 3.3.0.
- Results change substantially even where flags did not, because 2.0.0 reported false
  positives and missed real findings. Re-baseline any stored output.

### Deprecated
- `--ignore-case` is now the default and warns when passed.
- `--json` is superseded by `--format json`.

## [2.0.0] - 2025-10-01
- Major: Complete overhaul from shell to Rust CLI.
- Port to Rust CLI: ASCII and UTF-16LE string extraction, banned function scanning.
- Add hashing (MD5/SHA1/SHA256) and JSON output for full report.
- Add custom banned list via `--banned-list`.
- Add matches-only export with `--matches-only` and `--format {text,json,csv}`.
- Warn/limit: CSV format is only supported with `--matches-only`.
- Add toggles `--no-ascii` and `--no-utf16` to control extraction sources.
- Add `--ignore-case` for case-insensitive matching.
- Add `--banned-filter REGEX` to filter the banned function names considered.
- Sanitize banned list entries (strip zero-width/format/control chars; split tokens on whitespace).
- Validate flags: error if both `--no-ascii` and `--no-utf16` are set.
- Add Makefile, Dockerfile, and GitHub Actions CI for Linux/macOS/Windows (x64/arm64).
- Update README and add .gitignore.
