Purpose

- Resource lists and references used to curate banned/dangerous C function names and related material. These files are not loaded by the Rust CLI at runtime by default, but can be used as custom inputs via `--banned-list`.

Contents

- `sdl_banned_funct.list`: Canonical list used by the Rust CLI by default.
- `banner_h.list`: Function names derived from Windows/`Banned.h` style sources.
- `banned.h`: Reference header collected from public sources.
- `sql_extended.list`: Extra SQL-related strings sometimes useful in static string scans.
- `sdl_banned_funct.old`: Legacy variant of the SDL banned functions list kept for reference.
- `references.txt`: Links and notes that informed the lists above.

Notes

- The default list used by Binspector (Rust) is `rsc/sdl_banned_funct.list`, embedded at build time. To use any other file in this folder instead, run: `binspector <bin> --banned-list rsc/<file>`.

Normalization

- One token per line; `#` starts a comment line.
- Strip zero‑width and control characters (seen in copy/pasted lists).
- Deduplicate and sort for stable diffs; keep natural casing of identifiers.
- The Rust CLI also sanitizes at runtime, but keeping this file clean helps portability.

Suggested cleanup snippet:

```
python3 - << 'PY'
import unicodedata
infile='rsc/sdl_banned_funct.list'
ZW = dict.fromkeys(map(ord, ['\u200b','\u200c','\u200d','\ufeff','\u2060','\u00ad','\u034f']))
seen=set(); out=[]
for line in open(infile, encoding='utf-8', errors='ignore'):
    s=line.strip()
    if not s or s.startswith('#'): continue
    s=s.translate(ZW)
    s=''.join(ch for ch in s if not unicodedata.category(ch).startswith('C'))
    for tok in s.split():
        if tok and tok not in seen:
            seen.add(tok); out.append(tok)
open(infile,'w',encoding='utf-8').write('\n'.join(sorted(out))+"\n")
PY
```
