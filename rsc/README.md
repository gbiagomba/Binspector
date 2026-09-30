# Banned function lists

## Purpose

Curated lists of banned and dangerous C/C++ function names, plus the reference material
they came from. `sdl_banned_funct.list` is compiled into the binary with `include_str!`,
so a default scan needs no files at runtime. Any other list here can be used instead:

```bash
binspector <binary> --banned-list rsc/<file>
```

## Contents

| File | Lines | What it actually holds |
|---|---:|---|
| `sdl_banned_funct.list` | 197 | The default list, compiled in. Windows API and CRT names, alphabetically sorted. |
| `banner_h.list` | 168 | The `strcpy` / `strcat` / `sprintf` families, derived from Microsoft's `Banned.h`. 156 of its entries are already in the default list. |
| `sql_extended.list` | 198 | Despite the name, this is **not** SQL. It is another banned function list, starting with `gets`, `_getts`, `_gettws`, and `IsBadWritePtr`. 144 of its entries are already in the default list. The name is historical and misleading. |
| `banned.h` | 68 | The reference header collected from public sources. Not a list format; kept for provenance. |
| `references.txt` | | Links and notes that informed the lists above. |

The three `.list` files overlap heavily, which is why the default is a single one rather
than a merge. They are kept separate rather than consolidated so that an existing
`--banned-list rsc/<file>` invocation keeps producing the same result.

## Severity and category are not stored here

The lists are flat names. Binspector derives severity (`critical`, `high`, `medium`) and
category (`buffer-overflow`, `format-string`, and so on) from the function family at
scan time, in `src/scan/banned.rs`. A custom list supplied with `--banned-list` therefore
gets the same tiering with no extra annotation, and a name the classifier does not
recognise defaults to `high` rather than being dropped.

## Format

- One token per line. A line starting with `#` is a comment.
- Several whitespace separated tokens on one line are accepted, a quirk of the legacy
  lists.
- Zero-width and control characters are stripped, because hand-edited and copy-pasted
  lists have carried them.
- Identifier casing is preserved. It matters: the classifier and the confidence scorer
  both treat a lowercase name differently from a mixed-case Windows API name such as
  `lstrcpyA`, since a lowercase CRT name appearing with different capitalization is
  usually namespace or prose text rather than a call.

Binspector sanitizes at runtime regardless, so a slightly untidy custom list still works.
Keeping the files clean just makes diffs readable.

## Normalizing

```bash
make normalize-banned-list
```

This runs `scripts/normalize_banned_list.py` against `sdl_banned_funct.list`: it strips
zero-width and control characters, splits multi-token lines, deduplicates, and sorts for
stable diffs.
