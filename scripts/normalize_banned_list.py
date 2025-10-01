#!/usr/bin/env python3
import unicodedata
from pathlib import Path

INFILE = Path(__file__).resolve().parent.parent / "rsc" / "sdl_banned_funct.list"

ZW = {
    ord("\u200b"),  # ZERO WIDTH SPACE
    ord("\u200c"),  # ZERO WIDTH NON-JOINER
    ord("\u200d"),  # ZERO WIDTH JOINER
    ord("\ufeff"),  # ZERO WIDTH NO-BREAK SPACE
    ord("\u2060"),  # WORD JOINER
    ord("\u00ad"),  # SOFT HYPHEN
    ord("\u034f"),  # COMBINING GRAPHEME JOINER
}

def clean_token_stream(lines):
    seen = set()
    out = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        # strip zero-width and control chars
        s = "".join(ch for ch in s if (ord(ch) not in ZW) and not unicodedata.category(ch).startswith("C"))
        for tok in s.split():
            t = tok.strip()
            if t and t not in seen:
                seen.add(t)
                out.append(t)
    return sorted(out)

def main():
    with INFILE.open("r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    cleaned = clean_token_stream(lines)
    with INFILE.open("w", encoding="utf-8") as f:
        for t in cleaned:
            f.write(t + "\n")
    print(f"Normalized {len(cleaned)} entries to {INFILE}")

if __name__ == "__main__":
    main()

