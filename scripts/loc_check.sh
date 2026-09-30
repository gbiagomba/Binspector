#!/usr/bin/env bash
# Enforce the per-file size budget: no .rs file over HARD lines, warn over SOFT.
# Splitting by concern keeps ownership obvious; this guard keeps it honest.
set -uo pipefail

HARD=${HARD:-1500}
SOFT=${SOFT:-1000}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

fail=0
warned=0

while IFS= read -r file; do
  lines=$(wc -l < "$file" | tr -d ' ')
  rel=${file#"$ROOT"/}
  if [ "$lines" -gt "$HARD" ]; then
    printf 'FAIL  %-44s %5s lines (hard limit %s)\n' "$rel" "$lines" "$HARD"
    fail=1
  elif [ "$lines" -gt "$SOFT" ]; then
    printf 'WARN  %-44s %5s lines (split before adding more; soft limit %s)\n' "$rel" "$lines" "$SOFT"
    warned=1
  fi
done < <(find "$ROOT/src" "$ROOT/tests" -name '*.rs' -type f 2>/dev/null | sort)

total=$(find "$ROOT/src" "$ROOT/tests" -name '*.rs' -type f 2>/dev/null | wc -l | tr -d ' ')
largest=$(find "$ROOT/src" "$ROOT/tests" -name '*.rs' -type f 2>/dev/null -exec wc -l {} + \
  | grep -v ' total$' | sort -rn | head -1 | awk '{print $2" ("$1" lines)"}')

if [ "$fail" -ne 0 ]; then
  echo "loc-check: FAILED. Split the file(s) above along an ownership seam."
  exit 1
fi
if [ "$warned" -ne 0 ]; then
  echo "loc-check: passed with warnings. $total files, largest ${largest}."
  exit 0
fi
echo "loc-check: passed. $total files, largest ${largest}, hard limit $HARD."
