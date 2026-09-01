#!/usr/bin/env sh
# Offline self-test: falcon_report.py reproduces the committed golden HTML
# byte-for-byte from the committed fixture.
#
# A golden-file check rather than a self-consistency one: a deliberate CSS edit
# shows up as a reviewable HTML diff instead of passing silently.
#
# No credentials, no tenant: --render reads a report JSON from disk.
#
#   ./scripts/test-render-parity.sh

set -eu

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
OUT=$(mktemp "${TMPDIR:-/tmp}/render-parity.XXXXXX")
trap 'rm -f -- "$OUT"' EXIT INT TERM

python3 "$ROOT/scripts/falcon_report.py" --render "$ROOT/tests/fixtures/report.json" "$OUT"

# cmp, not diff: a one-byte trailing-newline mismatch is exactly what this catches.
if cmp -s -- "$OUT" "$ROOT/tests/golden/report.html"; then
  echo "  ok    falcon_report.py --render matches tests/golden/report.html"
else
  echo "  FAIL  $(cmp -- "$OUT" "$ROOT/tests/golden/report.html" 2>&1 | sed -n 1p)" >&2
  exit 1
fi
