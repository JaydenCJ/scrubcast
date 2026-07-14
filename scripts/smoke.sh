#!/usr/bin/env bash
# Smoke test for scrubcast: scrub the example recording and CI log end to
# end, verify the output stays playable (valid asciicast, escapes intact),
# and check the CI gate exit codes.
# Self-contained: pure stdlib, no network, idempotent (works from a clean tree).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
if [ -x "$ROOT/.venv/bin/python" ]; then
  PYTHON="$ROOT/.venv/bin/python"
fi

# The package has zero runtime dependencies, so running from src/ needs no install.
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/scrubcast-smoke.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

fail() { echo "SMOKE FAIL: $1" >&2; exit 1; }

echo "[smoke] python: $("$PYTHON" --version 2>&1)"

# 1. --version agrees with the package version.
version_out="$("$PYTHON" -m scrubcast --version)"
pkg_version="$("$PYTHON" -c 'import scrubcast; print(scrubcast.__version__)')"
[ "$version_out" = "scrubcast $pkg_version" ] \
  || fail "--version mismatch: '$version_out' vs package '$pkg_version'"

# 2. Scrub the example recording to a file; summary goes to stderr.
scrub_err="$("$PYTHON" -m scrubcast scrub "$ROOT/examples/demo.cast" \
  -o "$WORKDIR/clean.cast" 2>&1 >/dev/null)" || fail "scrub demo.cast exited non-zero"
echo "$scrub_err" | sed 's/^/[scrub] /'
echo "$scrub_err" | grep -q "4 secrets found (cast)" || fail "expected 4 findings in demo.cast"
for rule in github-token jwt aws-secret-access-key aws-access-key-id; do
  echo "$scrub_err" | grep -q "$rule" || fail "summary missing rule $rule"
done

# 3. No secret material survives, placeholders are present.
grep -q "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "$WORKDIR/clean.cast" \
  && fail "GitHub token survived the scrub"
grep -q "wJalrXUtnFEMI" "$WORKDIR/clean.cast" && fail "AWS secret key survived the scrub"
grep -q "AKIAIOSFODNN7EXAMPLE" "$WORKDIR/clean.cast" && fail "AWS key id survived the scrub"
grep -q "\[REDACTED:github-token\]" "$WORKDIR/clean.cast" || fail "placeholder missing"

# 4. The scrubbed cast is still playable: every line valid JSON, same event
#    count and timestamps, SGR escapes still present.
"$PYTHON" - "$ROOT/examples/demo.cast" "$WORKDIR/clean.cast" <<'PY' || fail "scrubbed cast broke playability"
import json, sys
before = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
after = [json.loads(l) for l in open(sys.argv[2], encoding="utf-8") if l.strip()]
assert len(before) == len(after), "event count changed"
assert [e[0] for e in before[1:]] == [e[0] for e in after[1:]], "timestamps changed"
assert any("\x1b[1m" in e[2] for e in after[1:]), "SGR escapes lost"
PY

# 5. Re-scrubbing the clean file is a no-op (idempotent).
"$PYTHON" -m scrubcast scan "$WORKDIR/clean.cast" >/dev/null \
  || fail "scan of scrubbed cast should exit 0 (idempotency)"

# 6. scan gates CI: leaky log exits 1, clean text exits 0.
set +e
"$PYTHON" -m scrubcast scan "$ROOT/examples/ci-log.txt" > "$WORKDIR/scan.txt"
scan_rc=$?
set -e
[ "$scan_rc" -eq 1 ] || fail "scan of leaky log should exit 1, got $scan_rc"
grep -q "slack-webhook" "$WORKDIR/scan.txt" || fail "scan missed the Slack webhook"
grep -q "entropy" "$WORKDIR/scan.txt" || fail "scan missed the entropy finding"
printf 'nothing to see here\n' > "$WORKDIR/clean.txt"
"$PYTHON" -m scrubcast scan "$WORKDIR/clean.txt" >/dev/null || fail "clean scan should exit 0"

# 7. Mask style preserves byte length of the log exactly.
"$PYTHON" -m scrubcast scrub "$ROOT/examples/ci-log.txt" --style mask -q > "$WORKDIR/masked.txt"
orig_bytes="$(wc -c < "$ROOT/examples/ci-log.txt")"
masked_bytes="$(wc -c < "$WORKDIR/masked.txt")"
[ "$orig_bytes" -eq "$masked_bytes" ] \
  || fail "mask style changed byte count: $orig_bytes -> $masked_bytes"

# 8. JSON report is machine-readable and names the stream.
"$PYTHON" -m scrubcast scan "$ROOT/examples/demo.cast" --json > "$WORKDIR/report.json" || true
"$PYTHON" - "$WORKDIR/report.json" <<'PY' || fail "JSON report malformed"
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report["count"] == 4
assert all("rule" in f and "location" in f for f in report["findings"])
PY

# 9. rules subcommand lists built-ins; custom rules file applies.
"$PYTHON" -m scrubcast rules | grep -q "aws-access-key-id" || fail "rules listing incomplete"
set +e
"$PYTHON" -m scrubcast scan "$ROOT/examples/ci-log.txt" \
  --rules "$ROOT/examples/scrubcast-rules.json" > "$WORKDIR/custom.txt"
set -e
grep -q "aws-access-key-id" "$WORKDIR/custom.txt" || fail "custom rules run lost built-ins"

echo "SMOKE OK"
