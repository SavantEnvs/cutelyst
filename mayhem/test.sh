#!/usr/bin/env bash
#
# mayhem/test.sh — run Cutelyst's own QtTest suite (built by mayhem/build.sh into build-tests/)
# Each test binary QCOMPAREs request/response/dispatcher/plugin/server results
# against expected values, so a neutered build fails. Emits a CTRF report.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

shopt -s nullglob
bins=(build-tests/tests/*_exec)
if [ "${#bins[@]}" -eq 0 ]; then
  echo "test.sh: no build-tests/tests/*_exec — mayhem/build.sh did not build the test suite" >&2
  emit_ctrf "qtest" 0 1 0
  exit 1
fi

# Run every QtTest binary upstream's ctest registers and read QtTest's own verdict line
# "Totals: P passed, F failed, S skipped, B blacklisted, ...". Each test function QCOMPAREs
# real values (request parsing, dispatch, responses, plugins), so a binary that prints no Totals
# line (crashed, or did nothing) is a failure, not a pass.
export QT_QPA_PLATFORM=offscreen
passed=0 failed=0 skipped=0
for b in "${bins[@]}"; do
  name=$(basename "$b" _exec)
  out=$(cd build-tests/tests && "./$(basename "$b")" 2>&1)
  rc=$?
  totals=$(grep -E '^Totals: [0-9]+ passed, [0-9]+ failed, [0-9]+ skipped' <<<"$out" | tail -1)
  if [ -z "$totals" ]; then
    echo "FAIL $name: no QtTest Totals line (exit $rc)"
    printf '%s\n' "$out" | tail -20
    failed=$((failed + 1))
    continue
  fi
  p=$(sed -E 's/^Totals: ([0-9]+) passed.*/\1/' <<<"$totals")
  f=$(sed -E 's/^Totals: [0-9]+ passed, ([0-9]+) failed.*/\1/' <<<"$totals")
  sk=$(sed -E 's/^Totals: [0-9]+ passed, [0-9]+ failed, ([0-9]+) skipped.*/\1/' <<<"$totals")
  if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then
    f=1
  fi
  [ "$f" -eq 0 ] || printf '%s\n' "$out" | grep -E '^(FAIL!|   Loc:|   Actual|   Expected)' | head -40
  echo "$name: $totals"
  passed=$((passed + p)); failed=$((failed + f)); skipped=$((skipped + sk))
done
emit_ctrf "qtest" "$passed" "$failed" "$skipped"
