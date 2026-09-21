#!/usr/bin/env bash
# The harness every other suite reports through, checked before they are trusted.
#
# A reporting helper that gets this wrong does not announce itself: it makes a suite green.
# The three properties below are the ones that would do that, so they are measured rather
# than assumed.
#
# - bad must record a failure and return successfully. If it returned non-zero, a suite
#   under `set -e` would end at its first failure and the checks after it would never run,
#   which reads as a shorter suite rather than as a broken one.
# - finish must answer non-zero when anything failed, and zero otherwise, and its printed
#   summary must agree with the status it exits with.
# - a skip must be counted apart from a pass, because a skip that counted as a pass is
#   exactly the silence tests/README.md warns about.
#
# It does not source the harness into itself, which would leave it reporting through the
# thing it is testing. Each case runs a small suite in a shell of its own and reads what
# that shell printed and answered.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${HERE}/harness.sh"

passed=0
failed=0

# Reports a check of this file's own, without using the harness under test.
own_ok() {
  printf 'ok    %s\n' "$1"
  passed=$((passed + 1))
}

own_bad() {
  printf 'FAIL  %s\n        expected: %s\n        actual:   %s\n' "$1" "$2" "$3"
  failed=$((failed + 1))
}

# Runs a small suite that sources the harness, and prints "<exit>|<output with newlines as
# spaces>". The body runs under the shell options a suite would use.
run_suite() {
  local body="$1"
  local options="$2"
  local output
  output="$(bash -c "set ${options}
source '${HARNESS}'
${body}" 2>&1)"
  printf '%s|%s' "$?" "$(printf '%s' "$output" | tr '\n' ' ')"
}

field() { cut -d'|' -f"$2" <<<"$1"; }

echo "== a failure is recorded and the suite carries on =="
r="$(run_suite 'bad "first" "wanted" "got"
ok "second"
finish' '-uo pipefail')"
[[ "$(field "$r" 2)" == *"ok    second"* ]] \
  && own_ok "the check after a failure still runs" \
  || own_bad "the check after a failure still runs" "ok    second in the output" "$(field "$r" 2)"
[[ "$(field "$r" 2)" == *"1 passed, 1 failed"* ]] \
  && own_ok "both outcomes are counted" \
  || own_bad "both outcomes are counted" "1 passed, 1 failed" "$(field "$r" 2)"

echo
echo "== bad does not end a suite that runs under set -e =="
r="$(run_suite 'bad "first" "detail"
ok "reached"
finish' '-euo pipefail')"
[[ "$(field "$r" 2)" == *"ok    reached"* ]] \
  && own_ok "bad returns successfully, so set -e does not end the suite" \
  || own_bad "bad returns successfully, so set -e does not end the suite" \
             "ok    reached in the output" "$(field "$r" 2)"

echo
echo "== the status and the summary agree =="
r="$(run_suite 'ok "one"
finish' '-uo pipefail')"
[[ "$(field "$r" 1)" == 0 ]] \
  && own_ok "a suite with no failure answers zero" \
  || own_bad "a suite with no failure answers zero" "0" "$(field "$r" 1)"
r="$(run_suite 'ok "one"
bad "two" "detail"
finish' '-uo pipefail')"
[[ "$(field "$r" 1)" == 1 ]] \
  && own_ok "a suite with a failure answers one" \
  || own_bad "a suite with a failure answers one" "1" "$(field "$r" 1)"

echo
echo "== a skipped check is not a passing one =="
r="$(run_suite 'ok "one"
skip "two" "no kernel for it"
finish' '-uo pipefail')"
[[ "$(field "$r" 2)" == *"1 passed, 0 failed, 1 skipped"* ]] \
  && own_ok "a skip is counted apart and named in the summary" \
  || own_bad "a skip is counted apart and named in the summary" \
             "1 passed, 0 failed, 1 skipped" "$(field "$r" 2)"
[[ "$(field "$r" 1)" == 0 ]] \
  && own_ok "a skip alone does not fail the suite" \
  || own_bad "a skip alone does not fail the suite" "0" "$(field "$r" 1)"

echo
echo "== every shape of failure detail the suites use =="
r="$(run_suite 'bad "no detail"
finish' '-uo pipefail')"
[[ "$(field "$r" 2)" == *"FAIL  no detail"* ]] \
  && own_ok "a failure with no detail names itself" \
  || own_bad "a failure with no detail names itself" "FAIL  no detail" "$(field "$r" 2)"
r="$(run_suite 'bad "one line" "the detail"
finish' '-uo pipefail')"
[[ "$(field "$r" 2)" == *"FAIL  one line         the detail"* ]] \
  && own_ok "one line of detail is printed as it was given" \
  || own_bad "one line of detail is printed as it was given" "the detail, unlabelled" "$(field "$r" 2)"
r="$(run_suite 'bad "a pair" "wanted" "got"
finish' '-uo pipefail')"
[[ "$(field "$r" 2)" == *"expected: wanted"* && "$(field "$r" 2)" == *"actual:   got"* ]] \
  && own_ok "an expected and an actual value are labelled" \
  || own_bad "an expected and an actual value are labelled" "expected: wanted, actual: got" "$(field "$r" 2)"

echo
echo "== check compares and records =="
r="$(run_suite 'check "same" "x" "x"
check "different" "x" "y"
finish' '-uo pipefail')"
[[ "$(field "$r" 2)" == *"1 passed, 1 failed"* ]] \
  && own_ok "check records a match as a pass and a mismatch as a failure" \
  || own_bad "check records a match as a pass and a mismatch as a failure" \
             "1 passed, 1 failed" "$(field "$r" 2)"

echo
printf '%d passed, %d failed\n' "$passed" "$failed"
(( failed == 0 )) || exit 1
exit 0
