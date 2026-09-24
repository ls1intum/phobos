#!/usr/bin/env bash
# shellcheck shell=bash
# What every suite here uses to report a check, and nothing else.
#
# Each suite used to carry its own ok, bad and counters, and they had drifted into three
# dialects: two counter namings, two colour schemes and three shapes of failure detail. The
# reporting is now stated once, and a suite that sources this file keeps everything else of
# its own: its shell options, its fixtures, its cleanup trap. That is deliberate. The
# acceptance suites run without `set -e` on purpose, and a shared trap or a shared option
# would change what a suite does rather than only how it prints.
#
# Sourced as "${HERE}/harness.sh" by the suites beside it and as "../harness.sh" by the
# acceptance suites below, which is why the acceptance job mounts tests/ rather than
# tests/landlock-filesystem-and-networksystem-acceptance/.
#
# The contract the suites depend on, which tests/harness_self_test.sh pins:
#
# - bad records a failure and RETURNS SUCCESSFULLY, so the checks after it still run and a
#   suite under `set -e` is not ended by its own first failure. Only finish answers non-zero.
# - bad prints whatever detail it was given: nothing, one free line, or an expected and an
#   actual pair. That is what lets every existing call site stay as it was written.
# - a skipped check is not a passing one. It is counted apart and finish names it.

# The checks this suite has reported so far.
passed=0
failed=0
skipped=0

# Reports a check that held. Takes its name, which may be several words.
ok() {
  printf 'ok    %s\n' "$*"
  passed=$((passed + 1))
}

# Reports a check that did not hold, and returns successfully so the suite carries on.
# Takes its name, then nothing, or one line of detail, or an expected and an actual value.
bad() {
  local name="$1"
  shift
  printf 'FAIL  %s\n' "$name"
  if (( $# == 1 )); then
    printf '        %s\n' "$1"
  elif (( $# >= 2 )); then
    printf '        expected: %s\n        actual:   %s\n' "$1" "$2"
  fi
  failed=$((failed + 1))
  return 0
}

# Reports a check that did not run, with the reason it did not. A skip is not a pass, so it
# is counted apart and finish says so.
skip() {
  printf 'SKIP  %s\n        reason:   %s\n' "$1" "$2"
  skipped=$((skipped + 1))
  return 0
}

# Compares what a case produced with what it should produce, and records the outcome.
check() {
  local name="$1"
  local want="$2"
  local got="$3"
  if [[ "$got" == "$want" ]]; then ok "$name"; else bad "$name" "$want" "$got"; fi
}

# Prints the counts and ends the suite, non-zero when anything failed. A suite ends with
# this rather than with a bare test, so that the status and the printed summary can never
# disagree.
finish() {
  echo
  if (( skipped > 0 )); then
    printf '%d passed, %d failed, %d skipped\n' "$passed" "$failed" "$skipped"
  else
    printf '%d passed, %d failed\n' "$passed" "$failed"
  fi
  (( failed == 0 )) || exit 1
  exit 0
}
