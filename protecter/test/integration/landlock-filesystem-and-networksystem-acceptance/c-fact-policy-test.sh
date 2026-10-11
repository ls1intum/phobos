#!/usr/bin/env bash
# Runs the FACT reference exercise under the C base the FACT image ships, in both directions.
#
# The base is the one the layer pruner derived from this very exercise, so the exercise must pass under it as it
# ships, with only the limits of an exercise added. Permitted direction: the template's phases (compile with the
# tester's Makefile, then FACT's tester) run, the three tests of the template pass and the JUnit report is written.
# Containment direction: a canary file outside every directory the base names is refused for read, a write into a
# directory the base only reads is refused, a connection to an address no rule names is refused, and a file the
# run writes can be executed in the directory of the submission and nowhere else (the one widening this base
# has, stated in its header).
#
# It needs the FACT run-phase image with the exercise mounted read-only at /exercise, and an ordinary
# container: no --privileged, no --cap-add, no --security-opt, and --network none.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

CORE="${PHOBOS_HOME:-/var/tmp/opt/core}"
check_base_set "$CORE" BaseLanguage-c-fact.cfg
EXERCISE_SOURCE=/exercise
EXERCISE=/var/tmp/testing-dir
CANARY=/srv/phobos-c-fact-canary
LIMITS="$(mktemp)"
trap 'rm -f "${LIMITS}"' EXIT
printf '[limits]\ntimeout=60\ncpu=30\nnproc=64\nnofile=512\nfsize_mb=16\n' > "${LIMITS}"

# Runs a command in the working directory under the shipped base and the exercise's limits, its
# combined output in $1 and its status in the file $1.status.
under_base() {
  local output="$1"
  shift
  (cd "${EXERCISE}" && "${CORE}/phobos.sh" --config "${LIMITS}" -- "$@") > "${output}" 2>&1
  printf '%s' "$?" > "${output}.status"
}

if [[ ! -d "${EXERCISE_SOURCE}" ]]; then
  bad "the reference exercise is mounted read-only at ${EXERCISE_SOURCE}"
  finish
  exit 1
fi
rm -rf "${EXERCISE:?}"/*
cp -a "${EXERCISE_SOURCE}/." "${EXERCISE}/"
WORK="$(mktemp -d)"
mkdir -p "${CANARY}"
printf 'canary\n' > "${CANARY}/secret"

under_base "${WORK}/exercise.out" bash build_script.sh
check "the exercise's build script ends with status 0 under the FACT base" 0 "$(cat "${WORK}/exercise.out.status")"
if grep -q "SUCCESS: 3" "${WORK}/exercise.out"; then
  ok "the three tests of the template pass"
else
  bad "the three tests of the template pass" "$(tail -12 "${WORK}/exercise.out")"
fi
if [[ -s "${EXERCISE}/test-reports/tests-results.xml" ]] && grep -q 'tests="3"' "${EXERCISE}/test-reports/tests-results.xml" \
    && grep -q 'failures="0"' "${EXERCISE}/test-reports/tests-results.xml" \
    && grep -q 'errors="0"' "${EXERCISE}/test-reports/tests-results.xml"; then
  ok "the JUnit report is written and holds 3 tests and no failure"
else
  bad "the JUnit report is written and holds 3 tests and no failure" "$(head -c 600 "${EXERCISE}/test-reports/tests-results.xml" 2>&1)"
fi

under_base "${WORK}/canary.out" cat "${CANARY}/secret"
if grep -q "Permission denied" "${WORK}/canary.out"; then
  ok "a canary file outside every directory the base names is refused for read"
else
  bad "a canary file outside every directory the base names is refused for read" "$(cat "${WORK}/canary.out")"
fi
printf 'original\n' > /usr/lib/phobos-c-fact-probe
under_base "${WORK}/write.out" sh -c 'echo x > /usr/lib/phobos-c-fact-probe'
if grep -q "Permission denied" "${WORK}/write.out"; then
  ok "an overwrite of a file in a directory the base only reads is refused"
else
  bad "an overwrite of a file in a directory the base only reads is refused" "$(cat "${WORK}/write.out")"
fi
under_base "${WORK}/connect.out" python3 -c 'import socket; socket.create_connection(("10.0.0.1", 80), timeout=2)'
if grep -q "PermissionError: \[Errno 13\]" "${WORK}/connect.out"; then
  ok "a connection to an address no rule names is refused"
else
  bad "a connection to an address no rule names is refused" "$(cat "${WORK}/connect.out")"
fi

for directory in /tmp "${EXERCISE}/test"; do
  under_base "${WORK}/exec-refused.out" sh -c 'printf "#!/bin/sh\necho ran-here\n" > "$1/probe" && chmod +x "$1/probe" && echo prepared && "$1/probe"' sh "${directory}"
  if grep -q "^prepared$" "${WORK}/exec-refused.out" && grep -q "Permission denied" "${WORK}/exec-refused.out" \
      && ! grep -q "ran-here" "${WORK}/exec-refused.out"; then
    ok "a file the run writes into ${directory} is not made executable"
  else
    bad "a file the run writes into ${directory} is not made executable" "$(cat "${WORK}/exec-refused.out")"
  fi
done
under_base "${WORK}/exec-allowed.out" sh -c 'printf "#!/bin/sh\necho ran-here\n" > "$1/probe" && chmod +x "$1/probe" && "$1/probe"' sh "${EXERCISE}/assignment"
if grep -q "ran-here" "${WORK}/exec-allowed.out"; then
  ok "a file the run writes into the directory of the submission can be executed there"
else
  bad "a file the run writes into the directory of the submission can be executed there" "$(cat "${WORK}/exec-allowed.out")"
fi

if [[ "$(cat /usr/lib/phobos-c-fact-probe)" == original ]]; then
  ok "and the file in that directory is unchanged"
else
  bad "and the file in that directory is unchanged" "$(cat /usr/lib/phobos-c-fact-probe)"
fi
rm -rf "${WORK}" "${CANARY}" /usr/lib/phobos-c-fact-probe
finish
