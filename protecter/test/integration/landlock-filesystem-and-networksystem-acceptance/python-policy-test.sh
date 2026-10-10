#!/usr/bin/env bash
# Runs the Python reference exercise under the Python base the image ships, in both directions.
#
# The base is the one the layer pruner derived from this very exercise, so the exercise must pass
# under it as it ships, with only the limits of an exercise added. Permitted direction: the
# template's two phases (compileall, then pytest) run, both test cases pass and the JUnit report
# is written. Containment direction: a canary file outside every directory the base names is refused
# for read, a write outside the working directory is refused, and a connection to an address no rule
# names is refused.
#
# It needs the Python run-phase image with the exercise mounted read-only at /exercise, and an
# ordinary container: no --privileged, no --cap-add, no --security-opt, and --network none.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

CORE="${PHOBOS_HOME:-/var/tmp/opt/core}"
check_base_set "$CORE" BaseLanguage-python.cfg
EXERCISE_SOURCE=/exercise
EXERCISE=/var/tmp/testing-dir
CANARY=/srv/phobos-python-canary
LIMITS="$(mktemp)"
trap 'rm -f "${LIMITS}"' EXIT
printf '[limits]\ntimeout=120\ncpu=60\nnproc=128\nnofile=512\nfsize_mb=16\n' > "${LIMITS}"

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
check "the exercise's build script ends with status 0 under the Python base" 0 "$(cat "${WORK}/exercise.out.status")"
if grep -q "2 passed" "${WORK}/exercise.out"; then
  ok "both test cases pass"
else
  bad "both test cases pass" "$(tail -12 "${WORK}/exercise.out")"
fi
if [[ -s "${EXERCISE}/test-reports/results.xml" ]] && grep -q 'tests="2"' "${EXERCISE}/test-reports/results.xml" \
    && grep -q 'failures="0"' "${EXERCISE}/test-reports/results.xml"; then
  ok "the JUnit report is written and holds two tests and no failure"
else
  bad "the JUnit report is written and holds two tests and no failure" "$(head -c 600 "${EXERCISE}/test-reports/results.xml" 2>&1)"
fi

under_base "${WORK}/canary.out" cat "${CANARY}/secret"
if grep -q "Permission denied" "${WORK}/canary.out"; then
  ok "a canary file outside every directory the base names is refused for read"
else
  bad "a canary file outside every directory the base names is refused for read" "$(cat "${WORK}/canary.out")"
fi
under_base "${WORK}/write.out" sh -c 'echo x > /usr/local/lib/phobos-python-probe'
if grep -q "Permission denied" "${WORK}/write.out"; then
  ok "a write into a directory the base only reads is refused"
else
  bad "a write into a directory the base only reads is refused" "$(cat "${WORK}/write.out")"
fi
under_base "${WORK}/connect.out" python3 -c 'import socket; socket.create_connection(("10.0.0.1", 80), timeout=2)'
if grep -q "PermissionError: \[Errno 13\]" "${WORK}/connect.out"; then
  ok "a connection to an address no rule names is refused"
else
  bad "a connection to an address no rule names is refused" "$(cat "${WORK}/connect.out")"
fi

rm -rf "${WORK}" "${CANARY}"
finish
