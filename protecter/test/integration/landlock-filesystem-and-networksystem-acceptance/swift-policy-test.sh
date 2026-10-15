#!/usr/bin/env bash
# Runs the Swift reference exercise under the Swift base the Swift image ships, in both directions.
#
# The base is the one the layer pruner derived from this very exercise, so the exercise must pass under it as it
# ships, with only the limits of an exercise added. Permitted direction: the template's three phases (setup, swift
# build, swift test) pass, the ten tests of the template succeed and the JUnit report is written. Containment
# direction: a canary file outside every directory the base names is refused for read, an overwrite of a file in a
# directory the base only reads is refused, a connection to an address no rule names is refused, and a file the run
# writes can be executed in the directory of the solution and nowhere else.
#
# /dev/urandom, the one row of the base kept by hand: Foundation 6.2 reads the bytes of every UUID() from it without
# checking the open, and SwiftPM's repository queue loses a waiting fetch when its UUIDs are equal. Permitted direction:
# a run reads 16 bytes from it, a program compiled under the base makes two different UUIDs, and the build passes again
# with SwiftPM's queue narrowed to one operation (SWIFTPM_MAX_CONCURRENT_OPERATIONS=1, as with 2 CPUs), which runs the
# fetches one at a time whenever they overlap. Containment direction: opening /dev/urandom for writing and /dev/random,
# which no row names, are refused with EACCES, where the same opens succeed outside Phobos.
#
# It needs the Swift run-phase image with the exercise mounted read-only at /exercise, and an ordinary container: no
# --privileged, no --cap-add, no --security-opt, and --network none.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

CORE="${PHOBOS_HOME:-/var/tmp/opt/core}"
check_base_set "$CORE" BaseLanguage-swift.cfg
EXERCISE_SOURCE=/exercise
EXERCISE=/var/tmp/testing-dir
CANARY=/srv/phobos-swift-canary
LIMITS="$(mktemp)"
trap 'rm -f "${LIMITS}"' EXIT
printf '[limits]\ntimeout=300\ncpu=200\nnproc=512\nnofile=2048\nfsize_mb=64\n' > "${LIMITS}"

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

REPORT="${EXERCISE}/assignment/tests.xml"
under_base "${WORK}/exercise.out" bash build_script.sh
check "the exercise's build script ends with status 0 under the Swift base" 0 "$(cat "${WORK}/exercise.out.status")"
if [[ -s "${REPORT}" ]] && [[ "$(grep -c '<testcase ' "${REPORT}")" == 10 ]] && ! grep -q '<failure' "${REPORT}"; then
  ok "the JUnit report is written and holds 10 tests and no failure"
else
  bad "the JUnit report is written and holds 10 tests and no failure" "$(head -c 600 "${REPORT}" 2>&1; tail -12 "${WORK}/exercise.out")"
fi

under_base "${WORK}/canary.out" cat "${CANARY}/secret"
if grep -q "Permission denied" "${WORK}/canary.out"; then
  ok "a canary file outside every directory the base names is refused for read"
else
  bad "a canary file outside every directory the base names is refused for read" "$(cat "${WORK}/canary.out")"
fi
printf 'original\n' > /usr/lib/phobos-swift-probe
under_base "${WORK}/write.out" sh -c 'echo x > /usr/lib/phobos-swift-probe'
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

for directory in "${EXERCISE}/home" "${EXERCISE}/test"; do
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
  ok "a file the run writes into the directory of the solution can be executed there"
else
  bad "a file the run writes into the directory of the solution can be executed there" "$(cat "${WORK}/exec-allowed.out")"
fi

if [[ "$(cat /usr/lib/phobos-swift-probe)" == original ]]; then
  ok "and the file in the read-only directory is unchanged"
else
  bad "and the file in the read-only directory is unchanged" "$(cat /usr/lib/phobos-swift-probe)"
fi

OPEN_PROBE='import os, sys
flags = os.O_WRONLY if sys.argv[2] == "write" else os.O_RDONLY
try:
    fd = os.open(sys.argv[1], flags)
except PermissionError as refusal:
    print("errno", refusal.errno)
else:
    if sys.argv[2] == "read":
        print("read", len(os.read(fd, 16)))
    else:
        print("opened")
    os.close(fd)'
under_base "${WORK}/urandom-read.out" python3 -c "${OPEN_PROBE}" /dev/urandom read
if grep -q "^read 16$" "${WORK}/urandom-read.out"; then
  ok "a run reads 16 bytes from /dev/urandom under the base"
else
  bad "a run reads 16 bytes from /dev/urandom under the base" "$(cat "${WORK}/urandom-read.out")"
fi
for probe in "/dev/urandom write" "/dev/random open"; do
  read -r device mode <<< "${probe}"
  outside="$(python3 -c "${OPEN_PROBE}" "${device}" "${mode}" 2>&1)"
  under_base "${WORK}/device.out" python3 -c "${OPEN_PROBE}" "${device}" "${mode}"
  if [[ "${outside}" == "opened" ]] && grep -q "^errno 13$" "${WORK}/device.out"; then
    ok "opening ${device} to ${mode} is refused with EACCES under the base and succeeds outside Phobos"
  else
    bad "opening ${device} to ${mode} is refused with EACCES under the base and succeeds outside Phobos" \
      "outside: ${outside}; under the base: $(cat "${WORK}/device.out")"
  fi
done

UUID_PROBE="${EXERCISE}/assignment/uuid-probe"
printf 'import Foundation\nlet first = UUID()\nlet second = UUID()\nprint(first == second ? "equal \\(first)" : "distinct")\n' \
  > "${UUID_PROBE}.swift"
under_base "${WORK}/uuid-build.out" env HOME="${EXERCISE}/home" TMPDIR="${EXERCISE}/assignment/.tmp" \
  swiftc -o "${UUID_PROBE}" "${UUID_PROBE}.swift"
under_base "${WORK}/uuid.out" "${UUID_PROBE}"
outside="$("${UUID_PROBE}" 2>&1)"
if [[ "$(cat "${WORK}/uuid-build.out.status")" == 0 ]] && [[ "${outside}" == distinct ]] \
    && grep -q "^distinct$" "${WORK}/uuid.out"; then
  ok "a program compiled under the base makes two different UUIDs there, as it does outside Phobos"
else
  bad "a program compiled under the base makes two different UUIDs there, as it does outside Phobos" \
    "outside: ${outside}; under the base: $(cat "${WORK}/uuid.out"); build: $(tail -5 "${WORK}/uuid-build.out")"
fi

rm -rf "${EXERCISE:?}"/*
cp -a "${EXERCISE_SOURCE}/." "${EXERCISE}/"
under_base "${WORK}/narrow.out" env SWIFTPM_MAX_CONCURRENT_OPERATIONS=1 bash build_script.sh
check "the build script ends with status 0 with SwiftPM's queue narrowed to one operation" 0 \
  "$(cat "${WORK}/narrow.out.status")"
if [[ -s "${REPORT}" ]] && [[ "$(grep -c '<testcase ' "${REPORT}")" == 10 ]] && ! grep -q '<failure' "${REPORT}"; then
  ok "and its JUnit report holds 10 tests and no failure"
else
  bad "and its JUnit report holds 10 tests and no failure" "$(head -c 600 "${REPORT}" 2>&1; tail -12 "${WORK}/narrow.out")"
fi
rm -rf "${WORK}" "${CANARY}" /usr/lib/phobos-swift-probe
finish
