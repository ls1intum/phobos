#!/usr/bin/env bash
# Runs the generic reference exercise under the base the generic image ships, in both directions.
#
# The base is the one the layer pruner derived from this very exercise, so the exercise must pass under it as it
# ships, with only the limits of an exercise added. Permitted direction: exactly the twelve cases of the tester
# pass, each once, and gcc's driver, which lies in /usr/bin like every tool, starts. Containment direction: a C
# compilation that succeeds outside Phobos is refused inside it at cc1, because the base grants none of gcc's
# internals; no row of the base reaches gcc's internals or the C headers; a canary outside every directory the
# base names is refused for read; a write into /usr/bin is refused; a connection is refused by the connect guard;
# and a file the run creates cannot be executed directly, though bash may run it as a script, which the base
# permits and this suite states.
#
# It needs the generic run-phase image with the exercise mounted read-only at /exercise, and an ordinary
# container: no --privileged, no --cap-add, no --security-opt, and --network none.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

CORE="${PHOBOS_HOME:-/var/tmp/opt/core}"
check_base_set "$CORE" BaseLanguage-generic.cfg
EXERCISE_SOURCE=/exercise
EXERCISE=/var/tmp/testing-dir
CANARY=/srv/phobos-generic-canary
CASES="bash solution sort_uniq_wc cut_tr_head_tail_cat mktemp find_xargs grep sed awk diff make words"
REPORTER='^Phobos Security Error: the program tried to illegally '
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

# Returns 0 when a row of a Base*.cfg in CORE, in any section, names the path $1, a path beneath it, or
# an ancestor of it, which is any row whose rights would reach into $1.
base_reaches() {
  local row
  while IFS= read -r row; do
    [[ -z "${row}" || "${row}" == \#* || "${row}" == \[* ]] && continue
    [[ "${row}" == / || "${row}" == "$1" || "${row}" == "$1"/* || "$1" == "${row}"/* ]] && return 0
  done < <(cat "${CORE}"/Base*.cfg)
  return 1
}

# Writes to $1 the report the tester writes when every case of CASES passed, byte for byte. The image has no
# XML parser, and the tester's writer is fixed, so comparing with this canonical report checks every
# element, its order and its closing tag at once.
expected_report() {
  local name
  local body=""
  for name in ${CASES}; do
    body+="    <testcase classname=\"generic\" name=\"${name}\"/>"$'\n'
  done
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<testsuites>\n  <testsuite name="generic" tests="12" failures="0" errors="0" skipped="0">\n%s  </testsuite>\n</testsuites>\n' \
    "${body}" > "$1"
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

under_base "${WORK}/exercise.out" /bin/bash build_script.sh
check "the exercise's build script ends with status 0 under the generic base" 0 "$(cat "${WORK}/exercise.out.status")"
expected_report "${WORK}/expected.xml"
if cmp -s "${WORK}/expected.xml" "${EXERCISE}/test-reports/results.xml"; then
  ok "the JUnit report holds exactly the twelve cases, each once and passed"
else
  bad "the JUnit report holds exactly the twelve cases, each once and passed" "$(cat "${EXERCISE}/test-reports/results.xml" 2>&1; cat "${WORK}/exercise.out")"
fi

printf 'int answer(void) { return 42; }\n' > "${EXERCISE}/probe.c"
(cd "${EXERCISE}" && gcc-14 -c probe.c -o probe.o) > "${WORK}/outside.out" 2>&1
outside=$?
if [[ "${outside}" == 0 && -s "${EXERCISE}/probe.o" ]]; then
  ok "the same compilation succeeds outside Phobos in this image"
else
  bad "the same compilation succeeds outside Phobos in this image" "$(cat "${WORK}/outside.out")"
fi
rm -f "${EXERCISE}/probe.o"
under_base "${WORK}/version.out" gcc-14 --version
check "gcc's driver starts under the base, since /usr/bin is granted whole" 0 "$(cat "${WORK}/version.out.status")"
under_base "${WORK}/compile.out" gcc-14 -c probe.c -o probe.o
if [[ "$(cat "${WORK}/compile.out.status")" != 0 && ! -e "${EXERCISE}/probe.o" ]] \
    && grep -qE "${REPORTER}execute the File '/usr/libexec/gcc/[^']*/cc1'" "${WORK}/compile.out"; then
  ok "the compilation is refused by the sandbox at cc1 and writes no object file"
else
  bad "the compilation is refused by the sandbox at cc1 and writes no object file" "$(cat "${WORK}/compile.out")"
fi
for internal in /usr/libexec/gcc /usr/lib/gcc /usr/include; do
  if base_reaches "${internal}"; then
    bad "no row of the base reaches ${internal}" "$(cat "${CORE}"/Base*.cfg)"
  else
    ok "no row of the base reaches ${internal}"
  fi
done

under_base "${WORK}/canary.out" cat "${CANARY}/secret"
if [[ "$(cat "${WORK}/canary.out.status")" != 0 ]] && grep -q "Permission denied" "${WORK}/canary.out" && ! grep -q '^canary$' "${WORK}/canary.out"; then
  ok "a canary file outside every directory the base names is refused for read"
else
  bad "a canary file outside every directory the base names is refused for read" "$(cat "${WORK}/canary.out")"
fi
under_base "${WORK}/write.out" /bin/bash -c 'echo x > /usr/bin/phobos-generic-probe'
if [[ "$(cat "${WORK}/write.out.status")" != 0 && ! -e /usr/bin/phobos-generic-probe ]]; then
  ok "a write into /usr/bin, which the base only reads and executes, is refused"
else
  bad "a write into /usr/bin, which the base only reads and executes, is refused" "$(cat "${WORK}/write.out")"
fi
under_base "${WORK}/connect.out" /bin/bash -c 'exec 3<>/dev/tcp/10.0.0.1/80'
if [[ "$(cat "${WORK}/connect.out.status")" != 0 ]] \
    && grep -qE "${REPORTER}connect to the Endpoint 10\.0\.0\.1:80 over TCP" "${WORK}/connect.out"; then
  ok "a connection to an address no rule names is refused by the connect guard"
else
  bad "a connection to an address no rule names is refused by the connect guard" "$(cat "${WORK}/connect.out")"
fi

for directory in /tmp "${EXERCISE}"; do
  under_base "${WORK}/exec.out" /bin/bash -c 'printf "#!/bin/bash\necho ran-here\n" > "$1/probe" && chmod +x "$1/probe" && echo prepared && "$1/probe"' sh "${directory}"
  if grep -q "^prepared$" "${WORK}/exec.out" && grep -q "Permission denied" "${WORK}/exec.out" && ! grep -q "ran-here" "${WORK}/exec.out"; then
    ok "a file the run creates in ${directory} cannot be executed directly"
  else
    bad "a file the run creates in ${directory} cannot be executed directly" "$(cat "${WORK}/exec.out")"
  fi
  under_base "${WORK}/script.out" /bin/bash -c 'printf "echo ran-here\n" > "$1/script" && /bin/bash "$1/script"' sh "${directory}"
  if grep -q "ran-here" "${WORK}/script.out"; then
    ok "bash may run a script the run creates in ${directory}, which the base permits"
  else
    bad "bash may run a script the run creates in ${directory}, which the base permits" "$(cat "${WORK}/script.out")"
  fi
done

rm -rf "${WORK}" "${CANARY}"
finish
