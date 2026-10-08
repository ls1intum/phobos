#!/usr/bin/env bash
# Where a run's temporary files are made. Every one belongs in the scratch subdirectory of the
# run's own specification directory, which phobos.sh refuses to place beneath a write path, and
# never in TMPDIR or /tmp, which the shipped policies make writable to the graded command: a
# command of a concurrent run could otherwise see, and with the same user write, a file another
# run is still reading its rules from.
#
# Both directions. Every temporary file phobos.sh, the policy program and the layers make is
# recorded, through a mktemp on PATH that logs and then runs the real one: each lies under the
# run's specification directory, the run itself works, and the network layer is among them, so
# the check is not vacuous. A PHOBOS_SCRATCH left in the environment is never used, and a helper
# called with no scratch directory refuses rather than falling back to TMPDIR.
#
# No Landlock kernel and no compiler is needed: a pass-through stand-in takes the place of each
# enforcer, since what is measured happens before any of them starts.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../src"
# shellcheck source=../../src/phobos-tools-common/phobos-constants.sh
source "${CORE}/phobos-tools-common/phobos-constants.sh"
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
unset PHOBOS_SCRATCH
# The name of the scratch subdirectory, read from the library that defines it.
PHB_SPEC_SCRATCH="$(bash -c 'source "$1/phobos-tools-common/phobos-common.sh"; printf %s "$PHB_SPEC_SCRATCH"' _ "$CORE")"
[[ -n "$PHB_SPEC_SCRATCH" ]] || { echo "cannot read PHB_SPEC_SCRATCH from ${CORE}" >&2; exit 1; }

# A copy of core with a minimal base policy, and one pass-through stand-in that serves as the
# Landlock enforcer, the timeout's group lock and the connect guard.
CORE_X="$WORK/core-x"
cp -R "$CORE" "$CORE_X"
chmod +x "$CORE_X"/*.sh
printf '[read]\n/usr\n' > "$CORE_X/BaseTest.cfg"
PASS="$WORK/passthrough"
printf '%s\n' '#!/bin/sh' 'while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done' 'shift' 'exec "$@"' > "$PASS"
chmod +x "$PASS"
NET_CFG="$WORK/net.cfg"
printf '[connect]\nallow 127.0.0.1:9 tcp\n[bind]\nallow 8080\n' > "$NET_CFG"
SPECS="$WORK/specs"
mkdir -p "$SPECS"

# A mktemp that records every path it makes and then is the real one.
MKTEMP_LOG="$WORK/mktemp.log"
REAL_MKTEMP="$(command -v mktemp)"
mkdir -p "$WORK/bin"
printf '#!/bin/sh\nout="$(%q "$@")" || exit $?\nprintf "%%s\\n" "$out" >> %q\nprintf "%%s\\n" "$out"\n' \
  "$REAL_MKTEMP" "$MKTEMP_LOG" > "$WORK/bin/mktemp"
chmod +x "$WORK/bin/mktemp"
RUN_PATH="$WORK/bin:$PATH"

# A TMPDIR naming no directory, so that a temporary file made through TMPDIR fails the run.
NO_TMPDIR="$WORK/no-such-tmpdir"

# Runs the command line given with the logging mktemp, a TMPDIR naming no directory and the
# environment assignments in EXTRA_ENV; OUT holds stdout and stderr and RC the status.
run_logged() {
  : > "$MKTEMP_LOG"
  OUT="$(env "${EXTRA_ENV[@]}" PATH="$RUN_PATH" TMPDIR="$NO_TMPDIR" bash "$@" 2>&1)"
  RC=$?
}

# Prints the temporary paths of the last run that lie outside every specification directory
# under SPECS, which is what the run may use besides the directories themselves.
stray_paths() {
  grep -v -e "^${SPECS}/phobos-spec\.[^/]*$" -e "^${SPECS}/phobos-spec\.[^/]*/${PHB_SPEC_SCRATCH}/" "$MKTEMP_LOG" || true
}

# Checks the last run: it ended with status 0, it made a temporary file of each template named,
# and every temporary file it made lies under its specification directory.
check_run() {
  local name="$1"
  shift
  local missing=""
  local template
  for template in "$@"; do
    grep -q "/${template}\.[^/]*$" "$MKTEMP_LOG" || missing="${missing} ${template}"
  done
  if [[ "$RC" -eq 0 && -z "$missing" && -z "$(stray_paths)" ]]; then
    ok "$name"
  else
    bad "$name" "exit 0, files of $* made, none outside the specification directory" \
      "exit ${RC}, missing:${missing}, outside: $(stray_paths | tr '\n' ' ') ${OUT}"
  fi
}

EXTRA_ENV=()
echo "== every temporary file of a run lies in its own specification directory =="
run_logged "$CORE_X/phobos.sh" --spec-parent "$SPECS" --landlock-bin "$PASS" --pgroup-lock-bin "$PASS" \
  --connect-guard-bin "$PASS" --config "$NET_CFG" -- /bin/true
check_run "phobos.sh: the policy program, the network and the filesystem layer keep their files in the run's specification directory" \
  phobos-ports phobos-wildcard phobos-bindports phobos-rights
run_logged "$CORE_X/phobos-networksystem.sh" --spec-parent "$SPECS" --connect-guard-bin "$PASS" \
  --landlock-bin "$PASS" --config "$NET_CFG" -- /bin/true
check_run "phobos-networksystem.sh on its own keeps its files in its specification directory" \
  phobos-ports phobos-wildcard phobos-bindports
run_logged "$CORE_X/phobos-filesystem.sh" --spec-parent "$SPECS" --landlock-bin "$PASS" \
  --config "$NET_CFG" -- /bin/true
check_run "phobos-filesystem.sh on its own keeps its files in its specification directory" phobos-rights

echo
echo "== a PHOBOS_SCRATCH left in the environment is never used =="
EXTRA_ENV=( PHOBOS_SCRATCH="$WORK/foreign-scratch" )
mkdir -p "$WORK/foreign-scratch"
run_logged "$CORE_X/phobos.sh" --spec-parent "$SPECS" --landlock-bin "$PASS" --pgroup-lock-bin "$PASS" \
  --connect-guard-bin "$PASS" --config "$NET_CFG" -- /bin/true
check_run "phobos.sh with PHOBOS_SCRATCH in its environment still keeps every file in its own specification directory" \
  phobos-ports phobos-bindports phobos-rights
run_logged "$CORE_X/phobos-networksystem.sh" --spec-parent "$SPECS" --connect-guard-bin "$PASS" \
  --landlock-bin "$PASS" --config "$NET_CFG" -- /bin/true
check_run "phobos-networksystem.sh with PHOBOS_SCRATCH in its environment still keeps every file in its own" \
  phobos-ports phobos-bindports
EXTRA_ENV=()

echo
echo "== a helper given no scratch directory refuses rather than fall back to TMPDIR =="
mkdir -p "$WORK/tmpdir"
for helper in "new_scratch_file phobos-probe.XXXXXX" "new_parse_directory"; do
  OUT="$(TMPDIR="$WORK/tmpdir" bash -c 'unset PHOBOS_SCRATCH; source "$1/phobos-tools-common/phobos-common.sh"; $2' _ "$CORE" "$helper" 2>&1)"
  RC=$?
  left="$(find "$WORK/tmpdir" -mindepth 1 | wc -l | tr -d ' ')"
  if [[ "$RC" -eq "$PHB_ERUNTIME" && "$left" -eq 0 && "$OUT" == *PHB-ERUNTIME* ]]; then
    ok "${helper%% *} with no PHOBOS_SCRATCH refuses with PHB-ERUNTIME and makes nothing in TMPDIR"
  else
    bad "${helper%% *} with no PHOBOS_SCRATCH refuses with PHB-ERUNTIME and makes nothing in TMPDIR" \
      "exit ${PHB_ERUNTIME}, nothing in TMPDIR" "exit ${RC}, ${left} made: ${OUT}"
  fi
  rm -rf "${WORK:?}/tmpdir/"*
done
mkdir -p "$WORK/given"
OUT="$(bash -c 'source "$1/phobos-tools-common/phobos-common.sh"; PHOBOS_SCRATCH="$2"; new_scratch_file phobos-probe.XXXXXX' _ "$CORE" "$WORK/given" 2>&1)"
RC=$?
if [[ "$RC" -eq 0 && "$OUT" == "$WORK/given/phobos-probe."* && -f "$OUT" ]]; then
  ok "new_scratch_file with PHOBOS_SCRATCH makes its file there"
else
  bad "new_scratch_file with PHOBOS_SCRATCH makes its file there" "a file under ${WORK}/given" "exit ${RC}: ${OUT}"
fi

finish
