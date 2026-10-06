#!/usr/bin/env bash
# What every entry point does with the environment it is started in, before it runs anything:
# no PATH entry that is relative or empty, which means the current directory, is ever used to
# find a program, CDPATH never redirects the entry point's own cd, a relative TMPDIR never reaches
# a program that would make its temporary files beneath the current directory, the C library's own
# path variables keep only what is absolute, and a PATH with no absolute entry at all is refused rather than searched.
# The current directory is the submission's tree when a grader starts Phobos there, and every
# program found through it would run before any sandbox exists.
#
# Both directions. A tool of every name the absolute PATH holds is planted in the current
# directory, in a relative directory and in a directory spelled with a tilde, each one a stub
# that records that it ran and then runs the real tool; no entry point may run one of them.
# And a run with a clean absolute PATH behaves as it did, the command seeing that PATH unchanged,
# while the command of a run with a polluted PATH sees exactly the absolute entries.
#
# Every entry point is started through bash by its absolute path rather than as a program. The
# #!/usr/bin/env bash line would otherwise find bash itself through the polluted PATH before the
# entry point runs a line, which no script can prevent; SECURITY.md states that as an
# integration requirement, and this suite measures what the scripts themselves do.
#
# No Landlock kernel and no compiler is needed: pass-through stand-ins take the place of the
# enforcers, since what is measured here happens before any of them is started.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../core"
# shellcheck source=../../core/phobos-tools-common/phobos-constants.sh
source "${CORE}/phobos-tools-common/phobos-constants.sh"
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
# Every variable this suite sets for a run on purpose, so that a value the caller's environment
# carries can neither pass a control nor fail a check that expects it absent.
unset TMPDIR CDPATH GCONV_PATH LOCPATH NLSPATH HOSTALIASES TZDIR

# The suite's own PATH with only its absolute directories, the PATH a clean run is given.
CLEAN_PATH=""
IFS=: read -r -a own_entries <<< "$PATH"
for entry in "${own_entries[@]}"; do
  if [[ "$entry" == /* && -d "$entry" ]]; then CLEAN_PATH="${CLEAN_PATH:+${CLEAN_PATH}:}${entry}"; fi
done
IFS=: read -r -a clean_entries <<< "$CLEAN_PATH"
BASH_BIN="$(command -v bash)"

# A copy of core with a minimal base policy, and one pass-through stand-in that serves as the
# Landlock enforcer, the timeout's group lock, the connect guard and the filesystem layer's denial
# reporter: it skips its own options up to -- and execs the rest, so a run reaches the command
# without a kernel feature, and no layer prints a notice for a program the copy does not hold.
CORE_X="$WORK/core-x"
cp -R "$CORE" "$CORE_X"
chmod +x "$CORE_X"/*.sh
printf '[read]\n/usr\n' > "$CORE_X/BaseTest.cfg"
BASE="$CORE_X/BaseTest.cfg"
PASS="$WORK/passthrough"
printf '%s\n' '#!/bin/sh' 'while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done' 'shift' 'exec "$@"' > "$PASS"
chmod +x "$PASS"
CONNECT_CFG="$WORK/connect.cfg"
printf '[connect]\nallow 127.0.0.1:9 tcp\n' > "$CONNECT_CFG"
SPECS="$WORK/specs"
mkdir -p "$SPECS"
export HOME="$WORK/home"
mkdir -p "$HOME"

# The submission's tree, which is the current directory of every run below, and the record
# every planted stub appends its name to.
SUB="$WORK/submission"
PLANTED_LOG="$WORK/planted.log"
mkdir -p "$SUB/relative/dir" "$SUB/~/bin"

# Plants in directory $1 a stub for every program the clean PATH holds, the first one of each
# name: it appends its name to PLANTED_LOG and then runs the real program, so a run that uses
# one goes on as it would have and the record alone says that it happened.
plant_every_tool() {
  local target="$1"
  local dir
  local program
  local name
  for dir in "${clean_entries[@]}"; do
    for program in "$dir"/*; do
      [[ -f "$program" && -x "$program" ]] || continue
      name="${program##*/}"
      [[ -e "$target/$name" ]] && continue
      printf '#!/bin/sh\nprintf "%%s\\n" %q >> %q\nexec %q "$@"\n' "$name" "$PLANTED_LOG" "$program" > "$target/$name"
      chmod +x "$target/$name"
    done
  done
}
plant_every_tool "$SUB"
plant_every_tool "$SUB/relative/dir"
plant_every_tool "$SUB/~/bin"

# A directory holding every program of the clean PATH except dirname, so that a PATH made of it
# and a trailing empty entry can find dirname only in the current directory.
NO_DIRNAME="$WORK/no-dirname"
mkdir -p "$NO_DIRNAME"
for dir in "${clean_entries[@]}"; do
  for program in "$dir"/*; do
    name="${program##*/}"
    [[ -f "$program" && -x "$program" && "$name" != dirname && ! -e "$NO_DIRNAME/$name" ]] || continue
    ln -s "$program" "$NO_DIRNAME/$name"
  done
done

# Runs one entry point from the submission's tree under the PATH in $1, through bash by its
# absolute path, with the rest of the arguments; OUT holds stdout and stderr, RC the status, and
# PLANTED the names of the planted stubs that ran, sorted and on one line.
run_entry() {
  local path="$1"
  shift
  : > "$PLANTED_LOG"
  OUT="$(cd "$SUB" && PATH="$path" "$BASH_BIN" "$@" 2>&1)"
  RC=$?
  PLANTED="$(sort -u "$PLANTED_LOG" | tr '\n' ' ')"
}

# The argument vectors of the six entry points, each ending in the command it runs, which is
# env, so its output is the environment the command was given. phobos-policysystem.sh runs no
# command and is given a fresh specification directory instead.
entry_args() {
  local entry="$1"
  case "$entry" in
    phobos.sh)
      printf '%s\0' "$CORE_X/phobos.sh" --spec-parent "$SPECS" --landlock-bin "$PASS" \
        --pgroup-lock-bin "$PASS" --connect-guard-bin "$PASS" --config "$BASE" -- /usr/bin/env ;;
    phobos-policysystem.sh)
      printf '%s\0' "$CORE_X/phobos-policysystem.sh" --spec-dir "$(mktemp -d "$WORK/policy.XXXXXX")" --config "$BASE" ;;
    phobos-filesystem.sh)
      printf '%s\0' "$CORE_X/phobos-filesystem.sh" --spec-parent "$SPECS" --landlock-bin "$PASS" \
        --reporter-bin "$PASS" --config "$BASE" -- /usr/bin/env ;;
    phobos-networksystem.sh)
      printf '%s\0' "$CORE_X/phobos-networksystem.sh" --spec-parent "$SPECS" --connect-guard-bin "$PASS" \
        --landlock-bin "$PASS" --config "$BASE" -- /usr/bin/env ;;
    phobos-timeoutsystem.sh)
      printf '%s\0' "$CORE_X/phobos-timeoutsystem.sh" --spec-parent "$SPECS" --pgroup-lock-bin "$PASS" \
        --config "$BASE" -- /usr/bin/env ;;
    phobos-resourcesystem.sh)
      printf '%s\0' "$CORE_X/phobos-resourcesystem.sh" --spec-parent "$SPECS" --config "$BASE" -- /usr/bin/env ;;
  esac
}
ENTRIES=( phobos.sh phobos-policysystem.sh phobos-filesystem.sh phobos-networksystem.sh
          phobos-timeoutsystem.sh phobos-resourcesystem.sh )

# Prints the PATH line of the environment in OUT, which env printed for the command.
command_path() {
  grep '^PATH=' <<<"$OUT" | tail -n 1
}

echo "== a clean absolute PATH: every entry point behaves as before, the command sees it unchanged =="
for entry in "${ENTRIES[@]}"; do
  mapfile -d '' -t args < <(entry_args "$entry")
  run_entry "$CLEAN_PATH" "${args[@]}"
  if [[ "$entry" == phobos-policysystem.sh ]]; then
    if [[ "$RC" -eq 0 && -z "$PLANTED" ]]; then
      ok "$entry with a clean PATH writes its specification"
    else
      bad "$entry with a clean PATH writes its specification" "exit 0, nothing planted ran" "exit ${RC}, planted: ${PLANTED}: ${OUT}"
    fi
    continue
  fi
  if [[ "$RC" -eq 0 && "$(command_path)" == "PATH=${CLEAN_PATH}" && "$OUT" != *NOTICE*PATH* && -z "$PLANTED" ]]; then
    ok "$entry with a clean PATH runs the command, which sees that PATH unchanged"
  else
    bad "$entry with a clean PATH runs the command, which sees that PATH unchanged" \
      "exit 0, PATH=${CLEAN_PATH}, no notice" "exit ${RC}, $(command_path), planted: ${PLANTED}: ${OUT}"
  fi
done

echo
echo "== a relative or empty PATH entry never finds a program in the current directory =="
# Each polluted PATH, of which the command must see only the absolute entries.
# The tilde is meant literally: execvp, unlike bash, takes ~/bin as a directory in the current one.
# shellcheck disable=SC2088
POLLUTED=( ".:${CLEAN_PATH}" ":${CLEAN_PATH}" "${CLEAN_PATH}::" "relative/dir:${CLEAN_PATH}"
           "~/bin:${CLEAN_PATH}" "${CLEAN_PATH%%:*}:.:${CLEAN_PATH#*:}" )
for polluted in "${POLLUTED[@]}"; do
  for entry in "${ENTRIES[@]}"; do
    mapfile -d '' -t args < <(entry_args "$entry")
    run_entry "$polluted" "${args[@]}"
    if [[ "$entry" == phobos-policysystem.sh ]]; then
      if [[ "$RC" -eq 0 && -z "$PLANTED" ]]; then
        ok "$entry under PATH='${polluted:0:24}...' runs no planted tool"
      else
        bad "$entry under PATH='${polluted:0:24}...' runs no planted tool" "exit 0, nothing planted ran" "exit ${RC}, planted: ${PLANTED}: ${OUT}"
      fi
      continue
    fi
    if [[ "$RC" -eq 0 && -z "$PLANTED" && "$(command_path)" == "PATH=${CLEAN_PATH}" ]]; then
      ok "$entry under PATH='${polluted:0:24}...' runs no planted tool, the command sees only the absolute entries"
    else
      bad "$entry under PATH='${polluted:0:24}...' runs no planted tool, the command sees only the absolute entries" \
        "exit 0, nothing planted ran, PATH=${CLEAN_PATH}" "exit ${RC}, $(command_path), planted: ${PLANTED}: ${OUT}"
    fi
  done
done

echo
echo "== a trailing empty entry is not the fallback for a program the absolute entries lack =="
for entry in "${ENTRIES[@]}"; do
  mapfile -d '' -t args < <(entry_args "$entry")
  run_entry "${NO_DIRNAME}:" "${args[@]}"
  if [[ "$PLANTED" != *dirname* ]]; then
    ok "$entry under PATH='<no dirname>:' never runs the planted dirname"
  else
    bad "$entry under PATH='<no dirname>:' never runs the planted dirname" "no planted dirname" "exit ${RC}, planted: ${PLANTED}: ${OUT}"
  fi
done

echo
echo "== a PATH with no absolute entry is refused before anything runs =="
for entry in "${ENTRIES[@]}"; do
  mapfile -d '' -t args < <(entry_args "$entry")
  run_entry ".:relative/dir::" "${args[@]}"
  if [[ "$RC" -eq "$PHB_ERUNTIME" && -z "$PLANTED" && "$OUT" == *PATH*PHB-ERUNTIME* && "$OUT" != *"HOME="* ]]; then
    ok "$entry under PATH='.:relative/dir::' is refused with PHB-ERUNTIME and runs nothing"
  else
    bad "$entry under PATH='.:relative/dir::' is refused with PHB-ERUNTIME and runs nothing" \
      "exit ${PHB_ERUNTIME}, a PATH message, nothing planted ran, command not run" "exit ${RC}, planted: ${PLANTED}: ${OUT}"
  fi
done

echo
echo "== CDPATH never redirects an entry point's own cd =="
# Started by a relative path from the work directory, so the entry point's cd to its own
# directory takes a relative name, which is what CDPATH applies to. A decoy tree of the same
# name under CDPATH would otherwise be where it looks.
mkdir -p "$WORK/decoy/core-x"
for entry in "${ENTRIES[@]}"; do
  mapfile -d '' -t args < <(entry_args "$entry")
  args[0]="core-x/${entry}"
  OUT="$(cd "$WORK" && PATH="$CLEAN_PATH" CDPATH="$WORK/decoy" "$BASH_BIN" "${args[@]}" 2>&1)"
  RC=$?
  if [[ "$RC" -eq 0 && "$OUT" != *CDPATH=* ]]; then
    ok "$entry started by a relative path ignores CDPATH, and the command is not given it"
  else
    bad "$entry started by a relative path ignores CDPATH, and the command is not given it" "exit 0, no CDPATH" "exit ${RC}: ${OUT}"
  fi
done

echo
echo "== a relative TMPDIR is dropped, an absolute one is kept =="
# A program that honours TMPDIR, mktemp -t among them, makes its temporary files beneath the
# current directory when TMPDIR is relative, so no program Phobos or the command starts is given
# one. A relative TMPDIR naming no directory would also fail any such use in the run. An absolute
# TMPDIR is the grader's choice and is kept. Phobos's own files never go through TMPDIR, which
# scratch_location.sh holds.
run_entry "$CLEAN_PATH" "$CORE_X/phobos.sh" --spec-parent "$SPECS" --landlock-bin "$PASS" --pgroup-lock-bin "$PASS" \
  --connect-guard-bin "$PASS" --config "$CONNECT_CFG" -- /usr/bin/env
if [[ "$RC" -eq 0 && "$OUT" != *TMPDIR=* ]]; then
  ok "a [connect] run with no TMPDIR runs (control)"
else
  bad "a [connect] run with no TMPDIR runs (control)" "exit 0" "exit ${RC}: ${OUT}"
fi
OUT="$(cd "$SUB" && PATH="$CLEAN_PATH" TMPDIR=no-such-relative-dir "$BASH_BIN" "$CORE_X/phobos.sh" --spec-parent "$SPECS" \
  --landlock-bin "$PASS" --pgroup-lock-bin "$PASS" --connect-guard-bin "$PASS" --config "$CONNECT_CFG" -- /usr/bin/env 2>&1)"
RC=$?
if [[ "$RC" -eq 0 && "$OUT" != *TMPDIR=* ]]; then
  ok "a relative TMPDIR is dropped: the run works and the command is not given it"
else
  bad "a relative TMPDIR is dropped: the run works and the command is not given it" \
    "exit 0, no TMPDIR" "exit ${RC}: ${OUT}"
fi
mkdir -p "$WORK/tmp"
OUT="$(cd "$SUB" && PATH="$CLEAN_PATH" TMPDIR="$WORK/tmp" "$BASH_BIN" "$CORE_X/phobos.sh" --spec-parent "$SPECS" \
  --landlock-bin "$PASS" --pgroup-lock-bin "$PASS" --connect-guard-bin "$PASS" --config "$CONNECT_CFG" -- /usr/bin/env 2>&1)"
RC=$?
if [[ "$RC" -eq 0 && "$OUT" == *"TMPDIR=${WORK}/tmp"* ]]; then
  ok "an absolute TMPDIR is kept, and the command is given it"
else
  bad "an absolute TMPDIR is kept, and the command is given it" "exit 0, TMPDIR=${WORK}/tmp" "exit ${RC}: ${OUT}"
fi

echo
echo "== the C library's own path variables keep only what is absolute =="
# GCONV_PATH, LOCPATH and NLSPATH are lists the C library searches in every program Phobos
# starts, GCONV_PATH for code it loads; HOSTALIASES and TZDIR name one file or directory. A
# relative entry in any of them resolves against the submission's tree. The command's own
# environment, printed by env, shows what every program before it was given.
# Whether OUT holds the line $1 exactly, as env prints one variable.
out_has_line() {
  grep -qxF -- "$1" <<<"$OUT"
}
for entry in "${ENTRIES[@]}"; do
  [[ "$entry" == phobos-policysystem.sh ]] && continue
  mapfile -d '' -t args < <(entry_args "$entry")
  OUT="$(cd "$SUB" && PATH="$CLEAN_PATH" GCONV_PATH=".:/gconv-a::relative/dir" LOCPATH="relative/dir" \
    NLSPATH="/nls/%N:%N" HOSTALIASES="hosts" TZDIR="zone" "$BASH_BIN" "${args[@]}" 2>&1)"
  RC=$?
  if [[ "$RC" -eq 0 ]] && out_has_line "GCONV_PATH=/gconv-a" && out_has_line "NLSPATH=/nls/%N" \
        && [[ "$OUT" != *LOCPATH=* && "$OUT" != *HOSTALIASES=* && "$OUT" != *TZDIR=* ]]; then
    ok "$entry drops the relative entries of GCONV_PATH, LOCPATH and NLSPATH, and a relative HOSTALIASES and TZDIR"
  else
    bad "$entry drops the relative entries of GCONV_PATH, LOCPATH and NLSPATH, and a relative HOSTALIASES and TZDIR" \
      "exit 0, GCONV_PATH=/gconv-a, NLSPATH=/nls/%N, no LOCPATH, HOSTALIASES or TZDIR" "exit ${RC}: ${OUT}"
  fi
  OUT="$(cd "$SUB" && PATH="$CLEAN_PATH" GCONV_PATH="/gconv-a:/gconv-b" LOCPATH="/locale" NLSPATH="/nls/%N" \
    HOSTALIASES="/etc/host.aliases" TZDIR="/zone" "$BASH_BIN" "${args[@]}" 2>&1)"
  RC=$?
  if [[ "$RC" -eq 0 && "$OUT" != *NOTICE* ]] && out_has_line "GCONV_PATH=/gconv-a:/gconv-b" \
        && out_has_line "LOCPATH=/locale" && out_has_line "NLSPATH=/nls/%N" \
        && out_has_line "HOSTALIASES=/etc/host.aliases" && out_has_line "TZDIR=/zone"; then
    ok "$entry passes absolute values of the same five variables on unchanged and without a notice"
  else
    bad "$entry passes absolute values of the same five variables on unchanged and without a notice" \
      "exit 0, all five as given, no notice" "exit ${RC}: ${OUT}"
  fi
done

echo
echo "== no PATH in the environment: the command is given none, as before, and nothing is said =="
# Bash invents a PATH when its environment has none, without exporting it, and the default of
# some builds ends in ".". Each entry point cleans that invented PATH for its own lookups and
# leaves it unexported, so the command is given no PATH, as it was before, and a run says nothing
# about a PATH its caller never gave.
for entry in "${ENTRIES[@]}"; do
  [[ "$entry" == phobos-policysystem.sh ]] && continue
  mapfile -d '' -t args < <(entry_args "$entry")
  : > "$PLANTED_LOG"
  OUT="$(cd "$SUB" && env -u PATH "$BASH_BIN" "${args[@]}" 2>&1)"
  RC=$?
  PLANTED="$(sort -u "$PLANTED_LOG" | tr '\n' ' ')"
  if [[ "$RC" -eq 0 && -z "$PLANTED" && "$OUT" == *"HOME="* && "$OUT" != *NOTICE* ]] && ! grep -q '^PATH=' <<<"$OUT"; then
    ok "$entry with no PATH runs the command, gives it no PATH and prints no notice"
  else
    bad "$entry with no PATH runs the command, gives it no PATH and prints no notice" \
      "exit 0, nothing planted ran, no PATH line, no notice" "exit ${RC}, planted: ${PLANTED}: ${OUT}"
  fi
done

finish
