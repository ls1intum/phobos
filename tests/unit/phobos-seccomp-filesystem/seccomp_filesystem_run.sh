#!/usr/bin/env bash
# Builds and runs the unit tests of the denial reporter's sources under core/phobos-seccomp-filesystem.
# With --coverage the build is instrumented, and the run fails unless every line of every reporter
# source ran. Needs gcc-14, gcov-14 for --coverage, and bash itself, whose quoting the reporter's is
# compared with.
#
#   tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_run.sh               build with -Werror and run
#   tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_run.sh --coverage    build instrumented, run, hold lines to 100 %
#
# The enforcer's diagnostics-free model is linked beside the reporter without the enforcer's
# -diagnostics.c, which is the link test that a supervisor can carry it. Its lines are not gated
# here: the enforcer's own suite and its mutation run measure those sources.
#
# Lines are gated the way the connect guard's suite gates them, by counting gcov's uncovered
# markers rather than trusting its summary percentage.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

COMPILER="${COMPILER:-gcc-14}"
COVERAGE_TOOL="${COVERAGE_TOOL:-gcov-14}"
if ! command -v "$COMPILER" >/dev/null 2>&1; then
  echo "This suite needs $COMPILER (the sources are C23). On Ubuntu: apt-get install gcc-14" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CORE="${HERE}/../../../core"
# The reporter's own sources, each held to every line.
MODULES=(
  "${CORE}/phobos-seccomp-filesystem/phobos-seccomp-filesystem-message.c"
  "${CORE}/phobos-seccomp-filesystem/phobos-seccomp-filesystem-access.c"
  "${CORE}/phobos-seccomp-filesystem/phobos-seccomp-filesystem-path.c"
  "${CORE}/phobos-seccomp-filesystem/phobos-seccomp-filesystem-judge.c"
)
# The enforcer's diagnostics-free model, linked without its diagnostics.
MODEL=(
  "${CORE}/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-policy.c"
  "${CORE}/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-path-rule.c"
  "${CORE}/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-model.c"
)
UNIT_TEST_DEFINE=-DPHOBOS_REPORTER_UNIT_TEST

# What the supervisor reads about the command, and the few answers a case has to force, are
# interposed through the linker. Each wrap passes through to the real call unless a case fakes it.
# The commas belong to the -Wl, linker flags, not to the array syntax.
# shellcheck disable=SC2054
WRAPS=(
  -Wl,--wrap=process_vm_readv
  -Wl,--wrap=readlink
  -Wl,--wrap=ioctl
  -Wl,--wrap=faccessat
  -Wl,--wrap=statvfs
  -Wl,--wrap=statx
  -Wl,--wrap=read_small_file
  -Wl,--wrap=geteuid
  -Wl,--wrap=realpath
)

# Holds the reporter's quoting to bash's own: a corpus of names is quoted by both and compared.
# The empty name cannot pass through a NUL-separated list and is covered by a C case instead.
check_quoting_against_bash() {
  local name
  local expected
  local actual
  while IFS= read -r -d '' name; do
    expected="$(LC_ALL=C bash -c 'printf "%s" "${1@Q}"' _ "$name")"
    actual="$("$WORK/unit" --quote "$name")"
    if [[ "$expected" != "$actual" ]]; then
      echo "quoting differs from bash: bash wrote ${expected}, the reporter ${actual}" >&2
      exit 1
    fi
  done < <(printf '%s\0' '/plain' "/it's" $'/new\nline' $'/tab\there' $'/esc\e[31m' $'/\xc3\xa9' \
    '/back\slash' '/sp ace' $'/cr\r' $'/bell\a' $'/del\x7f' $'/q\'and\nnl' $'/b\\s\nx' $'/vt\v\f\b')
  printf 'the quoting agrees with bash on every name of the corpus\n'
}

if [[ "${1:-}" == "--coverage" ]]; then
  "$COMPILER" -std=gnu23 -O0 -g --coverage "$UNIT_TEST_DEFINE" -o "$WORK/unit" \
    "${HERE}/seccomp_filesystem_unit.c" "${MODULES[@]}" "${MODEL[@]}" "${WRAPS[@]}"
  ( cd "$WORK" && ./unit )
  check_quoting_against_bash
  ( cd "$WORK" && for notes in unit-*.gcno; do
      "$COVERAGE_TOOL" -b -o "$notes" "${notes%.gcno}" >/dev/null 2>&1
    done )
  uncovered_total=0
  for source in "${MODULES[@]##*/}"; do
    gcov_file="$WORK/${source}.gcov"
    if [[ ! -f "$gcov_file" ]]; then
      echo "no coverage was produced for core/phobos-seccomp-filesystem/${source}" >&2
      exit 1
    fi
    # A gcov that cannot open the source still writes a .gcov with no counted lines, which would
    # pass the gate below having measured nothing, so real line data is required.
    counted="$(grep -cE '^[[:space:]]*[0-9]+:' "$gcov_file" || true)"
    if [[ "$counted" -eq 0 ]]; then
      echo "coverage for ${source} holds no executed lines; gcov likely could not read the source" >&2
      exit 1
    fi
    uncovered="$(grep -c '#####' "$gcov_file" || true)"
    printf '%-52s %s executed lines, %s uncovered\n' "core/phobos-seccomp-filesystem/${source}" "$counted" "$uncovered"
    if [[ "$uncovered" -ne 0 ]]; then
      grep -nE '#####' "$gcov_file" >&2
    fi
    uncovered_total=$(( uncovered_total + uncovered ))
  done
  if [[ "$uncovered_total" -ne 0 ]]; then
    echo "not every line of the reporter ran; ${uncovered_total} line(s) uncovered" >&2
    exit 1
  fi
  printf 'every line of the reporter ran\n'
else
  "$COMPILER" -std=gnu23 -O0 -g -Wall -Wextra -Werror "$UNIT_TEST_DEFINE" -o "$WORK/unit" \
    "${HERE}/seccomp_filesystem_unit.c" "${MODULES[@]}" "${MODEL[@]}" "${WRAPS[@]}"
  "$WORK/unit"
  check_quoting_against_bash
fi
