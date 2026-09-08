#!/usr/bin/env bash
# Builds and runs the phobos-landlock unit tests, and optionally reports
# coverage. Needs gcc only: the syscalls are interposed through the linker, so
# no Landlock-capable kernel is required and no container flags are involved.
#
#   tests/unit/run.sh            build and run
#   tests/unit/run.sh --coverage build instrumented, run, print the summary
set -euo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Every syscall the tool makes is wrapped so a failure can be injected.
# The commas belong to the -Wl, linker flags, not to the array syntax.
# shellcheck disable=SC2054
WRAPS=(
  -Wl,--wrap=open
  -Wl,--wrap=fstat
  -Wl,--wrap=syscall
  -Wl,--wrap=prctl
  -Wl,--wrap=chdir
  -Wl,--wrap=execvp
  -Wl,--wrap=close
)

if [[ "${1:-}" == "--coverage" ]]; then
  gcc -O0 -g --coverage -o "$WORK/unit" "${HERE}/landlock_unit.c" "${WRAPS[@]}"
  ( cd "$WORK" && ./unit )
  # Report only the file under test; gcov also prints a block for the test file.
  ( cd "$WORK" && gcov -b -o "$WORK/unit-landlock_unit.gcno" "${HERE}/landlock_unit.c" ) \
    | awk '/^File .*phobos-landlock\.c/ { show = 1 }
           show && /^(File|Lines|Branches|Taken)/ { print }
           show && /^Taken/ { exit }' 
else
  gcc -O0 -g -Wall -Wextra -o "$WORK/unit" "${HERE}/landlock_unit.c" "${WRAPS[@]}"
  "$WORK/unit"
fi
