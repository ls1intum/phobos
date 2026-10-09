#!/usr/bin/env bash
# Holds the recording pruner to what keeps it from being mistaken for grading (plan A.10).
#
# The recorder runs a program with no sandbox at all. The guarantee that grading never reaches it is
# structural: nothing under protecter/src/ names it and the run-phase image holds neither it nor strace. What
# is checked here are the safeguards beside that guarantee, in both directions: a grading option or
# the layers as the command are refused with status 2, while an ordinary program is recorded.
# record_host.sh checks the run-phase image itself, from outside it.
#
# Runs inside the prune image with the test trees at /repo/protecter/test and /repo/pruner, pruner at
# /var/tmp/helpers and the repository's protecter/src/ at /repo/protecter/src, all read-only, in an ordinary container: --network none, no
# --privileged, no --cap-add, no --security-opt.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../../protecter/test/harness.sh
source "${HERE}/../../../../../protecter/test/harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

PHOBOS_HOME="${PHOBOS_HOME:-/var/tmp/opt/core}"
RECORDER="${PHOBOS_RECORD:-/var/tmp/helpers/runtime_pruner/src/interface/phobos-record}"
CORE="${REPO_CORE:-/repo/protecter/src}"

# Runs the recorder and prints its status, its output going to the file named first.
status_of_recorder() {
  local output="$1"
  shift
  "${RECORDER}" "$@" < /dev/null > "${output}" 2>&1
  printf '%s' "$?"
}

# record refuses a grading configuration with status 2 and says it does not grade.
check_record_refuses_config() {
  local output
  local status
  output="$(mktemp)"
  status="$(status_of_recorder "${output}" record --config /dev/null -- true)"
  if [[ "$status" == 2 ]] && grep -q 'does not grade' "${output}"; then
    ok "record refuses --config"
  else
    bad "record refuses --config" "status ${status}: $(cat "${output}")"
  fi
  rm -f "${output}"
}

# record refuses to trace the layers themselves, started directly or through an interpreter.
check_record_refuses_the_layers() {
  local output
  output="$(mktemp)"
  check "record refuses phobos.sh" 2 "$(status_of_recorder "${output}" record -- "${PHOBOS_HOME}/phobos.sh" -- true)"
  check "record refuses sh phobos.sh" 2 "$(status_of_recorder "${output}" record -- sh "${PHOBOS_HOME}/phobos.sh" -- true)"
  check "record refuses phobos found through PATH" 2 "$(status_of_recorder "${output}" record -- phobos -- true)"
  rm -f "${output}"
}

# The permitted direction: an ordinary program is recorded and keeps its own status.
check_record_records_an_ordinary_program() {
  local output
  output="$(mktemp)"
  check "record runs an ordinary program and keeps its status" 7 \
    "$(status_of_recorder "${output}" record --name safety -- sh -c 'exit 7')"
  if [[ -s /var/tmp/recordings/safety/sessions/1/trace ]]; then
    ok "the ordinary program's session left a trace"
  else
    bad "the ordinary program's session left a trace" "$(cat "${output}")"
  fi
  rm -f "${output}"
}

# Nothing under protecter/src/ knows the recorder or strace.
check_core_does_not_reach_the_recorder() {
  local found
  local status
  if [[ ! -f "${CORE}/phobos.sh" ]]; then
    bad "protecter/src/ never names the recorder or strace" "protecter/src/ is not mounted at ${CORE}"
    return
  fi
  found="$(grep -rIl -e 'phobos-record' -e 'runtime_pruner' -e 'strace' "${CORE}")"
  status=$?
  if [[ "$status" == 1 ]]; then
    ok "protecter/src/ never names the recorder or strace"
  else
    bad "protecter/src/ never names the recorder or strace" "grep status ${status}: ${found}"
  fi
}

check_record_refuses_config
check_record_refuses_the_layers
check_record_records_an_ordinary_program
check_core_does_not_reach_the_recorder
finish
