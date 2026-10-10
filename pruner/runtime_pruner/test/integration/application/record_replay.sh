#!/usr/bin/env bash
# Holds the recording pruner's record and replay check to what they promise, one phase per container.
#
# A recorded session and its replay must run in different containers, and one container cannot
# start another, so record_host.sh starts a new container for each phase and passes its name:
#
#   record     record the fixture session; the replay check refuses this container without
#              --same-container, before it changes anything, and runs in it, warning, with it
#   python     record an interactive Python session, in a container of its own, so that its
#              starting state is the image's and not what the fixture session left behind
#   fresh      a new container: the replay passes with no regression and says fresh-container, and a
#              replay of another command than the recorded one fails
#   leftover   a new container with one file added before the check: refused as not fresh, and
#              with --same-container it runs as changed-container
#   modified   a new container in which an existing file of the image was changed: refused too
#   narrowed   a new container whose policy lacks a creation the session needed: the check fails
#              and names that refusal as a regression
#   hand       a new container in which a person's keystrokes are typed into an interactive bash
#              that runs the check by hand around python3 -q: the terminal reaches Python under
#              the layers (Ctrl+C, Ctrl+Z and fg included), and the replay passes
#
# The policies are written by hand (record-fixture/*.cfg), standing in for the ones generate will
# write, so the check is proven on its own: in both directions, against a policy that grants the
# session and one that does not.
#
# Runs inside the prune image with the test trees at /repo/protecter/test and /repo/pruner and pruner at /var/tmp/helpers, all
# read-only, the fixture exercise at /srv/phobos-record-exercise and a volume shared by the phases at
# /var/tmp/recordings, in an ordinary container: --network none, no --privileged, no --cap-add, no
# --security-opt.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../../protecter/test/harness.sh
source "${HERE}/../../../../../protecter/test/harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

PHASE="${1:?usage: record_replay.sh record|python|fresh|leftover|modified|narrowed|hand}"
RECORDER="${PHOBOS_RECORD:-/var/tmp/helpers/runtime_pruner/src/interface/phobos-record}"
HELPERS="${LAYER_RECORD_HELPERS:-/var/tmp/helpers}"
FIXTURE="${HERE}/../interface/record-fixture"
RECORDING=/var/tmp/recordings/replay
PYTHON_RECORDING=/var/tmp/recordings/python
# Inside the recordings, which no listing walks, so the suite's own scratch never makes a container
# look changed.
OUT="$(mktemp -d /var/tmp/recordings/.replay-scratch.XXXXXX)" || { echo "cannot create a working directory" >&2; exit 1; }
# The fixture session: read the exercise's input, create out.txt beside it, and print the marker the
# script waits for. Written in two halves so that no echo of the command line could contain it.
SESSION=(sh -c 'cat input.txt > /dev/null; echo x > out.txt; echo "OK-""DONE"')

# Removes the phase's own scratch directory however the phase ends.
cleanup() {
  rm -rf "${OUT}"
}
trap cleanup EXIT

# Runs the recorder with the given arguments, its output in ${OUT}/<label>.out and its status in
# ${OUT}/<label>.status. Assumes the recorder never reads standard input, which is /dev/null here.
recorder() {
  local label="$1"
  shift
  "${RECORDER}" "$@" < /dev/null > "${OUT}/${label}.out" 2>&1
  printf '%s' "$?" > "${OUT}/${label}.status"
}

# The status a recorder run of the given label ended with.
status_of() {
  cat "${OUT}/$1.status"
}

# A key of the newest check.json of the given recording, printed by Python; a list as its length.
newest_check() {
  python3 - "$1" "$2" <<'PYTHON'
import json
import pathlib
import sys

recording = pathlib.Path(sys.argv[1])
newest = max(recording.glob("check-*"), key=lambda path: int(path.name.removeprefix("check-")))
value = json.loads((newest / "check.json").read_text())[sys.argv[2]]
print(len(value) if isinstance(value, list) else value)
PYTHON
}

# Every regression, new behaviour and reason of the newest check of the given recording, one per line.
newest_findings() {
  python3 - "$1" <<'PYTHON'
import json
import pathlib
import sys

recording = pathlib.Path(sys.argv[1])
newest = max(recording.glob("check-*"), key=lambda path: int(path.name.removeprefix("check-")))
report = json.loads((newest / "check.json").read_text())
for key in ("regressions", "new_behaviour"):
    for entry in report[key]:
        print(key, entry["call"], entry["pairs"])
for reason in report["not_completed"]:
    print("not completed:", reason)
PYTHON
}

# Types a script into a command through a pseudo-terminal and prints "<status> <expectations met>". Each step
# may take 180 s: the replay's judgement after the last keystroke parses a trace of every process under strace,
# which took over a minute once on a loaded arm64 runner.
# Takes the script file, then the command.
typed() {
  local script="$1"
  shift
  PS1='SHELL$ ' TERM=dumb python3 - "${HELPERS}" "${script}" "${OUT}" "$@" <<'PYTHON'
import pathlib
import sys

sys.path.insert(0, sys.argv[1])
from runtime_pruner.src.infrastructure import pty_script

script = pathlib.Path(sys.argv[2])
out = pathlib.Path(sys.argv[3])
outcome = pty_script.drive(sys.argv[4:], pty_script.parse(script.read_text()), out, out / "transcript", 180.0)
print(outcome.status, outcome.expectations_met)
PYTHON
}

# Phase record: the fixture session, then the replay check in the very same container.
phase_record() {
  recorder record record --name replay --script "${FIXTURE}/session.script" -- "${SESSION[@]}"
  check "the recorded session ends with the command's own status" 0 "$(status_of record)"
  if grep -q 'input.txt' "${RECORDING}/sessions/1/trace" 2>/dev/null; then
    ok "the trace holds the session's read of its input"
  else
    bad "the trace holds the session's read of its input" "$(cat "${OUT}/record.out")"
  fi
  cp "${FIXTURE}/policy.cfg" "${RECORDING}/policy.cfg"
  echo "changed by the session" > /var/tmp/testing-dir/out.txt
  recorder same check --name replay --script "${FIXTURE}/session.script" -- "${SESSION[@]}"
  check "a check in the recording's own container is refused without --same-container" 3 "$(status_of same)"
  if grep -q 'recorded a session' "${OUT}/same.out" && [[ ! -d "${RECORDING}/check-1" ]]; then
    ok "the refusal names the reason and replays nothing"
  else
    bad "the refusal names the reason and replays nothing" "$(cat "${OUT}/same.out")"
  fi
  check "the refusal changed nothing in the working directory" "changed by the session" \
    "$(cat /var/tmp/testing-dir/out.txt)"
  recorder optin check --name replay --same-container --script "${FIXTURE}/session.script" -- "${SESSION[@]}"
  check "with --same-container the replay runs and passes" 0 "$(status_of optin)"
  check "check.json says it ran in the same container" same-container "$(newest_check "${RECORDING}" mode)"
  check "the warning is printed before and after the replay" 2 "$(grep -c 'does not run in a fresh container' "${OUT}/optin.out")"
}

# Phase python: the interactive Python session the phase hand replays by hand.
phase_python() {
  recorder python record --name python --script "${FIXTURE}/python.script" -- python3 -q
  check "the interactive Python session is recorded with its own status" 0 "$(status_of python)"
  cp "${FIXTURE}/policy-python.cfg" "${PYTHON_RECORDING}/policy.cfg"
}

# Phase fresh: a new container with the recording's starting state.
phase_fresh() {
  recorder fresh check --name replay --script "${FIXTURE}/session.script" -- "${SESSION[@]}"
  check "the replay in a fresh container passes" 0 "$(status_of fresh)"
  check "check.json says it ran in a fresh container" fresh-container "$(newest_check "${RECORDING}" mode)"
  check "no regression is found" 0 "$(newest_check "${RECORDING}" regressions)"
  check "the replay ran the session" 0 "$(newest_check "${RECORDING}" not_completed)"
  check "no warning is printed in a fresh container" 0 "$(grep -c 'does not run in a fresh container' "${OUT}/fresh.out")"
  recorder other check --name replay --same-container --script "${FIXTURE}/session.script" -- sh -c 'echo "OK-""DONE"'
  check "a replay of another command than the recorded one fails" 1 "$(status_of other)"
  if grep -q 'no recorded session ran' "${OUT}/other.out"; then
    ok "it fails because no recorded session ran that command"
  else
    bad "it fails because no recorded session ran that command" "$(cat "${OUT}/other.out")"
  fi
}

# Phase leftover: a file added before the check makes the container not fresh.
phase_leftover() {
  touch /var/tmp/leftover
  recorder refused check --name replay --script "${FIXTURE}/session.script" -- "${SESSION[@]}"
  check "a container with a leftover file is refused as not fresh" 3 "$(status_of refused)"
  if grep -q "/var/tmp/leftover" "${OUT}/refused.out"; then
    ok "the refusal names the leftover file"
  else
    bad "the refusal names the leftover file" "$(cat "${OUT}/refused.out")"
  fi
  recorder changed check --name replay --same-container --script "${FIXTURE}/session.script" -- "${SESSION[@]}"
  check "with --same-container it runs" 0 "$(status_of changed)"
  check "check.json says the container was changed" changed-container "$(newest_check "${RECORDING}" mode)"
}

# Phase modified: an existing file of the image changed before the check makes it not fresh either.
phase_modified() {
  echo "# changed" >> /etc/os-release
  recorder modified check --name replay --script "${FIXTURE}/session.script" -- "${SESSION[@]}"
  check "a container with a modified file is refused as not fresh" 3 "$(status_of modified)"
  if grep -q "os-release" "${OUT}/modified.out"; then
    ok "the refusal names the modified file"
  else
    bad "the refusal names the modified file" "$(cat "${OUT}/modified.out")"
  fi
}

# Phase narrowed: the policy lacks the creation of out.txt, so the replay is refused it.
phase_narrowed() {
  cp "${FIXTURE}/narrowed.cfg" "${RECORDING}/policy.cfg"
  recorder narrowed check --name replay --script "${FIXTURE}/session.script" -- "${SESSION[@]}"
  check "a policy without a creation the session needed fails the check" 1 "$(status_of narrowed)"
  if newest_findings "${RECORDING}" | grep -q '^regressions .*out.txt'; then
    ok "the regression names the refused creation of out.txt"
  else
    bad "the regression names the refused creation of out.txt" "$(cat "${OUT}/narrowed.out")"
  fi
  cp "${FIXTURE}/policy.cfg" "${RECORDING}/policy.cfg"
}

# Phase hand: a person's keystrokes, typed into bash, run the check by hand around python3 -q.
phase_hand() {
  local outcome
  sed "s|@RECORDER@|${RECORDER}|" "${FIXTURE}/hand.script" > "${OUT}/hand.script"
  outcome="$(typed "${OUT}/hand.script" bash --norc --noprofile -i)"
  check "Python under the layers answered every keystroke: Ctrl+C, Ctrl+Z and fg, and its exit" "0 True" "${outcome}"
  if [[ "${outcome}" != "0 True" ]]; then
    printf 'transcript:\n%s\n' "$(tail -c 3000 "${OUT}/transcript" 2>/dev/null)"
  fi
  check "the replay by hand ran in a fresh container" fresh-container "$(newest_check "${PYTHON_RECORDING}" mode)"
  check "the replay by hand found no regression" 0 "$(newest_check "${PYTHON_RECORDING}" regressions)"
  check "the replay by hand ran the session" 0 "$(newest_check "${PYTHON_RECORDING}" not_completed)"
  newest_findings "${PYTHON_RECORDING}"
}

case "${PHASE}" in
  record) phase_record ;;
  python) phase_python ;;
  fresh) phase_fresh ;;
  leftover) phase_leftover ;;
  modified) phase_modified ;;
  narrowed) phase_narrowed ;;
  hand) phase_hand ;;
  *) bad "known phase" "record, python, fresh, leftover, modified, narrowed or hand" "${PHASE}" ;;
esac
finish
