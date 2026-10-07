#!/usr/bin/env bash
# Holds the recorder to a real terminal: the program it records keeps its terminal, its signals and
# the calling shell's job control, and its exit status (plan A.3.3).
#
# An interactive bash runs in a pseudo-terminal, typed from a script through pty_script, and starts
# the recorder around python3. Ctrl+C must interrupt Python and leave its prompt working, Ctrl+Z
# must stop the job in bash and fg bring the same Python back, standard error must still reach the
# terminal, and the recorder must end with Python's own status. A second session leaves a child
# running after its command ends, and its trace must still hold that child's end: the recorder
# waits for the detached tracer.
#
# Runs inside the prune image with tests/ at /tests and var/tmp/helpers at /var/tmp/helpers, both
# read-only, in an ordinary container: --network none, no --privileged, no --cap-add, no
# --security-opt.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

RECORDER="${PHOBOS_RECORD:-/var/tmp/helpers/layer_record/phobos-record}"
HELPERS="${LAYER_RECORD_HELPERS:-/var/tmp/helpers}"
OUT="$(mktemp -d /var/tmp/phobos-record-interactive.XXXXXX)" || { echo "cannot create a working directory" >&2; exit 1; }

# Removes the suite's scratch directory however it ends.
cleanup() {
  rm -rf "${OUT}"
}
trap cleanup EXIT

# Writes the script typed into the interactive bash. Every marker is printed in two halves, so the
# echo of the typed line can never satisfy an expectation.
write_script() {
  cat > "${OUT}/session.script" <<SCRIPT
expect SHELL[$]
send ${RECORDER} record --name interactive -- python3 -q
expect >>>
send import time, sys
send time.sleep(60)
sleep 1
key ctrl-c
expect KeyboardInterrupt
send print("OK-" + "C1")
expect OK-C1
key ctrl-z
expect Stopped
send fg
sleep 1
send print("OK-" + "Z1")
expect OK-Z1
send sys.stderr.write("OK-" + "E2" + "\\n")
expect OK-E2
send raise SystemExit(5)
expect SHELL[$]
send echo "STATUS-""\$?"
expect STATUS-5
send exit
SCRIPT
}

# Types the script into an interactive bash and prints the outcome, "<status> <expectations met>".
drive_shell() {
  PS1='SHELL$ ' TERM=dumb python3 - "${HELPERS}" "${OUT}" <<'PYTHON'
import pathlib
import sys

sys.path.insert(0, sys.argv[1])
from layer_record import pty_script

out = pathlib.Path(sys.argv[2])
actions = pty_script.parse((out / "session.script").read_text())
outcome = pty_script.drive(["bash", "--norc", "--noprofile", "-i"], actions, out, out / "transcript", 30.0)
print(outcome.status, outcome.expectations_met)
PYTHON
}

# The value of one key of an interactive session's session.json.
session_value() {
  python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' \
    "/var/tmp/recordings/$1/sessions/1/session.json" "$2"
}

write_script
outcome="$(drive_shell)"
check "every step of the interactive session held: Ctrl+C, Ctrl+Z and fg, stderr, the status" "0 True" "${outcome}"
if [[ "${outcome}" != "0 True" ]]; then
  printf 'transcript:\n%s\n' "$(tail -c 2000 "${OUT}/transcript" 2>/dev/null)"
fi
check "the recorded session holds Python's own status" 5 "$(session_value interactive status)"
check "the recorded session ran with a terminal" True "$(session_value interactive interactive)"
if grep -q 'KeyboardInterrupt' "${OUT}/transcript" 2>/dev/null; then
  ok "the traceback of Ctrl+C reached the terminal"
else
  bad "the traceback of Ctrl+C reached the terminal"
fi

"${RECORDER}" record --name outlived -- sh -c 'sleep 2 & exit 0' < /dev/null > "${OUT}/outlived.out" 2>&1
check "a session whose child outlives it ends with the command's status" 0 "$?"
if [[ "$(grep -c 'exit_group(0)' /var/tmp/recordings/outlived/sessions/1/trace 2>/dev/null)" -ge 2 ]]; then
  ok "the trace holds the end of the child that outlived the command"
else
  bad "the trace holds the end of the child that outlived the command" "$(cat "${OUT}/outlived.out")"
fi
finish
