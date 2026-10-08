#!/usr/bin/env bash
# What the filesystem layer does with the command's standard error now that the heuristic counter
# is gone: nothing. The command's stderr is the layer's own, unchanged and uncounted, so words of
# refusal the command prints itself are no denial, no line begins with "Sandbox denials", and a run
# in which the supervisor blocked nothing ends without a summary. The stream must never cost the
# command its output or change its exit status, whether a process the command left behind holds it
# open or the signal a terminal sends the whole run reaches the command and its helpers together.
# Every run goes through phobos.sh with a pass-through stand-in for
# phobos-landlock-filesystem-and-networksystem, so no Landlock kernel is needed, and captures stdout
# and stderr together, so the checks do not depend on which of the two a refusal is printed to. The
# signal checks need python3 and /proc.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../core"
WORK="$(mktemp -d)"
export TMPDIR="$WORK"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

CORE_X="$WORK/core-x"
cp -R "$CORE" "$CORE_X"
chmod +x "$CORE_X"/*.sh
printf '[read]\n/usr\n' > "$CORE_X/BaseTest.cfg"
printf '%s\n' '#!/usr/bin/env bash' \
  'while [[ $# -gt 0 && "$1" != "--" ]]; do shift; done; shift; exec "$@"' > "$WORK/passthrough-landlock"
chmod +x "$WORK/passthrough-landlock"
SPECS="$WORK/specs"
mkdir -p "$SPECS"
# One stderr line far longer than any buffer a pass-through could hold.
LARGE_LINE_BYTES=100000000
# How long a process the command leaves behind keeps its stderr open, and the longest the run
# may take while that process is still alive.
LEFTOVER_SECONDS=8
LEFTOVER_RUN_BOUND_MS=6000
MICROSECONDS_PER_MILLISECOND=1000
# A status of the command's own, which the report must hand on unchanged.
COMMAND_OWN_EXIT=3

# Runs a bash snippet under phobos.sh with the timeout and the network layer off, capturing
# stdout and stderr together in OUT and the status in RC, in this shell so both survive.
run_snippet() {
  OUT="$(bash "$CORE_X/phobos.sh" --spec-parent "$SPECS" --landlock-bin "$WORK/passthrough-landlock" \
    -ntr -nnr -- bash -c "$1" 2>&1)"
  RC=$?
}

echo "== words of refusal the command prints itself are no denial =="
run_snippet 'echo "cat: /secret: Permission denied" >&2; echo "getaddrinfo: EAI_AGAIN" >&2'
if [[ "$OUT" == *"cat: /secret: Permission denied"* && "$OUT" == *"getaddrinfo: EAI_AGAIN"* ]]; then
  ok "the words still reach stderr unchanged"
else
  bad "the words still reach stderr unchanged" "both lines in the output" "$OUT"
fi
if [[ "$OUT" != *"Sandbox denials"* && "$OUT" != *"PHB-EDENY"* && "$OUT" != *"Phobos Security"* ]]; then
  ok "and count for nothing: no old line, no line of the report, no summary"
else
  bad "and count for nothing: no old line, no line of the report, no summary" "no report of any kind" "$OUT"
fi

run_snippet 'echo "all good"; echo "a warning that is no denial" >&2'
if [[ "$OUT" != *"PHB-EDENY"* && "$OUT" == *"all good"* ]]; then
  ok "a clean run reports nothing"
else
  bad "a clean run reports nothing" "no PHB-EDENY" "$OUT"
fi

run_snippet 'printf "open: EROFS" >&2'
if [[ "$OUT" == *"open: EROFS"* && "$OUT" != *"PHB-EDENY"* ]]; then
  ok "a last stderr line without a newline passes through and counts for nothing"
else
  bad "a last stderr line without a newline passes through and counts for nothing" "open: EROFS and no report" "$OUT"
fi

run_snippet "echo 'x: EACCES' >&2; exit ${COMMAND_OWN_EXIT}"
if [[ "$RC" -eq "$COMMAND_OWN_EXIT" && "$OUT" != *"PHB-EDENY"* ]]; then
  ok "the command's own exit status stands"
else
  bad "the command's own exit status stands" "exit ${COMMAND_OWN_EXIT} with no report" "exit ${RC}: $OUT"
fi

echo
echo "== the command sees only the descriptors it would see without Phobos =="
# The same listing made once without Phobos, the way run_snippet captures a run, is what the
# command may see: a CI runner hands its steps descriptors of its own, which every process
# inherits. Anything beyond that set was opened by Phobos and handed on.
LIST_OWN_DESCRIPTORS='ls /proc/$$/fd | tr "\n" " "; echo'
without_phobos="$(bash -c "$LIST_OWN_DESCRIPTORS" 2>&1 | tail -n 1)"
run_snippet "$LIST_OWN_DESCRIPTORS"
descriptors="$(printf '%s\n' "$OUT" | tail -n 1)"
if [[ "$descriptors" == "$without_phobos" ]]; then
  ok "no descriptor of Phobos's is handed to the command"
else
  bad "no descriptor of Phobos's is handed to the command" "$without_phobos" "$descriptors"
fi

echo
echo "== the report never costs the command its output =="
run_snippet "head -c ${LARGE_LINE_BYTES} /dev/zero | tr '\\0' q >&2; echo done"
# Only the command's own output is counted: Phobos's log lines, which start with their time in
# brackets, name the run's temporary paths, and the random letters of those may include a q.
length="$(printf '%s' "$OUT" | grep -v '^\[[0-9T:Z-]*\] ' | tr -cd q | wc -c | tr -d ' ')"
if [[ "$RC" -eq 0 && "$length" -eq "$LARGE_LINE_BYTES" && "$OUT" == *done* && "$OUT" != *"PHB-EDENY"* ]]; then
  ok "one stderr line of a hundred megabytes passes whole"
else
  bad "one stderr line of a hundred megabytes passes whole" \
    "exit 0, ${LARGE_LINE_BYTES} bytes and no report" "exit ${RC}, ${length} bytes"
fi

start="${EPOCHREALTIME//[!0-9]/}"
bash "$CORE_X/phobos.sh" --spec-parent "$SPECS" --landlock-bin "$WORK/passthrough-landlock" -ntr -nnr -- \
  bash -c "(sleep ${LEFTOVER_SECONDS} > /dev/null; echo late >&2) & echo 'x: Permission denied' >&2; exit 0" \
  > "$WORK/leftover.out" 2>&1
RC=$?
elapsed_ms=$(( (${EPOCHREALTIME//[!0-9]/} - start) / MICROSECONDS_PER_MILLISECOND ))
if [[ "$RC" -eq 0 ]] && (( elapsed_ms < LEFTOVER_RUN_BOUND_MS )); then
  ok "a process left holding stderr does not delay the end of the run"
else
  bad "a process left holding stderr does not delay the end of the run" \
    "exit 0 within ${LEFTOVER_RUN_BOUND_MS} ms" "exit ${RC} after ${elapsed_ms} ms"
fi

echo
echo "== a signal to the whole run never costs the command what it writes afterwards =="
# A terminal's Ctrl+C sends SIGINT to the whole foreground process group, so every layer of the
# run receives it beside the command; a hangup, a quit or a group-wide SIGTERM do the same. The
# command below handles each of them by writing to stderr for a while afterwards and ending with
# a status of its own, so the layers have to outlive the signal and the command's stderr has to
# stay open until it closes.
# The status the command ends with after the signal it handles, and how many tenths of a second a
# run may take to start, and once signalled to end, far beyond the time the command spends
# writing afterwards.
SIGNALLED_OWN_EXIT=130
SIGNALLED_RUN_BOUND_TENTHS=100
# Starts a command in a session of its own with every signal at its default action, as a terminal
# starts a foreground job, whatever this suite itself inherited.
cat > "$WORK/foreground-job.py" <<'PYTHON'
import os
import signal
import sys

for number in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
    signal.signal(number, signal.SIG_DFL)
os.setsid()
os.execvp(sys.argv[1], sys.argv[1:])
PYTHON
# Writes its process group into $READY, then waits; once signalled it ignores further signals,
# writes a denial line and, a while later, one more line, and ends with its own status.
cat > "$WORK/writes-after-signal.sh" <<EOF
#!/usr/bin/env bash
trap 'trap "" HUP INT QUIT TERM; sleep 0.3; echo "after the signal: Permission denied" >&2; sleep 0.3; echo "the last line" >&2; exit ${SIGNALLED_OWN_EXIT}' HUP INT QUIT TERM
cut -d " " -f 5 /proc/\$\$/stat > "\$READY.tmp" && mv "\$READY.tmp" "\$READY"
while :; do sleep 0.05; done
EOF
chmod +x "$WORK/writes-after-signal.sh"
# Writes its process group into $READY and waits, so that SIGINT ends it with Python's own
# KeyboardInterrupt traceback on stderr.
cat > "$WORK/interrupted.py" <<'PYTHON'
import os
import time

with open(os.environ["READY"] + ".tmp", "w") as ready:
    ready.write(str(os.getpgid(0)))
os.rename(os.environ["READY"] + ".tmp", os.environ["READY"])
while True:
    time.sleep(0.05)
PYTHON

# Runs the command given as the remaining arguments under phobos.sh as a foreground job, waits until
# it has written its process group into $WORK/ready, sends the signal named by $1 to that whole group
# and puts the combined output in OUT and the status in RC. A run that has not ended within the
# bound is killed with its group and reported with the status "hung". Assumes python3 and /proc.
signal_whole_run() {
  local sig="$1"
  local pid
  local pgid
  local tenths=0
  shift
  rm -f "$WORK/ready"
  READY="$WORK/ready" python3 "$WORK/foreground-job.py" bash "$CORE_X/phobos.sh" --spec-parent "$SPECS" \
    --landlock-bin "$WORK/passthrough-landlock" -ntr -nnr -- "$@" > "$WORK/signalled.out" 2>&1 &
  pid=$!
  while [[ ! -s "$WORK/ready" ]] && (( tenths < SIGNALLED_RUN_BOUND_TENTHS )); do sleep 0.1; tenths=$(( tenths + 1 )); done
  pgid="$(<"$WORK/ready")"
  if [[ -z "$pgid" || "$pgid" == "$(cut -d ' ' -f 5 /proc/$$/stat)" ]]; then
    kill -KILL "$pid" 2>/dev/null
    wait "$pid"
    RC="not started in a group of its own"
    OUT="$(<"$WORK/signalled.out")"
    return
  fi
  kill -s "$sig" -- "-${pgid}"
  tenths=0
  while kill -0 "$pid" 2>/dev/null && (( tenths < SIGNALLED_RUN_BOUND_TENTHS )); do sleep 0.1; tenths=$(( tenths + 1 )); done
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL -- "-${pgid}" 2>/dev/null
    wait "$pid"
    RC="hung"
  else
    wait "$pid"
    RC=$?
  fi
  OUT="$(<"$WORK/signalled.out")"
}

for sig in INT QUIT HUP TERM; do
  signal_whole_run "$sig" "$WORK/writes-after-signal.sh"
  if [[ "$RC" == "$SIGNALLED_OWN_EXIT" && "$OUT" == *"after the signal: Permission denied"* \
        && "$OUT" == *"the last line"* && "$OUT" != *"PHB-EDENY"* ]]; then
    ok "SIG${sig} to the whole run: what the command writes afterwards passes through, and its status is its own"
  else
    bad "SIG${sig} to the whole run: what the command writes afterwards passes through, and its status is its own" \
      "exit ${SIGNALLED_OWN_EXIT}, both lines and no report" "exit ${RC}: $OUT"
  fi
done

signal_whole_run INT python3 "$WORK/interrupted.py"
if [[ "$RC" == "$SIGNALLED_OWN_EXIT" && "$OUT" == *"Traceback"* && "$OUT" == *"KeyboardInterrupt"* ]]; then
  ok "a Ctrl+C to the whole run leaves Python's KeyboardInterrupt traceback in the output"
else
  bad "a Ctrl+C to the whole run leaves Python's KeyboardInterrupt traceback in the output" \
    "exit ${SIGNALLED_OWN_EXIT} with the traceback" "exit ${RC}: $OUT"
fi

finish
