#!/usr/bin/env bash
# run_forwarding_signals, the helper every layer waits through: a signal sent to the layer reaches the
# command it waits for, the status answered is the command's own, standard input stays the command's,
# the layer's own traps come back afterwards, and a job that is not the command is never signalled.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../../core"
# shellcheck source=../../../core/phobos-tools-common/phobos-common.sh
source "${CORE}/phobos-tools-common/phobos-common.sh"
set +e
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The command the helper runs: it ends with the status given when it receives the signal named, and runs until then.
waits_for_signal() {
  local signal="$1"
  local status="$2"
  printf 'trap "exit %s" %s; echo READY; while :; do sleep 0.1; done' "$status" "$signal"
}
# wait_ready FILE: until the command wrote READY, which is when its trap is in place.
wait_ready() {
  local polls=0
  while ! grep -q READY "$1" 2> /dev/null && (( polls < 100 )); do
    sleep 0.1
    polls=$(( polls + 1 ))
  done
}

echo "== a signal sent to the waiting shell reaches the command =="
for entry in "TERM:11" "HUP:12" "INT:13" "QUIT:14"; do
  IFS=: read -r signal status <<< "$entry"
  out="$WORK/${signal}.out"
  : > "$out"
  (
    trap - INT QUIT
    trap '' TERM
    run_forwarding_signals sh -c "$(waits_for_signal "$signal" "$status")" > "$out"
    echo "STATUS $?" >> "$out"
  ) &
  shell=$!
  wait_ready "$out"
  kill -s "$signal" "$shell"
  wait "$shell" 2> /dev/null
  if grep -q "^STATUS ${status}\$" "$out"; then ok "SIG${signal} reaches the command, which ends with its own status ${status}"; else bad "SIG${signal} reaches the command" "status ${status}" "$(tr '\n' ' ' < "$out")"; fi
done

echo
echo "== the status is the command's own =="
for status in 0 1 2 42 126 127 130 143 255; do
  run_forwarding_signals sh -c "exit ${status}"
  got=$?
  if [[ "$got" == "$status" ]]; then ok "exit status ${status} passes through"; else bad "exit status ${status} passes through" "$status" "$got"; fi
done
run_forwarding_signals sh -c 'kill -s KILL $$'
got=$?
if [[ "$got" == 137 ]]; then ok "a command killed by a signal answers 128 plus its number"; else bad "a killed command answers 137" "137" "$got"; fi
out="$WORK/handled.out"
: > "$out"
(
  trap '' TERM
  run_forwarding_signals sh -c 'trap "exit 0" TERM; echo READY; while :; do sleep 0.1; done' > "$out"
  echo "STATUS $?" >> "$out"
) &
shell=$!
wait_ready "$out"
kill -s TERM "$shell"
wait "$shell" 2> /dev/null
if grep -q '^STATUS 0$' "$out"; then ok "a command that handles the signal and exits 0 is answered 0, never the interrupted wait's 143"; else bad "a handled signal does not change the status" "STATUS 0" "$(tr '\n' ' ' < "$out")"; fi

echo
echo "== standard input stays the command's =="
printf 'hello\0world\n' | run_forwarding_signals cat > "$WORK/cat.out"
if [[ "$(cksum < "$WORK/cat.out")" == "$(printf 'hello\0world\n' | cksum)" ]]; then ok "bytes on standard input reach the command, a NUL among them"; else bad "standard input reaches the command" "same bytes" "$(od -c "$WORK/cat.out" | head -2)"; fi
head -c 1048576 /dev/urandom > "$WORK/big"
run_forwarding_signals cat < "$WORK/big" > "$WORK/big.out"
if cmp -s "$WORK/big" "$WORK/big.out"; then ok "a megabyte on standard input comes back whole"; else bad "a megabyte on standard input comes back whole" "same bytes" "different"; fi

echo
echo "== the command's standard error and inherited descriptors are set for the command alone =="
exec 7> "$WORK/err.out"
exec 8> "$WORK/closed.out"
PHB_FORWARD_STDERR_FD=7 PHB_FORWARD_CLOSE_FDS="7 8" run_forwarding_signals sh -c 'echo child-says >&2; if [ -e /proc/self/fd/7 ] || [ -e /proc/self/fd/8 ]; then echo inherited >&2; fi; kill -s HUP $$'
got=$?
if [[ "$(< "$WORK/err.out")" == "child-says" ]]; then ok "the command's standard error is the descriptor named, and it holds neither that descriptor nor the one listed"; else bad "the command's standard error is the descriptor named" "child-says" "$(< "$WORK/err.out")"; fi
if [[ "$got" == 129 ]]; then ok "and a command that dies of a signal is answered 129"; else bad "the status of a signalled command" "129" "$got"; fi
echo "still open" >&7
if [[ "$(< "$WORK/err.out")" == $'child-says\nstill open' ]]; then ok "this shell's own descriptors are untouched"; else bad "this shell keeps its descriptors" "still open written" "$(< "$WORK/err.out")"; fi
exec 7>&- 8>&-
exec 9> "$WORK/env.out"
PHB_FORWARD_STDERR_FD=9 PHB_FORWARD_CLOSE_FDS="" run_forwarding_signals sh -c 'echo "[${PHB_FORWARD_STDERR_FD:-}][${PHB_FORWARD_CLOSE_FDS-unset}]" >&2'
exec 9>&-
if [[ "$(< "$WORK/env.out")" == "[][unset]" ]]; then ok "neither setting is left in the command's environment"; else bad "the settings are removed from the command's environment" "[][unset]" "$(< "$WORK/env.out")"; fi
echo
echo "== the shell's own traps come back =="
trap '' TERM
trap ': SIGTERM' HUP
run_forwarding_signals true
if [[ "$(trap -p TERM)" == "trap -- '' SIGTERM" ]]; then ok "a signal that was ignored is ignored again"; else bad "TERM is ignored again" "trap -- '' SIGTERM" "$(trap -p TERM)"; fi
if [[ "$(trap -p HUP)" == "trap -- ': SIGTERM' SIGHUP" ]]; then ok "a trap whose text names another signal is put back as it was, and does not leave that signal's handler behind"; else bad "HUP trap is put back" "trap -- ': SIGTERM' SIGHUP" "$(trap -p HUP)"; fi
if [[ -z "$(trap -p INT)" && -z "$(trap -p QUIT)" ]]; then ok "signals that had no trap have none again"; else bad "INT and QUIT have no trap again" "none" "$(trap -p INT QUIT)"; fi
trap - TERM HUP
if [[ -z "$(trap -p TERM)" ]]; then ok "TERM has its default again after the shell dropped its own trap"; else bad "TERM default" "none" "$(trap -p TERM)"; fi

echo
echo "== a job that is not the command is left alone =="
sleep 30 &
other=$!
out="$WORK/job.out"
: > "$out"
(
  trap '' TERM
  run_forwarding_signals sh -c "$(waits_for_signal TERM 9)" > "$out"
  echo "STATUS $?" >> "$out"
) &
shell=$!
wait_ready "$out"
kill -s TERM "$shell"
wait "$shell" 2> /dev/null
if grep -q '^STATUS 9$' "$out"; then ok "the command got the signal although another job started before it"; else bad "the command got the signal" "STATUS 9" "$(tr '\n' ' ' < "$out")"; fi
if kill -0 "$other" 2> /dev/null; then ok "and the other job did not"; else bad "the other job survives" "alive" "gone"; fi
kill "$other" 2> /dev/null

echo
echo "== a signal that the command survives does not end the wait =="
out="$WORK/survive.out"
: > "$out"
(
  trap '' TERM
  run_forwarding_signals sh -c 'trap "echo GOT" TERM; echo READY; sleep 1; echo LATE; exit 5' > "$out"
  echo "STATUS $?" >> "$out"
) &
shell=$!
wait_ready "$out"
kill -s TERM "$shell"
wait "$shell" 2> /dev/null
if [[ "$(tr '\n' ' ' < "$out")" == "READY GOT LATE STATUS 5 " ]]; then ok "the helper kept waiting after the signal and answered the command's own status 5 once it ended"; else bad "the wait survives a signal the command handles" "READY GOT LATE STATUS 5" "$(tr '\n' ' ' < "$out")"; fi

echo
echo "== a process number is told from the process that held it =="
odd_name=$'x (y) z\n1 2 ) 3'
printf '#!/bin/sh\nsleep 5\n' > "${WORK}/${odd_name}"
chmod +x "${WORK}/${odd_name}"
"${WORK}/${odd_name}" &
odd=$!
polls=0
until [[ "$(cat "/proc/${odd}/comm" 2> /dev/null)" == "x (y) z"* ]] || (( polls >= 100 )); do
  sleep 0.02
  polls=$(( polls + 1 ))
done
if process_start_ticks "$odd" && [[ "$REPLY" =~ ^[0-9]+$ ]]; then ok "the start time of a process whose name holds spaces, brackets and a newline is read: ${REPLY}"; else bad "the start time is read for an odd name" "a number" "$REPLY"; fi
odd_start="$REPLY"
if process_start_ticks "$$" && [[ "$REPLY" != "$odd_start" || "$$" == "$odd" ]]; then ok "and it differs from this shell's"; else bad "start times differ" "different" "$REPLY"; fi
PHB_SIGNAL_CHILD_START="$odd_start"
if process_is_current_child "$odd"; then ok "a process whose start time matches is the child"; else bad "the child is current" "success" "failure"; fi
PHB_SIGNAL_CHILD_START=$(( odd_start + 1 ))
if ! process_is_current_child "$odd"; then ok "a process holding the number with another start time is not the child"; else bad "another start time is not the child" "failure" "success"; fi
kill "$odd" 2> /dev/null
wait "$odd" 2> /dev/null
PHB_SIGNAL_CHILD_START="$odd_start"
if ! process_is_current_child "$odd"; then ok "and an ended process is not the child"; else bad "an ended process is not the child" "failure" "success"; fi
# The helper functions this file sources read this variable, which the checker cannot see.
# shellcheck disable=SC2034
PHB_SIGNAL_CHILD_START=""

finish
