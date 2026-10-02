#!/usr/bin/env bash
# The timeout stops a command that ignores SIGTERM, and lets a well-behaved one finish.
#
# The timeout layer runs GNU timeout without --foreground, so it signals the command's whole
# process group and, with --kill-after, escalates to SIGKILL. That escalation only fires while
# GNU timeout's own child is still alive, so the layers between the timeout and the command
# ignore SIGTERM and stay, and it is the SIGKILL that stops a command which ignores SIGTERM.
# This proves that end to end through the real chain, with a stand-in for phobos-landlock-filesystem-and-networksystem so no
# Landlock kernel is needed, a stand-in for the timeout's group lock so no seccomp is needed here
# (the lock's own behaviour is tests/integration/seccomp_timeoutsystem.sh), and the network layer off to spare its
# readelf dependency.
#
# It needs GNU timeout (the real one, not a stand-in) and a C compiler. Where either is
# missing the checks skip, saying so, rather than passing without having run.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../core"
# shellcheck source=../../core/phobos-tools-common/phobos-constants.sh
source "${CORE}/phobos-tools-common/phobos-constants.sh"
WORK="$(mktemp -d)"
export TMPDIR="$WORK"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

if ! command -v timeout >/dev/null 2>&1; then
  skip "the timeout escalation" "GNU timeout is not installed"
  finish
fi
compiler=cc
command -v "$compiler" >/dev/null 2>&1 || compiler=gcc
if ! command -v "$compiler" >/dev/null 2>&1; then
  skip "the timeout escalation" "no C compiler to build the SIGTERM-ignoring probe"
  finish
fi

cat > "$WORK/ignorer.c" <<'C'
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
/* How long the probe runs when it is not told. */
enum { DEFAULT_SECONDS = 30 };
int main(int argc, char **argv) {
    signal(SIGTERM, SIG_IGN);
    unsigned seconds = (argc > 1) ? (unsigned)atoi(argv[1]) : DEFAULT_SECONDS;
    sleep(seconds);
    return 0;
}
C
if ! "$compiler" -O2 -o "$WORK/ignorer" "$WORK/ignorer.c" 2>"$WORK/cc.log"; then
  bad "the timeout escalation" "the probe did not compile: $(cat "$WORK/cc.log")"
  finish
fi

# A stand-in for phobos-landlock-filesystem-and-networksystem: it drops its own options up to the "--" and exec's the
# command, so the real filesystem layer runs its Landlock branch without a Landlock kernel.
printf '%s\n' '#!/usr/bin/env bash' \
  'while [[ $# -gt 0 && "$1" != "--" ]]; do shift; done; shift; exec "$@"' > "$WORK/passthrough-landlock"
chmod +x "$WORK/passthrough-landlock"

CORE_X="$WORK/core-x"
cp -R "$CORE" "$CORE_X"
chmod +x "$CORE_X"/*.sh
# The outer bound every run of the chain gets, so a broken escalation cannot hang the suite.
OUTER_BOUND_SECONDS=30
SPECS="$WORK/specs"
mkdir -p "$SPECS"

# Runs the whole chain over a base policy with the given timeout, against a command, under an
# outer real timeout so a broken escalation cannot hang the suite. The first argument selects
# the filesystem layer: "landlock" runs its Landlock branch with a stand-in enforcement helper,
# "nolandlock" runs the --no-landlock branch, so both branches of the SIGTERM survival are
# exercised. Prints "<exit>|<elapsed>|<output>".
run_chain() {
  local mode=$1
  local timeout_value=$2
  shift 2
  printf '[limits]\ntimeout=%s\n' "$timeout_value" > "$CORE_X/BaseTimeout.cfg"
  local sandbox=()
  if [[ "$mode" == "nolandlock" ]]; then
    sandbox=(--no-filesystem-restriction)
  else
    sandbox=(--landlock-bin "$WORK/passthrough-landlock")
  fi
  local start
  local end
  local out
  local rc
  start=$(date +%s)
  out="$(timeout "${OUTER_BOUND_SECONDS}s" bash "$CORE_X/phobos.sh" --spec-parent "$SPECS" \
    "${sandbox[@]}" --pgroup-lock-bin "$WORK/passthrough-landlock" --no-networksystem-restriction -- "$@" 2>&1)"
  rc=$?
  end=$(date +%s)
  printf '%s|%s|%s' "$rc" "$((end - start))" "$out"
}

# The timeout the SIGTERM-ignoring command runs under, how long it would run without one, and the
# timeout a well-behaved command is given, far longer than it needs.
SHORT_TIMEOUT_SECONDS=1
IGNORER_SECONDS=30
LONG_TIMEOUT_SECONDS=60
# The escalation waits PHB_KILL_AFTER_SECONDS after the timeout; the elapsed time is measured in
# whole seconds, which can round it down by one.
ESCALATION_MINIMUM_SECONDS=$(( PHB_KILL_AFTER_SECONDS - 1 ))

echo "== a command that ignores SIGTERM is stopped by the escalation =="
res="$(run_chain landlock "$SHORT_TIMEOUT_SECONDS" "$WORK/ignorer" "$IGNORER_SECONDS")"
rc="${res%%|*}"
rest="${res#*|}"
elapsed="${rest%%|*}"
out="${rest#*|}"

# The escalation waited PHB_KILL_AFTER_SECONDS after the timeout, so a run that returned sooner
# did not escalate, which is the regression this guards.
if [[ "$rc" == "$PHB_ETIMEOUT" ]]; then
  ok "the run ends with PHB-ETIMEOUT"
else
  bad "the run ends with PHB-ETIMEOUT" "exit ${PHB_ETIMEOUT}, got exit ${rc}: ${out}"
fi
if [[ "$out" == *"PHB-ETIMEOUT"* ]]; then
  ok "it reports the timeout"
else
  bad "it reports the timeout" "PHB-ETIMEOUT in the output, got: ${out}"
fi
if (( elapsed >= ESCALATION_MINIMUM_SECONDS )); then
  ok "the escalation waited its kill-after before SIGKILL (elapsed ${elapsed}s)"
else
  bad "the escalation waited its kill-after before SIGKILL" "at least ${ESCALATION_MINIMUM_SECONDS}s, got ${elapsed}s"
fi
# The command must actually be gone, not merely be judged by a marker it has not yet had time
# to write: a survivor that escaped the group-kill would still be sleeping. Check for a
# residual process directly, the way the acceptance suite does. A killed process leaves at most
# a reaped-away zombie, which has no command line for pgrep to match.
sleep 1
if ! command -v pgrep >/dev/null 2>&1; then
  skip "no residual SIGTERM-ignoring process" "pgrep is not available to check"
elif pgrep -f "$WORK/ignorer" >/dev/null 2>&1; then
  bad "no residual SIGTERM-ignoring process" "the command is still running after the run returned"
else
  ok "no residual SIGTERM-ignoring process: the command was killed, not left running"
fi

echo
echo "== the --no-landlock branch also stops a SIGTERM-ignoring command =="
res="$(run_chain nolandlock "$SHORT_TIMEOUT_SECONDS" "$WORK/ignorer" "$IGNORER_SECONDS")"
rc="${res%%|*}"
rest="${res#*|}"
elapsed="${rest%%|*}"
out="${rest#*|}"
if [[ "$rc" == "$PHB_ETIMEOUT" && "$out" == *"PHB-ETIMEOUT"* && "$elapsed" -ge "$ESCALATION_MINIMUM_SECONDS" ]]; then
  ok "with the filesystem layer off, the escalation still stops the command (elapsed ${elapsed}s)"
else
  bad "with the filesystem layer off, the escalation still stops the command" "exit ${PHB_ETIMEOUT}, PHB-ETIMEOUT and elapsed >= ${ESCALATION_MINIMUM_SECONDS}s; got exit ${rc}, elapsed ${elapsed}s: ${out}"
fi
sleep 1
if ! command -v pgrep >/dev/null 2>&1; then
  skip "no residual process, --no-landlock branch" "pgrep is not available to check"
elif pgrep -f "$WORK/ignorer" >/dev/null 2>&1; then
  bad "no residual process, --no-landlock branch" "the command is still running after the run returned"
else
  ok "no residual process, --no-landlock branch: the command was killed"
fi

echo
echo "== a well-behaved command finishes and is not killed =="
res="$(run_chain landlock "$LONG_TIMEOUT_SECONDS" /bin/echo command-ran)"
rc="${res%%|*}"
rest="${res#*|}"
elapsed="${rest%%|*}"
out="${rest#*|}"
if [[ "$rc" == "0" && "$out" == *"command-ran"* ]]; then
  ok "it runs to completion with its own exit status"
else
  bad "it runs to completion with its own exit status" "exit 0 and its output, got exit ${rc}: ${out}"
fi
if [[ "$out" != *"PHB-ETIMEOUT"* ]]; then
  ok "no timeout is reported for a command within its limit"
else
  bad "no timeout is reported for a command within its limit" "unexpected PHB-ETIMEOUT: ${out}"
fi

echo
echo "== a command's own 124 or 137 is not reported as a timeout =="
# GNU timeout passes the command's status through when it did not time out, and a command that
# someone else kills with SIGKILL, the OOM killer among them, ends with 137 like the escalation.
# Neither, well inside a long timeout, is the timeout's doing.
res="$(run_chain landlock "$LONG_TIMEOUT_SECONDS" bash -c "exit ${PHB_TIMEOUT_EXPIRED_EXIT}")"
rc="${res%%|*}"
out="${res#*|}"
out="${out#*|}"
if [[ "$rc" == "$PHB_TIMEOUT_EXPIRED_EXIT" && "$out" != *"PHB-ETIMEOUT"* ]]; then
  ok "a command exiting 124 at once keeps its status and no timeout is reported"
else
  bad "a command exiting 124 at once keeps its status and no timeout is reported" "exit ${PHB_TIMEOUT_EXPIRED_EXIT} without PHB-ETIMEOUT, got exit ${rc}: ${out}"
fi
res="$(run_chain landlock "$LONG_TIMEOUT_SECONDS" bash -c 'kill -KILL $$')"
rc="${res%%|*}"
out="${res#*|}"
out="${out#*|}"
if [[ "$rc" == "$PHB_TIMEOUT_KILLED_EXIT" && "$out" != *"PHB-ETIMEOUT"* ]]; then
  ok "a command killed by SIGKILL at once keeps its status and no timeout is reported"
else
  bad "a command killed by SIGKILL at once keeps its status and no timeout is reported" "exit ${PHB_TIMEOUT_KILLED_EXIT} without PHB-ETIMEOUT, got exit ${rc}: ${out}"
fi

finish
