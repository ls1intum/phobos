#!/usr/bin/env bash
# The denial report of the filesystem layer: the command's stderr passes through unchanged, a
# copy is counted for the lines that look like a sandbox denial, and PHB-EDENY names the two
# counts. Both directions: a denial is counted and reported, and a clean run reports nothing.
# The report must never cost the command its output or change its exit status, whether the
# counter finishes, dies at its own limits, or is kept waiting by a process the command left
# behind. Every run goes through phobos.sh with a pass-through stand-in for phobos-landlock-filesystem-and-networksystem,
# so no Landlock kernel is needed, and captures stdout and stderr together, so the checks do
# not depend on which of the two a refusal is printed to.
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
# One stderr line longer than the denial counter's own memory bound lets it hold.
LARGE_LINE_BYTES=100000000
# How long a process the command leaves behind keeps its stderr open, longer than the grace
# period, and the longest the run may take while that process is still alive.
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

echo "== a denial is counted and reported, a clean run reports nothing =="
run_snippet 'echo "cat: /secret: Permission denied" >&2; echo "getaddrinfo: EAI_AGAIN" >&2'
if [[ "$OUT" == *"Sandbox denials: network=1, filesystem=1. (PHB-EDENY)"* ]]; then
  ok "one network and one filesystem denial are both counted"
else
  bad "one network and one filesystem denial are both counted" "network=1, filesystem=1" "$OUT"
fi
if [[ "$OUT" == *"cat: /secret: Permission denied"* && "$OUT" == *"getaddrinfo: EAI_AGAIN"* ]]; then
  ok "the counted lines still reach stderr unchanged"
else
  bad "the counted lines still reach stderr unchanged" "both lines in the output" "$OUT"
fi

run_snippet 'echo "all good"; echo "a warning that is no denial" >&2'
if [[ "$OUT" != *"PHB-EDENY"* && "$OUT" == *"all good"* ]]; then
  ok "a run with no denial line reports no PHB-EDENY"
else
  bad "a run with no denial line reports no PHB-EDENY" "no PHB-EDENY" "$OUT"
fi

run_snippet 'printf "open: EROFS" >&2'
if [[ "$OUT" == *"network=0, filesystem=1. (PHB-EDENY)"* ]]; then
  ok "a last stderr line without a newline is counted"
else
  bad "a last stderr line without a newline is counted" "network=0, filesystem=1" "$OUT"
fi

run_snippet "echo 'x: EACCES' >&2; exit ${COMMAND_OWN_EXIT}"
if [[ "$RC" -eq "$COMMAND_OWN_EXIT" && "$OUT" == *"PHB-EDENY"* ]]; then
  ok "the report keeps the command's own exit status"
else
  bad "the report keeps the command's own exit status" "exit ${COMMAND_OWN_EXIT} with a PHB-EDENY report" "exit ${RC}: $OUT"
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
  ok "neither the stderr filter nor the counts pipe is handed to the command"
else
  bad "neither the stderr filter nor the counts pipe is handed to the command" "$without_phobos" "$descriptors"
fi

echo
echo "== the report never costs the command its output =="
run_snippet "head -c ${LARGE_LINE_BYTES} /dev/zero | tr '\\0' q >&2; echo done"
length="$(printf '%s' "$OUT" | tr -cd q | wc -c | tr -d ' ')"
if [[ "$RC" -eq 0 && "$length" -eq "$LARGE_LINE_BYTES" && "$OUT" == *done* && "$OUT" != *"PHB-EDENY"* \
      && "$OUT" != *"awk:"* ]]; then
  ok "one stderr line far beyond the counter's bound passes whole even when the counter gives up on it"
else
  bad "one stderr line far beyond the counter's bound passes whole even when the counter gives up on it" \
    "exit 0, ${LARGE_LINE_BYTES} bytes, no PHB-EDENY and no message of the counter's own" "exit ${RC}, ${length} bytes"
fi

start="${EPOCHREALTIME//[!0-9]/}"
bash "$CORE_X/phobos.sh" --spec-parent "$SPECS" --landlock-bin "$WORK/passthrough-landlock" -ntr -nnr -- \
  bash -c "(sleep ${LEFTOVER_SECONDS} > /dev/null; echo late >&2) & echo 'x: Permission denied' >&2; exit 0" \
  > "$WORK/leftover.out" 2>&1
RC=$?
elapsed_ms=$(( (${EPOCHREALTIME//[!0-9]/} - start) / MICROSECONDS_PER_MILLISECOND ))
if [[ "$RC" -eq 0 ]] && (( elapsed_ms < LEFTOVER_RUN_BOUND_MS )); then
  ok "a process left holding stderr delays the run by the grace period at most"
else
  bad "a process left holding stderr delays the run by the grace period at most" \
    "exit 0 within ${LEFTOVER_RUN_BOUND_MS} ms" "exit ${RC} after ${elapsed_ms} ms"
fi

finish
