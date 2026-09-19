#!/usr/bin/env bash
# Proves Landlock scoping: a sandboxed process cannot signal a process outside the sandbox,
# but can still signal one inside it.
#
# Without scoping (which the wrapper now sets from ABI 6 on), a submission could send a
# signal to the grading process beside it, which the filesystem and network rules do not
# cover. This checks both directions: an outside process is out of reach, an inside one is
# not, so scoping confines rather than forbidding signals altogether.
#
# It needs the run-phase image and an ordinary container: no --privileged, no --cap-add,
# no --security-opt. Scoping needs Landlock ABI 6 (kernel 6.12) or newer; below that the
# suite skips, because there is nothing to enforce in its place.
set -uo pipefail

CORE="${PHOBOS_HOME:-/var/tmp/opt/core}"
LANDLOCK="${CORE}/phobos-landlock"

pass=0
fail=0
skipped=0
ok()   { printf 'ok    %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf 'FAIL  %s\n        %s\n' "$1" "$2"; fail=$((fail + 1)); }
skip() { printf 'SKIP  %s\n        %s\n' "$1" "$2"; skipped=$((skipped + 1)); }

# The Landlock version that brings scoping, and how long the processes the checks signal live:
# long enough to outlast the checks, and killed when they are done.
FIRST_LANDLOCK_VERSION_WITH_SCOPING=6
OUTSIDE_PROCESS_SECONDS=300
INSIDE_PROCESS_SECONDS=30
version="$("$LANDLOCK" --verbose --rights=rx /usr -- /bin/true 2>&1 \
    | sed -n 's/.*Landlock version \([0-9][0-9]*\).*/\1/p' | head -1)"

if [[ -z "$version" ]] || (( version < FIRST_LANDLOCK_VERSION_WITH_SCOPING )); then
    skip "Landlock scoping" "the kernel offers Landlock version ${version:-<none>}; scoping needs 6"
    echo
    printf '%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skipped"
    exit 0
fi

# A process outside the sandbox, started before it, that the sandboxed process will try to
# reach with a harmless signal-0 (an existence check that still needs signal permission).
sleep "$OUTSIDE_PROCESS_SECONDS" &
outside_pid=$!

out="$("$LANDLOCK" --rights=rx /usr --rights=rx /lib -- \
    /bin/sh -c "kill -0 ${outside_pid} && echo outside=REACHED || echo outside=denied" 2>&1)"
kill "$outside_pid" 2>/dev/null || true
if [[ "$out" == *"outside=denied"* && "$out" != *"outside=REACHED"* ]]; then
    ok "a sandboxed process cannot signal a process outside the sandbox"
else
    bad "a sandboxed process cannot signal a process outside the sandbox" "$out"
fi

# A process the sandbox starts itself is inside the same Landlock domain, so signalling it
# must still work: scoping confines signals, it does not forbid them.
out="$("$LANDLOCK" --rights=rx /usr --rights=rx /lib -- \
    /bin/sh -c "sleep ${INSIDE_PROCESS_SECONDS}"' & inside=$!; kill -0 "$inside" && echo inside=ok || echo inside=DENIED; kill "$inside" 2>/dev/null' 2>&1)"
if [[ "$out" == *"inside=ok"* && "$out" != *"inside=DENIED"* ]]; then
    ok "a sandboxed process can still signal a process inside the sandbox"
else
    bad "a sandboxed process can still signal a process inside the sandbox" "$out"
fi

echo
printf '%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skipped"
(( fail == 0 ))
