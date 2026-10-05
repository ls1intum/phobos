#!/usr/bin/env bash
# shellcheck shell=bash
# What the suites of the protection matrix share: the probe, a minimal base policy, and the helpers that
# turn one attempted operation into a trustworthy verdict.
#
# A denial only counts as the sandbox's when three things hold, and every deny_* helper checks them:
#   1. the probe, run directly in the container as the same user, SUCCEEDS at the operation (the control:
#      otherwise the container itself, not Phobos, would be refusing it, and there is no evidence);
#   2. through phobos.sh the probe starts (START line) and the one intended operation fails with the
#      errno a sandbox answers with (an OP line, not a setup or startup failure);
#   3. the SAME policy with ONLY the layer under test switched off lets the operation succeed, which
#      names the layer that refused it.
# A sibling operation that must still work is checked next to every denial by the allow_* helpers, so a
# sandbox that denies everything cannot pass.
#
# Sourced by the suites. It sets no shell options of its own beyond nounset and pipefail: a suite counts
# its failures and goes on, as the acceptance suites do.

# The variables here are read by the suites that source this file and never in it, so SC2034 would fire on each of
# them by design.
# shellcheck disable=SC2034
# shellcheck source=../../harness.sh
source "${PM_HERE}/../../harness.sh" || { echo "cannot source the harness" >&2; exit 1; }

PHOBOS_HOME="${PHOBOS_HOME:-/var/tmp/opt/core}"
# The area every case works in. Nothing in it is granted unless a case's policy says so.
PM=/var/tmp/pm
# How long one case may run before the watchdog ends it, whatever Phobos does.
WATCHDOG_SECONDS="${WATCHDOG_SECONDS:-150}"
# The names of the errno a sandbox answers a refused operation with.
DENIED_ERRNOS="EACCES EPERM"

PM_OUT=""
PM_ERR=""
PM_STATUS=0

export PATH="${PHOBOS_HOME}:${PATH}"

# Compiles the probe twice, dynamic and static, and lays out the fixtures and the minimal base policy.
# Restores the image's own base policy when the suite ends. Answers 0 when ready.
pm_setup() {
  mkdir -p "$PM"/{ro,rw,rw2,none,work,bin,cfg,out,exec,tmp}
  gcc-14 -std=gnu23 -O2 -Wall -Wextra -o "$PM/bin/pprobe" "${PM_HERE}/probe.c" -pthread 2>"$PM/out/cc.log" \
    || { bad "the probe builds" "$(cat "$PM/out/cc.log")"; return 1; }
  gcc-14 -std=gnu23 -O2 -Wall -Wextra -o "$PM/bin/pedge" "${PM_HERE}/edge.c" -pthread 2>"$PM/out/cc-edge.log" \
    || { bad "the second probe builds" "$(cat "$PM/out/cc-edge.log")"; return 1; }
  gcc-14 -std=gnu23 -O2 -static -o "$PM/exec/pprobe-static" "${PM_HERE}/probe.c" -pthread 2>/dev/null \
    || { bad "the static probe builds"; return 1; }
  cp "$PM/exec/pprobe-static" "$PM/ro/pprobe-static"
  cp "$PM/exec/pprobe-static" "$PM/none/pprobe-static"
  printf 'READ-OK\n' > "$PM/ro/data.txt"
  printf 'RW-OK\n' > "$PM/rw/data.txt"
  printf 'TOP-SECRET\n' > "$PM/none/secret.txt"
  chmod 0644 "$PM"/ro/data.txt "$PM"/rw/data.txt "$PM"/none/secret.txt
  chmod 0755 "$PM"/ro/pprobe-static "$PM"/none/pprobe-static
  if [[ -f "${PHOBOS_HOME}/BaseLanguage-java.cfg" ]] && ! pm_base_is_ours; then
    cp "${PHOBOS_HOME}/BaseLanguage-java.cfg" "$PM/base.original"
  fi
  pm_install_base
  printf -- '--chdir %s/work\n' "$PM" > "$PM/tail.flags"
  return 0
}

# Prints the minimal base policy: the system to run programs from, the probe, and nothing else.
pm_minimal_base() {
  cat <<BASE
[read]
/usr
/lib
/lib64
/bin
/sbin
/etc
/dev/null
${PM}/bin
${PM}/work

[execute]
/usr
/lib
/lib64
/bin
/sbin
${PM}/bin

[write]
/dev/null
BASE
}

# Writes the minimal base policy over the image's.
pm_install_base() {
  pm_minimal_base > "${PHOBOS_HOME}/BaseLanguage-java.cfg"
}

# Whether the base policy in place is the minimal one this library wrote, so that a backup is taken of the image's
# own and never of a leftover from an earlier suite that did not get to restore it.
pm_base_is_ours() {
  [[ "$(cat "${PHOBOS_HOME}/BaseLanguage-java.cfg")" == "$(pm_minimal_base)" ]]
}

pm_restore() {
  if [[ -f "$PM/base.original" ]]; then
    cp "$PM/base.original" "${PHOBOS_HOME}/BaseLanguage-java.cfg"
  fi
}

# Prints the Landlock version the kernel offers, or 0.
pm_abi() {
  local reported
  reported="$(phobos-landlock-filesystem-and-networksystem --verbose --rights=rx /usr -- /bin/true 2>&1 \
    | sed -n 's/.*Landlock version \([0-9]*\).*/\1/p' | head -1)"
  printf '%s\n' "${reported:-0}"
}

# Writes the policy given on standard input to a named file under cfg/ and prints its path.
cfg() {
  local path="$PM/cfg/$1.cfg"
  cat > "$path"
  printf '%s\n' "$path"
}

# Runs phobos.sh with the arguments given, under the watchdog, and keeps its streams and status.
# Everything is read back from PM_OUT, PM_ERR and PM_STATUS. The test tail flags are always given.
run_pm() {
  PM_OUT="$PM/out/last.out"
  PM_ERR="$PM/out/last.err"
  timeout --kill-after=5 "$WATCHDOG_SECONDS" phobos.sh --tail-flags-file "$PM/tail.flags" "$@" \
    > "$PM_OUT" 2> "$PM_ERR" < /dev/null
  PM_STATUS=$?
}

# Runs a command directly, with no sandbox, under the watchdog: the control.
run_direct() {
  PM_OUT="$PM/out/last.out"
  PM_ERR="$PM/out/last.err"
  timeout --kill-after=5 "$WATCHDOG_SECONDS" "$@" > "$PM_OUT" 2> "$PM_ERR" < /dev/null
  PM_STATUS=$?
}

# Prints "<ret> <errno>" of the first OP line of that name in the last output, or nothing.
op_result() {
  sed -n "s/^OP $1 ret=\\(-\\{0,1\\}[0-9]*\\) errno=\\([A-Za-z0-9]*\\).*/\\1 \\2/p" "$PM_OUT" | head -1
}

# Whether the last run's operation of that name succeeded: 0 yes, 1 no or absent.
op_ok() {
  local result
  result="$(op_result "$1")"
  [[ -n "$result" && "${result%% *}" -ge 0 ]]
}

# Whether it failed with one of the errno names given: 0 yes.
op_failed_with() {
  local name="$1"
  shift
  local result
  local number
  local errno_name
  result="$(op_result "$name")"
  [[ -n "$result" ]] || return 1
  number="${result%% *}"
  errno_name="${result##* }"
  (( number < 0 )) || return 1
  [[ " $* " == *" ${errno_name} "* ]]
}

# One line that says what a run did, for a failure message.
pm_describe() {
  printf 'status=%s out=[%s] err=[%s]' "$PM_STATUS" "$(tr '\n' '|' < "$PM_OUT" | cut -c1-300)" \
    "$(tr '\n' '|' < "$PM_ERR" | cut -c1-300)"
}

# The flags that switch the named layers off: fs, net, time, res, or several joined by commas.
layer_flag() {
  local flags=""
  local layer
  for layer in ${1//,/ }; do
    case "$layer" in
      fs) flags="${flags} --no-filesystem-restriction" ;;
      net) flags="${flags} --no-networksystem-restriction" ;;
      time) flags="${flags} --no-timeoutsystem-restriction" ;;
      res) flags="${flags} --no-resourcesystem-restriction" ;;
    esac
  done
  printf '%s\n' "${flags# }"
}

# Sets up what a case needs before every run of it, from the PREP command string, when one is given.
pm_prep() {
  if [[ -n "${PREP:-}" ]]; then
    eval "$PREP"
  fi
}

# deny_case TITLE LAYER CONFIG OPNAME ERRNOS -- PROBE ARGS...
# The operation OPNAME of the probe must succeed unprotected, fail with one of ERRNOS through phobos.sh
# with CONFIG, and succeed again with only LAYER switched off. PM_EXTRA, when set, holds phobos.sh options that stay
# the same in the protected run and the last one, to keep another layer out of the comparison. Any other result is
# a failure of the case, and an unprotected control that fails is no evidence at all and is skipped, never passed.
deny_case() {
  local title="$1"
  local layer="$2"
  local config="$3"
  local opname="$4"
  local errnos="$5"
  shift 6
  local flag
  flag="$(layer_flag "$layer")"
  pm_prep
  run_direct "$@"
  if ! op_ok "$opname"; then
    skip "$title" "the unprotected control did not succeed ($(pm_describe)), so there is no evidence either way"
    return 0
  fi
  pm_prep
  # PM_EXTRA is a space-separated list of options, none of which holds a space, so it must split into words.
  # shellcheck disable=SC2086
  run_pm ${PM_EXTRA:-} --config "$config" -- "$@"
  if ! grep -q '^START' "$PM_OUT"; then
    bad "$title" "the probe never started under phobos.sh: $(pm_describe)"
    return 0
  fi
  if ! op_failed_with "$opname" $errnos; then
    bad "$title" "expected $opname to fail with ${errnos}, got: $(op_result "$opname" || true) $(pm_describe)"
    return 0
  fi
  pm_prep
  # The flags are a space-separated list of options, none of which holds a space, so they must split into words.
  # shellcheck disable=SC2086
  run_pm ${PM_EXTRA:-} $flag --config "$config" -- "$@"
  if ! op_ok "$opname"; then
    bad "$title" "refused even with the ${layer} layer off, so the ${layer} layer is not what refused it: $(pm_describe)"
    return 0
  fi
  ok "$title"
}

# allow_case TITLE CONFIG OPNAME -- PROBE ARGS...
# The operation succeeds through phobos.sh with CONFIG.
allow_case() {
  local title="$1"
  local config="$2"
  local opname="$3"
  shift 4
  pm_prep
  run_pm --config "$config" -- "$@"
  if grep -q '^START' "$PM_OUT" && op_ok "$opname"; then
    ok "$title"
  else
    bad "$title" "expected $opname to succeed: $(pm_describe)"
  fi
}

# expect_output TITLE CONFIG PATTERN -- PROBE ARGS...
# The run's standard output contains the pattern.
expect_output() {
  local title="$1"
  local config="$2"
  local pattern="$3"
  shift 4
  pm_prep
  run_pm --config "$config" -- "$@"
  if grep -q -- "$pattern" "$PM_OUT"; then
    ok "$title"
  else
    bad "$title" "expected output matching '${pattern}': $(pm_describe)"
  fi
}

# A GAP check: the behaviour is a documented limit and this asserts it as it is today, so a change in either
# direction turns the suite red until the check and the documentation agree. Takes the title, the document
# that states it, and the result of the check as 0 or non-zero.
gap_case() {
  local title="$1"
  local document="$2"
  local holds="$3"
  if (( holds == 0 )); then
    ok "GAP: ${title} (documented in ${document})"
  else
    bad "GAP: ${title} (documented in ${document})" "the documented behaviour no longer holds: $(pm_describe)"
  fi
}

# Prints 0 when the command given succeeds and 1 when it does not, for gap_case and known_defect.
holds_if() {
  if "$@"; then printf '0\n'; else printf '1\n'; fi
}

# A KNOWN DEFECT check: the behaviour is a defect of Phobos, reported and not fixed in the change that wrote this
# check. It is counted as skipped, with the defect named, while the defect holds, so the suite stays honest about
# it. The moment the behaviour changes, so that the defect no longer holds, the check fails, and whoever fixed it
# turns it into an ordinary check. Takes the title, the defect's name, and 0 when the defect still holds.
known_defect() {
  local title="$1"
  local defect="$2"
  local holds="$3"
  if (( holds == 0 )); then
    skip "KNOWN DEFECT: ${title}" "${defect}"
  else
    bad "KNOWN DEFECT no longer holds: ${title}" "${defect} appears fixed: replace this check with an ordinary one"
  fi
}

# Kills a disposable process the suite started, whatever state it is in, and waits until it is gone. SIGKILL, because
# a process that a tracer left stopped does not die of SIGTERM. Only a child of the calling shell can be reaped; a
# process started inside a command substitution is collected by the container's init instead.
reap() {
  [[ "${1:-}" =~ ^[1-9][0-9]*$ ]] || return 0
  kill -KILL "$1" 2>/dev/null
  local polls=0
  while kill -0 "$1" 2>/dev/null && (( polls < 50 )); do
    sleep 0.1
    polls=$(( polls + 1 ))
  done
  wait "$1" 2>/dev/null
  return 0
}

# Skips a case unless the kernel offers at least this Landlock version. Answers 0 when it does.
needs_abi() {
  local wanted="$1"
  local title="$2"
  if (( PM_ABI >= wanted )); then
    return 0
  fi
  skip "$title" "needs Landlock version ${wanted}, this kernel offers ${PM_ABI}"
  return 1
}

# Waits until a file holds a line, up to a number of tenths of a second. Answers 0 when it did.
wait_for_line() {
  local file="$1"
  local pattern="$2"
  local tenths="${3:-50}"
  local waited=0
  while (( waited < tenths )); do
    grep -q -- "$pattern" "$file" 2>/dev/null && return 0
    sleep 0.1
    waited=$((waited + 1))
  done
  return 1
}

# Starts the probe's TCP server outside the sandbox and waits for it. Prints its pid. When the server does not
# come up it prints nothing and answers 1, which reap ignores and require_started turns into a failure.
start_tcp_server() {
  local address="$1"
  local port="$2"
  local rounds="${3:-1}"
  local idle="${4:-8}"
  local log="$PM/out/server-${address}-${port}.log"
  : > "$log"
  "$PM/bin/pprobe" tcpserver "$address" "$port" "$rounds" "$idle" > "$log" 2>&1 &
  local pid=$!
  if ! wait_for_line "$log" LISTENING 50; then
    kill -KILL "$pid" 2>/dev/null
    return 1
  fi
  printf '%s\n' "$pid"
}

# Starts a UDP receiver outside the sandbox for a number of seconds, and waits for it. Prints its pid, or nothing
# and answers 1 when it does not come up.
start_udp_receiver() {
  local address="$1"
  local port="$2"
  local seconds="$3"
  local log="$PM/out/udp-${address}-${port}.log"
  : > "$log"
  "$PM/bin/pprobe" udp_arrivals "$address" "$port" "$seconds" > "$log" 2>&1 &
  local pid=$!
  if ! wait_for_line "$log" RECEIVER-UP 50; then
    kill -KILL "$pid" 2>/dev/null
    return 1
  fi
  printf '%s\n' "$pid"
}

# Records a failure when a helper process did not come up, so the checks that follow are not read as evidence.
# Takes what the helper is and the pid the start function printed.
require_started() {
  [[ "${2:-}" =~ ^[1-9][0-9]*$ ]] || bad "$1 starts" "it did not come up, so every check that depends on it is without evidence"
}

# Starts phobos.sh in the background under the watchdog with its streams sent to the two files given, and leaves the
# pid of the watchdog in BG_PID. Waiting for that pid is bounded by the watchdog.
bg_pm() {
  local out="$1"
  local err="$2"
  shift 2
  timeout --kill-after=5 "$WATCHDOG_SECONDS" phobos.sh --tail-flags-file "$PM/tail.flags" "$@" > "$out" 2> "$err" < /dev/null &
  BG_PID=$!
}

# The monotonic-enough clock the suites time a run with, in milliseconds.
now_ms() {
  local microseconds="${EPOCHREALTIME//[!0-9]/}"
  printf '%s\n' "$(( microseconds / 1000 ))"
}

# Runs phobos.sh as run_pm does and sets PM_ELAPSED_MS to how long it took.
run_pm_timed() {
  local started
  started="$(now_ms)"
  run_pm "$@"
  PM_ELAPSED_MS=$(( $(now_ms) - started ))
}

# The exit statuses Phobos itself answers with, read from the shipped constants, never copied.
# shellcheck source=/dev/null
source "${PHOBOS_HOME}/phobos-tools-common/phobos-constants.sh"

PM_ELAPSED_MS=0
PM_ABI=0
PM_USER_ID="$(id -u)"
