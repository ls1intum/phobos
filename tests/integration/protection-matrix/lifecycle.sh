#!/usr/bin/env bash
# What a run leaves behind. After every way a run can end, the specification directory is gone, no helper process
# stays, and the hosts file is as it was. Then what a signal sent to phobos.sh does, and the hosts-file lock.
set -uo pipefail
PM_HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${PM_HERE}/lib.sh"
pm_setup || finish
PM_ABI="$(pm_abi)"
P="$PM/bin/pprobe"
SPEC_PARENT="$PM/tmp"
pids=()
cleanup() {
  local pid
  for pid in "${pids[@]}"; do
    reap "$pid"
  done
  pkill -KILL -f "$PM/bin/pprobe" 2> /dev/null
  pm_restore
}
trap cleanup EXIT
cd "$PM/work" || exit 1
chmod 0777 "$PM/rw" "$PM/out"
echo "  landlock ABI ${PM_ABI}"

c_ok="$(cfg ok <<EOF2
[read]
$PM/ro
[limits]
timeout=60
EOF2
)"
c_short="$(cfg short <<EOF2
[read]
$PM/ro
[limits]
timeout=2
EOF2
)"
c_none="$(cfg nolimit <<EOF2
[read]
$PM/ro
[limits]
timeout=0
EOF2
)"

# The names left in the specification parent, and the helper processes still alive.
spec_dirs() {
  find "$SPEC_PARENT" -mindepth 1 -maxdepth 1 -name 'phobos-spec.*' | wc -l | tr -d ' '
}
helpers_alive() {
  pgrep -f 'phobos-seccomp-networksystem|phobos-seccomp-timeoutsystem|phobos-seccomp-filesystem|phobos-timeoutsystem|phobos-networksystem|phobos-filesystem|haproxy' | wc -l | tr -d ' '
}
# The report-only supervisor and its drainer still alive.
reporters_alive() {
  pgrep -f 'phobos-seccomp-filesystem' | wc -l | tr -d ' '
}
# leaves_nothing TITLE EXPECTED_STATUS_OR_EMPTY ARGS...: one run through phobos.sh with the specification parent
# set aside, and then nothing of it may be left.
leaves_nothing() {
  local title="$1"
  local expected="$2"
  shift 2
  [[ "$expected" =~ ^[0-9]+$ ]] || { bad "$title" "the case names no expected status"; return; }
  rm -rf "${SPEC_PARENT:?}"/*
  run_pm --spec-parent "$SPEC_PARENT" "$@"
  sleep 0.3
  local dirs
  local helpers
  local started_ok=1
  dirs="$(spec_dirs)"
  helpers="$(helpers_alive)"
  case "$expected" in
    "$PHB_EPOLICY" | "$PHB_ERUNTIME" | 125 | 127) grep -q '^START' "$PM_OUT" && started_ok=0 ;;
    *) grep -q '^START' "$PM_OUT" || started_ok=0 ;;
  esac
  if [[ "$dirs" == 0 && "$helpers" == 0 && "$started_ok" == 1 && "$PM_STATUS" == "$expected" ]]; then
    ok "$title"
  else
    bad "$title" "${dirs} specification directories and ${helpers} helper processes left, status ${PM_STATUS} (wanted ${expected}), start marker ok=${started_ok}: $(pm_describe)"
  fi
}

echo
echo "== every way a run can end leaves nothing behind =="
leaves_nothing "a run that succeeds" 0 --config "$c_ok" -- "$P" cwd
leaves_nothing "a run whose command fails" 3 --config "$c_ok" -- "$P" exitwith 3
leaves_nothing "a run whose command is denied something" 10 --config "$c_ok" -- "$P" read "$PM/none/secret.txt"
leaves_nothing "a run whose command kills itself with a signal" 137 --config "$c_ok" -- "$P" selfsignal 9
leaves_nothing "a run that ends at its time limit" "$PHB_ETIMEOUT" --config "$c_short" -- "$P" sleep 30
leaves_nothing "a run with no timeout layer" 0 --no-timeoutsystem-restriction --config "$c_ok" -- "$P" cwd
leaves_nothing "a run with the network layer off" 0 --no-networksystem-restriction --config "$c_ok" -- "$P" cwd
leaves_nothing "a run with every layer off" 0 -nfr -nnr -ntr -nrr --config "$c_ok" -- "$P" cwd
leaves_nothing "a run with --debug" 0 --debug --config "$c_ok" -- "$P" cwd
printf '[bogus]\n' > "$PM/cfg/invalid.cfg"
leaves_nothing "a run refused for an invalid policy, which had already made its directory" "$PHB_EPOLICY" --config "$PM/cfg/invalid.cfg" -- "$P" cwd
leaves_nothing "a run refused for a missing connect guard" "$PHB_ERUNTIME" --connect-guard-bin /nonexistent --config "$c_ok" -- "$P" cwd
leaves_nothing "a run refused for a missing group lock" "$PHB_ERUNTIME" --pgroup-lock-bin /nonexistent --config "$c_ok" -- "$P" cwd
leaves_nothing "a run whose command does not exist" 127 --config "$c_ok" -- /nonexistent/binary
printf -- '--chdir %s/work\n--minimum-landlock-version 99\n' "$PM" > "$PM/strict.flags"
leaves_nothing "a run refused for a minimum Landlock version no kernel has" 125 --tail-flags-file "$PM/strict.flags" --config "$c_ok" -- "$P" cwd
rm -rf "${SPEC_PARENT:?}"/*
timeout 20 phobos.sh --spec-parent "$SPEC_PARENT" > /dev/null 2>&1 < /dev/null
if [[ "$(spec_dirs)" == 0 ]]; then ok "a call that is only a usage error never makes a specification directory"; else bad "a usage error makes no specification directory" "$(spec_dirs) left"; fi
rm -rf "${SPEC_PARENT:?}"/*
run_pm --spec-parent "$SPEC_PARENT" --no-restriction -- "$P" cwd
if [[ "$(spec_dirs)" == 0 ]]; then ok "and neither does --no-restriction, which builds no specification"; else bad "--no-restriction makes no specification directory" "$(spec_dirs) left"; fi
c_accept="$(cfg acceptlife <<EOF2
[bind]
allow 39610
[accept]
expose 39600 to 39610 from 127.0.0.1
EOF2
)"
leaves_nothing "a run with an inbound filter in front of its listener, stopped with it" 0 --config "$c_accept" -- "$P" tcpserver 127.0.0.1 39610 1 1
rm -rf "${SPEC_PARENT:?}"/*
burst=()
for index in 1 2 3 4 5; do
  bg_pm "$PM/out/burst-$index.out" "$PM/out/burst-$index.err" --spec-parent "$SPEC_PARENT" --config "$c_ok" -- "$P" sleep 2
  burst+=("$BG_PID")
done
burst_failed=0
for index in 1 2 3 4 5; do
  wait "${burst[$((index - 1))]}" || burst_failed=1
  grep -q '^START' "$PM/out/burst-$index.out" && grep -q '^SLEPT' "$PM/out/burst-$index.out" || burst_failed=1
done
sleep 0.3
if [[ "$burst_failed" == 0 && "$(spec_dirs)" == 0 && "$(helpers_alive)" == 0 ]]; then ok "five runs at once in one specification parent all complete and leave nothing behind"; else bad "five concurrent runs complete and leave nothing behind" "failed=${burst_failed}, $(spec_dirs) directories, $(helpers_alive) helpers"; fi
# The temporary files a run builds its rules from are out of reach of the command of a concurrent run. The shipped
# policies grant /tmp, so a command that may read /tmp lists it over and over while runs with [connect] and [bind]
# rules, whose network layer builds its port lists in temporary files, start beside it. A marker put in /tmp while
# it lists is the control: a lister that never sees it proves nothing.
c_tmpread="$(cfg tmpread <<EOF2
[read]
/tmp
EOF2
)"
c_ports="$(cfg portfiles <<EOF2
[connect]
allow 127.0.0.1:9 tcp
[bind]
allow 39620
EOF2
)"
rm -f /tmp/pm-visible-marker /tmp/pm-stop-lister
bg_pm "$PM/out/tmplister.out" "$PM/out/tmplister.err" --config "$c_tmpread" -- /bin/sh -c 'while [ ! -e /tmp/pm-stop-lister ]; do ls -A /tmp; done | sort -u'
lister="$BG_PID"
pids+=("$lister")
for index in 1 2 3 4 5 6; do
  run_pm --config "$c_ports" -- "$P" cwd
  if (( index == 3 )); then touch /tmp/pm-visible-marker; fi
done
sleep 0.5
touch /tmp/pm-stop-lister
wait "$lister"
rm -f /tmp/pm-visible-marker /tmp/pm-stop-lister
if ! grep -qx 'pm-visible-marker' "$PM/out/tmplister.out"; then
  skip "a concurrent command sees none of a run's temporary files in /tmp" "the lister never saw the marker put in /tmp, so it proves nothing: $(head -c 300 "$PM/out/tmplister.err")"
elif grep -q '^phobos-' "$PM/out/tmplister.out"; then
  bad "a concurrent command sees none of a run's temporary files in /tmp" "it saw: $(grep '^phobos-' "$PM/out/tmplister.out" | head -5 | tr '\n' ' ')"
else
  ok "a concurrent command sees none of a run's temporary files in /tmp, while it does see a file put there"
fi

echo
echo "== a process the command leaves behind, with the network layer off =="
# With the network layer off the report-only supervisor watches the command. Once the command's
# direct child has ended, a drainer keeps answering what it left behind: a granted read must still
# work, a refused one must still fail with EACCES (not ENOSYS, which a dead supervisor would give),
# and once the leftover has ended nothing of the supervisor may be left. The drainer sees the
# leftover go only once its zombie is reaped; the suite's own shell is the container's first process
# and reaps it, but under an init that reaps nothing the last check would fail.
c_left="$(cfg leftover <<EOF2
[read]
$PM/ro
$PM/rw
[write]
$PM/rw
[create]
$PM/rw
[limits]
timeout=60
EOF2
)"
rm -f "$PM/rw/left.out" "$PM/rw/left.err" "$PM/rw/left.done"
run_pm --spec-parent "$SPEC_PARENT" -nnr --config "$c_left" -- /bin/sh -c \
  "( sleep 1; cat $PM/ro/data.txt > $PM/rw/left.out; cat $PM/none/secret.txt 2> $PM/rw/left.err > /dev/null; echo done > $PM/rw/left.done ) < /dev/null > /dev/null 2>&1 & exit 0"
run_status="$PM_STATUS"
for _ in $(seq 1 50); do
  [[ -s "$PM/rw/left.done" ]] && break
  sleep 0.1
done
sleep 0.5
if (( run_status == 0 )) && [[ "$(cat "$PM/rw/left.out" 2> /dev/null)" == "READ-OK" ]]; then
  ok "a granted read by a process left behind still works through the drainer"
else
  bad "a granted read by a process left behind still works" "status ${run_status}, out: $(cat "$PM/rw/left.out" 2> /dev/null), err: $(cat "$PM/rw/left.err" 2> /dev/null): $(pm_describe)"
fi
if grep -q 'Permission denied' "$PM/rw/left.err" 2> /dev/null && ! grep -q 'Function not implemented' "$PM/rw/left.err"; then
  ok "and a refused read by it is still refused with EACCES, not ENOSYS"
else
  bad "a refused read by a process left behind is still EACCES" "err: $(cat "$PM/rw/left.err" 2> /dev/null)"
fi
if [[ "$(reporters_alive)" == 0 && "$(helpers_alive)" == 0 && "$(spec_dirs)" == 0 ]]; then
  ok "and once it has ended, no supervisor, drainer or helper of the run is left"
else
  bad "nothing of the run is left once the leftover has ended" "$(reporters_alive) reporters, $(helpers_alive) helpers, $(spec_dirs) directories"
fi
leaves_nothing "a run with the network layer off whose command fails" 3 -nnr --config "$c_ok" -- "$P" exitwith 3
leaves_nothing "and one with the timeout layer off as well" 0 -nnr -ntr --config "$c_ok" -- "$P" cwd

echo
echo "== a caller that ignores SIGCHLD still gets the command's own status =="
# An ignored SIGCHLD is handed on across exec and makes the kernel reap every child by itself. A
# supervisor that inherits it could then never read its command's status, and ended with 0, which
# would grade a command that failed as one that passed. The supervisors give SIGCHLD its default
# for themselves and give the command back what its caller gave it. With the timeout layer on, GNU
# timeout already gives its child the default, so the command sees what its caller gave it only
# without that layer.
# ignoring_sigchld SWITCHES COMMAND...: one run through phobos.sh, started by a caller that ignores
# SIGCHLD, the layer switches given as one word.
ignoring_sigchld() {
  local -a switches
  read -r -a switches <<< "$1"
  shift
  rm -rf "${SPEC_PARENT:?}"/*
  PM_OUT="$PM/out/last.out"
  PM_ERR="$PM/out/last.err"
  timeout --kill-after=5 "$WATCHDOG_SECONDS" bash -c 'trap "" CHLD; exec "$@"' _ \
    phobos.sh --tail-flags-file "$PM/tail.flags" --spec-parent "$SPEC_PARENT" "${switches[@]}" --config "$c_ok" -- "$@" \
    > "$PM_OUT" 2> "$PM_ERR" < /dev/null
  PM_STATUS=$?
}
for shape in "-nnr -ntr" "-ntr" "-nnr" ""; do
  ignoring_sigchld "$shape" "$P" exitwith 3
  if (( PM_STATUS == 3 )); then
    ok "with SIGCHLD ignored by the caller, phobos.sh ${shape:-with every layer} ends with the command's 3"
  else
    bad "with SIGCHLD ignored by the caller, phobos.sh ${shape:-with every layer} ends with the command's 3" "$(pm_describe)"
  fi
done
for shape in "-nnr -ntr" "-ntr"; do
  ignoring_sigchld "$shape" "$PM/bin/pedge" sigdisp
  if (( PM_STATUS == 0 )) && grep -q "^SIG $(kill -l CHLD) ign" "$PM_OUT"; then
    ok "and under phobos.sh ${shape} the command still starts with SIGCHLD ignored, as its caller gave it"
  else
    bad "under phobos.sh ${shape} the command starts with the SIGCHLD disposition its caller gave" "$(pm_describe)"
  fi
done

echo
echo "== the hosts file is as it was =="
if ! command -v haproxy > /dev/null || [[ ! -w /etc/hosts ]]; then
  skip "the hosts file after a run that names a host" "haproxy or a writable /etc/hosts is missing"
else
  gcc-14 -O2 -o "$PM/bin/stubdns" "${PM_HERE}/stubdns.c" 2> /dev/null
  "$PM/bin/stubdns" 39460 600 > "$PM/out/dns.log" 2>&1 &
  pids+=("$!")
  wait_for_line "$PM/out/dns.log" STUB-UP 50
  c_host="$(cfg lifehost <<EOF2
[read]
$PM/ro
[connect]
allow lifetime.example:39461
EOF2
)"
  before="$(cksum < /etc/hosts)"
  run_pm --spec-parent "$SPEC_PARENT" --resolver 127.0.0.1:39460 --config "$c_host" -- /bin/grep lifetime.example /etc/hosts
  if grep -q 'lifetime.example' "$PM_OUT" && grep -q 'phobos-run' "$PM_OUT"; then ok "while the run lasts the command sees its name mapped, with a tag that says which run added it"; else bad "the command sees its name mapped" "$(pm_describe)"; fi
  if [[ "$(cksum < /etc/hosts)" == "$before" ]]; then ok "after it the hosts file is byte for byte what it was"; else bad "the hosts file is restored" "$(cat /etc/hosts)"; fi
  c_host_timed="$(cfg lifehosttimed <<EOF2
[read]
$PM/ro
[connect]
allow lifetime.example:39461
[limits]
timeout=2
EOF2
)"
  run_pm --spec-parent "$SPEC_PARENT" --resolver 127.0.0.1:39460 --config "$c_host_timed" -- "$P" sleep 30
  if (( PM_STATUS == PHB_ETIMEOUT )) && [[ "$(cksum < /etc/hosts)" == "$before" ]]; then ok "also after a run that ended at its time limit"; else bad "the hosts file is restored after a timeout" "status ${PM_STATUS}"; fi
  burst=()
  for index in 1 2 3 4; do
    bg_pm "$PM/out/hosts-$index.out" "$PM/out/hosts-$index.err" --spec-parent "$SPEC_PARENT" --resolver 127.0.0.1:39460 --config "$c_host" -- /bin/grep lifetime.example /etc/hosts
    burst+=("$BG_PID")
  done
  wait "${burst[@]}"
  intact=1
  for index in 1 2 3 4; do
    grep -q 'lifetime.example' "$PM/out/hosts-$index.out" || intact=0
  done
  if (( intact )) && [[ "$(cksum < /etc/hosts)" == "$before" ]]; then ok "four runs naming the same host at once each see their mapping, and the file is clean afterwards"; else bad "four concurrent runs naming a host" "intact=${intact}: $(cat /etc/hosts)"; fi
  flock -x /run/lock/phobos-hosts.lock sleep 41 &
  lock_holder=$!
  for _ in $(seq 1 50); do
    flock -n /run/lock/phobos-hosts.lock true 2> /dev/null || break
    sleep 0.1
  done
  started="$(now_ms)"
  run_pm --spec-parent "$SPEC_PARENT" --resolver 127.0.0.1:39460 --config "$c_host" -- "$P" cwd
  elapsed=$(( $(now_ms) - started ))
  held_dirs="$(spec_dirs)"
  pkill -KILL -P "$lock_holder" 2> /dev/null
  reap "$lock_holder"
  if (( PM_STATUS == PHB_ERUNTIME )) && ! grep -q '^START' "$PM_OUT" && (( elapsed >= 9000 && elapsed < 40000 )); then ok "a hosts-file lock that nothing lets go of ends the run in a refusal after ${elapsed} ms, bounded, rather than a hang (${held_dirs} specification directory kept for an outer layer, as phobos-spec-dir.sh says it may be)"; else bad "a held hosts lock refuses the run within its wait" "status ${PM_STATUS} after ${elapsed} ms, ${held_dirs} directories left: $(pm_describe)"; fi
  rm -rf "${SPEC_PARENT:?}"/*
  run_pm --spec-parent "$SPEC_PARENT" --resolver 127.0.0.1:39460 --config "$c_host" -- "$P" cwd
  if (( PM_STATUS == 0 )) && grep -q '^START' "$PM_OUT"; then ok "and once the lock is free the next run works"; else bad "the next run works once the lock is free" "$(pm_describe)"; fi
  touch /run/lock/phobos-hosts.lock
  pm_restore
  run_pm_original() {
    PM_OUT="$PM/out/last.out"
    PM_ERR="$PM/out/last.err"
    timeout --kill-after=5 "$WATCHDOG_SECONDS" phobos.sh --tail-flags-file "$PM/tail.flags" "$@" > "$PM_OUT" 2> "$PM_ERR" < /dev/null
    PM_STATUS=$?
  }
  run_direct /bin/cat /run/lock/phobos-hosts.lock
  if (( PM_STATUS == 0 )); then
    run_pm_original --config "$c_ok" -- /bin/cat /run/lock/phobos-hosts.lock
    if (( PM_STATUS != 0 )) && grep -q 'Permission denied' "$PM_ERR"; then ok "under the shipped policy the command cannot open the hosts lock, so it cannot hold it to stall a clean-up"; else bad "the shipped policy hides the hosts lock" "$(pm_describe)"; fi
  else
    skip "the shipped policy hides the hosts lock" "the unprotected control could not read it: $(pm_describe)"
  fi
  pm_install_base
fi

echo
echo "== a signal sent to phobos.sh =="
# signal_case SIGNAL CONFIG COMMAND...: starts a run of the command, signals the process phobos.sh became, waits three
# seconds and reports in SIGNAL_STARTED, SIGNAL_ENDED (phobos.sh is gone), SIGNAL_STATUS (what it answered),
# SIGNAL_DIRS (the specification directories left) and SIGNAL_ALIVE (the command still runs). The command's own
# marker line is the word it prints when it is ready, SIGNAL_MARKER. It then removes what is left. SIGINT needs
# the run started with that signal at its default, which a shell does not give a background command, and the same for SIGQUIT.
SIGNAL_MARKER=SLEEPING
signal_case() {
  local signal="$1"
  local config="$2"
  shift 2
  rm -rf "${SPEC_PARENT:?}"/*
  : > "$PM/out/signalled.out"
  ( trap - INT QUIT; exec phobos.sh --spec-parent "$SPEC_PARENT" --tail-flags-file "$PM/tail.flags" --config "$config" -- "$@" ) > "$PM/out/signalled.out" 2> "$PM/out/signalled.err" < /dev/null &
  local pid=$!
  SIGNAL_STARTED=1
  wait_for_line "$PM/out/signalled.out" "$SIGNAL_MARKER" 100 || SIGNAL_STARTED=0
  kill -"$signal" "$pid"
  sleep 3
  if kill -0 "$pid" 2> /dev/null; then SIGNAL_ENDED=0; else SIGNAL_ENDED=1; fi
  SIGNAL_DIRS="$(spec_dirs)"
  if pgrep -f -- "$*" > /dev/null; then SIGNAL_ALIVE=1; else SIGNAL_ALIVE=0; fi
  pkill -KILL -f -- "$*" 2> /dev/null
  kill -KILL "$pid" 2> /dev/null
  SIGNAL_STATUS=0
  wait "$pid" 2> /dev/null || SIGNAL_STATUS=$?
  sleep 1
  pkill -KILL -f 'phobos-seccomp|phobos-networksystem|phobos-filesystem|phobos-timeoutsystem' 2> /dev/null
  rm -rf "${SPEC_PARENT:?}"/*
}
# signal_ends TITLE SIGNAL NUMBER CONFIG SECONDS: the signal ends the run at once with 128 plus its number, the command
# is gone and no specification directory is left.
signal_ends() {
  local title="$1"
  local signal="$2"
  local number="$3"
  local config="$4"
  local seconds="$5"
  SIGNAL_MARKER=SLEEPING
  signal_case "$signal" "$config" "$P" sleep "$seconds"
  if [[ "$SIGNAL_STARTED" == 1 && "$SIGNAL_ENDED" == 1 && "$SIGNAL_ALIVE" == 0 && "$SIGNAL_DIRS" == 0 && "$SIGNAL_STATUS" == $(( 128 + number )) ]]; then
    ok "$title"
  else
    bad "$title" "started ${SIGNAL_STARTED}, ended ${SIGNAL_ENDED}, command alive ${SIGNAL_ALIVE}, ${SIGNAL_DIRS} directories, status ${SIGNAL_STATUS} (wanted $(( 128 + number )))"
  fi
}
signal_ends "SIGTERM to a run with a timeout layer reaches the command: the run ends, answers 143 and leaves nothing" TERM 15 "$c_ok" 20
signal_ends "SIGHUP to a run with a timeout layer reaches the command" HUP 1 "$c_ok" 21
signal_ends "SIGINT to a run with a timeout layer reaches the command" INT 2 "$c_ok" 22
signal_ends "SIGQUIT to a run with a timeout layer reaches the command" QUIT 3 "$c_ok" 23
signal_ends "SIGTERM to a run with no timeout layer reaches the command" TERM 15 "$c_none" 24
signal_ends "SIGHUP to a run with no timeout layer reaches the command" HUP 1 "$c_none" 25
signal_ends "SIGINT to a run with no timeout layer reaches the command" INT 2 "$c_none" 26
signal_ends "SIGQUIT to a run with no timeout layer reaches the command" QUIT 3 "$c_none" 27
SIGNAL_MARKER=TRAPPING
signal_case TERM "$c_ok" "$P" trapterm 20
gap_case "a command that ignores SIGTERM is not ended by the signal passed on to it, and the run goes on" "the manual, SIGNALS" "$(holds_if test "$SIGNAL_STARTED" = 1 -a "$SIGNAL_ENDED" = 0 -a "$SIGNAL_ALIVE" = 1)"
SIGNAL_MARKER=SLEEPING
signal_case KILL "$c_none" "$P" sleep 28
gap_case "SIGKILL to phobos.sh cannot be passed on: its specification directory is left, as is the command" "the signal cannot be caught" "$(holds_if test "$SIGNAL_STARTED" = 1 -a "$SIGNAL_DIRS" = 1 -a "$SIGNAL_ALIVE" = 1)"
finish
