#!/usr/bin/env bash
# The timeout layer through phobos.sh: a run past its limit is ended, however the command tries to avoid it, a
# run within it is left alone, and the limit is merged, defaulted and validated as promised.
set -uo pipefail
PM_HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${PM_HERE}/lib.sh"
pm_setup || finish
trap pm_restore EXIT
PM_ABI="$(pm_abi)"
P="$PM/bin/pprobe"
cd "$PM/work" || exit 1
echo "  landlock ABI ${PM_ABI}, uid ${PM_USER_ID}"

cfg_time() {
  local name="$1"
  shift
  {
    printf '[read]\n%s\n[limits]\n' "$PM/ro"
    printf '%s\n' "$@"
  } | cfg "$name"
}
c_t3="$(cfg_time t3 timeout=3)"
c_t5="$(cfg_time t5 timeout=5)"
c_t2="$(cfg_time t2 timeout=2)"
c_t30="$(cfg_time t30 timeout=30)"
c_t0="$(cfg_time t0 timeout=0)"
c_frac="$(cfg_time frac timeout=2.500)"

# Whether any process of this name is still alive, by a pattern that cannot match this shell.
alive() {
  pgrep -f -- "$1" > /dev/null
}

echo
echo "== a run past its limit is ended =="
run_pm_timed --config "$c_t3" -- "$P" sleep 60
if (( PM_STATUS == PHB_ETIMEOUT && PM_ELAPSED_MS >= 3000 && PM_ELAPSED_MS < 15000 )); then ok "a command that sleeps past the limit is ended at it and reported as a timeout (${PM_ELAPSED_MS} ms)"; else bad "a sleeping command is ended at the limit" "status ${PM_STATUS} after ${PM_ELAPSED_MS} ms: $(pm_describe)"; fi
run_pm_timed --config "$c_t3" -- "$P" spin 60
if (( PM_STATUS == PHB_ETIMEOUT && PM_ELAPSED_MS >= 3000 && PM_ELAPSED_MS < 15000 )); then ok "a command that burns processor time is ended at the limit (${PM_ELAPSED_MS} ms)"; else bad "a busy command is ended at the limit" "status ${PM_STATUS} after ${PM_ELAPSED_MS} ms"; fi
run_pm_timed --no-timeoutsystem-restriction --config "$c_t3" -- "$P" sleep 6
if (( PM_STATUS == 0 && PM_ELAPSED_MS >= 6000 )) && grep -q SLEPT "$PM_OUT"; then ok "with the timeout layer off the same command runs to its end, so the layer is what stopped it"; else bad "with the timeout layer off the command runs to its end" "status ${PM_STATUS} after ${PM_ELAPSED_MS} ms: $(pm_describe)"; fi
run_pm_timed --config "$c_t5" -- "$P" sleep 1
if (( PM_STATUS == 0 && PM_ELAPSED_MS < 4500 )) && grep -q SLEPT "$PM_OUT"; then ok "a command that finishes before the limit is not delayed to it (${PM_ELAPSED_MS} ms)"; else bad "an early command is not delayed" "status ${PM_STATUS} after ${PM_ELAPSED_MS} ms"; fi
run_pm_timed --config "$c_t3" -- "$P" trapterm 60
if (( PM_STATUS == PHB_ETIMEOUT && PM_ELAPSED_MS >= 3000 && PM_ELAPSED_MS < 20000 )) && ! alive "pprobe trapterm 60"; then ok "a command that traps SIGTERM is ended by the escalation to SIGKILL (${PM_ELAPSED_MS} ms) and no process of it is left"; else bad "a SIGTERM-trapping command is ended" "status ${PM_STATUS} after ${PM_ELAPSED_MS} ms alive=$(alive 'pprobe trapterm 60' && echo yes || echo no)"; fi
run_pm_timed --config "$c_t3" -- /bin/sh -c "$P sleep 58 & $P sleep 57 & wait"
if (( PM_STATUS == PHB_ETIMEOUT )) && ! alive "pprobe sleep 58" && ! alive "pprobe sleep 57"; then ok "the children of the command die with it"; else bad "the children of the command die with it" "status ${PM_STATUS}; alive=$(alive 'pprobe sleep 5[78]' && echo yes || echo no)"; fi

echo
echo "== an imported Ares 2 timeout =="
a_t1500="$(ares_cfg ares_t1500 "fs $PM/ro r" "timeout 1500")"
run_pm_timed --debug --config "$a_t1500" -- "$P" sleep 60
if (( PM_STATUS == PHB_ETIMEOUT && PM_ELAPSED_MS >= 1500 && PM_ELAPSED_MS < 15000 )) && grep -q 'timeout.sec: 1.500' "$PM_ERR"; then
  ok "an Ares timeout of 1500 ms becomes 1.500 s in the specification, not a rounded 1 or 2, and ends a sleeping run (${PM_ELAPSED_MS} ms)"
else
  bad "an Ares timeout of 1500 ms bounds the run at 1.5 s" "status ${PM_STATUS} after ${PM_ELAPSED_MS} ms: $(pm_describe)"
fi
a_t8000="$(ares_cfg ares_t8000 "fs $PM/ro r" "timeout 8000")"
run_pm_timed --config "$a_t8000" -- "$P" sleep 1
if (( PM_STATUS == 0 )) && grep -q SLEPT "$PM_OUT"; then ok "and a command that ends within an Ares timeout is left alone"; else bad "a command within an Ares timeout is left alone" "status ${PM_STATUS} after ${PM_ELAPSED_MS} ms: $(pm_describe)"; fi

echo
echo "== leaving the process group: answered from the supervisor's ledger, or refused where there is none =="
for call in setsid setpgid; do
  run_pm --config "$c_t5" -- "$P" "$call"
  if op_ok "$call"; then ok "${call} succeeds, answered from the ledger (the process stays in the group the timeout kills)"; else bad "${call} succeeds with the supervisor on" "$(pm_describe)"; fi
  run_pm --no-timeoutsystem-restriction --config "$c_t5" -- "$P" "$call"
  if op_ok "$call"; then ok "${call} succeeds with the timeout layer off, answered by the connect guard"; else bad "${call} succeeds with the timeout layer off" "$(pm_describe)"; fi
  run_pm --no-networksystem-restriction --config "$c_t5" -- "$P" "$call"
  if op_ok "$call"; then ok "${call} succeeds with the network layer off, answered by the report-only supervisor"; else bad "${call} succeeds with the network layer off" "$(pm_describe)"; fi
  run_pm --no-networksystem-restriction --no-filesystem-restriction --config "$c_t5" -- "$P" "$call"
  if op_failed_with "$call" $DENIED_ERRNOS; then ok "${call} is refused by the group lock alone when no supervisor runs"; else bad "${call} is refused by the group lock alone" "$(pm_describe)"; fi
  run_pm --no-timeoutsystem-restriction --no-networksystem-restriction --config "$c_t5" -- "$P" "$call"
  if op_ok "$call"; then ok "${call} works with the timeout and network layers off"; else bad "${call} works with both off" "$(pm_describe)"; fi
done

echo
echo "== a descendant that tries to outlive the run =="
rm -f "$PM/work/marker-stay" "$PM/rw/marker-stay"
c_t3_write="$(cfg_time t3w timeout=3)"
printf '[write]\n%s\n[create]\n%s\n' "$PM/rw" "$PM/rw" >> "$c_t3_write"
rm -f "$PM/rw/marker-stay"
run_pm_timed --config "$c_t3_write" -- "$P" daemonize 7 "$PM/rw/marker-stay" stay
sleep 6
if (( PM_STATUS == PHB_ETIMEOUT )) && [[ ! -e "$PM/rw/marker-stay" ]]; then ok "a double-forked descendant dies with a command that is still running at the limit, and never writes its marker"; else bad "a descendant dies with the command at the limit" "status ${PM_STATUS}, marker=$([[ -e $PM/rw/marker-stay ]] && echo present || echo absent)"; fi
rm -f "$PM/rw/marker-orphan"
run_pm_timed --config "$c_t3_write" -- "$P" daemonize 7 "$PM/rw/marker-orphan" orphan
sleep 6
if (( PM_STATUS == PHB_ETIMEOUT )) && [[ ! -e "$PM/rw/marker-orphan" ]]; then ok "a descendant outlives a command that has already exited, and the limit still ends it: the run waits for the group and reports the timeout"; else bad "an orphaned descendant is ended at the limit" "status ${PM_STATUS}, marker=$([[ -e $PM/rw/marker-orphan ]] && echo present || echo absent)"; fi
rm -f "$PM/rw/marker-orphan"
run_pm_timed --no-timeoutsystem-restriction --config "$c_t3_write" -- "$P" daemonize 7 "$PM/rw/marker-orphan" orphan
sleep 9
if (( PM_STATUS == 0 )) && [[ -e "$PM/rw/marker-orphan" ]]; then ok "and with the timeout layer off the same descendant runs to its end and writes its marker, so the layer is what ended it"; else bad "the orphan outlives the command with the layer off" "status ${PM_STATUS}, marker=$([[ -e $PM/rw/marker-orphan ]] && echo present || echo absent)"; fi
rm -f "$PM/rw/marker-orphan"
if alive "pprobe daemonize"; then pkill -KILL -f "pprobe daemonize" 2>/dev/null; fi

echo
echo "== the descendants of a timed-out run do not keep a caller waiting =="
# The run's own standard output is the pipe here, so a descendant that outlives the limit holds the reader open.
piped_run() {
  timeout --kill-after=5 "$WATCHDOG_SECONDS" phobos.sh --tail-flags-file "$PM/tail.flags" "$@" -- /bin/sh -c "$P sleep 12 & echo started; $P sleep 13" 2> /dev/null < /dev/null | cat > "$PM/out/piped.out"
  PIPED_STATUS="${PIPESTATUS[0]}"
}
started="$(now_ms)"
piped_run --config "$c_t3"
elapsed=$(( $(now_ms) - started ))
if [[ "$PIPED_STATUS" == "$PHB_ETIMEOUT" && "$(grep -c '^SLEEPING' "$PM/out/piped.out")" == 2 ]] && (( elapsed < 9000 )); then ok "a caller reading the run's own output through a pipe is released at the limit with the timeout status, not when the descendants end (${elapsed} ms)"; else bad "a caller reading through a pipe is released" "status ${PIPED_STATUS}, took ${elapsed} ms, output: $(tr '\n' '|' < "$PM/out/piped.out")"; fi
started="$(now_ms)"
piped_run -ntr --config "$c_t3"
elapsed=$(( $(now_ms) - started ))
if [[ "$PIPED_STATUS" == 0 && "$(grep -c '^SLEPT' "$PM/out/piped.out")" == 2 ]] && (( elapsed >= 11500 )); then ok "and with the timeout layer off the same reader waits for both sleeping processes to finish, so the pipe was held open (${elapsed} ms)"; else bad "the pipe is held open with the timeout layer off" "status ${PIPED_STATUS}, took ${elapsed} ms: $(tr '\n' '|' < "$PM/out/piped.out")"; fi

echo
echo "== the limit is merged, defaulted and validated =="
run_pm_timed --config "$c_t2" --config "$c_t30" -- "$P" sleep 4
if (( PM_STATUS == 0 )) && grep -q SLEPT "$PM_OUT"; then ok "of two configurations the larger limit wins"; else bad "the larger limit wins" "status ${PM_STATUS}: $(pm_describe)"; fi
run_pm_timed --config "$c_t30" --config "$c_t2" -- "$P" sleep 4
if (( PM_STATUS == 0 )); then ok "in either order"; else bad "in either order" "$(pm_describe)"; fi
run_pm_timed --config "$c_t2" --config "$c_t0" -- "$P" sleep 4
if (( PM_STATUS == 0 )) && grep -q SLEPT "$PM_OUT"; then ok "a zero switches the limit off and beats a finite one"; else bad "a zero beats a finite limit" "status ${PM_STATUS}: $(pm_describe)"; fi
run_pm_timed --config "$c_frac" -- "$P" sleep 30
if (( PM_STATUS == PHB_ETIMEOUT && PM_ELAPSED_MS >= 2500 && PM_ELAPSED_MS < 12000 )); then ok "a limit with milliseconds, 2.500 seconds, is kept to the millisecond (${PM_ELAPSED_MS} ms)"; else bad "a fractional limit is kept" "status ${PM_STATUS} after ${PM_ELAPSED_MS} ms"; fi
run_pm --debug --config "$c_t30" -- "$P" cwd
if grep -q "30s" "$PM_ERR"; then ok "the limit the layer applies is the one named, in GNU timeout's own spelling"; else bad "the limit the layer applies is the one named" "$(pm_describe)"; fi
run_pm --debug --config "$PM/cfg/ro.cfg" -- "$P" cwd 2>/dev/null
c_nolimit="$(cfg nolimit <<EOF2
[read]
$PM/ro
EOF2
)"
run_pm --debug --config "$c_nolimit" -- "$P" cwd
if grep -q "600s" "$PM_ERR"; then ok "with no limit named anywhere the default of 600 seconds applies"; else bad "the default timeout is 600 seconds" "$(pm_describe)"; fi
for bad_value in "abc" "-1" "1e3" "5 s" "1.5" "1.2345" ""; do
  c_bad="$(cfg_time bad timeout="$bad_value")"
  run_pm --config "$c_bad" -- "$P" cwd
  if (( PM_STATUS == PHB_EPOLICY )) && ! grep -q '^START' "$PM_OUT"; then ok "the limit value '${bad_value}' is refused as a policy error, before the command starts"; else bad "the limit value '${bad_value}' is refused" "$(pm_describe)"; fi
done

echo
echo "== a command's own statuses pass through =="
for code in 0 1 2 124 137 255; do
  run_pm --config "$c_t30" -- "$P" exitwith "$code"
  if [[ "$code" == 124 || "$code" == 137 ]]; then
    check "a command that exits ${code} by itself, long before the limit, is not relabelled as a timeout" "$code" "$PM_STATUS"
  else
    check "a command that exits ${code} is reported with ${code}" "$code" "$PM_STATUS"
  fi
done

finish
