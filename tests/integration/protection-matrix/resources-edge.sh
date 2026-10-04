#!/usr/bin/env bash
# The resource layer's edges: each limit met through the call that meets it (duplicating a descriptor, a pipe, a
# socket, a thread, a file mapping, the data segment, growing a file), with the layer switched off as the control,
# plus the limits Phobos does not set and a sleeping command that uses no processor time.
set -uo pipefail
PM_HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${PM_HERE}/lib.sh"
pm_setup || finish
trap pm_restore EXIT
PE="$PM/bin/pedge"
P="$PM/bin/pprobe"
cd "$PM/work" || exit 1
chmod 0777 "$PM/out" "$PM/rw"
echo "  landlock ABI $(pm_abi), uid ${PM_USER_ID}"

cfg_limits() {
  local name="$1"
  shift
  {
    printf '[read]\n%s\n[write]\n%s\n[create]\n%s\n[delete]\n%s\n[limits]\n' "$PM/ro" "$PM/rw" "$PM/rw" "$PM/rw"
    printf '%s\n' "$@"
  } | cfg "$name"
}
# count_of WORD: the number printed after WORD in the last run, as in "DUPS 31 of cap".
count_of() {
  sed -n "s/^$1 \\([0-9]*\\).*/\\1/p" "$PM_OUT" | head -1
}
# bounded NAME CONFIG WORD LOW HIGH ERRNO COMMAND...: under the limit the count lies in the range and ends with the
# errno; with the resource layer off it goes past HIGH.
bounded() {
  local title="$1"
  local config="$2"
  local word="$3"
  local low="$4"
  local high="$5"
  local errno_name="$6"
  shift 6
  run_pm --config "$config" -- "$@"
  local counted
  counted="$(count_of "$word")"
  if [[ -n "$counted" ]] && (( counted >= low && counted <= high )) && grep -q "errno=${errno_name}" "$PM_OUT"; then
    ok "${title}: ${counted} made, then ${errno_name}"
  else
    bad "${title}" "expected ${low} to ${high} then ${errno_name}: $(pm_describe)"
  fi
  run_pm --no-resourcesystem-restriction --config "$config" -- "$@"
  counted="$(count_of "$word")"
  if [[ -n "$counted" ]] && (( counted > high )); then
    ok "${title}: with the layer off ${counted} are made, so the layer is what stopped it"
  else
    bad "${title}: more are made with the layer off" "$(pm_describe)"
  fi
}

echo
echo "== open descriptors, met three ways =="
c_nofile="$(cfg_limits nofile40 nofile=40)"
bounded "duplicating a descriptor under nofile=40" "$c_nofile" DUPS 25 40 EMFILE "$PE" dup_until
bounded "making pipes under nofile=40" "$c_nofile" PIPES 10 20 EMFILE "$PE" pipe_until
bounded "making sockets under nofile=40" "$c_nofile" SOCKETS 25 40 EMFILE "$PE" socket_until
c_nofile_big="$(cfg_limits nofile200 nofile=200)"
bounded "duplicating a descriptor under nofile=200" "$c_nofile_big" DUPS 150 200 EMFILE "$PE" dup_until
run_pm --config "$c_nofile" -- /bin/sh -c "$PE dup_until"
if grep -q 'errno=EMFILE' "$PM_OUT"; then ok "a child process meets the same open-file limit"; else bad "a child process meets the same open-file limit" "$(pm_describe)"; fi

echo
echo "== threads, for a user the kernel counts them against =="
if id nobody > /dev/null 2>&1 && command -v setpriv > /dev/null; then
  as_nobody() {
    PM_OUT="$PM/out/last.out"
    PM_ERR="$PM/out/last.err"
    timeout --kill-after=5 "$WATCHDOG_SECONDS" setpriv --reuid=65534 --regid=65534 --clear-groups \
      phobos.sh --tail-flags-file "$PM/tail.flags" "$@" > "$PM_OUT" 2> "$PM_ERR" < /dev/null
    PM_STATUS=$?
  }
  c_threads="$(cfg_limits threads60 nproc=60)"
  as_nobody --config "$c_threads" -- "$PE" threads_until
  counted="$(count_of THREADS)"
  if [[ -n "$counted" ]] && (( counted >= 20 && counted <= 60 )) && grep -q 'errno=EAGAIN' "$PM_OUT"; then ok "threads under nproc=60: ${counted} made, then EAGAIN"; else bad "threads under nproc=60" "$(pm_describe)"; fi
  as_nobody --no-resourcesystem-restriction --config "$c_threads" -- "$PE" threads_until
  counted="$(count_of THREADS)"
  if [[ -n "$counted" ]] && (( counted > 60 )); then ok "with the layer off the same user makes ${counted} threads"; else bad "more threads with the layer off" "$(pm_describe)"; fi
else
  skip "threads under nproc" "no unprivileged user or setpriv in the image"
fi

echo
echo "== address space, met by a file mapping and by the data segment =="
dd if=/dev/zero of="$PM/ro/big.bin" bs=1048576 count=600 2> /dev/null
c_mem="$(cfg_limits mem300 mem_mb=300)"
run_pm --config "$c_mem" -- "$PE" mmap_file "$PM/ro/big.bin" 500
if op_failed_with mmap_file ENOMEM; then ok "mapping a 500 MiB file under mem_mb=300 fails with ENOMEM"; else bad "mapping a 500 MiB file under mem_mb=300 fails" "$(pm_describe)"; fi
run_pm --config "$c_mem" -- "$PE" mmap_file "$PM/ro/big.bin" 50
if op_ok mmap_file; then ok "and mapping 50 MiB works"; else bad "mapping 50 MiB under mem_mb=300 works" "$(pm_describe)"; fi
run_pm --no-resourcesystem-restriction --config "$c_mem" -- "$PE" mmap_file "$PM/ro/big.bin" 500
if op_ok mmap_file; then ok "and mapping 500 MiB works with the layer off"; else bad "mapping 500 MiB works with the layer off" "$(pm_describe)"; fi
run_pm --config "$c_mem" -- "$PE" brk_grow 500
if op_failed_with brk ENOMEM; then ok "growing the data segment by 500 MiB fails with ENOMEM"; else bad "growing the data segment by 500 MiB fails" "$(pm_describe)"; fi
run_pm --config "$c_mem" -- "$PE" brk_grow 20
if op_ok brk; then ok "and growing it by 20 MiB works"; else bad "growing the data segment by 20 MiB works" "$(pm_describe)"; fi
run_pm --no-resourcesystem-restriction --config "$c_mem" -- "$PE" brk_grow 500
if op_ok brk; then ok "and growing it by 500 MiB works with the layer off"; else bad "growing the data segment by 500 MiB works with the layer off" "$(pm_describe)"; fi

echo
echo "== the size of one file, met by growing it =="
c_fsize="$(cfg_limits fsize2 fsize_mb=2)"
rm -f "$PM/rw/grow"
run_pm --config "$c_fsize" -- "$PE" ftruncate_size "$PM/rw/grow" 6
if (( PM_STATUS == 153 )); then ok "growing a file to 6 MiB under fsize_mb=2 ends the command with SIGXFSZ"; else bad "growing a file past the limit ends the command" "$(pm_describe)"; fi
run_pm --config "$c_fsize" -- "$PE" ftruncate_size "$PM/rw/grow" 6 ignore
if op_failed_with ftruncate_size EFBIG; then ok "and with the signal ignored the call fails with EFBIG"; else bad "growing past the limit with the signal ignored fails with EFBIG" "$(pm_describe)"; fi
run_pm --config "$c_fsize" -- "$PE" ftruncate_size "$PM/rw/grow" 1
if op_ok ftruncate_size; then ok "growing it to 1 MiB works"; else bad "growing a file to 1 MiB works" "$(pm_describe)"; fi
run_pm --config "$c_fsize" -- "$PE" ftruncate_size "$PM/rw/grow" 2
if op_ok ftruncate_size; then ok "and to exactly the limit"; else bad "growing a file to exactly the limit works" "$(pm_describe)"; fi
rm -f "$PM/rw/grow"
run_pm --config "$c_fsize" -- "$PE" fallocate "$PM/rw/grow" 6
if op_failed_with fallocate EFBIG; then ok "reserving 6 MiB with fallocate fails with EFBIG"; else bad "fallocate past the limit fails with EFBIG" "$(pm_describe)"; fi
rm -f "$PM/rw/grow"
run_pm --no-resourcesystem-restriction --config "$c_fsize" -- "$PE" fallocate "$PM/rw/grow" 6
if op_ok fallocate; then ok "and works with the layer off"; else bad "fallocate works with the layer off" "$(pm_describe)"; fi
rm -f "$PM/rw/grow"

echo
echo "== processor time that is not used =="
c_cpu="$(cfg_limits cpu1 cpu=1)"
run_pm --config "$c_cpu" -- "$P" sleep 4
if (( PM_STATUS == 0 )) && grep -q SLEPT "$PM_OUT"; then ok "a command that sleeps four seconds under cpu=1 is not ended, since sleeping uses no processor time"; else bad "a sleeping command under cpu=1 is not ended" "$(pm_describe)"; fi

echo
echo "== limits Phobos does not set =="
run_direct "$PE" getrlimit_all
direct_all="$(grep '^RLIMIT' "$PM_OUT")"
run_pm --config "$c_cpu" -- "$PE" getrlimit_all
protected_all="$(grep '^RLIMIT' "$PM_OUT")"
for resource in core data stack memlock sigpending msgqueue locks nice rtprio; do
  direct_line="$(grep "^RLIMIT ${resource} " <<< "$direct_all")"
  protected_line="$(grep "^RLIMIT ${resource} " <<< "$protected_all")"
  if [[ -n "$direct_line" && "$direct_line" == "$protected_line" ]]; then
    ok "GAP: the ${resource} limit is the container's own, Phobos sets none (${protected_line#RLIMIT ${resource} })"
  else
    bad "the ${resource} limit is the container's own" "direct [${direct_line}] protected [${protected_line}]"
  fi
done

finish
