#!/usr/bin/env bash
# The resource layer through phobos.sh: each limit is set as the policy says, read back from the kernel,
# enforced on a bounded behaviour, inherited, not raisable, merged, defaulted and validated, and the helpers
# Phobos runs beside the command are not held to them.
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
chmod 0777 "$PM/rw" "$PM/out"
CORES="$(nproc)"

# A policy that grants writing in rw and names the limits given.
cfg_limits() {
  local name="$1"
  shift
  {
    printf '[read]\n%s\n[write]\n%s\n[create]\n%s\n[delete]\n%s\n[limits]\n' "$PM/ro" "$PM/rw" "$PM/rw" "$PM/rw"
    printf '%s\n' "$@"
  } | cfg "$name"
}
# The soft and hard value the last run's probe read back for a resource, as "soft hard".
rlimit() {
  sed -n "s/^RLIMIT $1 soft=\\([0-9]*\\) hard=\\([0-9]*\\)/\\1 \\2/p" "$PM_OUT" | head -1
}
# limit_is TITLE EXPECTED RESOURCE [PHOBOS ARGS...]: runs the read-back through phobos.sh in this shell, so the
# later checks can read the same output, and compares "soft hard" of one resource.
limit_is() {
  local title="$1"
  local expected="$2"
  local resource="$3"
  shift 3
  run_pm "$@" -- "$P" getrlimit
  check "$title" "$expected" "$(rlimit "$resource")"
}
MB=$((1024 * 1024))

echo
echo "== each limit is set, soft and hard, as named =="
c_n64="$(cfg_limits n64 nofile=64)"
limit_is "nofile=64 sets both the soft and the hard limit to 64" "64 64" nofile --config "$c_n64"
c_m300="$(cfg_limits m300 mem_mb=300)"
limit_is "mem_mb=300 sets the address space to 300 MiB, soft and hard" "$((300 * MB)) $((300 * MB))" as --config "$c_m300"
c_f2="$(cfg_limits f2 fsize_mb=2)"
limit_is "fsize_mb=2 sets the largest file to 2 MiB, soft and hard" "$((2 * MB)) $((2 * MB))" fsize --config "$c_f2"
c_c2="$(cfg_limits c2 cpu=2)"
limit_is "cpu=2 sets the processor time to 2 seconds, soft and hard" "2 2" cpu --config "$c_c2"
c_p50="$(cfg_limits p50 nproc=50)"
limit_is "nproc=50 sets the process count to 50, soft and hard" "50 50" nproc --config "$c_p50"
c_nolimits="$(cfg_limits nolimits)"
limit_is "with no limit named anywhere the default of 1024 open files applies" "1024 1024" nofile --config "$c_nolimits"
check "and 8192 MiB of address space" "$((8192 * MB)) $((8192 * MB))" "$(rlimit as)"
check "and 600 seconds of processor time" "600 600" "$(rlimit cpu)"
check "and 256 processes" "256 256" "$(rlimit nproc)"
check "and 256 MiB for one file" "$((256 * MB)) $((256 * MB))" "$(rlimit fsize)"
c_n128="$(cfg_limits n128 nofile=128)"
run_pm --config "$c_n64" --config "$c_n128" -- "$P" getrlimit
check "of two configurations the larger value wins" "128 128" "$(rlimit nofile)"
run_pm --config "$c_n128" --config "$c_n64" -- "$P" getrlimit
check "in either order" "128 128" "$(rlimit nofile)"
c_n0="$(cfg_limits n0 nofile=0)"
run_pm --config "$c_n64" --config "$c_n0" -- "$P" getrlimit
check "a zero switches the limit off and beats a finite one: the container's own limit stays" "$(ulimit -Sn) $(ulimit -Hn)" "$(rlimit nofile)"
c_m0="$(cfg_limits m0 mem_mb=0)"
limit_is "mem_mb=0 leaves the address space unlimited" "0 0" as --config "$c_m0"
run_pm --no-resourcesystem-restriction --config "$c_n64" -- "$P" getrlimit
check "with the resource layer off no limit is set" "$(ulimit -Sn) $(ulimit -Hn)" "$(rlimit nofile)"
check "and no limit is set on the address space either" "0 0" "$(rlimit as)"

echo
echo "== a limit is enforced on a bounded behaviour =="
check_files() {
  run_pm --config "$c_n64" -- "$P" openfiles 200
  grep -q "OPENED [0-9]* of 200 errno=EMFILE" "$PM_OUT"
}
if check_files; then ok "opening 200 files under nofile=64 stops with EMFILE before 200"; else bad "opening 200 files under nofile=64 stops with EMFILE" "$(pm_describe)"; fi
run_pm --config "$c_n128" -- "$P" openfiles 100
if grep -q "OPENED 100 of 100" "$PM_OUT"; then ok "and 100 files open fine under nofile=128"; else bad "100 files open under nofile=128" "$(pm_describe)"; fi
run_direct "$P" alloc 800
if op_ok mmap; then
  run_pm --config "$c_m300" -- "$P" alloc 800
  if op_failed_with mmap ENOMEM; then ok "800 MiB of address space cannot be mapped under mem_mb=300"; else bad "800 MiB cannot be mapped under mem_mb=300" "$(pm_describe)"; fi
  run_pm --config "$c_m300" -- "$P" alloc 100
  if op_ok mmap; then ok "and 100 MiB can"; else bad "100 MiB can be mapped under mem_mb=300" "$(pm_describe)"; fi
  run_pm --no-resourcesystem-restriction --config "$c_m300" -- "$P" alloc 800
  if op_ok mmap; then ok "and 800 MiB can with the resource layer off, so the layer is what refused it"; else bad "800 MiB can be mapped with the layer off" "$(pm_describe)"; fi
else
  skip "mem_mb behaviour" "the unprotected control could not map 800 MiB"
fi
rm -f "$PM/rw/big" "$PM/rw/big2"
run_pm --config "$c_f2" -- "$P" writebig "$PM/rw/big" 6
if grep -q "WROTE 2 of 6 MB errno=EFBIG" "$PM_OUT" || grep -q "WROTE 1 of 6 MB errno=EFBIG" "$PM_OUT"; then ok "a file larger than fsize_mb allows is cut at the limit with EFBIG"; else bad "a file is cut at fsize_mb" "$(pm_describe)"; fi
rm -f "$PM/rw/big"
run_pm --config "$c_f2" -- /bin/sh -c "$P writebig $PM/rw/big 2; $P writebig $PM/rw/big2 2"
if [[ "$(grep -c 'WROTE 2 of 2 MB' "$PM_OUT")" == 2 ]]; then ok "the limit is per file: two files of exactly the limit are both written"; else bad "the limit is per file" "$(pm_describe)"; fi
rm -f "$PM/rw/big" "$PM/rw/big2"
run_pm --no-resourcesystem-restriction --config "$c_f2" -- "$P" writebig "$PM/rw/big" 6
if grep -q "WROTE 6 of 6 MB" "$PM_OUT"; then ok "and with the resource layer off the 6 MiB file is written whole"; else bad "the 6 MiB file is written whole with the layer off" "$(pm_describe)"; fi
rm -f "$PM/rw/big"
started="$(now_ms)"
run_pm --config "$c_c2" -- "$P" spin 100
elapsed=$(( $(now_ms) - started ))
if (( PM_STATUS == 137 )) && grep -q "^START" "$PM_OUT" && ! grep -q SPUN "$PM_OUT" && (( elapsed < 80000 )); then ok "a command that burns more processor time than cpu allows is ended by the kernel (SIGKILL at the hard limit) long before its 100 seconds are up (status ${PM_STATUS}, ${elapsed} ms)"; else bad "a busy command is ended at the cpu limit" "status ${PM_STATUS}, ${elapsed} ms: $(pm_describe)"; fi
run_pm --no-resourcesystem-restriction --config "$c_c2" -- "$P" spin 3
if (( PM_STATUS == 0 )) && grep -q SPUN "$PM_OUT"; then ok "and with the layer off it runs to its end"; else bad "a busy command runs to its end with the layer off" "$(pm_describe)"; fi
if (( CORES >= 4 )); then
  c_c3="$(cfg_limits c3 cpu=3)"
  started="$(now_ms)"
  run_pm --config "$c_c3" -- "$P" spin_threads 4 100
  elapsed=$(( $(now_ms) - started ))
  if (( PM_STATUS == 137 )) && grep -q "^START" "$PM_OUT" && ! grep -q SPUN "$PM_OUT" && (( elapsed < 80000 )); then ok "a command with four busy threads is ended by the kernel (SIGKILL at the hard limit) long before its 100 seconds are up (${elapsed} ms)"; else bad "a threaded busy command is ended at the processor limit" "status ${PM_STATUS}, ${elapsed} ms: $(pm_describe)"; fi
else
  skip "cpu time across threads" "needs four processor cores, this container has ${CORES}"
fi

echo
echo "== the process count, as an unprivileged user (the kernel does not apply it to root) =="
if id nobody > /dev/null 2>&1 && command -v setpriv > /dev/null; then
  as_nobody() {
    PM_OUT="$PM/out/last.out"
    PM_ERR="$PM/out/last.err"
    timeout --kill-after=5 "$WATCHDOG_SECONDS" setpriv --reuid=65534 --regid=65534 --clear-groups \
      phobos.sh --tail-flags-file "$PM/tail.flags" "$@" > "$PM_OUT" 2> "$PM_ERR" < /dev/null
    PM_STATUS=$?
  }
  c_p80="$(cfg_limits p80 nproc=80)"
  as_nobody --config "$c_p80" -- "$P" fork_n 300
  if grep -q "FORKED [0-9]* of 300 errno=EAGAIN" "$PM_OUT"; then ok "forking more than nproc allows stops with EAGAIN"; else bad "forking more than nproc allows stops with EAGAIN" "$(pm_describe)"; fi
  as_nobody --config "$c_p80" -- "$P" getrlimit
  check "the limit the kernel holds for that user is the 80 the policy named" "80 80" "$(rlimit nproc)"
  as_nobody --no-resourcesystem-restriction --config "$c_p80" -- "$P" fork_n 300
  if grep -q "FORKED 300 of 300" "$PM_OUT"; then ok "and the same 300 forks all work with the resource layer off, so the layer is what stopped them"; else bad "the same 300 forks work with the layer off" "$(pm_describe)"; fi
else
  skip "the process count" "no unprivileged user or setpriv in the image"
fi

echo
echo "== limits are inherited =="
run_pm --config "$c_n64" -- /bin/sh -c "$P getrlimit"
check "a child process has the limits too" "64 64" "$(rlimit nofile)"
run_pm --config "$c_n64" -- /bin/sh -c "/bin/sh -c \"$P getrlimit\""
check "and a grandchild" "64 64" "$(rlimit nofile)"
run_pm --config "$c_n64" -- /bin/sh -c "ulimit -n 10; $P getrlimit"
check "a command may lower a limit for its children, and the lowered value holds" "10 10" "$(rlimit nofile)"

echo
echo "== what a limit does not do, asserted as it is today =="
run_pm --config "$c_m300" -- /bin/sh -c "$P alloc 200 & $P alloc 200 & wait"
gap_case "the address space limit is per process: two processes of 200 MiB each map their memory under mem_mb=300" "phobos-resourcesystem.sh --help" "$(holds_if test "$(grep -c 'OP mmap ret=0' "$PM_OUT")" = 2)"

echo
echo "== the supervisor around the command is not held to its limits, and the limit holds the command's own files =="
c_tight="$(cfg_limits tight nofile=16 fsize_mb=1)"
# Standard error through a pipe: the file-size limit counts files, so three megabytes pass whole, and the
# supervisor, which writes there as well and is started before the limits are set, is not cut short.
run_pm_stderr_through_pipe() {
  PM_OUT="$PM/out/last.out"
  PM_ERR="$PM/out/last.err"
  { timeout --kill-after=5 "$WATCHDOG_SECONDS" phobos.sh --tail-flags-file "$PM/tail.flags" "$@" > "$PM_OUT" < /dev/null; } 2>&1 | cat > "$PM_ERR"
  PM_STATUS=${PIPESTATUS[0]}
}
run_direct "$P" emit e 3145728
direct_sum="$(tail -c 3145729 "$PM_ERR" | cksum)"
run_pm_stderr_through_pipe --config "$c_tight" -- "$P" emit e 3145728
if [[ "$(tail -c 3145729 "$PM_ERR" | cksum)" == "$direct_sum" && "$(wc -c < "$PM_ERR" | tr -d ' ')" -ge 3145729 ]]; then ok "three megabytes and a newline written to a pipe on standard error arrive whole under a one megabyte file limit"; else bad "standard error through a pipe arrives whole under a tight file limit" "$(wc -c < "$PM_ERR") bytes arrived"; fi
if grep -q 'Phobos Security Summary' "$PM_ERR"; then bad "nothing was blocked, so no summary" "a summary appeared although nothing was denied"; else ok "and nothing is summarised for a run in which nothing was blocked"; fi
run_pm --config "$c_tight" -- "$P" emit e 3145728
if (( PM_STATUS == 153 )) && [[ "$(wc -c < "$PM_ERR" | tr -d ' ')" -lt 3145729 ]] \
  && grep -qxF 'Phobos Security Error: the program tried to illegally exceed the File Size Limit of 1 MB but was blocked by Phobos.' "$PM_ERR"; then
  ok "the same three megabytes written into a file are cut at the limit, the command ends with SIGXFSZ (153) and the limit is worded"
else
  bad "a file on standard error is held to the file-size limit" "status ${PM_STATUS}, $(wc -c < "$PM_ERR" | tr -d ' ') bytes: $(pm_describe | cut -c1-300)"
fi
run_pm --config "$c_tight" -- "$P" emit o 100000
check "output on standard output below the file limit arrives whole" "100001" "$(grep -v '^START$' "$PM_OUT" | wc -c | tr -d ' ')"
if (( PM_STATUS == 0 )); then ok "and the run ends with the command's own status"; else bad "the run ends with the command's own status" "status $PM_STATUS"; fi

echo
echo "== limit values are validated =="
for value in "nofile=abc" "nofile=-1" "nofile=" "nofile=1.5" "mem_mb=99999999999999999999" "nproc=0x10" "bogus=1" "timeout=oops"; do
  c_bad="$(cfg_limits bad "$value")"
  run_pm --config "$c_bad" -- "$P" cwd
  if (( PM_STATUS == PHB_EPOLICY )) && ! grep -q '^START' "$PM_OUT"; then ok "the limit line '${value}' is refused as a policy error, before the command starts"; else bad "the limit line '${value}' is refused" "$(pm_describe)"; fi
done

c_split="$(cfg_limits split "cpu=5 5")"
run_pm --config "$c_split" -- "$P" cwd
if (( PM_STATUS == PHB_EPOLICY )) && ! grep -q '^START' "$PM_OUT"; then ok "a limit value with a space inside it is refused, not read as the digits run together"; else bad "a limit value with a space inside it is refused" "$(pm_describe)"; fi

finish
