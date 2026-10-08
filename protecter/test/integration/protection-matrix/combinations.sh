#!/usr/bin/env bash
# The four layers together through phobos.sh. One run per subset of switched-off layers (all sixteen) carries a
# witness for every layer, so each layer must hold exactly when it is on, whatever the others do. Then the flag
# spellings and their order, --no-restriction against all four layers off, nested runs and concurrent runs.
set -uo pipefail
PM_HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${PM_HERE}/lib.sh"
pm_setup || finish
PM_ABI="$(pm_abi)"
P="$PM/bin/pprobe"
SERVER_ALLOWED=39500
SERVER_FORBIDDEN=39501
pids=()
cleanup() {
  local pid
  for pid in "${pids[@]}"; do
    reap "$pid"
  done
  pm_restore
}
trap cleanup EXIT
cd "$PM/work" || exit 1
chmod 0777 "$PM/rw" "$PM/out"
echo "  landlock ABI ${PM_ABI}"

srv_allowed="$(start_tcp_server 127.0.0.1 "$SERVER_ALLOWED" 500 900)"
pids+=("$srv_allowed")
require_started "the allowed TCP server" "$srv_allowed"
srv_forbidden="$(start_tcp_server 127.0.0.1 "$SERVER_FORBIDDEN" 500 900)"
pids+=("$srv_forbidden")
require_started "the forbidden TCP server" "$srv_forbidden"

c_all="$(cfg all <<EOF2
[read]
$PM/ro
[connect]
allow 127.0.0.1:$SERVER_ALLOWED
[limits]
timeout=3
nofile=32
EOF2
)"
WITNESSES="echo W=fs; $P read $PM/none/secret.txt; echo W=fsallow; $P read $PM/ro/data.txt; echo W=net; $P tcp 127.0.0.1 $SERVER_FORBIDDEN; echo W=netallow; $P tcp 127.0.0.1 $SERVER_ALLOWED; echo W=res; $P getrlimit; echo W=time; $P sleep 6"

# The part of the last run's output that belongs to one witness.
section() {
  sed -n "/^W=$1\$/,/^W=/p" "$PM_OUT" | sed '/^W=/d'
}
# Whether an operation named in a witness's section succeeded, 0 yes, 1 no, 2 absent.
section_op() {
  local line
  line="$(section "$1" | sed -n "s/^OP $2 ret=\\(-\\{0,1\\}[0-9]*\\) errno=\\([A-Za-z0-9]*\\).*/\\1 \\2/p" | head -1)"
  [[ -n "$line" ]] || return 2
  (( ${line%% *} >= 0 ))
}
# The errno of that operation, or nothing.
section_errno() {
  section "$1" | sed -n "s/^OP $2 ret=-\\{0,1\\}[0-9]* errno=\\([A-Za-z0-9]*\\).*/\\1/p" | head -1
}
# The soft nofile limit the res witness read back.
section_nofile() {
  section res | sed -n 's/^RLIMIT nofile soft=\([0-9]*\) .*/\1/p'
}

# subset_case OFF-LIST: runs the witnesses with those layers off ("none" for no layer) and judges all four layers.
subset_case() {
  local off="$1"
  local flags=""
  [[ "$off" == "none" ]] || flags="$(layer_flag "$off")"
  local on_fs=1
  local on_net=1
  local on_time=1
  local on_res=1
  local layer
  for layer in ${off//,/ }; do
    case "$layer" in
      fs) on_fs=0 ;;
      net) on_net=0 ;;
      time) on_time=0 ;;
      res) on_res=0 ;;
    esac
  done
  local label="layers off: ${off}"
  local started
  started="$(now_ms)"
  # The flags are a space-separated list of options, none of which holds a space, so they must split into words.
  # shellcheck disable=SC2086
  run_pm $flags --config "$c_all" -- /bin/sh -c "$WITNESSES"
  local elapsed=$(( $(now_ms) - started ))
  local problems=""
  if (( on_fs )); then
    section_op fs open; [[ $? == 1 && "$(section_errno fs open)" =~ ^(EACCES|EPERM)$ ]] || problems="${problems} fs-witness-not-denied"
  else
    section_op fs open || problems="${problems} fs-witness-denied-with-layer-off"
  fi
  section_op fsallow open || problems="${problems} fs-allowed-read-broken"
  if (( on_net )); then
    section_op net connect; [[ $? == 1 && "$(section_errno net connect)" =~ ^(EACCES|EPERM)$ ]] || problems="${problems} net-witness-not-denied"
  else
    section_op net connect || problems="${problems} net-witness-denied-with-layer-off"
  fi
  section_op netallow connect || problems="${problems} net-allowed-connect-broken"
  if (( on_res )); then
    [[ "$(section_nofile)" == 32 ]] || problems="${problems} res-limit-missing(nofile=$(section_nofile))"
  else
    [[ "$(section_nofile)" != 32 && -n "$(section_nofile)" ]] || problems="${problems} res-limit-applied-with-layer-off"
  fi
  if (( on_time )); then
    (( PM_STATUS == PHB_ETIMEOUT )) && ! grep -q '^SLEPT' "$PM_OUT" || problems="${problems} time-not-enforced(status=${PM_STATUS},${elapsed}ms)"
  else
    (( PM_STATUS == 0 )) && grep -q '^SLEPT' "$PM_OUT" || problems="${problems} time-enforced-with-layer-off(status=${PM_STATUS})"
  fi
  if [[ -z "$problems" ]]; then
    ok "${label}: every layer holds exactly when it is on (${elapsed} ms)"
  else
    bad "${label}" "${problems# } :: $(pm_describe)"
  fi
}

echo
echo "== every subset of switched-off layers, one witness per layer =="
subset_case none
for off in fs net time res fs,net fs,time fs,res net,time net,res time,res fs,net,time fs,net,res fs,time,res net,time,res fs,net,time,res; do
  subset_case "$off"
done

echo
echo "== the unrestricted switch against all four layers off =="
run_pm --no-restriction -- /bin/sh -c "$WITNESSES"
if section_op fs open && section_op net connect && [[ "$(section_nofile)" =~ ^[0-9]+$ && "$(section_nofile)" != 32 ]] && (( PM_STATUS == 0 )) && grep -q '^SLEPT' "$PM_OUT"; then ok "--no-restriction without a policy runs the command with no layer at all"; else bad "--no-restriction runs with no layer" "$(pm_describe)"; fi
run_pm --no-restriction --config "$c_all" -- "$P" cwd
if (( PM_STATUS != 0 )) && ! grep -q '^START' "$PM_OUT" && grep -q 'Did you mean -nrr' "$PM_ERR"; then ok "--no-restriction with a policy is refused and names the flag that was probably meant, rather than running the policy unconfined"; else bad "--no-restriction with a policy is refused" "$(pm_describe)"; fi
run_pm -nfr -nnr -ntr -nrr --config "$c_all" -- /bin/sh -c "$WITNESSES"
if section_op fs open && section_op net connect && [[ "$(section_nofile)" =~ ^[0-9]+$ && "$(section_nofile)" != 32 ]] && (( PM_STATUS == 0 )) && grep -q '^SLEPT' "$PM_OUT"; then ok "all four layer switches together with a policy give the same unrestricted run, and the policy is accepted"; else bad "all four switches together" "$(pm_describe)"; fi
run_pm -nfr -nnr -ntr -nrr --config "$PM/cfg/does-not-exist.cfg" -- "$P" cwd
if (( PM_STATUS == PHB_EPOLICY )); then ok "even with every layer off a policy that cannot be read is refused, so a typo in --config is not hidden"; else bad "an unreadable policy is refused with every layer off" "$(pm_describe)"; fi
printf '[bogus]\nx\n' > "$PM/cfg/bad-section.cfg"
run_pm -nfr -nnr -ntr -nrr --config "$PM/cfg/bad-section.cfg" -- "$P" cwd
if (( PM_STATUS == PHB_EPOLICY )); then ok "and a policy with an unknown section is refused with every layer off, since validation does not depend on enforcement"; else bad "an invalid policy is refused with every layer off" "$(pm_describe)"; fi

echo
echo "== flag spellings, order and repetition =="
for pair in "-nfr:fs" "--no-filesystem-restriction:fs" "-nnr:net" "--no-networksystem-restriction:net" "-ntr:time" "--no-timeoutsystem-restriction:time" "-nrr:res" "--no-resourcesystem-restriction:res"; do
  flag="${pair%%:*}"
  layer="${pair##*:}"
  run_pm "$flag" --config "$c_all" -- /bin/sh -c "$WITNESSES"
  case "$layer" in
    fs) if section_op fs open; then ok "${flag} switches the filesystem layer off"; else bad "${flag} switches the filesystem layer off" "$(pm_describe)"; fi ;;
    net) if section_op net connect; then ok "${flag} switches the network layer off"; else bad "${flag} switches the network layer off" "$(pm_describe)"; fi ;;
    time) if (( PM_STATUS == 0 )) && grep -q '^SLEPT' "$PM_OUT"; then ok "${flag} switches the timeout layer off"; else bad "${flag} switches the timeout layer off" "$(pm_describe)"; fi ;;
    res) if [[ "$(section_nofile)" =~ ^[0-9]+$ && "$(section_nofile)" != 32 ]]; then ok "${flag} switches the resource layer off"; else bad "${flag} switches the resource layer off" "$(pm_describe)"; fi ;;
  esac
done
run_pm --config "$c_all" -nfr -- /bin/sh -c "$WITNESSES"
if section_op fs open; then ok "a layer switch after --config counts as much as one before it"; else bad "a switch after --config counts" "$(pm_describe)"; fi
run_pm -nfr -nfr -nfr --config "$c_all" -- /bin/sh -c "$WITNESSES"
if section_op fs open && ! section_op net connect; then ok "repeating a switch changes nothing else: the other layers stay on"; else bad "repeating a switch" "$(pm_describe)"; fi
run_pm --config "$c_all" -- "$P" argv -nfr --no-restriction
if grep -q '^ARG\[0\]=<-nfr>' "$PM_OUT" && grep -q '^ARG\[1\]=<--no-restriction>' "$PM_OUT"; then ok "a switch written after the command is the command's own argument and switches nothing off"; else bad "a switch after the command is an argument" "$(pm_describe)"; fi
run_pm --config "$c_all" "$P" read "$PM/none/secret.txt"
if op_failed_with open $DENIED_ERRNOS; then ok "the command may follow the policy without a double dash and is just as confined"; else bad "a command without a double dash is confined" "$(pm_describe)"; fi
run_pm --config "$c_all" -nnn -- "$P" cwd
if (( PM_STATUS != 0 )) && ! grep -q '^START' "$PM_OUT"; then ok "a mistyped switch is refused rather than run as part of the command"; else bad "a mistyped switch is refused" "$(pm_describe)"; fi

echo
echo "== the environment cannot switch a layer off or swap an enforcer =="
hostile=(
  PHB_ENABLE_FILESYSTEM=0
  PHB_ENABLE_NETWORK=0
  PHB_ENABLE_TIMEOUT=0
  PHB_ENABLE_RESOURCES=0
  PHB_NO_LANDLOCK=1
  PHB_DEBUG_ENABLED=1
  PHB_LANDLOCK_BIN=/bin/true
  PHB_TIMEOUT_BIN=/bin/true
  PHB_CONNECT_GUARD_BIN=/bin/true
  PHB_PGROUP_LOCK_BIN=/bin/true
  PHB_HAPROXY_BIN=/bin/true
  PHB_TAIL_FLAGS_FILE=/dev/null
  PHB_SPEC_DIR=/tmp
  LANDLOCK_BIN=/bin/true
  TIMEOUT_BIN=/bin/true
  CONNECT_GUARD_BIN=/bin/true
  PHOBOS_HOME=/nonexistent
  PHOBOS_SCRATCH=/tmp
)
run_pm_env() {
  PM_OUT="$PM/out/last.out"
  PM_ERR="$PM/out/last.err"
  started="$(now_ms)"
  env "${hostile[@]}" timeout --kill-after=5 "$WATCHDOG_SECONDS" phobos.sh --tail-flags-file "$PM/tail.flags" --config "$c_all" -- /bin/sh -c "$WITNESSES" > "$PM_OUT" 2> "$PM_ERR" < /dev/null
  PM_STATUS=$?
  elapsed=$(( $(now_ms) - started ))
}
run_pm_env
hostile_problems=""
section_op fs open; [[ $? == 1 ]] || hostile_problems="${hostile_problems} fs-not-denied"
section_op net connect; [[ $? == 1 ]] || hostile_problems="${hostile_problems} net-not-denied"
section_op fsallow open || hostile_problems="${hostile_problems} allowed-read-broken"
[[ "$(section_nofile)" == 32 ]] || hostile_problems="${hostile_problems} limit-missing"
(( PM_STATUS == PHB_ETIMEOUT )) && ! grep -q '^SLEPT' "$PM_OUT" || hostile_problems="${hostile_problems} timeout-not-enforced(status=${PM_STATUS})"
grep -q '^\[phobos\]' "$PM_ERR" && hostile_problems="${hostile_problems} debug-switched-on"
if [[ -z "$hostile_problems" ]]; then ok "eighteen environment variables that name a layer switch, an enforcer binary or a path change nothing: every layer still holds"; else bad "the environment cannot weaken a run" "${hostile_problems# } :: $(pm_describe)"; fi

echo
echo "== runs at the same time do not disturb each other =="
burst=()
for index in 1 2 3; do
  extra=""
  if (( index == 2 )); then
    extra="-nfr"
  fi
  (
    # The switch is empty or one option without a space, so it must split into zero or one word.
    # shellcheck disable=SC2086
    timeout --kill-after=5 "$WATCHDOG_SECONDS" phobos.sh --tail-flags-file "$PM/tail.flags" $extra --config "$c_all" -- /bin/sh -c "$WITNESSES" > "$PM/out/conc-$index.out" 2> "$PM/out/conc-$index.err" < /dev/null
    echo $? > "$PM/out/conc-$index.status"
  ) &
  burst+=("$!")
done
wait "${burst[@]}"
concurrent_problems=""
for index in 1 2 3; do
  PM_OUT="$PM/out/conc-$index.out"
  PM_ERR="$PM/out/conc-$index.err"
  PM_STATUS="$(cat "$PM/out/conc-$index.status")"
  if (( index == 2 )); then
    section_op fs open || concurrent_problems="${concurrent_problems} run2-fs-should-be-open"
  else
    section_op fs open; [[ $? == 1 ]] || concurrent_problems="${concurrent_problems} run${index}-fs-should-be-denied"
  fi
  section_op net connect; [[ $? == 1 ]] || concurrent_problems="${concurrent_problems} run${index}-net-should-be-denied"
  (( PM_STATUS == PHB_ETIMEOUT )) || concurrent_problems="${concurrent_problems} run${index}-status=${PM_STATUS}"
done
if [[ -z "$concurrent_problems" ]]; then ok "three runs at once, one with the filesystem layer off, each get exactly their own policy"; else bad "concurrent runs keep their own policy" "${concurrent_problems# }"; fi

echo
echo "== a sandboxed run cannot widen itself by running phobos.sh inside =="
mkdir -p "$PM/inner-spec"
c_inner="$(cfg inner <<EOF2
[read]
$PM/ro
$PM/none
[limits]
timeout=0
EOF2
)"
c_outer_home="$(cfg outerhome <<EOF2
[read]
$PM/ro
$PM/cfg
$PM/tail.flags
${PHOBOS_HOME}
/var/tmp/opt
$PM/inner-spec
[execute]
${PHOBOS_HOME}
/var/tmp/opt
[write]
$PM/inner-spec
[create]
$PM/inner-spec
[delete]
$PM/inner-spec
[limits]
timeout=0
EOF2
)"
inner_run() {
  run_pm --config "$c_outer_home" -- phobos.sh -nnr --spec-parent "$PM/inner-spec" --tail-flags-file "$PM/tail.flags" --config "$c_inner" -- "$@"
}
inner_run "$P" read "$PM/ro/data.txt"
if (( PM_STATUS == 0 )) && grep -q '^START' "$PM_OUT" && op_ok open && grep -q 'CONTENT READ-OK' "$PM_OUT"; then ok "an inner phobos.sh starts inside the outer sandbox and its command reads what both policies grant"; else bad "an inner phobos.sh starts and reads what both grant" "$(pm_describe)"; fi
inner_run "$P" read "$PM/none/secret.txt"
if grep -q '^START' "$PM_OUT" && op_failed_with open $DENIED_ERRNOS && ! grep -q 'TOP-SECRET' "$PM_OUT" "$PM_ERR"; then ok "and the same inner command is refused the hidden file although its own, wider policy names it"; else bad "an inner policy cannot widen the outer sandbox" "$(pm_describe)"; fi
run_pm --config "$c_outer_home" -- phobos.sh --spec-parent "$PM/inner-spec" --tail-flags-file "$PM/tail.flags" --config "$c_inner" -- "$P" cwd
gap_case "an inner phobos.sh with its network layer on is refused, because one process tree can have only one connect guard" "README.md of this suite, limits found, observation 4" "$(holds_if test "$PM_STATUS" = 125 -a "$(grep -c '^START' "$PM_OUT")" = 0)"


finish
