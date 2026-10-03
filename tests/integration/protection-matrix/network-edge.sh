#!/usr/bin/env bash
# The network layer's edges: where a CIDR range ends, the port boundaries, special addresses, IPv6 spellings,
# non-blocking connects, odd address lengths, which kinds of socket can be made, and a TCP destination rewritten
# while the connect runs. The guard is the whole boundary here, so a destination counts as refused when the run
# answers EACCES or EPERM, and as passed when it answers anything else, a refusal by the server included.
set -uo pipefail
PM_HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${PM_HERE}/lib.sh"
pm_setup || finish
PM_ABI="$(pm_abi)"
P="$PM/bin/pprobe"
PE="$PM/bin/pedge"
PORT=39801
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
chmod 0777 "$PM/out"
echo "  landlock ABI ${PM_ABI}"

hits() {
  grep -c -- "$2" "$1" 2> /dev/null || true
}
srv="$(start_tcp_server 127.0.0.1 "$PORT" 4000 900)"
pids+=("$srv")
require_started "the TCP server on 127.0.0.1:${PORT}" "$srv"
srv="$(start_tcp_server 127.0.0.1 65535 400 900)"
pids+=("$srv")
require_started "the TCP server on 127.0.0.1:65535" "$srv"

# rule_run RULE... -- COMMAND...: one run with the [connect] lines given.
rule_run() {
  local lines=()
  while [[ "$1" != "--" ]]; do
    lines+=("$1")
    shift
  done
  shift
  { printf '[connect]\n'; printf '%s\n' "${lines[@]}"; } > "$PM/cfg/edge.cfg"
  run_pm --config "$PM/cfg/edge.cfg" -- "$@"
}
# verdict OPNAME: refused, passed, or unstarted, for what the last run did.
verdict() {
  if ! grep -q '^START' "$PM_OUT"; then
    echo unstarted
  elif op_failed_with "$1" $DENIED_ERRNOS; then
    echo refused
  elif [[ -n "$(op_result "$1")" ]]; then
    echo passed
  else
    echo unstarted
  fi
}
# expect_verdict TITLE EXPECTED OPNAME RULE... -- COMMAND...
expect_verdict() {
  local title="$1"
  local expected="$2"
  local opname="$3"
  shift 3
  rule_run "$@"
  local seen
  seen="$(verdict "$opname")"
  if [[ "$seen" == "$expected" ]]; then ok "$title"; else bad "$title" "expected ${expected}, saw ${seen}: $(pm_describe)"; fi
}

echo
echo "== where a range ends =="
TARGETS=(127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.9 127.0.0.254 127.0.1.1 127.1.0.1 128.0.0.1)
range_case() {
  local rule="$1"
  local allowed=" $2 "
  local target
  local expected
  local verb
  for target in "${TARGETS[@]}"; do
    expected=refused
    verb=refuses
    if [[ "$allowed" == *" ${target} "* ]]; then
      expected=passed
      verb=admits
    fi
    expect_verdict "${rule} ${verb} ${target}" "$expected" connect "allow ${rule}:${PORT}" -- "$P" tcp "$target" "$PORT"
  done
}
LOOPBACK="127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.9 127.0.0.254 127.0.1.1 127.1.0.1"
range_case "127.0.0.1" "127.0.0.1"
range_case "127.0.0.1/32" "127.0.0.1"
range_case "127.0.0.0/31" "127.0.0.1"
range_case "127.0.0.2/31" "127.0.0.2 127.0.0.3"
range_case "127.0.0.0/30" "127.0.0.1 127.0.0.2 127.0.0.3"
range_case "127.0.0.0/29" "127.0.0.1 127.0.0.2 127.0.0.3"
range_case "127.0.0.0/28" "127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.9"
range_case "127.0.0.0/24" "127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.9 127.0.0.254"
range_case "127.0.0.0/16" "127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.9 127.0.0.254 127.0.1.1"
range_case "127.0.0.0/8" "$LOOPBACK"
range_case "127.0.0.9/32" "127.0.0.9"
range_case "127.0.0.5/32" ""
range_case "localhost" "$LOOPBACK"
range_case "*" "$LOOPBACK 128.0.0.1"
expect_verdict "two rules add up: one address from each" passed connect "allow 127.0.0.1:${PORT}" "allow 127.0.0.9:${PORT}" -- "$P" tcp 127.0.0.9 "$PORT"
expect_verdict "and the first of them still works" passed connect "allow 127.0.0.1:${PORT}" "allow 127.0.0.9:${PORT}" -- "$P" tcp 127.0.0.1 "$PORT"
expect_verdict "and a third address is still refused" refused connect "allow 127.0.0.1:${PORT}" "allow 127.0.0.9:${PORT}" -- "$P" tcp 127.0.0.2 "$PORT"

echo
echo "== ports =="
expect_verdict "the highest port, when the rule names it, passes" passed connect "allow 127.0.0.1:65535" -- "$P" tcp 127.0.0.1 65535
expect_verdict "the port below the highest is refused" refused connect "allow 127.0.0.1:65535" -- "$P" tcp 127.0.0.1 65534
expect_verdict "port 1, when the rule names it, passes" passed connect "allow 127.0.0.1:1" -- "$P" tcp 127.0.0.1 1
expect_verdict "port 2 is refused beside a rule for port 1" refused connect "allow 127.0.0.1:1" -- "$P" tcp 127.0.0.1 2
expect_verdict "a star for the port admits the port of the server" passed connect "allow 127.0.0.1:*" -- "$P" tcp 127.0.0.1 "$PORT"
expect_verdict "and the highest port" passed connect "allow 127.0.0.1:*" -- "$P" tcp 127.0.0.1 65535
expect_verdict "and port 1" passed connect "allow 127.0.0.1:*" -- "$P" tcp 127.0.0.1 1
expect_verdict "but only for that address" refused connect "allow 127.0.0.1:*" -- "$P" tcp 127.0.0.2 "$PORT"
expect_verdict "a rule with no port is the same as a star" passed connect "allow 127.0.0.1" -- "$P" tcp 127.0.0.1 65535
expect_verdict "two port rules add up: the first" passed connect "allow 127.0.0.1:${PORT}" "allow 127.0.0.1:65535" -- "$P" tcp 127.0.0.1 "$PORT"
expect_verdict "and the second" passed connect "allow 127.0.0.1:${PORT}" "allow 127.0.0.1:65535" -- "$P" tcp 127.0.0.1 65535
expect_verdict "and a third port is refused" refused connect "allow 127.0.0.1:${PORT}" "allow 127.0.0.1:65535" -- "$P" tcp 127.0.0.1 39802
expect_verdict "a port rule for another address does not open this one" refused connect "allow 127.0.0.2:${PORT}" -- "$P" tcp 127.0.0.1 "$PORT"

echo
echo "== addresses that are not a host =="
expect_verdict "the unspecified address is refused beside a rule for loopback" refused connect "allow 127.0.0.1:${PORT}" -- "$P" tcp 0.0.0.0 "$PORT"
expect_verdict "the broadcast address is refused" refused connect "allow 127.0.0.1:${PORT}" -- "$P" tcp 255.255.255.255 "$PORT"
expect_verdict "a multicast address is refused" refused connect "allow 127.0.0.1:${PORT}" -- "$P" tcp 224.0.0.1 "$PORT"
expect_verdict "a private address outside the rule is refused" refused connect "allow 127.0.0.1:${PORT}" -- "$P" tcp 10.0.0.1 "$PORT"
rule_run "allow 10.0.0.0/8:80" -- "$P" tcp 10.0.0.1 80
if op_failed_with connect ENETUNREACH; then ok "a private address inside the rule passes the guard and meets the missing network, not the sandbox"; else bad "a private address inside the rule passes the guard" "$(pm_describe)"; fi
expect_verdict "a rule for the unspecified address does not open loopback" refused connect "allow 0.0.0.0:${PORT}" -- "$P" tcp 127.0.0.1 "$PORT"

echo
echo "== non-blocking connects =="
rule_run "allow 127.0.0.1:${PORT}" -- "$PE" tcp_nb 127.0.0.1 "$PORT"
if grep -q '^NB ready=1 so_error=0' "$PM_OUT"; then ok "an allowed non-blocking connect completes with no error"; else bad "an allowed non-blocking connect completes" "$(pm_describe)"; fi
rule_run "allow 127.0.0.1:${PORT}" -- "$PE" tcp_nb 127.0.0.1 39802
if op_failed_with connect_nb $DENIED_ERRNOS && ! grep -q '^NB' "$PM_OUT"; then ok "a non-blocking connect to another port is refused at once, not later through the socket"; else bad "a non-blocking connect to another port is refused at once" "$(pm_describe)"; fi
rule_run "allow 127.0.0.2:${PORT}" -- "$PE" tcp_nb 127.0.0.1 "$PORT"
if op_failed_with connect_nb $DENIED_ERRNOS && ! grep -q '^NB' "$PM_OUT"; then ok "and one to another address"; else bad "a non-blocking connect to another address is refused at once" "$(pm_describe)"; fi
run_direct "$PE" tcp_nb 127.0.0.1 "$PORT"
if grep -q '^NB ready=1 so_error=0' "$PM_OUT"; then ok "the unprotected control of the non-blocking connect works"; else bad "the control of the non-blocking connect" "$(pm_describe)"; fi
deny_case "a connect that names no address family is refused although the kernel allows it" net "$(printf '[connect]\nallow 127.0.0.1:%s\n' "$PORT" | cfg unspec)" connect_unspec "$DENIED_ERRNOS" -- "$PE" connect_unspec

echo
echo "== odd address lengths =="
for length in 16 17 28 64; do
  expect_verdict "an address of ${length} bytes to an allowed destination passes" passed connect_len "allow 127.0.0.1:${PORT}" -- "$PE" connect_len 127.0.0.1 "$PORT" "$length"
done
for length in 8 15; do
  rule_run "allow 127.0.0.1:${PORT}" -- "$PE" connect_len 127.0.0.1 "$PORT" "$length"
  if op_failed_with connect_len EINVAL; then ok "an address of ${length} bytes is too short and the kernel says so"; else bad "an address of ${length} bytes is rejected as invalid" "$(pm_describe)"; fi
done
for length in 0 4; do
  expect_verdict "an address of ${length} bytes is refused by the guard before the kernel could say it is invalid" refused connect_len "allow 127.0.0.1:${PORT}" -- "$PE" connect_len 127.0.0.1 "$PORT" "$length"
done
for length in 16 17 64; do
  expect_verdict "a forbidden address of ${length} bytes is refused" refused connect_len "allow 127.0.0.2:${PORT}" -- "$PE" connect_len 127.0.0.1 "$PORT" "$length"
done

echo
echo "== IPv6 spellings =="
v6_case() {
  local rule="$1"
  local allowed=" $2 "
  local target
  local expected
  local verb
  for target in ::1 ::2 ::ffff:127.0.0.1; do
    expected=refused
    verb=refuses
    if [[ "$allowed" == *" ${target} "* ]]; then
      expected=passed
      verb=admits
    fi
    expect_verdict "the rule ${rule} ${verb} ${target}" "$expected" connect6 "$rule" -- "$P" tcp6 "$target" "$PORT"
  done
}
v6_case "allow [::1]:${PORT}" "::1"
v6_case "allow ::1" "::1"
v6_case "allow [::ffff:127.0.0.1]:${PORT}" "::ffff:127.0.0.1"
v6_case "allow 127.0.0.1:${PORT}" ""
v6_case "allow [::]:${PORT}" ""
expect_verdict "the name localhost also admits the IPv6 loopback" passed connect6 "allow localhost:${PORT}" -- "$P" tcp6 ::1 "$PORT"
expect_verdict "and no other IPv6 address" refused connect6 "allow localhost:${PORT}" -- "$P" tcp6 ::2 "$PORT"

echo
echo "== which kinds of socket can be made =="
refused_kinds=(
  "1 3 a raw socket in the UNIX domain"
  "16 3 a raw netlink socket"
  "17 2 a packet datagram socket"
  "17 3 a raw packet socket"
  "24 3 a raw socket of an unusual family"
  "44 3 a raw socket in the XDP family"
)
for entry in "${refused_kinds[@]}"; do
  read -r family type description <<< "$entry"
  deny_case "${description} (family ${family}, type ${type}) is refused" net "$(printf '[read]\n%s\n' "$PM/ro" | cfg sockets)" socket "$DENIED_ERRNOS" -- "$PE" sock "$family" "$type" 0
done
made_kinds=(
  "1 1 a UNIX stream socket"
  "1 2 a UNIX datagram socket"
  "1 5 a UNIX sequenced-packet socket"
  "2 1 an IPv4 stream socket"
  "2 2 an IPv4 datagram socket"
  "2 5 an IPv4 sequenced-packet socket"
  "10 1 an IPv6 stream socket"
  "10 2 an IPv6 datagram socket"
  "10 5 an IPv6 sequenced-packet socket"
)
for entry in "${made_kinds[@]}"; do
  read -r family type description <<< "$entry"
  run_direct "$PE" sock "$family" "$type" 0
  if ! op_ok socket; then
    skip "${description} can still be made" "the unprotected control could not make it either"
    continue
  fi
  rule_run "allow 127.0.0.1:${PORT}" -- "$PE" sock "$family" "$type" 0
  if op_ok socket; then ok "${description} can still be made"; else bad "${description} can still be made" "$(pm_describe)"; fi
done
run_direct "$PE" sock 16 2 0
if op_ok socket; then
  rule_run "allow 127.0.0.1:${PORT}" -- "$PE" sock 16 2 0
  gap_case "a netlink datagram socket can be made, since the guard has no rule against that family" "README.md of this suite, limits found, observation 6" "$(op_ok socket; echo $?)"
else
  skip "a netlink datagram socket" "the unprotected control could not make it"
fi

echo
echo "== a destination rewritten while the connect runs =="
race_index=0
# One phase of the TCP race on ports of its own: two servers outside, the sender, a wait until the servers go quiet,
# and RACE_ALLOWED and RACE_FORBIDDEN as the number of tags each received.
race_phase() {
  local mode="$1"
  race_index=$(( race_index + 1 ))
  local port=$(( 39810 + race_index ))
  local allowed_pid
  local forbidden_pid
  allowed_pid="$(start_tcp_server 127.0.0.1 "$port" 5000 60)"
  forbidden_pid="$(start_tcp_server 127.0.0.2 "$port" 5000 60)"
  pids+=("$allowed_pid" "$forbidden_pid")
  require_started "the race server on 127.0.0.1:${port}" "$allowed_pid"
  require_started "the race server on 127.0.0.2:${port}" "$forbidden_pid"
  if [[ "$mode" == control ]]; then
    run_direct "$PE" tcp_race 127.0.0.1 127.0.0.2 "$port" 1500
  else
    rule_run "allow 127.0.0.1:${port}" -- "$PE" tcp_race 127.0.0.1 127.0.0.2 "$port" 1500
  fi
  local quiet=0
  local last=-1
  local now
  while (( quiet < 10 )); do
    sleep 0.2
    now=$(( $(hits "$PM/out/server-127.0.0.1-${port}.log" 'SERVER-GOT RACE') + $(hits "$PM/out/server-127.0.0.2-${port}.log" 'SERVER-GOT RACE') ))
    if (( now == last )); then quiet=$(( quiet + 1 )); else quiet=0; last="$now"; fi
  done
  reap "$allowed_pid"
  reap "$forbidden_pid"
  RACE_ALLOWED="$(hits "$PM/out/server-127.0.0.1-${port}.log" 'SERVER-GOT RACE')"
  RACE_FORBIDDEN="$(hits "$PM/out/server-127.0.0.2-${port}.log" 'SERVER-GOT RACE')"
}
for round in 1 2 3; do
  race_phase control
  leaked="$RACE_FORBIDDEN"
  if (( leaked <= 0 )); then
    skip "a destination rewritten while connect runs never reaches the forbidden server (round ${round})" "without Phobos it never did either, so the race cannot be reached here"
    continue
  fi
  race_phase protected
  refused="$(sed -n 's/.*refused=\([0-9]*\).*/\1/p' "$PM_OUT")"
  if [[ "$RACE_FORBIDDEN" == 0 && "$RACE_ALLOWED" -gt 0 && -n "$refused" && "$refused" -gt 0 ]]; then
    ok "a destination rewritten while connect runs never reaches the forbidden server, and the allowed one still answers (round ${round}, the control leaked ${leaked})"
  else
    bad "a destination rewritten while connect runs never reaches the forbidden server (round ${round})" "control leaked ${leaked}; protected: forbidden ${RACE_FORBIDDEN}, allowed ${RACE_ALLOWED}, refused ${refused:-none}: $(pm_describe)"
  fi
done

echo
echo "== rules that are accepted and do not mean what they say =="
for literal in 256.1.1.1 1.2.3 1.2.3.4.5 127.1 2130706433; do
  rule_run "allow ${literal}:${PORT}" -- "$P" tcp 127.0.0.9 "$PORT"
  literal_started="$(grep -c '^START' "$PM_OUT")"
  literal_verdict="$(verdict connect)"
  known_defect "the address ${literal} is refused as a policy error, or read as the address it spells" \
    "the rule starts the command (${literal_started}) and the connect to 127.0.0.9 is ${literal_verdict}: the port is open to every address (README.md, defect 4)" \
    "$(holds_if test "$literal_started" = 1 -a "$literal_verdict" = passed)"
done
rule_run "allow 0.0.0.0/0:${PORT}" -- "$P" tcp 127.0.0.1 "$PORT"
slash_zero="$(verdict connect)"
rule_run "allow 127.0.0.1/33:${PORT}" -- "$P" tcp 127.0.0.1 "$PORT"
slash_wide="$(verdict connect)"
known_defect "a range with prefix length 0 admits every address, and an out-of-range prefix is refused as a policy error" \
  "0.0.0.0/0 admits nothing (${slash_zero}) and /33 is accepted and admits nothing (${slash_wide}) (README.md, defect 5)" \
  "$(holds_if test "$slash_zero" = refused -a "$slash_wide" = refused)"
rule_run "allow 127.0.0.1:" -- "$P" tcp 127.0.0.1 "$PORT"
empty_port="$(verdict connect)"
known_defect "a rule that names a host and an empty port is refused as a policy error" \
  "it is accepted and admits nothing (${empty_port}) (README.md, defect 5)" \
  "$(holds_if test "$empty_port" = refused)"

finish
