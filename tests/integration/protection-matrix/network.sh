#!/usr/bin/env bash
# The network layer through phobos.sh: the connect guard, the Landlock port rules, the egress broker, bind and
# listen, for TCP and UDP, with the independent effect (what a real server outside the sandbox received) checked
# next to every verdict. See lib.sh for what makes a denial count.
set -uo pipefail
PM_HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${PM_HERE}/lib.sh"
pm_setup || finish
PM_ABI="$(pm_abi)"
P="$PM/bin/pprobe"
PORT_A=39401
PORT_B=39402
UDP_PORT=39411
RACE_PORT=39421
BIND_PORT=39431
BIND_OTHER=39433
RACE_BIND=39436
cd "$PM/work" || exit 1
pids=()
cleanup() {
  local pid
  for pid in "${pids[@]}"; do
    reap "$pid"
  done
  pm_restore
}
trap cleanup EXIT
echo "  landlock ABI ${PM_ABI}, uid ${PM_USER_ID}"

# The number of lines of a server's log that say it was reached.
hits() {
  grep -c -- "$2" "$1" 2>/dev/null || true
}

# ----------------------------------------------------------------- servers
srv_a="$(start_tcp_server 127.0.0.1 "$PORT_A" 400 600)"
pids+=("$srv_a")
require_started "the TCP server on 127.0.0.1:${PORT_A}" "$srv_a"
srv_b="$(start_tcp_server 127.0.0.1 "$PORT_B" 400 600)"
pids+=("$srv_b")
require_started "the TCP server on 127.0.0.1:${PORT_B}" "$srv_b"
srv_a2="$(start_tcp_server 127.0.0.2 "$PORT_A" 400 600)"
pids+=("$srv_a2")
require_started "the TCP server on 127.0.0.2:${PORT_A}" "$srv_a2"
srv_a5="$(start_tcp_server 127.0.0.5 "$PORT_A" 400 600)"
pids+=("$srv_a5")
require_started "the TCP server on 127.0.0.5:${PORT_A}" "$srv_a5"
log_a="$PM/out/server-127.0.0.1-${PORT_A}.log"
log_b="$PM/out/server-127.0.0.1-${PORT_B}.log"
if [[ -z "$srv_a" || -z "$srv_b" ]]; then
  finish
fi

c_tcp="$(cfg tcp <<EOF2
[connect]
allow 127.0.0.1:$PORT_A
EOF2
)"
c_range="$(cfg range <<EOF2
[connect]
allow 127.0.0.0/30:$PORT_A
EOF2
)"
c_localhost="$(cfg localhost <<EOF2
[connect]
allow localhost:$PORT_A
EOF2
)"
c_star="$(cfg star <<EOF2
[connect]
allow *:$PORT_A
EOF2
)"
c_v6="$(cfg v6 <<EOF2
[connect]
allow [::1]:$PORT_A
EOF2
)"
c_udp="$(cfg udp <<EOF2
[connect]
allow 127.0.0.1 udp
EOF2
)"
c_slash32="$(cfg slash32 <<EOF2
[connect]
allow 127.0.0.1/32
EOF2
)"
c_none="$(cfg none <<EOF2
[read]
$PM/ro
EOF2
)"

echo
echo "== TCP: connect =="
allow_case "an allowed address and port connects, and the server outside answers" "$c_tcp" connect -- "$P" tcp 127.0.0.1 "$PORT_A"
expect_output "and the reply is the server's own" "$c_tcp" "REPLY pong" -- "$P" tcp 127.0.0.1 "$PORT_A"
before="$(hits "$log_b" SERVER-GOT)"
deny_case "another port on the same address is refused" net "$c_tcp" connect "$DENIED_ERRNOS" -- "$P" tcp 127.0.0.1 "$PORT_B"
after="$(hits "$log_b" SERVER-GOT)"
check "the forbidden server was reached only by the two unprotected runs, not by the protected one" "2" "$(( after - before ))"
before="$(hits "$log_a" SERVER-GOT)"
deny_case "another loopback address on the same port is refused" net "$c_tcp" connect "$DENIED_ERRNOS" -- "$P" tcp 127.0.0.2 "$PORT_A"
allow_case "an address range allows an address inside it" "$c_range" connect -- "$P" tcp 127.0.0.1 "$PORT_A"
deny_case "and refuses one outside it on the same port" net "$c_range" connect "$DENIED_ERRNOS" -- "$P" tcp 127.0.0.5 "$PORT_A"
allow_case "the name localhost allows the loopback" "$c_localhost" connect -- "$P" tcp 127.0.0.1 "$PORT_A"
allow_case "the star host allows any host on its port" "$c_star" connect -- "$P" tcp 127.0.0.2 "$PORT_A"
deny_case "and still refuses another port" net "$c_star" connect "$DENIED_ERRNOS" -- "$P" tcp 127.0.0.1 "$PORT_B"
allow_case "a single loopback address written /32 with no port lets every port of it connect" "$c_slash32" connect -- "$P" tcp 127.0.0.1 "$PORT_B"
deny_case "and not another loopback address, since /32 is one address and not a range" net "$c_slash32" connect "$DENIED_ERRNOS" -- "$P" tcp 127.0.0.2 "$PORT_A"
run_pm --config "$c_v6" -- "$P" tcp6 ::1 "$PORT_A"
if op_failed_with connect6 ECONNREFUSED; then ok "an allowed IPv6 destination passes the guard (nothing listens there, so the target refuses, not the sandbox)"; else bad "an allowed IPv6 destination passes the guard" "$(pm_describe)"; fi
run_pm --config "$c_v6" -- "$P" tcp6 ::1 "$PORT_B"
if op_failed_with connect6 $DENIED_ERRNOS; then ok "an IPv6 destination on another port is refused by the sandbox"; else bad "an IPv6 destination on another port is refused" "$(pm_describe)"; fi
run_pm --config "$c_tcp" -- "$P" tcp6 ::ffff:127.0.0.1 "$PORT_A"
if op_failed_with connect6 $DENIED_ERRNOS; then ok "an IPv4-mapped IPv6 spelling of an allowed IPv4 address is refused, never read as the allowed one"; else bad "an IPv4-mapped IPv6 spelling is refused" "$(pm_describe)"; fi
run_pm --config "$c_tcp" -- "$P" unixconnect "$PM/work/no-such.sock"
if op_failed_with connect_unix $DENIED_ERRNOS; then ok "a UNIX-domain connect is refused by the guard, before the kernel could say the path is absent"; else bad "a UNIX-domain connect is refused by the guard" "$(pm_describe)"; fi
run_pm --no-networksystem-restriction --config "$c_tcp" -- "$P" unixconnect "$PM/work/no-such.sock"
if op_failed_with connect_unix ENOENT; then ok "and without the guard the kernel answers ENOENT, so the refusal was the guard's"; else bad "and without the guard the kernel answers ENOENT" "$(pm_describe)"; fi
deny_case "a raw socket is refused" net "$c_tcp" raw "$DENIED_ERRNOS" -- "$P" raw
deny_case "an ICMP datagram socket is refused" net "$c_tcp" icmp "$DENIED_ERRNOS" -- "$P" icmp
deny_case "a packet socket is refused" net "$c_tcp" packet "$DENIED_ERRNOS" -- "$P" packet
deny_case "io_uring is refused, so no second system call interface can reach connect" net "$c_tcp" io_uring_setup "$DENIED_ERRNOS" -- "$P" io_uring
deny_case "TCP Fast Open cannot carry a destination past connect" net "$c_tcp" sendto_fastopen "$DENIED_ERRNOS" -- "$P" tfo 127.0.0.1 "$PORT_B"
deny_case "a connect to a port the policy names, on the wrong transport, is refused: a udp rule admits no stream" net "$c_udp" connect "$DENIED_ERRNOS" -- "$P" tcp 127.0.0.1 "$PORT_A"

echo
echo "== a run with no exercise configuration reaches no network at all =="
run_pm -- "$P" tcp 127.0.0.1 "$PORT_A"
if op_failed_with connect $DENIED_ERRNOS; then ok "a bare run cannot even reach loopback"; else bad "a bare run cannot even reach loopback" "$(pm_describe)"; fi
run_pm --no-restriction -- "$P" tcp 127.0.0.1 "$PORT_A"
if op_ok connect; then ok "and the same run unconfined (-nr) can, so the refusal was Phobos's"; else bad "the same run unconfined can" "$(pm_describe)"; fi

echo
echo "== UDP: send, connect, and the transports kept apart =="
recv_ok="$(start_udp_receiver 127.0.0.1 "$UDP_PORT" 600)"
pids+=("$recv_ok")
require_started "the UDP receiver on 127.0.0.1:${UDP_PORT}" "$recv_ok"
recv_bad="$(start_udp_receiver 127.0.0.2 "$UDP_PORT" 600)"
pids+=("$recv_bad")
require_started "the UDP receiver on 127.0.0.2:${UDP_PORT}" "$recv_bad"
log_ok="$PM/out/udp-127.0.0.1-${UDP_PORT}.log"
log_bad="$PM/out/udp-127.0.0.2-${UDP_PORT}.log"
for mode in sendto sendmsg sendmmsg connect_send; do
  allow_case "a datagram by ${mode} to an allowed address is sent" "$c_udp" "$mode" -- "$P" udp_send "$mode" 127.0.0.1 "$UDP_PORT" "PAY-${mode}"
done
sleep 1
for mode in sendto sendmsg sendmmsg connect_send; do
  check "the receiver outside got the datagram by ${mode}" "1" "$(hits "$log_ok" "ARRIVED PAY-${mode}")"
done
for mode in sendto sendmsg sendmmsg connect_send; do
  op="$([[ $mode == connect_send ]] && echo connect_udp || echo "$mode")"
  deny_case "a datagram by ${mode} to another address is refused" net "$c_udp" "$op" "$DENIED_ERRNOS" -- "$P" udp_send "$mode" 127.0.0.2 "$UDP_PORT" "BAD-${mode}"
done
sleep 1
for mode in sendto sendmsg sendmmsg connect_send; do
  arrived="$(hits "$log_bad" "ARRIVED BAD-${mode}")"
  check "the forbidden receiver got ${mode} only from the two unprotected runs" "2" "$arrived"
done
deny_case "a datagram on a socket that was never bound is refused when no udp rule grants an ephemeral source port" net "$c_tcp" sendto "$DENIED_ERRNOS" -- "$P" udp_send sendto 127.0.0.1 "$UDP_PORT"
deny_case "a datagram with ancillary data, which can steer it, is refused" net "$c_udp" sendmsg_ancillary "$DENIED_ERRNOS" -- "$P" udp_ancillary 127.0.0.1 "$UDP_PORT"
c_tcp_only_udp="$(cfg tcp_for_udp <<EOF2
[connect]
allow 127.0.0.1:$UDP_PORT
EOF2
)"
deny_case "a tcp rule does not admit a datagram to the same address and port" net "$c_tcp_only_udp" sendto "$DENIED_ERRNOS" -- "$P" udp_send sendto 127.0.0.1 "$UDP_PORT"

c_udp_port="$(cfg udpport <<EOF2
[connect]
allow 127.0.0.1:$UDP_PORT udp
EOF2
)"
if (( PM_ABI >= 10 )); then
  recv_port_other="$(start_udp_receiver 127.0.0.1 "$((UDP_PORT + 1))" 120)"
  pids+=("$recv_port_other")
  require_started "the UDP receiver on 127.0.0.1:$((UDP_PORT + 1))" "$recv_port_other"
  allow_case "a udp rule that names a port lets a datagram to that port go" "$c_udp_port" sendto -- "$P" udp_send sendto 127.0.0.1 "$UDP_PORT" "PAY-port"
  deny_case "and refuses a datagram to another port on the same address" net "$c_udp_port" sendto "$DENIED_ERRNOS" -- "$P" udp_send sendto 127.0.0.1 "$((UDP_PORT + 1))" "BAD-port"
  sleep 1
  check "the other port's receiver got that datagram only from the two unprotected runs, never from the protected one" "2" "$(hits "$PM/out/udp-127.0.0.1-$((UDP_PORT + 1)).log" "ARRIVED BAD-port")"
  c_bind_udp="$(cfg bindudp <<EOF2
[bind]
allow $BIND_PORT udp
EOF2
)"
  allow_case "a [bind] row for one UDP port lets that port be bound" "$c_bind_udp" bind_udp -- "$P" bind 127.0.0.1 "$BIND_PORT" udp
  deny_case "and not another UDP port" net "$c_bind_udp" bind_udp "$DENIED_ERRNOS" -- "$P" bind 127.0.0.1 "$BIND_OTHER" udp
else
  run_pm --config "$c_udp_port" -- "$P" cwd
  if (( PM_STATUS == 125 )) && ! grep -q '^START' "$PM_OUT" && grep -q 'UDP network rules require Landlock version 10' "$PM_ERR"; then ok "below Landlock version 10 a udp rule that names a port is refused before the command, not left unenforced"; else bad "a udp rule that names a port is refused below Landlock version 10" "$(pm_describe)"; fi
fi

c_udp_mixed="$(cfg udpmixed <<EOF2
[connect]
allow 127.0.0.1 udp
allow 127.0.0.2:$UDP_PORT udp
EOF2
)"
# Landlock cannot keep loopback open on every UDP port and close the rest, so the guard alone holds the rule that names a
# port, on every kernel, the ones below Landlock version 10 included.
allow_case "a udp loopback wildcard beside a udp rule that names a port: a datagram to the wildcard address goes" "$c_udp_mixed" sendto -- "$P" udp_send sendto 127.0.0.1 "$UDP_PORT" "PAY-mixed-wild"
allow_case "and a datagram to the named address and port goes" "$c_udp_mixed" sendto -- "$P" udp_send sendto 127.0.0.2 "$UDP_PORT" "PAY-mixed-port"
deny_case "and a datagram to the named address on another port is refused" net "$c_udp_mixed" sendto "$DENIED_ERRNOS" -- "$P" udp_send sendto 127.0.0.2 "$((UDP_PORT + 1))" "BAD-mixed-port"
deny_case "and a datagram to another address on the named port is refused" net "$c_udp_mixed" sendto "$DENIED_ERRNOS" -- "$P" udp_send sendto 127.0.0.3 "$UDP_PORT" "BAD-mixed-address"

echo
echo "== an imported Ares 2 policy: TCP and UDP under a programming language configuration =="
# Each granted Ares entry becomes a TCP rule and the same rule for UDP, and the configuration adds allow localhost udp,
# so the UDP rules that name a port are held by the connect guard alone and the run starts below Landlock version 10.
# The minimal base has no TCP loopback wildcard, so a TCP port the import does not name stays closed.
a_net="$(ares_cfg ares_net "net 127.0.0.1 $PORT_A" "net 127.0.0.1 $UDP_PORT" "net 10.0.0.1 $UDP_PORT")"
allow_case "an imported loopback entry connects over TCP to its port" "$a_net" connect -- "$P" tcp 127.0.0.1 "$PORT_A"
deny_case "and not to another TCP port of the same address" net "$a_net" connect "$DENIED_ERRNOS" -- "$P" tcp 127.0.0.1 "$PORT_B"
allow_case "a datagram to the imported port goes, on every kernel, the ones below Landlock version 10 included" "$a_net" sendto -- "$P" udp_send sendto 127.0.0.1 "$UDP_PORT" "PAY-ares"
if grep -q 'connect guard alone enforces them' "$PM_ERR"; then ok "and the network layer says the connect guard alone enforces the udp port"; else bad "the network layer says the connect guard alone enforces the udp port" "$(pm_describe)"; fi
allow_case "the configuration's loopback rule lets a datagram to another port of 127.0.0.1 go" "$a_net" sendto -- "$P" udp_send sendto 127.0.0.1 "$((UDP_PORT + 1))" "PAY-ares-other"
allow_case "and one to 127.0.0.2, which is loopback too" "$a_net" sendto -- "$P" udp_send sendto 127.0.0.2 "$UDP_PORT" "PAY-ares-loop"
run_pm --config "$a_net" -- "$P" udp_send sendto 10.0.0.1 "$UDP_PORT" "PAY-ares-far"
if op_failed_with sendto ENETUNREACH; then ok "a datagram to an imported non-loopback entry passes the guard and meets the missing network"; else bad "a datagram to an imported non-loopback entry passes the guard" "$(pm_describe)"; fi
for target in "192.0.2.1 ${UDP_PORT}" "10.0.0.1 $((UDP_PORT + 1))"; do
  read -r address port <<< "$target"
  run_pm --config "$a_net" -- "$P" udp_send sendto "$address" "$port" "BAD-ares"
  refused_by_guard=0
  op_failed_with sendto $DENIED_ERRNOS && refused_by_guard=1
  guarded_run="$(pm_describe)"
  run_pm --no-networksystem-restriction --config "$a_net" -- "$P" udp_send sendto "$address" "$port" "BAD-ares"
  if (( refused_by_guard )) && op_failed_with sendto ENETUNREACH; then
    ok "a datagram to ${address}:${port}, which no rule names, is refused by the sandbox, and without the network layer it meets the missing network"
  else
    bad "a datagram to ${address}:${port} is refused by the sandbox" "guarded: ${guarded_run}; network layer off: $(pm_describe)"
  fi
done

echo
echo "== UDP: the destination cannot be swapped between the check and the send =="
run_direct_args() {
  shift
  run_direct "$@"
}
run_protected_args() {
  run_pm --config "$c_udp" "$@"
}
race_index=0
# One phase of the race on ports of its own, so no datagram can be counted in another run: starts the two receivers,
# runs the sender, waits for the receivers to go quiet, stops them and sets RACE_ALLOWED and RACE_FORBIDDEN.
race_phase() {
  local runner="$1"
  local mode="$2"
  shift 2
  race_index=$(( race_index + 1 ))
  local port=$(( RACE_PORT + race_index ))
  local allowed_pid
  local forbidden_pid
  allowed_pid="$(start_udp_receiver 127.0.0.1 "$port" 60)"
  forbidden_pid="$(start_udp_receiver 127.0.0.2 "$port" 60)"
  require_started "the race receiver on 127.0.0.1:${port}" "$allowed_pid"
  require_started "the race receiver on 127.0.0.2:${port}" "$forbidden_pid"
  "$runner" "$@" -- "$P" udp_race "$mode" "$port" 20000 outside
  local quiet=0
  local last=-1
  local now
  while (( quiet < 10 )); do
    sleep 0.2
    now=$(( $(hits "$PM/out/udp-127.0.0.1-${port}.log" ARRIVED) + $(hits "$PM/out/udp-127.0.0.2-${port}.log" ARRIVED) ))
    if (( now == last )); then quiet=$(( quiet + 1 )); else quiet=0; last="$now"; fi
  done
  reap "$allowed_pid"
  reap "$forbidden_pid"
  RACE_ALLOWED="$(hits "$PM/out/udp-127.0.0.1-${port}.log" ARRIVED)"
  RACE_FORBIDDEN="$(hits "$PM/out/udp-127.0.0.2-${port}.log" ARRIVED)"
}
for mode in sendto sendmsg sendmmsg connect; do
  race_phase run_direct_args "$mode"
  leaked="$RACE_FORBIDDEN"
  if (( leaked <= 0 )); then
    skip "a destination rewritten while ${mode} runs never reaches the forbidden receiver" "without Phobos it never did either ($(head -c 200 "$PM_OUT" | tr '\n' ' ')), so the race cannot be reached here"
    continue
  fi
  race_phase run_protected_args "$mode"
  refused="$(sed -n 's/.*refused=\([0-9]*\).*/\1/p' "$PM_OUT")"
  if [[ "$RACE_FORBIDDEN" == "0" && "$RACE_ALLOWED" -gt 0 && -n "$refused" && "$refused" -gt 0 ]]; then
    ok "a destination rewritten while ${mode} runs never reaches the forbidden receiver, and the allowed one still receives (the control leaked ${leaked})"
  else
    bad "a destination rewritten while ${mode} runs never reaches the forbidden receiver" "control leaked ${leaked}; protected: forbidden ${RACE_FORBIDDEN}, allowed ${RACE_ALLOWED}, refused ${refused:-none}: $(pm_describe)"
  fi
done

echo
echo "== sockets the guard did not create =="
( exec 7<> "/dev/tcp/127.0.0.1/${PORT_B}"; run_pm --config "$c_tcp" -- "$P" inherited_write 7
  op_ok send_inherited_stream && echo 0 > "$PM/out/gap-inh-tcp" || echo 1 > "$PM/out/gap-inh-tcp" )
sleep 1
gap_case "a stream socket connected before the sandbox keeps sending to its server although the policy does not allow that port" "SECURITY.md" "$(cat "$PM/out/gap-inh-tcp")"
check "and the forbidden server did receive it" "1" "$([[ "$(hits "$log_b" 'SERVER-GOT inherited')" -ge 1 ]] && echo 1 || echo 0)"
( exec 7<> "/dev/udp/127.0.0.1/${UDP_PORT}"; run_pm --config "$c_none" -- "$P" inherited_send 7
  op_ok send_inherited && echo 0 > "$PM/out/gap-inh-udp" || echo 1 > "$PM/out/gap-inh-udp" )
gap_case "a datagram socket connected before the sandbox keeps sending to its peer with an address-less send" "SECURITY.md" "$(cat "$PM/out/gap-inh-udp")"
( exec 7<> "/dev/udp/127.0.0.1/${UDP_PORT}"; run_pm --config "$c_udp" -- "$P" inherited_send 7 127.0.0.2 "$UDP_PORT" )
if op_failed_with sendto_inherited $DENIED_ERRNOS; then ok "but a send that names a destination on such a socket is refused, the guard holds no copy of it"; else bad "a send that names a destination on an inherited socket is refused" "$(pm_describe)"; fi
run_pm --config "$c_tcp" -- "$P" tcp_sendmsg 127.0.0.1 "$PORT_A"
gap_case "sendmsg on a connected TCP socket is refused by the guard, the price of closing the datagram race, so programs that send that way break under a [connect] rule" "SECURITY.md" "$(op_failed_with sendmsg_tcp $DENIED_ERRNOS; echo $?)"

echo
echo "== bind and listen are closed unless a [bind] row opens them =="
c_bind0="$(cfg bind0 <<EOF2
[connect]
allow 127.0.0.1:*
[bind]
allow 0
EOF2
)"
c_bind_port="$(cfg bindport <<EOF2
[connect]
allow 127.0.0.1:*
[bind]
allow $BIND_PORT
EOF2
)"
deny_case "with no [bind] row a TCP port cannot be bound" net "$c_none" bind_tcp "$DENIED_ERRNOS" -- "$P" bind 127.0.0.1 "$BIND_PORT" tcp
deny_case "nor a port the kernel would choose" net "$c_none" bind_tcp "$DENIED_ERRNOS" -- "$P" bind 127.0.0.1 0 tcp
deny_case "and a socket that was never bound cannot listen" net "$c_none" listen_unbound "$DENIED_ERRNOS" -- "$P" listen_unbound
allow_case "a [bind] row for port 0 lets a port the kernel chooses be bound" "$c_bind0" bind_tcp -- "$P" bind 127.0.0.1 0 tcp
deny_case "and still not a port the program names" net "$c_bind0" bind_tcp "$DENIED_ERRNOS" -- "$P" bind 127.0.0.1 "$BIND_PORT" tcp
allow_case "an unbound socket can listen under that row, and a whole server works" "$c_bind0" accept -- "$P" serve -1
allow_case "a [bind] row for one port lets that port be bound and served, with a client and accept" "$c_bind_port" accept -- "$P" serve "$BIND_PORT"
deny_case "and not another port" net "$c_bind_port" bind_tcp "$DENIED_ERRNOS" -- "$P" bind 127.0.0.1 "$BIND_OTHER" tcp
deny_case "an explicit port row does not open the kernel's own choice of port" net "$c_bind_port" bind_tcp "$DENIED_ERRNOS" -- "$P" bind 127.0.0.1 0 tcp
deny_case "an explicit port row does not let an unbound socket listen" net "$c_bind_port" listen_unbound "$DENIED_ERRNOS" -- "$P" listen_unbound
c_bind_race="$(cfg bindrace <<EOF2
[bind]
allow $RACE_BIND
EOF2
)"
run_direct "$P" listen_race "$RACE_BIND"
if grep -q 'LISTEN-RACE port=[1-9]' "$PM_OUT"; then
  run_pm --config "$c_bind_race" -- "$P" listen_race "$RACE_BIND"
  if grep -q 'LISTEN-RACE port=0' "$PM_OUT"; then ok "swapping a never-bound socket under a descriptor while it listens never creates a listener (the control did)"; else bad "swapping a never-bound socket under the listening descriptor never creates a listener" "$(pm_describe)"; fi
else
  skip "the listen race" "without Phobos it never created a listener either ($(tr '\n' ' ' < "$PM_OUT"))"
fi
if (( PM_ABI >= 10 )); then
  deny_case "with no [bind] row a UDP port cannot be bound" net "$c_none" bind_udp "$DENIED_ERRNOS" -- "$P" bind 127.0.0.1 "$BIND_PORT" udp
else
  run_pm --config "$c_none" -- "$P" bind 127.0.0.1 "$BIND_PORT" udp
  gap_case "below Landlock version 10 a UDP port can be bound with no [bind] row, and the enforcer says so" "SECURITY.md" "$(holds_if bash -c "grep -q 'cannot close UDP bind' '$PM_ERR' && grep -q 'OP bind_udp ret=0' '$PM_OUT'")"
fi
run_pm --config "$c_none" -- "$P" bind 127.0.0.1 "$BIND_PORT" tcp
if op_failed_with bind_tcp $DENIED_ERRNOS; then ok "and a bare policy without any connect or bind row closes TCP bind as well"; else bad "a bare policy closes TCP bind" "$(pm_describe)"; fi
run_pm -- "$P" serve "$BIND_PORT"
if op_failed_with bind $DENIED_ERRNOS; then ok "a run given no configuration cannot bind or listen"; else bad "a run given no configuration cannot bind or listen" "$(pm_describe)"; fi

echo
echo "== [accept]: the inbound filter in front of a listener =="
PUBLIC_PORT=39600
BACKEND_PORT=39610
# A policy that lets the command listen on the backend port and exposes the public port in front of it. The
# second argument is the "from" clause with its leading word; the bare word names no source.
accept_cfg() {
  cfg "$1" <<EOF3
[bind]
allow $BACKEND_PORT
[accept]
expose $PUBLIC_PORT to $BACKEND_PORT $2
EOF3
}
# Starts a sandboxed server behind the filter in the background, waits until it listens, and leaves its pid in
# ACCEPT_PID and its output file in ACCEPT_OUT. Extra arguments are phobos.sh flags.
accept_start() {
  local config="$1"
  shift
  ACCEPT_OUT="$PM/out/accept.out"
  : > "$ACCEPT_OUT"
  bg_pm "$ACCEPT_OUT" "$PM/out/accept.err" "$@" --config "$config" -- "$P" tcpserver 127.0.0.1 "$BACKEND_PORT" 3 4
  ACCEPT_PID="$BG_PID"
  wait_for_line "$ACCEPT_OUT" LISTENING 100 || true
}
accept_client() {
  PM_OUT="$PM/out/accept-client.out"
  run_direct "$P" tcpfrom "$1" 127.0.0.1 "$PUBLIC_PORT" "from-$1"
}
# Whether the last accept_client run was closed by the filter without an answer. The filter turns a source its rule
# does not name away with a reset right after the handshake, and a client sees that in one of two ways, depending on
# whether it has woken from its blocking connect() before the reset arrives: connect() succeeds and the first read then
# ends (CLOSED), or connect() itself fails with ECONNRESET. A slow runner produces the second about once in a hundred
# runs, so both are the filter refusing the connection. What is never accepted: any reply, a refusal because nothing
# listens (ECONNREFUSED, which would mean the filter was not up), a timeout, or silence.
accept_closed_without_answer() {
  ! grep -q '^REPLY' "$PM_OUT" && { { op_ok connect && grep -q '^CLOSED' "$PM_OUT"; } || op_failed_with connect ECONNRESET; }
}
c_accept_one="$(accept_cfg acceptone "from 127.0.0.1")"
accept_start "$c_accept_one"
accept_client 127.0.0.2
if accept_closed_without_answer; then ok "a connection from a source the rule does not name is closed by the filter without an answer"; else bad "a source the rule does not name is closed" "$(pm_describe)"; fi
accept_client 127.0.0.1
if grep -q '^REPLY pong' "$PM_OUT"; then ok "a connection from the named source reaches the sandboxed server and is answered"; else bad "the named source reaches the server" "$(pm_describe)"; fi
wait "$ACCEPT_PID"
if [[ "$(grep -c 'SERVER-GOT' "$ACCEPT_OUT")" == 1 ]] && grep -q 'SERVER-GOT from-127.0.0.1' "$ACCEPT_OUT"; then ok "and the server saw exactly the one allowed connection, never the refused one"; else bad "the server saw only the allowed connection" "$(cat "$ACCEPT_OUT")"; fi
c_accept_net="$(accept_cfg acceptnet "from 127.0.0.0/24")"
accept_start "$c_accept_net"
accept_client 127.0.0.2
if grep -q '^REPLY pong' "$PM_OUT"; then ok "a CIDR source admits an address inside it"; else bad "a CIDR source admits an address inside it" "$(pm_describe)"; fi
wait "$ACCEPT_PID"
c_accept_nosrc="$(accept_cfg acceptnosrc "from")"
accept_start "$c_accept_nosrc"
accept_client 127.0.0.1
if accept_closed_without_answer; then ok "a rule that names no source admits nobody, not even the loopback"; else bad "a rule with no source admits nobody" "$(pm_describe)"; fi
wait "$ACCEPT_PID"
if [[ "$(grep -c 'SERVER-GOT' "$ACCEPT_OUT")" == 0 ]]; then ok "and the server never saw a connection"; else bad "the server saw no connection" "$(cat "$ACCEPT_OUT")"; fi
c_accept_nofrom="$(accept_cfg acceptnofrom "")"
run_pm --config "$c_accept_nofrom" -- "$P" cwd
if (( PM_STATUS == PHB_EPOLICY )) && ! grep -q '^START' "$PM_OUT"; then ok "a rule that leaves out the word from is refused as a policy error, not read as open to everyone"; else bad "an accept rule without from is refused" "$(pm_describe)"; fi
accept_start "$c_accept_one" --no-networksystem-restriction
accept_client 127.0.0.1
if ! op_ok connect && op_failed_with connect ECONNREFUSED; then ok "with the network layer off no filter is started, so the public port is closed"; else bad "no filter with the network layer off" "$(pm_describe)"; fi
wait "$ACCEPT_PID"
if grep -q 'inbound filter from an \[accept\] rule IGNORED' "$PM/out/accept.err"; then ok "and the run says so rather than quietly dropping the rule"; else bad "the run says the filter is ignored" "$(cat "$PM/out/accept.err")"; fi
accept_client 127.0.0.1
if op_failed_with connect ECONNREFUSED; then ok "once the run has ended the public port is released and nothing answers on it"; else bad "the public port is released after the run" "$(pm_describe)"; fi
deny_case "the command cannot bind the public port itself, only the backend port its policy names" net "$c_accept_one" bind_tcp "$DENIED_ERRNOS" -- "$P" bind 127.0.0.1 "$PUBLIC_PORT" tcp

echo
echo "== names in [connect] =="
c_name="$(cfg name <<EOF2
[connect]
allow allowed.example:$PORT_A
EOF2
)"
run_pm --config "$c_name" -- "$P" read "$PM/ro/data.txt"
if (( PM_STATUS == 15 )) && ! grep -q '^START' "$PM_OUT" && grep -q "no resolver" "$PM_ERR"; then ok "an exact name with no resolver refuses the run before the command starts"; else bad "an exact name with no resolver refuses the run" "$(pm_describe)"; fi
c_wild="$(cfg wild <<EOF2
[connect]
allow *.example.org:443
EOF2
)"
run_pm --config "$c_wild" -- "$P" read "$PM/ro/data.txt"
if (( PM_STATUS == 11 )) && ! grep -q '^START' "$PM_OUT"; then ok "a wildcard host name is refused as a policy error"; else bad "a wildcard host name is refused" "$(pm_describe)"; fi
run_pm --no-networksystem-restriction --config "$c_wild" -- "$P" read "$PM/ro/data.txt"
if (( PM_STATUS == 11 )) && ! grep -q '^START' "$PM_OUT"; then ok "and still refused with the network layer switched off, since validation does not depend on enforcement"; else bad "a wildcard is still refused with the network layer off" "$(pm_describe)"; fi
c_udpname="$(cfg udpname <<EOF2
[connect]
allow dns.example:53 udp
EOF2
)"
run_pm --config "$c_udpname" -- "$P" read "$PM/ro/data.txt"
if (( PM_STATUS == 15 )) && ! grep -q '^START' "$PM_OUT"; then ok "a udp rule that names a host with no resolver refuses the run"; else bad "a udp host name with no resolver refuses the run" "$(pm_describe)"; fi
run_pm --resolver 127.0.0.1:1 --config "$c_udpname" -- "$P" read "$PM/ro/data.txt"
if (( PM_STATUS == 15 )) && ! grep -q '^START' "$PM_OUT"; then ok "and so does a resolver that does not answer, within the run's own time"; else bad "a resolver that does not answer refuses the run" "$(pm_describe)"; fi

# The broker, end to end, with a stub name server, a real TLS backend and a decoy.
if ! command -v openssl > /dev/null || ! command -v haproxy > /dev/null || [[ ! -w /etc/hosts ]]; then
  skip "the egress broker end to end" "openssl, haproxy or a writable /etc/hosts is missing"
else
  gcc-14 -O2 -o "$PM/bin/stubdns" "${PM_HERE}/stubdns.c" 2>/dev/null
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$PM/out/key.pem" -out "$PM/out/cert.pem" -subj /CN=allowed.example -days 1 > /dev/null 2>&1
  TLS_PORT=39451
  "$PM/bin/stubdns" 39450 400 > "$PM/out/dns.log" 2>&1 &
  pids+=("$!")
  wait_for_line "$PM/out/dns.log" STUB-UP 50
  openssl s_server -accept "127.0.0.1:${TLS_PORT}" -cert "$PM/out/cert.pem" -key "$PM/out/key.pem" -www > "$PM/out/backend.log" 2>&1 < /dev/null &
  pids+=("$!")
  decoy_pid="$(start_tcp_server 127.0.0.3 "$TLS_PORT" 60 120)"
  pids+=("$decoy_pid")
  require_started "the decoy server on 127.0.0.3:${TLS_PORT}" "$decoy_pid"
  decoy_log="$PM/out/server-127.0.0.3-${TLS_PORT}.log"
  plain_pid="$(start_tcp_server 127.0.0.2 "$TLS_PORT" 60 120)"
  pids+=("$plain_pid")
  require_started "the plain server on 127.0.0.2:${TLS_PORT}" "$plain_pid"
  plain_log="$PM/out/server-127.0.0.2-${TLS_PORT}.log"
  sleep 1
  c_tls="$(cfg tls <<EOF2
[connect]
allow allowed.example:$TLS_PORT
EOF2
)"
  # One HTTPS request to the address given with the TLS name given, from inside the sandbox. The backend answers
  # a request with a page that says what it is, which is the independent proof that the backend, and no other
  # server, was reached and spoke.
  page="Ciphers supported in s_server"
  request() {
    run_pm --resolver 127.0.0.1:39450 --config "$c_tls" -- /bin/sh -c "printf 'GET / HTTP/1.0\r\n\r\n' | /usr/bin/openssl s_client -ign_eof -connect $1 $2; echo CLIENT-DONE"
  }
  request "allowed.example:${TLS_PORT}" "-servername allowed.example"
  if grep -q "$page" "$PM_OUT"; then ok "a connection whose TLS name is the allowed one reaches the backend the resolver named, which answers"; else bad "an allowed TLS name reaches the backend" "$(pm_describe)"; fi
  run_direct /bin/sh -c "printf 'GET / HTTP/1.0\r\n\r\n' | /usr/bin/openssl s_client -ign_eof -connect 127.0.0.1:${TLS_PORT} -servername other.example"
  if grep -q "$page" "$PM_OUT"; then ok "the backend itself answers a request with another TLS name, so the broker is what cuts it off"; else bad "the backend answers another TLS name when reached directly" "$(pm_describe)"; fi
  run_direct /bin/sh -c "printf 'GET / HTTP/1.0\r\n\r\n' | /usr/bin/openssl s_client -ign_eof -connect 127.0.0.1:${TLS_PORT} -noservername"
  if grep -q "$page" "$PM_OUT"; then ok "and answers a request with no TLS name too"; else bad "the backend answers a request with no TLS name when reached directly" "$(pm_describe)"; fi
  request "allowed.example:${TLS_PORT}" "-servername other.example"
  if grep -q '^CONNECTED' "$PM_OUT" && grep -q '^CLIENT-DONE' "$PM_OUT" && ! grep -q "$page" "$PM_OUT"; then ok "a connection whose TLS name is another one is cut off after it connected, the backend never answers"; else bad "another TLS name is cut off" "$(pm_describe)"; fi
  request "allowed.example:${TLS_PORT}" "-noservername"
  if grep -q '^CONNECTED' "$PM_OUT" && grep -q '^CLIENT-DONE' "$PM_OUT" && ! grep -q "$page" "$PM_OUT"; then ok "a connection that names no TLS name at all is cut off after it connected"; else bad "a connection with no TLS name is cut off" "$(pm_describe)"; fi
  plain_before="$(hits "$plain_log" SERVER-GOT)"
  run_direct "$P" tcp 127.0.0.2 "$TLS_PORT"
  plain_control="$(( $(hits "$plain_log" SERVER-GOT) - plain_before ))"
  plain_before="$(hits "$plain_log" SERVER-GOT)"
  run_pm --resolver 127.0.0.1:39450 --config "$c_tls" -- "$P" tcp 127.0.0.2 "$TLS_PORT"
  sleep 1
  if (( plain_control == 1 )) && grep -q '^START' "$PM_OUT" && [[ -n "$(op_result connect)" ]] && (( $(hits "$plain_log" SERVER-GOT) == plain_before )) && ! grep -q 'REPLY pong' "$PM_OUT"; then ok "a plain connection with no ClientHello never reaches a listening server at the address it named (the unprotected control did)"; else bad "a plain connection is not forwarded" "control reached the server ${plain_control} times: $(pm_describe)"; fi
  decoy_before="$(hits "$decoy_log" SERVER-GOT)"
  request "127.0.0.3:${TLS_PORT}" "-servername allowed.example"
  sleep 1
  if grep -q "$page" "$PM_OUT" && (( $(hits "$decoy_log" SERVER-GOT) == decoy_before )); then ok "an allowed TLS name with a forged destination reaches the backend the resolver named, never the decoy it was aimed at"; else bad "a forged destination cannot redirect the connection" "decoy $(hits "$decoy_log" SERVER-GOT) vs $decoy_before; $(pm_describe)"; fi
  request "allowed.example:${TLS_PORT}" "-servername ALLOWED.EXAMPLE"
  if grep -q "$page" "$PM_OUT"; then ok "the TLS name is matched without regard to case, as names are"; else bad "the TLS name is matched without regard to case" "$(pm_describe)"; fi
fi

finish
