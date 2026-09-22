#!/usr/bin/env bash
# Tests how build_network_args turns a network allow-list into Landlock TCP-port rules.
#
# Landlock enforces ports, not hosts. The policy is therefore "both": a concrete port is
# enforced by the kernel, a loopback host with no port is tolerated because the no-network
# container is its boundary, and a non-loopback host with no port is refused rather than
# left to the connect guard alone. This suite pins each of those, in both directions.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=harness.sh
source "${HERE}/harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../core"
# shellcheck source=../core/phobos-constants.sh
source "${CORE}/phobos-constants.sh"
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# Runs build_network_args over a rules body in a subshell, so a policy refusal (which exits)
# is captured rather than ending this suite. Prints "<exit>|<args>|<log>".
run_rules() {
  local body=$1
  printf '%s\n' "$body" > "$WORK/net.rules"
  local out
  out="$(
    # shellcheck source=../core/phobos-common.sh
    source "${CORE}/phobos-common.sh"
    args=()
    build_network_args args "$WORK/net.rules" 2>"$WORK/log"
    printf '%s' "${args[*]}"
  )"
  local rc=$?
  printf '%s|%s|%s' "$rc" "$out" "$(tr '\n' ' ' <"$WORK/log")"
}

field() { cut -d'|' -f"$2" <<<"$1"; }

echo "== a concrete port is enforced by the kernel =="
r="$(run_rules "example.com 443")"
check_rc="$(field "$r" 1)"
check_args="$(field "$r" 2)"
[[ "$check_rc" == 0 ]] && ok "an external concrete port is accepted" || bad "an external concrete port is accepted" "exit 0" "exit $check_rc"
[[ "$check_args" == "--connect-tcp 443" ]] && ok "it emits --connect-tcp for the port" || bad "it emits --connect-tcp for the port" "--connect-tcp 443" "$check_args"

r="$(run_rules "127.0.0.1 8080")"
[[ "$(field "$r" 2)" == "--connect-tcp 8080" ]] && ok "a loopback concrete port is enforced too" || bad "a loopback concrete port is enforced too" "--connect-tcp 8080" "$(field "$r" 2)"

echo
echo "== a loopback host with no port is tolerated, the layer stays off =="
r="$(run_rules "127.0.0.1 *
::1 *")"
[[ "$(field "$r" 1)" == 0 && -z "$(field "$r" 2)" ]] && ok "loopback wildcards emit no port rule" || bad "loopback wildcards emit no port rule" "exit 0, no args" "exit $(field "$r" 1), args [$(field "$r" 2)]"
[[ "$(field "$r" 3)" == *"network layer stays off"* ]] && ok "and it says the layer stays off" || bad "and it says the layer stays off" "a log line saying the layer stays off" "$(field "$r" 3)"

echo
echo "== a non-loopback host with no port is refused =="
# report() writes the refusal to stderr, which run_rules captures in field 3.
r="$(run_rules "example.com *")"
if [[ "$(field "$r" 1)" == "${PHB_EPOLICY}" && "$(field "$r" 3)" == *"names a host with no port"* ]]; then
  ok "an external wildcard is refused with PHB-EPOLICY"
else
  bad "an external wildcard is refused with PHB-EPOLICY" "exit ${PHB_EPOLICY} naming the unenforceable host" "exit $(field "$r" 1): $(field "$r" 3)"
fi
if [[ -z "$(field "$r" 2)" ]]; then
  ok "the refusal leaves stdout empty"
else
  bad "the refusal leaves stdout empty" "no output on stdout" "$(field "$r" 2)"
fi

echo
echo "== a loopback wildcard mixed with a concrete port is refused =="
r="$(run_rules "127.0.0.1 *
example.com 443")"
if [[ "$(field "$r" 1)" != 0 && "$(field "$r" 3)" == *"half-enforced"* ]]; then
  ok "the mixed case is refused"
else
  bad "the mixed case is refused" "a non-zero exit naming the half-enforced policy" "exit $(field "$r" 1): $(field "$r" 3)"
fi

echo
echo "== an out-of-range port is refused =="
r="$(run_rules "example.com 70000")"
[[ "$(field "$r" 1)" != 0 ]] && ok "a port above 65535 is refused" || bad "a port above 65535 is refused" "a non-zero exit" "exit $(field "$r" 1)"

# Runs build_bind_args over a bind-rules body (one port per line) in a subshell, so a policy
# refusal (which exits) is captured. Prints "<exit>|<args>|<log>".
run_bind() {
  local body=$1
  printf '%s\n' "$body" > "$WORK/bind.rules"
  local out
  out="$(
    # shellcheck source=../core/phobos-common.sh
    source "${CORE}/phobos-common.sh"
    args=()
    build_bind_args args "$WORK/bind.rules" 2>"$WORK/blog"
    printf '%s' "${args[*]}"
  )"
  local rc=$?
  printf '%s|%s|%s' "$rc" "$out" "$(tr '\n' ' ' <"$WORK/blog")"
}

echo
echo "== [bind] emits one --bind-tcp per port; build_bind_args ignores the host field =="
r="$(run_bind "* 8080")"
[[ "$(field "$r" 1)" == 0 && "$(field "$r" 2)" == "--bind-tcp 8080" ]] && ok "a bind port emits --bind-tcp" || bad "a bind port emits --bind-tcp" "--bind-tcp 8080" "exit $(field "$r" 1): $(field "$r" 2)"
r="$(run_bind "* 9000
* 8080")"
[[ "$(field "$r" 2)" == "--bind-tcp 8080 --bind-tcp 9000" ]] && ok "several bind ports are sorted and each enforced" || bad "several bind ports are sorted and each enforced" "--bind-tcp 8080 --bind-tcp 9000" "$(field "$r" 2)"
r="$(run_bind "127.0.0.1 8080
0.0.0.0 8080")"
[[ "$(field "$r" 2)" == "--bind-tcp 8080" ]] && ok "two local addresses on one port collapse to one Landlock rule" || bad "two local addresses on one port collapse to one Landlock rule" "--bind-tcp 8080" "$(field "$r" 2)"

echo
echo "== an out-of-range bind port is refused =="
r="$(run_bind "* 70000")"
[[ "$(field "$r" 1)" != 0 ]] && ok "a bind port above 65535 is refused" || bad "a bind port above 65535 is refused" "a non-zero exit" "exit $(field "$r" 1)"

echo
echo "== a [connect] name rule needs the egress broker; the network layer refuses it otherwise =="
# The connect guard enforces a [connect] rule by address and port. A rule that names a host only
# constrains the onward address when the egress broker checks the TLS host name, so without the
# broker the network layer refuses the name rule rather than widen it to any address on the port.
# The guard binary is deliberately absent: the name check runs before the guard check, so a name
# rule is refused there, while an address rule passes the name check and reaches the guard check,
# a different PHB-ERUNTIME with its own message. That contrast shows the first refusal is the name
# check, not a blanket one.
name_spec="$(mktemp -d "$WORK/name-spec.XXXXXX")"
printf 'example.test 443\n' > "$name_spec/net.rules"
name_out="$(bash "$CORE/phobos-network.sh" --connect-guard-bin /nonexistent-guard "$name_spec" -- true 2>&1)"
name_rc=$?
if [[ "$name_rc" -eq "$PHB_ERUNTIME" && "$name_out" == *"--egress-broker"* ]]; then
  ok "a [connect] name rule without the egress broker is refused (PHB-ERUNTIME)"
else
  bad "a [connect] name rule without the egress broker is refused (PHB-ERUNTIME)" "exit ${PHB_ERUNTIME} naming --egress-broker" "exit ${name_rc}: ${name_out}"
fi

addr_spec="$(mktemp -d "$WORK/addr-spec.XXXXXX")"
printf '127.0.0.1 443\n' > "$addr_spec/net.rules"
addr_out="$(bash "$CORE/phobos-network.sh" --connect-guard-bin /nonexistent-guard "$addr_spec" -- true 2>&1)"
addr_rc=$?
if [[ "$addr_rc" -eq "$PHB_ERUNTIME" && "$addr_out" == *"connect guard"* && "$addr_out" != *"--egress-broker"* ]]; then
  ok "an address [connect] rule passes the name check and is left to the guard"
else
  bad "an address [connect] rule passes the name check and is left to the guard" "exit ${PHB_ERUNTIME} about the connect guard, not --egress-broker" "exit ${addr_rc}: ${addr_out}"
fi

finish
