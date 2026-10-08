#!/usr/bin/env bash
# Tests how build_network_args turns a network allow-list into Landlock TCP-port rules.
#
# Landlock enforces ports, not hosts. The policy is therefore "both": a concrete port is
# enforced by the kernel, a loopback host with no port is tolerated because the no-network
# container is its boundary, and a non-loopback host with no port is refused rather than
# left to the connect guard alone. This suite pins each of those, in both directions.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../../src"
# shellcheck source=../../../src/phobos-tools-common/phobos-constants.sh
source "${CORE}/phobos-tools-common/phobos-constants.sh"
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
# The scratch directory the port-rule builders make their files in, which the network layer
# sets beneath its specification directory; the helpers refuse to run without one.
export PHOBOS_SCRATCH="$WORK/scratch"
mkdir -p "$PHOBOS_SCRATCH"

# Runs build_network_args over a rules body in a subshell, so a policy refusal (which exits)
# is captured rather than ending this suite. Prints "<exit>|<args>|<log>".
run_rules() {
  local body=$1
  printf '%s\n' "$body" > "$WORK/net.rules"
  local out
  out="$(
    # shellcheck source=../../../src/phobos-tools-common/phobos-common.sh
    source "${CORE}/phobos-tools-common/phobos-common.sh"
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
echo "== every spelling of a single loopback address with no port is tolerated =="
for host in localhost 127.0.0.1 127.7.7.7 127.0.0.1/32 127.0.0.0 127.255.255.255 ::1 ::FFFF:7F00:1 0:0:0:0:0:0:0:1 0000:0000:0000:0000:0000:0000:0000:0001 ::ffff:127.0.0.1 ::ffff:7f00:1 ::ffff:127.9.9.9/128 ::1/128; do
  r="$(run_rules "${host} *")"
  if [[ "$(field "$r" 1)" == 0 && -z "$(field "$r" 2)" && "$(field "$r" 3)" == *"network layer stays off"* ]]; then
    ok "${host} with no port is loopback, and the layer stays off"
  else
    bad "${host} with no port is loopback, and the layer stays off" "exit 0, no args, the layer stays off" "exit $(field "$r" 1): $(field "$r" 3)"
  fi
done

echo
echo "== what only starts like loopback, or is wider than one address, is not loopback =="
# 127.0.0.1/1 is half the IPv4 space to the connect guard, 127.evil.example is a name a resolver may map anywhere, and a
# range of loopback is more than one address; none of them may stretch the tolerance for a loopback rule with no port.
for host in 127.0.0.1/1 127.0.0.0/8 127.0.0.1/31 127.evil.example 127.0.0.1.example.org 128.0.0.1 126.255.255.255 0.0.0.0 ::2 ::1/64 ::/0 ::ffff:128.0.0.1 ::ffff:127.0.0.1/96 ::ffff:0:1 1::1 localhost.example.org localhost/8 127.0.0.1/ ::1/ localhost/; do
  r="$(run_rules "${host} *")"
  if [[ "$(field "$r" 1)" == "${PHB_EPOLICY}" && "$(field "$r" 3)" == *"names a host with no port"* && -z "$(field "$r" 2)" ]]; then
    ok "${host} with no port is refused with PHB-EPOLICY"
  else
    bad "${host} with no port is refused with PHB-EPOLICY" "exit ${PHB_EPOLICY} naming the unenforceable host" "exit $(field "$r" 1): $(field "$r" 3)"
  fi
done
r="$(run_rules "127.0.0.1/1 8080")"
[[ "$(field "$r" 1)" == 0 && "$(field "$r" 2)" == "--connect-tcp 8080" ]] && ok "a range of loopback addresses is still fine with a concrete port" || bad "a range of loopback addresses is still fine with a concrete port" "--connect-tcp 8080" "exit $(field "$r" 1): $(field "$r" 2) $(field "$r" 3)"
r="$(run_rules "127.evil.example 443")"
[[ "$(field "$r" 1)" == 0 && "$(field "$r" 2)" == "--connect-tcp 443" ]] && ok "and a name that starts like loopback is still an ordinary name with a concrete port" || bad "and a name that starts like loopback is still an ordinary name with a concrete port" "--connect-tcp 443" "exit $(field "$r" 1): $(field "$r" 2) $(field "$r" 3)"

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
echo "== a loopback wildcard beside a concrete port is accepted, and the guard alone enforces the port =="
r="$(run_rules "127.0.0.1 *
example.com 443")"
if [[ "$(field "$r" 1)" == 0 && -z "$(field "$r" 2)" ]]; then
  ok "the mixed case is accepted and emits no Landlock port rule, so loopback stays open on every port"
else
  bad "the mixed case is accepted and emits no Landlock port rule" "exit 0, no args" "exit $(field "$r" 1), args [$(field "$r" 2)]: $(field "$r" 3)"
fi
if [[ "$(field "$r" 3)" == *"network layer stays off"* && "$(field "$r" 3)" == *"tcp ports 443"* && "$(field "$r" 3)" == *"connect guard alone enforces them"* ]]; then
  ok "and the log says the layer stays off and that the guard alone enforces port 443"
else
  bad "and the log says the guard alone enforces the port" "a log line naming port 443 and the guard" "$(field "$r" 3)"
fi
r="$(run_rules "127.0.0.1 *
example.com 443
example.org 80
example.com 443")"
[[ "$(field "$r" 3)" == *"tcp ports 80 443 named beside it"* ]] && ok "the ports named in the log are sorted and listed once" || bad "the ports named in the log are sorted and listed once" "tcp ports 80 443" "$(field "$r" 3)"
r="$(run_rules "127.0.0.1 *
example.com 443 udp")"
if [[ "$(field "$r" 1)" == 0 && "$(field "$r" 2)" == "--connect-udp 443" && "$(field "$r" 3)" != *"ports 443"* ]]; then
  ok "a wildcard on one transport does not touch a concrete port on the other"
else
  bad "a wildcard on one transport does not touch a concrete port on the other" "exit 0, --connect-udp 443, no mention of 443 in the tcp line" "exit $(field "$r" 1), args [$(field "$r" 2)]: $(field "$r" 3)"
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
    # shellcheck source=../../../src/phobos-tools-common/phobos-common.sh
    source "${CORE}/phobos-tools-common/phobos-common.sh"
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
echo "== [connect] emits --connect-udp for a udp rule; tcp stays --connect-tcp =="
r="$(run_rules "8.8.8.8 53 udp")"
[[ "$(field "$r" 1)" == 0 && "$(field "$r" 2)" == "--connect-udp 53" ]] && ok "a udp connect rule emits --connect-udp" || bad "a udp connect rule emits --connect-udp" "--connect-udp 53" "exit $(field "$r" 1): $(field "$r" 2)"
r="$(run_rules "1.2.3.4 443
8.8.8.8 53 udp")"
[[ "$(field "$r" 2)" == "--connect-tcp 443 --connect-udp 53" ]] && ok "tcp and udp connect rules are emitted apart" || bad "tcp and udp connect rules are emitted apart" "--connect-tcp 443 --connect-udp 53" "$(field "$r" 2)"

echo
echo "== [bind] emits --bind-udp for a udp rule; tcp stays --bind-tcp =="
r="$(run_bind "* 5353 udp")"
[[ "$(field "$r" 2)" == "--bind-udp 5353" ]] && ok "a udp bind rule emits --bind-udp" || bad "a udp bind rule emits --bind-udp" "--bind-udp 5353" "$(field "$r" 2)"
r="$(run_bind "* 8080
* 5353 udp")"
[[ "$(field "$r" 2)" == "--bind-tcp 8080 --bind-udp 5353" ]] && ok "tcp and udp bind rules are emitted apart" || bad "tcp and udp bind rules are emitted apart" "--bind-tcp 8080 --bind-udp 5353" "$(field "$r" 2)"

# Runs add_udp_ephemeral_bind_if_needed over a whitespace-separated argument list and a net.rules
# body in a subshell.
run_ephemeral() {
  local body=$1
  local rules=$2
  printf '%s' "$rules" > "$WORK/ephemeral.rules"
  (
    # shellcheck source=../../../src/phobos-tools-common/phobos-common.sh
    source "${CORE}/phobos-tools-common/phobos-common.sh"
    # Word-splitting the body into an argument array is intended here.
    # shellcheck disable=SC2206
    args=( $body )
    add_udp_ephemeral_bind_if_needed args "$WORK/ephemeral.rules"
    printf '%s' "${args[*]}"
  )
}

echo
echo "== a udp [connect] rule brings the ephemeral udp source bind with it, and nothing else does =="
got="$(run_ephemeral "--connect-udp 53" $'8.8.8.8 53 udp\n')"
[[ "$got" == "--connect-udp 53 --ephemeral-bind-udp" ]] && ok "a udp connect rule adds the ephemeral bind grant" || bad "a udp connect rule adds the ephemeral bind grant" "--connect-udp 53 --ephemeral-bind-udp" "$got"
got="$(run_ephemeral "" $'127.0.0.1 * udp\n')"
[[ "$got" == "--ephemeral-bind-udp" ]] && ok "a wildcard udp rule, which emits no --connect-udp, adds it too" || bad "a wildcard udp rule, which emits no --connect-udp, adds it too" "--ephemeral-bind-udp" "$got"
got="$(run_ephemeral "--ephemeral-bind-udp" $'8.8.8.8 53 udp\n')"
[[ "$got" == "--ephemeral-bind-udp" ]] && ok "a grant already present is not added twice" || bad "a grant already present is not added twice" "--ephemeral-bind-udp" "$got"
got="$(run_ephemeral "--connect-tcp 443 --bind-tcp 8080" $'1.2.3.4 443\n')"
[[ "$got" == "--connect-tcp 443 --bind-tcp 8080" ]] && ok "a tcp-only policy gains no udp bind" || bad "a tcp-only policy gains no udp bind" "no --ephemeral-bind-udp" "$got"
got="$(run_ephemeral "--close-bind" "")"
[[ "$got" == "--close-bind" ]] && ok "a policy with no connect rule gains no udp bind" || bad "a policy with no connect rule gains no udp bind" "--close-bind" "$got"
got="$(run_ephemeral "--close-bind" $'# a comment 53 udp\n8.8.8.8 53\n')"
[[ "$got" == "--close-bind" ]] && ok "a comment does not count as a udp rule" || bad "a comment does not count as a udp rule" "--close-bind" "$got"

echo
echo "== a [bind] row for port 0 is the ephemeral grant, and every other port is still a port rule =="
r="$(run_bind "* 0")"
[[ "$(field "$r" 1)" == 0 && "$(field "$r" 2)" == "--ephemeral-bind-tcp" ]] && ok "port 0 emits --ephemeral-bind-tcp, not --bind-tcp 0" || bad "port 0 emits --ephemeral-bind-tcp, not --bind-tcp 0" "--ephemeral-bind-tcp" "exit $(field "$r" 1): $(field "$r" 2)"
r="$(run_bind "* 0 udp")"
[[ "$(field "$r" 2)" == "--ephemeral-bind-udp" ]] && ok "udp port 0 emits --ephemeral-bind-udp" || bad "udp port 0 emits --ephemeral-bind-udp" "--ephemeral-bind-udp" "$(field "$r" 2)"
r="$(run_bind "* 8080
* 0
* 0 udp
* 5353 udp")"
[[ "$(field "$r" 2)" == "--ephemeral-bind-tcp --bind-tcp 8080 --ephemeral-bind-udp --bind-udp 5353" ]] && ok "the grant and the port rules come out together, each transport apart" || bad "the grant and the port rules come out together, each transport apart" "--ephemeral-bind-tcp --bind-tcp 8080 --ephemeral-bind-udp --bind-udp 5353" "$(field "$r" 2)"
for refused in "* 00" "* 65536" "* 08" "* -1" "* x"; do
  r="$(run_bind "$refused")"
  [[ "$(field "$r" 1)" != 0 ]] && ok "the bind port '${refused#* }' is refused" || bad "the bind port '${refused#* }' is refused" "a non-zero exit" "exit $(field "$r" 1)"
done
r="$(run_rules "example.com 0")"
[[ "$(field "$r" 1)" != 0 ]] && ok "port 0 is still refused for a [connect] rule" || bad "port 0 is still refused for a [connect] rule" "a non-zero exit" "exit $(field "$r" 1)"

echo
echo "== the helpers the network layer reads its flags with =="
printf '* 8080\n* 0 udp\n' > "$WORK/grant.rules"
( source "${CORE}/phobos-tools-common/phobos-common.sh"; bind_rules_grant_ephemeral_tcp "$WORK/grant.rules" ) && bad "a udp port 0 row is not an ephemeral listen grant" "no grant" "granted" || ok "a udp port 0 row is not an ephemeral listen grant"
printf '* 8080\n* 0' > "$WORK/grant.rules"
( source "${CORE}/phobos-tools-common/phobos-common.sh"; bind_rules_grant_ephemeral_tcp "$WORK/grant.rules" ) && ok "a tcp port 0 row grants it, even on a last line with no newline" || bad "a tcp port 0 row grants it, even on a last line with no newline" "granted" "no grant"
printf '* 8080\n' > "$WORK/grant.rules"
( source "${CORE}/phobos-tools-common/phobos-common.sh"; bind_rules_grant_ephemeral_tcp "$WORK/grant.rules" ) && bad "explicit ports alone grant no ephemeral listen" "no grant" "granted" || ok "explicit ports alone grant no ephemeral listen"
( source "${CORE}/phobos-tools-common/phobos-common.sh"; bind_rules_grant_ephemeral_tcp "$WORK/absent.rules" ) && bad "a missing bind.rules grants nothing" "no grant" "granted" || ok "a missing bind.rules grants nothing"
printf '8.8.8.8 53 udp\n' > "$WORK/udp.rules"
printf '8.8.8.8 53\n' > "$WORK/tcp.rules"
printf '# 53 udp\n\n8.8.8.8 443\n' > "$WORK/commented.rules"
( source "${CORE}/phobos-tools-common/phobos-common.sh"; connect_rules_name_udp "$WORK/udp.rules" ) && ok "a net.rules file with a udp row names a udp [connect] rule" || bad "a net.rules file with a udp row names a udp [connect] rule" "named" "not named"
( source "${CORE}/phobos-tools-common/phobos-common.sh"; connect_rules_name_udp "$WORK/tcp.rules" ) && bad "a tcp-only net.rules names no udp rule" "none" "named" || ok "a tcp-only net.rules names no udp rule"
( source "${CORE}/phobos-tools-common/phobos-common.sh"; connect_rules_name_udp "$WORK/commented.rules" ) && bad "a comment mentioning udp is not a udp rule" "none" "named" || ok "a comment mentioning udp is not a udp rule"
( source "${CORE}/phobos-tools-common/phobos-common.sh"; connect_rules_name_udp "$WORK/absent.rules" ) && bad "a missing net.rules names no udp rule" "none" "named" || ok "a missing net.rules names no udp rule"
printf '* 0 udp\n' > "$WORK/grant.rules"
( source "${CORE}/phobos-tools-common/phobos-common.sh"; ephemeral_udp_bind_granted "$WORK/grant.rules" "$WORK/tcp.rules" ) && ok "a udp port 0 row lets the kernel choose a udp source port" || bad "a udp port 0 row lets the kernel choose a udp source port" "granted" "no grant"
printf '* 0' > "$WORK/grant.rules"
( source "${CORE}/phobos-tools-common/phobos-common.sh"; ephemeral_udp_bind_granted "$WORK/grant.rules" "$WORK/tcp.rules" ) && bad "a tcp port 0 row is not a udp source port grant" "no grant" "granted" || ok "a tcp port 0 row is not a udp source port grant"
printf '* 0 udp' > "$WORK/grant.rules"
( source "${CORE}/phobos-tools-common/phobos-common.sh"; ephemeral_udp_bind_granted "$WORK/grant.rules" "$WORK/tcp.rules" ) && ok "a udp port 0 row grants it, even on a last line with no newline" || bad "a udp port 0 row grants it, even on a last line with no newline" "granted" "no grant"
printf '* 8080 udp\n' > "$WORK/grant.rules"
( source "${CORE}/phobos-tools-common/phobos-common.sh"; ephemeral_udp_bind_granted "$WORK/grant.rules" "$WORK/udp.rules" ) && ok "any udp [connect] rule grants it, whatever [bind] names" || bad "any udp [connect] rule grants it, whatever [bind] names" "granted" "no grant"
( source "${CORE}/phobos-tools-common/phobos-common.sh"; ephemeral_udp_bind_granted "$WORK/grant.rules" "$WORK/tcp.rules" ) && bad "an explicit udp bind port and tcp rules grant no ephemeral udp bind" "no grant" "granted" || ok "an explicit udp bind port and tcp rules grant no ephemeral udp bind"
( source "${CORE}/phobos-tools-common/phobos-common.sh"; ephemeral_udp_bind_granted "$WORK/absent.rules" "$WORK/absent.rules" ) && bad "missing files grant nothing" "no grant" "granted" || ok "missing files grant nothing"
printf -- '--chdir /var/tmp/testing-dir\n--minimum-landlock-version 4\n' > "$WORK/tail.flags"
got="$( source "${CORE}/phobos-tools-common/phobos-common.sh"; tail_minimum_landlock_version "$WORK/tail.flags" )"
[[ "$got" == "4" ]] && ok "the minimum Landlock version is read from the tail flags" || bad "the minimum Landlock version is read from the tail flags" "4" "$got"
printf -- '--chdir /var/tmp/testing-dir' > "$WORK/tail.flags"
got="$( source "${CORE}/phobos-tools-common/phobos-common.sh"; tail_minimum_landlock_version "$WORK/tail.flags" )"
[[ -z "$got" ]] && ok "tail flags without it name no minimum" || bad "tail flags without it name no minimum" "nothing" "$got"
printf -- '--minimum-landlock-version abc' > "$WORK/tail.flags"
got="$( source "${CORE}/phobos-tools-common/phobos-common.sh"; tail_minimum_landlock_version "$WORK/tail.flags" )"
[[ -z "$got" ]] && ok "a minimum that is not a number is left to the enforcer to refuse" || bad "a minimum that is not a number is left to the enforcer to refuse" "nothing" "$got"
got="$( source "${CORE}/phobos-tools-common/phobos-common.sh"; tail_minimum_landlock_version "$WORK/absent.flags" )"
[[ -z "$got" ]] && ok "a missing tail.flags names no minimum" || bad "a missing tail.flags names no minimum" "nothing" "$got"

echo
echo "== a [connect] name rule starts the egress broker automatically; an exact name still needs a resolver =="
# The connect guard enforces a [connect] rule by address and port. A rule that names a host only
# constrains the onward address when the egress broker checks the TLS host name, so the network
# layer now starts the broker automatically whenever the allow-list names a host, rather than
# demanding a flag. An exact name is bound by resolving it, so without a resolver the run is still
# refused fail-closed rather than run with a name the broker cannot pin. An executable stub guard
# passes the guard-binary check so this policy refusal, not a missing-guard one, is what fires.
stub_guard="$(mktemp "$WORK/stub-guard.XXXXXX")"
printf '#!/bin/sh\nexit 0\n' > "$stub_guard"
chmod +x "$stub_guard"
name_spec="$(mktemp -d "$WORK/name-spec.XXXXXX")"
printf 'example.test 443\n' > "$name_spec/net.rules"
name_out="$(bash "$CORE/phobos-networksystem.sh" --connect-guard-bin "$stub_guard" "$name_spec" -- true 2>&1)"
name_rc=$?
if [[ "$name_rc" -eq "$PHB_ERUNTIME" && "$name_out" == *"resolver"* && "$name_out" != *"--egress-broker"* ]]; then
  ok "an exact [connect] name without a resolver is refused fail-closed (PHB-ERUNTIME)"
else
  bad "an exact [connect] name without a resolver is refused fail-closed (PHB-ERUNTIME)" "exit ${PHB_ERUNTIME} naming a resolver, not --egress-broker" "exit ${name_rc}: ${name_out}"
fi

# A wildcard host name is refused by the network layer itself, before the broker is started and
# whichever transport the row names, so a specification handed to the layer on its own, never
# having met the policy parser, cannot bring a wildcard in. Each body is written with printf %s, so
# a last row with no newline is covered too, which the guard reads with fgets and a shell loop that
# stopped at the missing newline would drop.
for wildcard_body in $'*.example.test 443\n' $'a*b.example.test 443\n' $'name.* 443\n' $'127.0.0.1 53 udp\n*.example.test 53 udp\n' $'example.test 443\n*.example.test 53 udp' $'*.example.test 443'; do
  wildcard_spec="$(mktemp -d "$WORK/wildcard-spec.XXXXXX")"
  printf '%s' "$wildcard_body" > "$wildcard_spec/net.rules"
  wildcard_out="$(bash "$CORE/phobos-networksystem.sh" --connect-guard-bin "$stub_guard" --haproxy-bin /nonexistent-haproxy --resolver 192.0.2.53 "$wildcard_spec" -- true 2>&1)"
  wildcard_rc=$?
  wildcard_label="$(printf '%s' "$wildcard_body" | tr '\n' ',')"
  if [[ "$wildcard_rc" -eq "$PHB_EPOLICY" && "$wildcard_out" == *"wildcard host name"* && "$wildcard_out" != *"egress broker is started"* ]]; then
    ok "the layer refuses '${wildcard_label}' with PHB-EPOLICY before any broker starts"
  else
    bad "the layer refuses '${wildcard_label}' with PHB-EPOLICY before any broker starts" "exit ${PHB_EPOLICY} naming a wildcard host name, no broker NOTICE" "exit ${wildcard_rc}: ${wildcard_out}"
  fi
done

bare_star_spec="$(mktemp -d "$WORK/bare-star-spec.XXXXXX")"
printf '* 443\n' > "$bare_star_spec/net.rules"
bare_star_out="$(bash "$CORE/phobos-networksystem.sh" --connect-guard-bin /nonexistent-guard "$bare_star_spec" -- true 2>&1)"
bare_star_rc=$?
if [[ "$bare_star_rc" -eq "$PHB_ERUNTIME" && "$bare_star_out" == *"connect guard"* ]]; then
  ok "the bare star is not a wildcard name and is left to the guard"
else
  bad "the bare star is not a wildcard name and is left to the guard" "exit ${PHB_ERUNTIME} about the connect guard" "exit ${bare_star_rc}: ${bare_star_out}"
fi

# Runs refuse_unenforceable_network_rules over a net.rules body in a subshell, so the refusal's exit
# is captured. Prints "<exit>|<log>".
run_refuse() {
  local body=$1
  local out
  printf '%s' "$body" > "$WORK/refuse.rules"
  : > "$WORK/refuse.bind"
  out="$(
    # shellcheck source=../../../src/phobos-tools-common/phobos-common.sh
    source "${CORE}/phobos-tools-common/phobos-common.sh"
    refuse_unenforceable_network_rules "$WORK/refuse.rules" "$WORK/refuse.bind" 2>&1
  )"
  local rc=$?
  printf '%s|%s' "$rc" "$(tr '\n' ' ' <<<"$out")"
}

echo
echo "== the merged policy refuses a wildcard host name, and still accepts a name, an address and a star =="
for wildcard_body in $'*.example.test 443\n' $'a*b.example.test 443\n' $'name.* 443\n' $'*.example.test 53 udp\n' $'example.test 443\n*.example.test 53 udp'; do
  r="$(run_refuse "$wildcard_body")"
  wildcard_label="$(printf '%s' "$wildcard_body" | tr '\n' ',')"
  if [[ "$(cut -d'|' -f1 <<<"$r")" == "${PHB_EPOLICY}" && "$(cut -d'|' -f2- <<<"$r")" == *"wildcard host name"* ]]; then
    ok "'${wildcard_label}' is refused where the specification is judged"
  else
    bad "'${wildcard_label}' is refused where the specification is judged" "exit ${PHB_EPOLICY} naming a wildcard host name" "$r"
  fi
done
r="$(run_refuse $'example.test 443\n192.0.2.10 443\n* 8443\n127.0.0.1 53 udp\n')"
[[ "$(cut -d'|' -f1 <<<"$r")" == 0 ]] && ok "an exact name, an address, a bare star and a udp address are accepted" || bad "an exact name, an address, a bare star and a udp address are accepted" "exit 0" "$r"

echo
echo "== the validator judges the host column and nothing else =="
# A tab between the columns, a carriage return at the end of a row, an upper-case name and an
# indented row are still wildcard hosts. A comment is not a row, and a star in the port column is
# the port wildcard, not a wildcard name.
for wildcard_body in $'*.example.test\t443\n' $'*.example.test 443\r\n' $'*.EXAMPLE.TEST 443\n' $'   *.example.test 443\n' $'example.test 443 # fine\n*.example.test 443 # not fine\n'; do
  r="$(run_refuse "$wildcard_body")"
  wildcard_label="$(printf '%s' "$wildcard_body" | tr '\t\r\n' '^$,')"
  if [[ "$(cut -d'|' -f1 <<<"$r")" == "${PHB_EPOLICY}" && "$(cut -d'|' -f2- <<<"$r")" == *"wildcard host name"* ]]; then
    ok "'${wildcard_label}' is refused"
  else
    bad "'${wildcard_label}' is refused" "exit ${PHB_EPOLICY} naming a wildcard host name" "$r"
  fi
done
for control_body in $'# *.example.test 443\nexample.test 443\n' $'example.test 443 # *.example.test\n' $'127.0.0.1 *\n::1 *\n'; do
  r="$(run_refuse "$control_body")"
  control_label="$(printf '%s' "$control_body" | tr '\t\r\n' '^$,')"
  if [[ "$(cut -d'|' -f1 <<<"$r")" == 0 ]]; then
    ok "'${control_label}' is accepted"
  else
    bad "'${control_label}' is accepted" "exit 0" "$r"
  fi
done

addr_spec="$(mktemp -d "$WORK/addr-spec.XXXXXX")"
printf '127.0.0.1 443\n' > "$addr_spec/net.rules"
addr_out="$(bash "$CORE/phobos-networksystem.sh" --connect-guard-bin /nonexistent-guard "$addr_spec" -- true 2>&1)"
addr_rc=$?
if [[ "$addr_rc" -eq "$PHB_ERUNTIME" && "$addr_out" == *"connect guard"* && "$addr_out" != *"--egress-broker"* ]]; then
  ok "an address [connect] rule needs no broker and is left to the guard"
else
  bad "an address [connect] rule needs no broker and is left to the guard" "exit ${PHB_ERUNTIME} about the connect guard, not --egress-broker" "exit ${addr_rc}: ${addr_out}"
fi

echo
echo "== the network layer always applies the closed bind, and tells the guard what the policy grants =="
# A guard that only writes down the words it was given, and a Landlock enforcer that does nothing,
# so what the layer builds can be read without a kernel that has either.
stub_landlock="$(mktemp "$WORK/stub-landlock.XXXXXX")"
printf '#!/bin/sh\nexit 0\n' > "$stub_landlock"
chmod +x "$stub_landlock"
recording_guard="$(mktemp "$WORK/recording-guard.XXXXXX")"
cat > "$recording_guard" <<RECORDING
#!/bin/sh
for word in "\$@"; do printf '%s\n' "\$word"; done > "$WORK/guard-args"
exit 0
RECORDING
chmod +x "$recording_guard"

# Runs the layer over a net.rules body, a bind.rules body and optional tail flags, and prints the
# words the layer handed the guard on one line.
layer_arguments() {
  local spec
  spec="$(mktemp -d "$WORK/layer-spec.XXXXXX")"
  printf '%s' "$1" > "$spec/net.rules"
  printf '%s' "$2" > "$spec/bind.rules"
  printf '%s' "${3:-}" > "$spec/tail.flags"
  rm -f "$WORK/guard-args"
  bash "$CORE/phobos-networksystem.sh" --connect-guard-bin "$recording_guard" --landlock-bin "$stub_landlock" "$spec" -- true > /dev/null 2>&1
  tr '\n' ' ' < "$WORK/guard-args"
}

got="$(layer_arguments "" "")"
if [[ "$got" == *" --no-filesystem --close-bind "* && "$got" != *"--allow-ephemeral-listen"* && "$got" != *"--bind-tcp"* ]]; then
  ok "a policy that names nothing still runs the enforcer with the bind closed, and allows no unbound listen"
else
  bad "a policy that names nothing still runs the enforcer with the bind closed, and allows no unbound listen" "--no-filesystem --close-bind, no grant" "$got"
fi
got="$(layer_arguments "" $'* 0\n')"
if [[ "$got" == *"--ephemeral-bind-tcp"* && "$got" == *"--allow-ephemeral-listen "*"--rules "* ]]; then
  ok "a [bind] port 0 row grants the ephemeral bind and tells the guard an unbound listen is no wider"
else
  bad "a [bind] port 0 row grants the ephemeral bind and tells the guard an unbound listen is no wider" "--ephemeral-bind-tcp and --allow-ephemeral-listen before --rules" "$got"
fi
got="$(layer_arguments "" $'* 8080\n')"
if [[ "$got" == *"--bind-tcp 8080"* && "$got" != *"--ephemeral-bind-tcp"* && "$got" != *"--allow-ephemeral-listen"* ]]; then
  ok "an explicit [bind] port grants that port only, and an unbound listen stays refused"
else
  bad "an explicit [bind] port grants that port only, and an unbound listen stays refused" "--bind-tcp 8080, no ephemeral grant" "$got"
fi
got="$(layer_arguments "" $'* 0 udp\n')"
if [[ "$got" == *"--ephemeral-bind-udp"* && "$got" != *"--allow-ephemeral-listen"* ]]; then
  ok "a udp port 0 row grants the udp bind only, a listener is TCP"
else
  bad "a udp port 0 row grants the udp bind only, a listener is TCP" "--ephemeral-bind-udp, no --allow-ephemeral-listen" "$got"
fi
got="$(layer_arguments $'127.0.0.1 * udp\n' "")"
if [[ "$got" == *"--ephemeral-bind-udp"* ]]; then
  ok "a udp [connect] rule brings the ephemeral udp bind with it, for the source port of a send"
else
  bad "a udp [connect] rule brings the ephemeral udp bind with it, for the source port of a send" "--ephemeral-bind-udp" "$got"
fi
got="$(layer_arguments $'127.0.0.1 * udp\n' "")"
if [[ "$got" == *"--allow-ephemeral-udp-bind "*"--rules "* ]]; then
  ok "a udp [connect] rule tells the guard an unbound datagram socket may connect and send"
else
  bad "a udp [connect] rule tells the guard an unbound datagram socket may connect and send" "--allow-ephemeral-udp-bind before --rules" "$got"
fi
got="$(layer_arguments "" $'* 0 udp\n')"
if [[ "$got" == *"--allow-ephemeral-udp-bind "*"--rules "* ]]; then
  ok "a udp port 0 row tells the guard the same"
else
  bad "a udp port 0 row tells the guard the same" "--allow-ephemeral-udp-bind before --rules" "$got"
fi
got="$(layer_arguments $'1.2.3.4 443\n' $'* 8080\n')"
if [[ "$got" != *"--allow-ephemeral-udp-bind"* ]]; then
  ok "a policy with no udp rule and no udp port 0 leaves an unbound datagram socket refused"
else
  bad "a policy with no udp rule and no udp port 0 leaves an unbound datagram socket refused" "no --allow-ephemeral-udp-bind" "$got"
fi
# A udp rule that names a host is resolved once before the command starts. The cases here stop the
# run before it reaches /etc/hosts, so they change nothing on the machine: a layer given no
# resolver, and a guard whose lookup fails, each refuse the run and never start the command.
failing_resolve_guard="$(mktemp "$WORK/failing-resolve-guard.XXXXXX")"
cat > "$failing_resolve_guard" <<FAILING
#!/bin/sh
for word in "\$@"; do printf '%s\n' "\$word"; done > "$WORK/guard-args"
exit 125
FAILING
chmod +x "$failing_resolve_guard"
udp_name_spec="$(mktemp -d "$WORK/udp-name-spec.XXXXXX")"
printf 'dns.example 53 udp\n' > "$udp_name_spec/net.rules"
rm -f "$WORK/guard-args"
udp_out="$(bash "$CORE/phobos-networksystem.sh" --connect-guard-bin "$recording_guard" --landlock-bin "$stub_landlock" "$udp_name_spec" -- true 2>&1)"
udp_rc=$?
if [[ $udp_rc -eq "${PHB_ERUNTIME}" && "$udp_out" == *"names a host (dns.example)"*"no resolver was given"* && ! -e "$WORK/guard-args" ]]; then
  ok "a udp rule that names a host with no resolver given refuses the run before the guard is asked anything"
else
  bad "a udp rule that names a host with no resolver given refuses the run before the guard is asked anything" "PHB-ERUNTIME, no resolver, guard unused" "exit $udp_rc: $udp_out"
fi
udp_name_spec="$(mktemp -d "$WORK/udp-name-spec.XXXXXX")"
printf 'dns.example 53 udp\nother.example 5353 udp\n8.8.8.8 53 udp\n' > "$udp_name_spec/net.rules"
udp_out="$(bash "$CORE/phobos-networksystem.sh" --connect-guard-bin "$failing_resolve_guard" --landlock-bin "$stub_landlock" --resolver 192.0.2.53:5353 "$udp_name_spec" -- true 2>&1)"
udp_rc=$?
got="$(tr '\n' ' ' < "$WORK/guard-args")"
if [[ $udp_rc -eq "${PHB_ERUNTIME}" && "$udp_out" == *"could not be resolved through 192.0.2.53:5353"* ]]; then
  ok "a guard whose lookup fails refuses the run"
else
  bad "a guard whose lookup fails refuses the run" "PHB-ERUNTIME, could not be resolved" "exit $udp_rc: $udp_out"
fi
if [[ "$got" == "--resolve --resolver 192.0.2.53:5353 -- dns.example other.example " ]]; then
  ok "the guard is asked in resolve mode, through the given resolver, for each name once and for no address"
else
  bad "the guard is asked in resolve mode, through the given resolver, for each name once and for no address" "--resolve --resolver 192.0.2.53:5353 -- dns.example other.example" "$got"
fi
# The guard keeps 256 rules and drops the rest without a word, so a lookup that would grow the rules
# past that is refused before /etc/hosts is touched. The number is the guard's, read from its header.
guard_maximum="$(sed -n 's/.*MAXIMUM_RULES = \([0-9]*\);.*/\1/p' "$CORE/phobos-seccomp-networksystem/phobos-seccomp-networksystem-rules.h")"
[[ "$guard_maximum" == "$PHB_GUARD_RULES_MAXIMUM" ]] && ok "the layer's limit on the guard's rules is the guard's own" \
  || bad "the layer's limit on the guard's rules is the guard's own" "$guard_maximum" "$PHB_GUARD_RULES_MAXIMUM"
many_resolve_guard="$(mktemp "$WORK/many-resolve-guard.XXXXXX")"
cat > "$many_resolve_guard" <<'MANY'
#!/bin/sh
while [ "$1" != "--" ]; do shift; done
shift
for name in "$@"; do
  n=1
  while [ "$n" -le 16 ]; do printf '%s 198.51.100.%s\n' "$name" "$n"; n=$((n + 1)); done
done
MANY
chmod +x "$many_resolve_guard"
udp_name_spec="$(mktemp -d "$WORK/udp-name-spec.XXXXXX")"
: > "$udp_name_spec/net.rules"
for count in $(seq 1 17); do printf 'host%s.example 53 udp\n' "$count" >> "$udp_name_spec/net.rules"; done
udp_out="$(bash "$CORE/phobos-networksystem.sh" --connect-guard-bin "$many_resolve_guard" --landlock-bin "$stub_landlock" --resolver 192.0.2.53 "$udp_name_spec" -- true 2>&1)"
udp_rc=$?
if [[ $udp_rc -eq "${PHB_ERUNTIME}" && "$udp_out" == *"gives 272 rules, and the connect guard keeps 256"* ]]; then
  ok "seventeen names of sixteen addresses give more rules than the guard keeps, and the run is refused"
else
  bad "seventeen names of sixteen addresses give more rules than the guard keeps, and the run is refused" "PHB-ERUNTIME, 272 rules" "exit $udp_rc: $udp_out"
fi
got="$(layer_arguments "" "" $'--chdir /x\n--minimum-landlock-version 4\n')"
if [[ "$got" == *"--minimum-landlock-version 4 "* ]]; then
  ok "the operator's minimum Landlock version reaches the network layer's own enforcer call"
else
  bad "the operator's minimum Landlock version reaches the network layer's own enforcer call" "--minimum-landlock-version 4" "$got"
fi
missing_spec="$(mktemp -d "$WORK/missing-landlock.XXXXXX")"
missing_out="$(bash "$CORE/phobos-networksystem.sh" --connect-guard-bin "$recording_guard" --landlock-bin /nonexistent-landlock "$missing_spec" -- true 2>&1)"
missing_rc=$?
if [[ "$missing_rc" -eq "$PHB_ERUNTIME" && "$missing_out" == *"closed bind"* ]]; then
  ok "a run with no Landlock enforcer is refused, even with a policy that names no port"
else
  bad "a run with no Landlock enforcer is refused, even with a policy that names no port" "exit ${PHB_ERUNTIME} naming the closed bind" "exit ${missing_rc}: ${missing_out}"
fi

finish
