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
CORE="${HERE}/../../../core"
# shellcheck source=../../../core/phobos-tools-common/phobos-constants.sh
source "${CORE}/phobos-tools-common/phobos-constants.sh"
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
    # shellcheck source=../../../core/phobos-tools-common/phobos-common.sh
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
    # shellcheck source=../../../core/phobos-tools-common/phobos-common.sh
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

# Runs add_udp_ephemeral_bind_if_needed over a whitespace-separated argument list in a subshell.
run_ephemeral() {
  local body=$1
  (
    # shellcheck source=../../../core/phobos-tools-common/phobos-common.sh
    source "${CORE}/phobos-tools-common/phobos-common.sh"
    # Word-splitting the body into an argument array is intended here.
    # shellcheck disable=SC2206
    args=( $body )
    add_udp_ephemeral_bind_if_needed args
    printf '%s' "${args[*]}"
  )
}

echo
echo "== the ephemeral udp source bind is added only when both udp directions are present =="
got="$(run_ephemeral "--connect-udp 53 --bind-udp 5353")"
[[ "$got" == *"--bind-udp 0"* ]] && ok "both udp directions add --bind-udp 0 for the ephemeral source" || bad "both udp directions add --bind-udp 0 for the ephemeral source" "an argument list containing --bind-udp 0" "$got"
got="$(run_ephemeral "--connect-udp 53")"
[[ "$got" != *"--bind-udp"* ]] && ok "a connect-only udp policy adds no bind" || bad "a connect-only udp policy adds no bind" "no --bind-udp" "$got"
got="$(run_ephemeral "--connect-tcp 443 --bind-tcp 8080")"
[[ "$got" != *"--bind-udp"* ]] && ok "a tcp-only policy adds no udp bind" || bad "a tcp-only policy adds no udp bind" "no --bind-udp" "$got"

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
    # shellcheck source=../../../core/phobos-tools-common/phobos-common.sh
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

finish
