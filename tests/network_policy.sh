#!/usr/bin/env bash
# Tests how build_network_args turns a network allow-list into Landlock TCP-port rules.
#
# Landlock enforces ports, not hosts. The policy is therefore "both": a concrete port is
# enforced by the kernel, a loopback host with no port is tolerated because the no-network
# container is its boundary, and a non-loopback host with no port is refused rather than
# left to the preload library, which a submission can step around. This suite pins each of
# those, in both directions.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="${HERE}/../core"
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

passed=0
failed=0
ok()  { printf 'ok    %s\n' "$1"; passed=$((passed + 1)); }
bad() { printf 'FAIL  %s\n        expected: %s\n        actual:   %s\n' "$1" "$2" "$3"; failed=$((failed + 1)); }

# Runs build_network_args over a rules body in a subshell, so a policy refusal (which exits)
# is captured rather than ending this suite. Prints "<exit>|<args>|<log>".
run_rules() {
  local body=$1
  printf '%s\n' "$body" > "$WORK/net.rules"
  local out
  out="$(
    # shellcheck source=/dev/null
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
check_rc="$(field "$r" 1)"; check_args="$(field "$r" 2)"
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
# report() writes the refusal to stdout, which run_rules captures in field 2.
r="$(run_rules "example.com *")"
if [[ "$(field "$r" 1)" == "${PHB_EPOLICY:-11}" && "$(field "$r" 2)" == *"names a host with no port"* ]]; then
  ok "an external wildcard is refused with PHB-EPOLICY"
else
  bad "an external wildcard is refused with PHB-EPOLICY" "exit 11 naming the unenforceable host" "exit $(field "$r" 1): $(field "$r" 2)"
fi

echo
echo "== a loopback wildcard mixed with a concrete port is refused =="
r="$(run_rules "127.0.0.1 *
example.com 443")"
if [[ "$(field "$r" 1)" != 0 && "$(field "$r" 2)" == *"half-enforced"* ]]; then
  ok "the mixed case is refused"
else
  bad "the mixed case is refused" "a non-zero exit naming the half-enforced policy" "exit $(field "$r" 1): $(field "$r" 2)"
fi

echo
echo "== an out-of-range port is refused =="
r="$(run_rules "example.com 70000")"
[[ "$(field "$r" 1)" != 0 ]] && ok "a port above 65535 is refused" || bad "a port above 65535 is refused" "a non-zero exit" "exit $(field "$r" 1)"

echo
printf '%d passed, %d failed\n' "$passed" "$failed"
(( failed == 0 ))
