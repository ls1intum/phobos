#!/usr/bin/env bash
# Regression tests for the port authorisation the address cache records.
#
# Resolving a hostname yields addresses but no service, so a resolver reply
# carries no port authorisation of its own. The cache must therefore store the
# ports the matching policy rules grant. A rule naming one port stays limited
# to that port after the hostname behind it has been resolved, while a rule
# that deliberately permits every port keeps doing so.
#
# Every probe binds its own ephemeral loopback listener, so the checks use no
# external service and no fixed port number.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="${HERE}/../ld_preloader/netblocker.c"
PROBE_SOURCE="${HERE}/netcache_probe.c"

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

passed=0
failed=0
skipped=0

ok() {
  printf 'ok    %s\n' "$1"
  passed=$((passed + 1))
}

bad() {
  printf 'FAIL  %s\n        expected: %s\n        actual:   %s\n' "$1" "$2" "$3"
  failed=$((failed + 1))
}

skip() {
  printf 'SKIP  %s\n        reason:   %s\n' "$1" "$2"
  skipped=$((skipped + 1))
}

check() {
  local name=$1
  local want=$2
  local got=$3
  if [[ "$got" == "$want" ]]; then ok "$name"; else bad "$name" "$want" "$got"; fi
}

summary() {
  echo
  printf '%d passed, %d failed, %d skipped\n' "$passed" "$failed" "$skipped"
  if (( skipped > 0 )); then
    printf 'Skipped checks did not run and are not counted as passing.\n'
  fi
  (( failed == 0 )) || exit 1
  exit 0
}

if ! command -v gcc >/dev/null 2>&1; then
  skip "network cache port restrictions" \
       "no C compiler on this platform; these checks run on Linux"
  summary
fi

# The same build the run-phase image performs.
if ! gcc -fPIC -shared -o "$WORK/libnetblocker.so" "$SOURCE" 2>"$WORK/lib.log"; then
  bad "build the interposer" "a shared library" "$(cat "$WORK/lib.log")"
  summary
fi
ok "build the interposer"

if ! gcc -O0 -g -o "$WORK/probe" "$PROBE_SOURCE" 2>"$WORK/probe.log"; then
  bad "build the probe client" "an executable" "$(cat "$WORK/probe.log")"
  summary
fi
ok "build the probe client"

# Runs one scenario in its own process, so each starts with an empty cache.
run_scenario() {
  PROBE_RULES="$WORK/rules.cfg" PROBE_LIB="$WORK/libnetblocker.so" \
    "$WORK/probe" "$1" 2>&1
}

field() {
  local out=$1 key=$2 value
  value="$(sed -n "s/^${key}=//p" <<<"$out")"
  if [[ -z "$value" ]]; then value="<missing>
${out}"; fi
  printf '%s' "$value"
}

# ---------------------------------------------------------------------
# A rule naming one port stays limited to that port
# ---------------------------------------------------------------------

echo "== single permitted port =="
out="$(run_scenario port_specific)"
check "lookup without a service succeeds"        "ok"      "$(field "$out" resolve)"
check "the permitted port is reachable"          "allowed" "$(field "$out" permitted_port)"
check "another port stays refused after lookup"  "denied"  "$(field "$out" other_port)"

# The permitted port above is reachable only because the lookup cached it: with
# no lookup first, the same rule authorises nothing, which is what shows the
# cache carries the rule's port rather than a blanket authorisation.
echo
echo "== authorisation comes from the cached rule =="
out="$(run_scenario no_lookup)"
check "no lookup means no authorisation" "denied" "$(field "$out" without_lookup)"

# ---------------------------------------------------------------------
# Several permitted ports for one hostname stay distinguishable
# ---------------------------------------------------------------------

echo
echo "== two permitted ports =="
out="$(run_scenario multi_port)"
check "lookup without a service succeeds"    "ok"      "$(field "$out" resolve)"
check "the first permitted port is reachable"  "allowed" "$(field "$out" first_port)"
check "the second permitted port is reachable" "allowed" "$(field "$out" second_port)"
check "a third port stays refused"             "denied"  "$(field "$out" third_port)"

# ---------------------------------------------------------------------
# A rule that permits every port keeps doing so
# ---------------------------------------------------------------------

echo
echo "== explicit any-port rule =="
out="$(run_scenario any_port)"
check "lookup without a service succeeds" "ok"      "$(field "$out" resolve)"
check "the first port is reachable"       "allowed" "$(field "$out" first_port)"
check "the second port is reachable"      "allowed" "$(field "$out" second_port)"
check "the third port is reachable"       "allowed" "$(field "$out" third_port)"

# ---------------------------------------------------------------------
# Literal addresses are unaffected by whether a lookup happened
# ---------------------------------------------------------------------

echo
echo "== literal address rules =="
out="$(run_scenario literal_ip)"
check "literal rule permits its own port"   "allowed" "$(field "$out" permitted_port)"
check "literal rule refuses another port"   "denied"  "$(field "$out" other_port)"

out="$(run_scenario literal_ip_any)"
check "literal any-port rule permits one port"     "allowed" "$(field "$out" first_port)"
check "literal any-port rule permits another port" "allowed" "$(field "$out" second_port)"

# ---------------------------------------------------------------------
# IPv6 addresses follow the same restriction
# ---------------------------------------------------------------------

echo
echo "== IPv6 =="
out="$(run_scenario ipv6)"
if [[ "$out" == *"ipv6=unavailable"* || "$(field "$out" resolve)" != "ok" ]]; then
  skip "IPv6 port restriction" "no IPv6 loopback resolution on this host"
else
  check "the permitted port is reachable"         "allowed" "$(field "$out" permitted_port)"
  check "another port stays refused after lookup" "denied"  "$(field "$out" other_port)"
fi

summary
