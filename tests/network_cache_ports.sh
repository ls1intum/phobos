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

# Named rather than inherited: the sources are C23 and Ubuntu 24.04's default
# gcc 13 knows that standard only under its draft name.
COMPILER="${COMPILER:-gcc-14}"
if ! command -v "$COMPILER" >/dev/null 2>&1; then
  skip "network cache port restrictions" \
       "no $COMPILER on this platform; these checks run on Linux"
  summary
fi

# The same build the run-phase image performs, flags included: -O2 is what turns
# _FORTIFY_SOURCE on, and -Wl,-z,now completes RELRO. Testing an unhardened build
# of a library that ships hardened would leave the shipped one untested.
if ! "$COMPILER" -std=gnu23 -O2 -Wall -Wextra -fPIC -shared -Wl,-z,now \
     -o "$WORK/libnetblocker.so" "$SOURCE" 2>"$WORK/lib.log"; then
  bad "build the interposer" "a shared library" "$(cat "$WORK/lib.log")"
  summary
fi
ok "build the interposer"

if ! "$COMPILER" -std=gnu23 -O0 -g -o "$WORK/probe" "$PROBE_SOURCE" 2>"$WORK/probe.log"; then
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

# ---------------------------------------------------------------------
# The network layer refuses a library that would not filter anything
# ---------------------------------------------------------------------

# The loader skips a preload library it cannot use with only a warning, and the
# command then runs unfiltered. These checks run the network layer with the
# filesystem layer switched off, because that is the one way to reach the refusal
# without Landlock. They claim nothing about that composition being safe: without
# the filesystem layer nothing protects the rules file.
#
# The layers start one another with exec, so they have to be executable. A checkout
# does not mark them so, the image does, and a copy stands in for the image here.
cp -R "${HERE}/../core" "$WORK/core"
chmod +x "$WORK"/core/*.sh
NETWORK_LAYER="$WORK/core/phobos-network.sh"
mkdir -p "$WORK/spec"

# Runs the network layer over /bin/echo and prints its output and its exit status.
# The second argument switches the network layer itself off when it is 0.
run_network_layer() {
  local library=$1
  local network=${2:-1}
  local out
  local rc
  out="$(NETBLOCKER_SO="$library" PHB_ENABLE_FILESYSTEM=0 PHB_ENABLE_NETWORK="$network" \
         PHB_TIMEOUT_SEC="" bash "$NETWORK_LAYER" "$WORK/spec" -- /bin/echo command-ran 2>&1)"
  rc=$?
  printf '%s\nEXIT=%s' "$out" "$rc"
}

refused_because() {
  local name=$1
  local reason=$2
  local out=$3
  if [[ "$out" == *"EXIT=15"* && "$out" == *"PHB-ERUNTIME"* && "$out" == *"$reason"* \
        && "$out" != *"command-ran"* ]]; then
    ok "$name"
  else
    bad "$name" "exit 15, PHB-ERUNTIME naming '$reason', and no command run" "$out"
  fi
}

ran() {
  local name=$1
  local out=$2
  if [[ "$out" == *"EXIT=0"* && "$out" == *"command-ran"* ]]; then
    ok "$name"
  else
    bad "$name" "exit 0 and the command run" "$out"
  fi
}

echo
echo "== the network layer refuses an unusable library =="
ran "a freshly built interposer lets the command run" "$(run_network_layer "$WORK/libnetblocker.so")"
ran "with the network layer off no library is needed" "$(run_network_layer "$WORK/absent.so" 0)"

refused_because "a missing library is refused" "does not exist" \
  "$(run_network_layer "$WORK/absent.so")"

printf 'not a library\n' > "$WORK/text.so"
refused_because "a file that is not a library is refused" "does not define connect" \
  "$(run_network_layer "$WORK/text.so")"

# The same library with its ELF machine field, at offset 18, set to another
# architecture: x86-64 is 0x3e and AArch64 is 0xb7. Its symbols still read, so only
# the loader can tell that it would never be mapped.
cp "$WORK/libnetblocker.so" "$WORK/foreign.so"
if [[ "$(od -An -tx1 -j18 -N1 "$WORK/foreign.so" | tr -d ' ')" == "3e" ]]; then
  foreign_machine='\xb7'
else
  foreign_machine='\x3e'
fi
printf '%b' "$foreign_machine" | dd of="$WORK/foreign.so" bs=1 seek=18 conv=notrunc status=none
refused_because "a library for another architecture is refused" "does not load cleanly" \
  "$(run_network_layer "$WORK/foreign.so")"

printf 'int unrelated_function(void) { return 0; }\n' > "$WORK/unrelated.c"
if "$COMPILER" -std=gnu23 -O2 -fPIC -shared -o "$WORK/unrelated.so" "$WORK/unrelated.c" \
     2>"$WORK/unrelated.log"; then
  refused_because "a loadable library without the hooks is refused" "does not define connect" \
    "$(run_network_layer "$WORK/unrelated.so")"
else
  bad "build a library without the hooks" "a shared library" "$(cat "$WORK/unrelated.log")"
fi

mkdir -p "$WORK/with space"
cp "$WORK/libnetblocker.so" "$WORK/with space/libnetblocker.so"
refused_because "a path LD_PRELOAD cannot name is refused" "space or a colon" \
  "$(run_network_layer "$WORK/with space/libnetblocker.so")"

# Every command on this machine except readelf, so that only its absence differs.
mkdir -p "$WORK/no-readelf"
for tool in /usr/bin/* /bin/*; do
  case "${tool##*/}" in
    readelf|*-readelf) continue ;;
  esac
  [[ -e "$WORK/no-readelf/${tool##*/}" ]] || ln -s "$tool" "$WORK/no-readelf/${tool##*/}"
done
refused_because "a library that cannot be inspected is refused" "readelf is not installed" \
  "$(PATH="$WORK/no-readelf" run_network_layer "$WORK/libnetblocker.so")"

summary
