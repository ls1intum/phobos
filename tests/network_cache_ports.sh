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
# shellcheck source=harness.sh
source "${HERE}/harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
# shellcheck source=../core/phobos-constants.sh
source "${HERE}/../core/phobos-constants.sh"
SOURCE_DIRECTORY="${HERE}/../ld_preloader"
PROBE_SOURCE="${HERE}/netcache_probe.c"

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# Named rather than inherited: the sources are C23 and Ubuntu 24.04's default
# gcc 13 knows that standard only under its draft name.
COMPILER="${COMPILER:-gcc-14}"
if ! command -v "$COMPILER" >/dev/null 2>&1; then
  skip "network cache port restrictions" \
       "no $COMPILER on this platform; these checks run on Linux"
  finish
fi

# The same build the run-phase image performs, flags included: -O2 is what turns
# _FORTIFY_SOURCE on, and -Wl,-z,now completes RELRO. Testing an unhardened build
# of a library that ships hardened would leave the shipped one untested.
if ! "$COMPILER" -std=gnu23 -O2 -Wall -Wextra -fPIC -shared -fvisibility=hidden -Wl,-z,now \
     -o "$WORK/libnetblocker.so" "$SOURCE_DIRECTORY"/netblocker*.c 2>"$WORK/lib.log"; then
  bad "build the interposer" "a shared library" "$(cat "$WORK/lib.log")"
  finish
fi
ok "build the interposer"

# Only the six hooks may be visible. Any other function the library exported could
# take the place of one the program, or another library, defines under the same name.
exported="$(readelf --dyn-syms --wide "$WORK/libnetblocker.so" 2>/dev/null \
  | awk '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" { print $8 }' \
  | LC_ALL=C sort | paste -s -d ' ' -)"
check "the library exports exactly its six hooks" "bind connect getaddrinfo sendmmsg sendmsg sendto" "$exported"

if ! "$COMPILER" -std=gnu23 -O0 -g -o "$WORK/probe" "$PROBE_SOURCE" 2>"$WORK/probe.log"; then
  bad "build the probe client" "an executable" "$(cat "$WORK/probe.log")"
  finish
fi
ok "build the probe client"

# Runs one scenario in its own process, so each starts with an empty cache. The
# probe writes its rules into a private directory of its own. The limit is there for
# a library that blocks while reading its rules, which would otherwise hang the suite.
run_scenario() {
  PROBE_LIB="$WORK/libnetblocker.so" timeout 20 "$WORK/probe" "$1" 2>&1
}

field() {
  local out=$1
  local key=$2
  local value
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
# UDP datagrams are filtered too, on the destination they name themselves
# ---------------------------------------------------------------------

# A UDP datagram on an unconnected socket names its destination in the send call, which
# connect never sees. sendto and sendmsg carry the same rule as the literal address above:
# the permitted port goes through, another port is refused. This is defence in depth a raw
# system call still steps around, as with the connect hook.
echo
echo "== UDP datagrams =="
out="$(run_scenario datagram)"
check "sendto to the permitted port is allowed"  "allowed" "$(field "$out" sendto_permitted)"
check "sendto to another port is refused"        "denied"  "$(field "$out" sendto_other)"
check "sendmsg to the permitted port is allowed" "allowed" "$(field "$out" sendmsg_permitted)"
check "sendmsg to another port is refused"       "denied"  "$(field "$out" sendmsg_other)"

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
# The rules file is only ever read as the regular file it names
# ---------------------------------------------------------------------

# The same rule as the literal address checks above, which permit its port, but
# reached through something other than a regular file. No rules means every port
# is refused, and a FIFO must be refused without blocking the process.
echo
echo "== the rules file =="
out="$(run_scenario rules_symlink)"
check "a rules file reached through a symbolic link grants nothing" "denied" "$(field "$out" permitted_port)"
out="$(run_scenario rules_directory)"
check "a directory in place of the rules file grants nothing" "denied" "$(field "$out" permitted_port)"
out="$(run_scenario rules_fifo)"
check "a FIFO in place of the rules file neither blocks nor grants" "denied" "$(field "$out" permitted_port)"

# ---------------------------------------------------------------------
# An address range covers the addresses in it, and no others
# ---------------------------------------------------------------------

# An IPv4 address is compared as the IPv4-mapped IPv6 address, so an IPv4 prefix
# length has to count from bit 96. Counted from bit 0, the first bits of every IPv4
# address and of ::1 are zero, and a range such as 10.0.0.0/8 covered all of them.
echo
echo "== address ranges =="
out="$(run_scenario range_ipv4)"
check "an IPv4 range permits an address inside it" "allowed" "$(field "$out" inside)"
out="$(run_scenario range_other_ipv4)"
check "an IPv4 range refuses an address outside it" "denied" "$(field "$out" loopback)"
out="$(run_scenario range_single_ipv4)"
check "a /32 range permits its one address" "allowed" "$(field "$out" host)"
check "a /32 range refuses the address next to it" "denied" "$(field "$out" neighbour)"
out="$(run_scenario range_ipv4_too_long)"
check "an IPv4 prefix longer than 32 bits grants nothing" "denied" "$(field "$out" loopback)"
out="$(run_scenario range_mapped_ipv4)"
check "an IPv4 range in IPv6 notation permits an address inside it" "allowed" "$(field "$out" inside)"
out="$(run_scenario range_mapped_short)"
check "an IPv4-mapped address with a prefix under 96 bits grants nothing" "denied" "$(field "$out" loopback)"
out="$(run_scenario range_ipv4_against_ipv6)"
if [[ "$out" == *"ipv6=unavailable"* ]]; then
  skip "an IPv4 range refuses an IPv6 address" "no IPv6 loopback on this host"
else
  check "an IPv4 range refuses an IPv6 address" "denied" "$(field "$out" ipv6_loopback)"
fi
out="$(run_scenario range_ipv6)"
if [[ "$out" == *"ipv6=unavailable"* ]]; then
  skip "an IPv6 range" "no IPv6 loopback on this host"
else
  check "an IPv6 range permits an address inside it" "allowed" "$(field "$out" ipv6_loopback)"
  check "an IPv6 range refuses an IPv4 address" "denied" "$(field "$out" ipv4_loopback)"
fi

# ---------------------------------------------------------------------
# Behaviour the filter has today, recorded rather than endorsed
# ---------------------------------------------------------------------

# These pin down what the filter does now in cases a restructuring could change
# without anyone noticing. They describe behaviour, not a policy anyone chose: a
# change to any of them belongs in its own pull request, with this check changed there.
echo
echo "== behaviour the filter has today =="
out="$(run_scenario kept_any_host_with_port)"
check "'* <port>' fails every name lookup" "failed" "$(field "$out" resolve)"
check "'* <port>' permits any address on that port" "allowed" "$(field "$out" permitted_port)"
check "'* <port>' refuses another port" "denied" "$(field "$out" other_port)"
# Port 0 used to be the internal spelling of "every port", so a rule naming it read as a
# wildcard here while the connect guard dropped the same rule. The rule is dropped in both
# now, and a policy naming it never reaches either: phobos-policy.sh refuses it.
out="$(run_scenario kept_port_zero)"
check "port 0 in a rule grants no port" "denied" "$(field "$out" first_port)"
check "port 0 in a rule grants no other port either" "denied" "$(field "$out" second_port)"
out="$(run_scenario kept_third_token)"
check "a third word in a rule is ignored" "allowed" "$(field "$out" permitted_port)"
out="$(run_scenario kept_invalid_port)"
check "a rule with a port above 65535 grants nothing" "denied" "$(field "$out" permitted_port)"
out="$(run_scenario kept_unix_socket)"
check "a connection to a Unix socket is refused" "denied" "$(field "$out" unix_socket)"
out="$(run_scenario kept_named_service)"
check "a lookup with a named service counts as no port" "passed-to-resolver" "$(field "$out" named_service)"
check "a lookup naming a port the rule does not grant is refused" "refused" "$(field "$out" other_service)"
out="$(run_scenario kept_long_line)"
check "a rule after 511 characters of comment on one line takes effect" "allowed" "$(field "$out" first_port)"

# ---------------------------------------------------------------------
# SIGHUP belongs to the program, and reloads nothing
# ---------------------------------------------------------------------

echo
echo "== SIGHUP =="
out="$(run_scenario sighup_default)"
check "an inherited default SIGHUP disposition stays the default" "default" "$(field "$out" sighup)"
out="$(run_scenario sighup_ignored)"
check "an inherited ignored SIGHUP stays ignored" "ignored" "$(field "$out" sighup)"
out="$(run_scenario sighup_no_reload)"
check "a port the rules do not name is refused" "denied" "$(field "$out" before_rewrite)"
check "the rules file is rewritten to permit every port" "ok" "$(field "$out" rewrite)"
check "rewriting the rules and sending SIGHUP widens nothing" "denied" "$(field "$out" after_hangup)"

echo
echo "== the probe's rules directory =="
leftovers_before="$(find /tmp -maxdepth 1 -name 'phobos-netcache-probe.*' | wc -l)"
run_scenario literal_ip > /dev/null
run_scenario rules_fifo > /dev/null
leftovers_after="$(find /tmp -maxdepth 1 -name 'phobos-netcache-probe.*' | wc -l)"
check "every scenario removes the rules directory it created" "$leftovers_before" "$leftovers_after"

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
# A pass-through stand-in for the connect guard, the way record-landlock stands in for
# phobos-landlock: here the preload library, not the guard, is under test, so the network
# layer's fail-closed check for the guard is satisfied by a binary that drops its own options
# up to the "--" and execs the rest, handing over transparently.
printf '%s\n' '#!/bin/sh' \
  'while [ $# -gt 0 ] && [ "$1" != "--" ]; do shift; done' \
  'shift' \
  'exec "$@"' > "$WORK/core/phobos-connect-guard"
chmod +x "$WORK/core/phobos-connect-guard"
NETWORK_LAYER="$WORK/core/phobos-network.sh"
mkdir -p "$WORK/spec"

# Runs the network layer over /bin/echo and prints its output and its exit status. The layer
# is a generic wrapper now: called at all, it checks its library and execs the command.
# Whether it runs at all is phobos.sh's decision, covered by the command-line suite.
run_network_layer() {
  local library=$1
  local out
  local rc
  out="$(bash "$NETWORK_LAYER" --netblocker-so "$library" "$WORK/spec" -- /bin/echo command-ran 2>&1)"
  rc=$?
  printf '%s\nEXIT=%s' "$out" "$rc"
}

refused_because() {
  local name=$1
  local reason=$2
  local out=$3
  if [[ "$out" == *"EXIT=${PHB_ERUNTIME}"* && "$out" == *"PHB-ERUNTIME"* && "$out" == *"$reason"* \
        && "$out" != *"command-ran"* ]]; then
    ok "$name"
  else
    bad "$name" "exit ${PHB_ERUNTIME}, PHB-ERUNTIME naming '$reason', and no command run" "$out"
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

# Under --debug the network layer says what it preloads and runs, on stderr, and hands the
# connect guard --verbose. A stand-in guard records the options it was given, then hands over.
printf '%s\n' '#!/bin/sh' 'printf "%s\n" "$@" > "$GUARD_RECORD"' \
  'while [ $# -gt 0 ] && [ "$1" != "--" ]; do shift; done' 'shift' 'exec "$@"' > "$WORK/record-guard"
chmod +x "$WORK/record-guard"
GUARD_RECORD="$WORK/guard-record" bash "$NETWORK_LAYER" --debug --netblocker-so "$WORK/libnetblocker.so" \
  --connect-guard-bin "$WORK/record-guard" "$WORK/spec" -- /bin/echo command-ran \
  > "$WORK/debug.out" 2> "$WORK/debug.err"
if [[ "$(cat "$WORK/debug.out")" == "command-ran" ]] && grep -q '^\[phobos\] network: ' "$WORK/debug.err" \
   && grep -qx -- '--verbose' "$WORK/guard-record"; then
  ok "under --debug the network layer reports on stderr and the guard is handed --verbose"
else
  bad "under --debug the network layer reports on stderr and the guard is handed --verbose" \
    "stdout 'command-ran', a '[phobos] network:' line, --verbose for the guard" \
    "stdout '$(cat "$WORK/debug.out")', stderr '$(cat "$WORK/debug.err")', guard '$(tr '\n' ' ' < "$WORK/guard-record")'"
fi

refused_because "a missing library is refused" "does not exist" \
  "$(run_network_layer "$WORK/absent.so")"

printf 'not a library\n' > "$WORK/text.so"
refused_because "a file that is not a library is refused" "does not define bind" \
  "$(run_network_layer "$WORK/text.so")"

# The same library with its ELF machine field, at offset 18, set to another
# architecture: x86-64 is 0x3e and AArch64 is 0xb7. Its symbols still read, so only
# the loader can tell that it would never be mapped.
# Where an ELF header keeps the machine field.
ELF_MACHINE_OFFSET=18
cp "$WORK/libnetblocker.so" "$WORK/foreign.so"
if [[ "$(od -An -tx1 -j"$ELF_MACHINE_OFFSET" -N1 "$WORK/foreign.so" | tr -d ' ')" == "3e" ]]; then
  foreign_machine='\xb7'
else
  foreign_machine='\x3e'
fi
printf '%b' "$foreign_machine" | dd of="$WORK/foreign.so" bs=1 seek="$ELF_MACHINE_OFFSET" conv=notrunc status=none
refused_because "a library for another architecture is refused" "does not load cleanly" \
  "$(run_network_layer "$WORK/foreign.so")"

printf 'int unrelated_function(void) { return 0; }\n' > "$WORK/unrelated.c"
if "$COMPILER" -std=gnu23 -O2 -fPIC -shared -o "$WORK/unrelated.so" "$WORK/unrelated.c" \
     2>"$WORK/unrelated.log"; then
  refused_because "a loadable library without the hooks is refused" "does not define bind" \
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

# ---------------------------------------------------------------------
# The library and its rules file stay out of the sandbox's reach
# ---------------------------------------------------------------------

# Stands in for phobos-landlock: records the arguments it was handed, one per line,
# and runs the command after "--" without restricting anything. What is checked is
# the policy the layers hand to Landlock, not Landlock itself.
cat > "$WORK/record-landlock" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$PHB_TEST_RECORD"
while [[ $# -gt 0 && "$1" != "--" ]]; do shift; done
shift
exec "$@"
FAKE
chmod +x "$WORK/record-landlock"

REACH_SPEC="$WORK/reach-spec"
mkdir -p "$REACH_SPEC"
for f in read.paths execute.paths create.paths delete.paths tail.flags net.rules; do : > "$REACH_SPEC/$f"; done

# Runs the filesystem layer over the reach specification with the given write path,
# with the preload library and rules file set as phobos-network.sh sets them, and
# prints its output followed by an EXIT=<status> line. A second argument of
# "unterminated" writes the path without the newline that normally ends the line.
run_with_write_path() {
  local write_path=$1
  local ending=${2:-}
  local out
  local rc
  if [[ "$ending" == "unterminated" ]]; then
    printf '%s' "$write_path" > "$REACH_SPEC/write.paths"
  else
    printf '%s\n' "$write_path" > "$REACH_SPEC/write.paths"
  fi
  out="$(PHB_NETBLOCKER_SO="$WORK/libnetblocker.so" \
         NETBLOCKER_CONF="$REACH_SPEC/net.rules" \
         PHB_TEST_RECORD="$WORK/reach-record" \
         bash "$WORK/core/phobos-filesystem.sh" --landlock-bin "$WORK/record-landlock" "$REACH_SPEC" -- /bin/echo command-ran 2>&1)"
  rc=$?
  printf '%s\nEXIT=%s' "$out" "$rc"
}

refused_as_unenforceable() {
  local name=$1
  local out=$2
  if [[ "$out" == *"EXIT=${PHB_EPOLICY}"* && "$out" == *"lies beneath the write path"* && "$out" != *"command-ran"* ]]; then
    ok "$name"
  else
    bad "$name" "exit ${PHB_EPOLICY}, PHB-EPOLICY naming the write path, and no command run" "$out"
  fi
}

# Whether the recorded arguments hold the given option immediately followed by the path.
recorded_rule() {
  grep -x -A1 -- "$1" "$WORK/reach-record" 2>/dev/null | grep -qxF -- "$2"
}

echo
echo "== the library and its rules file stay out of the sandbox's reach =="
mkdir -p "$WORK/elsewhere"
out="$(run_with_write_path "$WORK/elsewhere")"
if [[ "$out" == *"EXIT=0"* && "$out" == *"command-ran"* ]] \
   && recorded_rule "--rights=rx" "$WORK/libnetblocker.so" \
   && recorded_rule "--rights=r" "$REACH_SPEC/net.rules"; then
  ok "an unchangeable library and rules file are handed to Landlock readable"
else
  bad "an unchangeable library and rules file are handed to Landlock readable" \
      "exit 0, --rights=rx on the library and --rights=r on the rules file" \
      "$out / $(tr '\n' ' ' < "$WORK/reach-record" 2>/dev/null)"
fi

refused_as_unenforceable "a rules file in a writable directory is refused" \
  "$(run_with_write_path "$REACH_SPEC")"
refused_as_unenforceable "a rules file and library beneath a writable ancestor are refused" \
  "$(run_with_write_path "$WORK")"
ln -sfn "$REACH_SPEC" "$WORK/reach-spec-link"
refused_as_unenforceable "a writable path that links to the rules file's directory is refused" \
  "$(run_with_write_path "$WORK/reach-spec-link")"
refused_as_unenforceable "a writable library is refused" \
  "$(run_with_write_path "$WORK/libnetblocker.so")"
refused_as_unenforceable "a write path on a last line without a newline is still refused" \
  "$(run_with_write_path "$REACH_SPEC" unterminated)"

if [[ -d "$REACH_SPEC" && -f "$REACH_SPEC/net.rules" ]]; then
  ok "a specification directory Phobos did not create is never removed"
else
  bad "a specification directory Phobos did not create is never removed" \
      "$REACH_SPEC and its rules file still in place" "it was removed"
fi

# ---------------------------------------------------------------------
# A run leaves no specification behind
# ---------------------------------------------------------------------

# A base policy for phobos.sh with one write path, so that a specification can be
# placed beneath it on purpose.
printf '[read]\n/usr\n\n[write]\n%s\n' "$WORK/writable" > "$WORK/core/BaseTest.cfg"
# Created before any run: a write path that does not exist yet is created as a file.
mkdir -p "$WORK/writable/specs"
printf '[limits]\ntimeout=1\n' > "$WORK/one-second.cfg"

# Runs phobos.sh with its specification under the given parent and the remaining
# arguments, through the recording stand-in for phobos-landlock, and prints its output
# followed by an EXIT=<status> line. NETBLOCKER_SO_FOR_RUN names another library.
run_phobos() {
  local parent=$1
  shift
  local out
  local rc
  out="$(PHB_TEST_RECORD="$WORK/phobos-record" \
         bash "$WORK/core/phobos.sh" --spec-parent "$parent" \
         --netblocker-so "${NETBLOCKER_SO_FOR_RUN:-$WORK/libnetblocker.so}" \
         --landlock-bin "$WORK/record-landlock" "$@" 2>&1)"
  rc=$?
  printf '%s\nEXIT=%s' "$out" "$rc"
}

# Creates an empty parent directory for one run and prints its path.
fresh_parent() {
  local parent="$WORK/specs-$1"
  mkdir -p "$parent"
  printf '%s' "$parent"
}

# Checks that a run ended with the wanted status, said what it had to, and left no
# specification directory in its parent.
left_nothing() {
  local name=$1
  local parent=$2
  local want=$3
  local says=$4
  local out=$5
  local left
  left="$(find "$parent" -mindepth 1 -maxdepth 1 -name 'phobos-spec.*' | wc -l | tr -d ' ')"
  if [[ "$out" == *"EXIT=${want}"* && "$out" == *"$says"* && "$left" == "0" ]]; then
    ok "$name"
  else
    bad "$name" "exit ${want}, output naming '${says}', and no specification left" \
        "${left} left: $out"
  fi
}

echo
echo "== a run leaves no specification behind =="
parent="$(fresh_parent success)"
left_nothing "after a run that succeeds" "$parent" 0 "command-ran" \
  "$(run_phobos "$parent" -- /bin/echo command-ran)"

parent="$(fresh_parent failure)"
left_nothing "after a command that fails" "$parent" 1 "" \
  "$(run_phobos "$parent" -- /bin/false)"

mkdir -p "$WORK/writable/specs"
left_nothing "after a policy refusal, for a specification beneath a write path" \
  "$WORK/writable/specs" "$PHB_EPOLICY" "lies beneath the write path" \
  "$(run_phobos "$WORK/writable/specs" -- /bin/echo command-ran)"

parent="$(fresh_parent unusable-library)"
left_nothing "after the network layer refuses its library" "$parent" "$PHB_ERUNTIME" "PHB-ERUNTIME" \
  "$(NETBLOCKER_SO_FOR_RUN="$WORK/absent.so" run_phobos "$parent" -- /bin/echo command-ran)"

parent="$(fresh_parent timeout)"
left_nothing "after a run that times out" "$parent" "$PHB_ETIMEOUT" "PHB-ETIMEOUT" \
  "$(run_phobos "$parent" --config "$WORK/one-second.cfg" -- /bin/sleep 10)"

out="$(run_phobos relative-parent -- /bin/echo command-ran)"
if [[ "$out" == *"EXIT=${PHB_EPOLICY}"* && "$out" == *"not an absolute path"* && "$out" != *"command-ran"* ]]; then
  ok "a relative --spec-parent is refused"
else
  bad "a relative --spec-parent is refused" "exit ${PHB_EPOLICY} naming the parent, and no command run" "$out"
fi

# The command leaves a file of its own in the specification directory, so it cannot be
# removed without deleting what Phobos did not write. That must not pass as success.
parent="$(fresh_parent unremovable)"
out="$(run_phobos "$parent" -- /bin/sh -c 'touch "$(dirname "$NETBLOCKER_CONF")/left-by-command"')"
left="$(find "$parent" -mindepth 1 -maxdepth 1 -name 'phobos-spec.*' | wc -l | tr -d ' ')"
if [[ "$out" == *"EXIT=${PHB_ERUNTIME}"* && "$out" == *"could not remove the specification directory"* && "$left" == "1" ]]; then
  ok "a specification that cannot be removed fails the run instead of passing silently"
else
  bad "a specification that cannot be removed fails the run instead of passing silently" \
      "exit ${PHB_ERUNTIME}, the cleanup failure reported, and the directory with the command's file kept" \
      "${left} left: $out"
fi

# phobos.sh ends with exec, so its own EXIT trap never runs; its scratch files must live
# under the specification directory and be removed with it, not left in TMPDIR (which is a
# write path the sandbox can read in both shipped policies).
echo
echo "== phobos.sh keeps no scratch behind and refuses to run without a base policy =="
scratch_tmp="$WORK/scratch-tmp"
mkdir -p "$scratch_tmp"
parent="$(fresh_parent scratch)"
TMPDIR="$scratch_tmp" \
  bash "$WORK/core/phobos.sh" --spec-parent "$parent" \
  --netblocker-so "$WORK/libnetblocker.so" --landlock-bin "$WORK/record-landlock" \
  -- /bin/echo command-ran >/dev/null 2>&1
left="$(find "$scratch_tmp" -mindepth 1 | wc -l | tr -d ' ')"
check "a run leaves no scratch files in TMPDIR" 0 "$left"

# A core directory with no Base*.cfg beside phobos.sh: the sandbox cannot be applied.
nobase="$WORK/nobase"
mkdir -p "$nobase"
cp "$WORK/core/"*.sh "$nobase/"
out="$(bash "$nobase/phobos.sh" --landlock-bin "$WORK/record-landlock" -- /bin/echo should-not-run 2>&1)"
rc=$?
if [[ "$rc" -eq "$PHB_EPOLICY" && "$out" == *"PHB-EPOLICY"* && "$out" != *"should-not-run"* ]]; then
  ok "no Base*.cfg refuses to run unconfined (PHB-EPOLICY), and runs nothing"
else
  bad "no Base*.cfg refuses to run unconfined (PHB-EPOLICY), and runs nothing" \
      "exit ${PHB_EPOLICY} naming PHB-EPOLICY, command not run" "exit ${rc}: $out"
fi

out="$(bash "$nobase/phobos.sh" --landlock-bin "$WORK/record-landlock" --allow-unsandboxed -- /bin/echo ran-raw 2>&1)"
rc=$?
if [[ "$rc" -eq 0 && "$out" == *"ran-raw"* ]]; then
  ok "--allow-unsandboxed runs the command raw when no Base*.cfg is present"
else
  bad "--allow-unsandboxed runs the command raw when no Base*.cfg is present" \
      "exit 0, command run" "exit ${rc}: $out"
fi

finish
