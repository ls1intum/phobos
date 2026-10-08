#!/usr/bin/env bash
# Tests how the [connect] allow-list becomes an haproxy.cfg: haproxy_allow_rules turns the
# "host port" lines phobos-policysystem.sh writes into the allow-list the egress broker enforces, and
# build_haproxy_conf wraps them in the fixed loopback-proxy preamble and backends. The broker's
# real enforcement is proven in the run-phase image by the acceptance suite; this pins the
# translation, which is deterministic and needs no HAProxy. Where haproxy is installed, it also
# checks that a generated config actually parses.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../../core"
# shellcheck source=../../../core/phobos-tools-common/phobos-common.sh
source "${CORE}/phobos-tools-common/phobos-common.sh"
# phobos-common.sh turns errexit and nounset on for whoever sources it. This suite counts failures
# and goes on, so it takes errexit back; the helpers under test run unchanged in either mode.
set +e
# shellcheck source=../../../core/phobos-tools-networksystem/phobos-haproxy.sh
source "${CORE}/phobos-tools-networksystem/phobos-haproxy.sh"

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# Prints the allow-list lines haproxy_allow_rules builds for one net.rules body.
emit() {
  printf '%s\n' "$1" > "$WORK/net.rules"
  haproxy_allow_rules "$WORK/net.rules"
}

# Records whether the generated config contains a line, or, with a leading !, does not.
has() {
  local name="$1"
  local body="$2"
  local needle="$3"
  if [[ "$needle" == "!"* ]]; then
    if grep -qF -- "${needle#!}" <<<"$body"; then bad "$name" "absent: ${needle#!}" "present"; else ok "$name"; fi
  else
    if grep -qF -- "$needle" <<<"$body"; then ok "$name"; else bad "$name" "present: $needle" "absent"; fi
  fi
}

echo "== an empty allow-list denies every destination =="
out="$(emit "")"
has "empty rules route to refuse by default" "$out" "default_backend refuse"
has "empty rules name no allowance" "$out" "!use_backend to_dst"

echo
echo "== a DNS name is resolved by the broker itself, and everything else is refused =="
out="$(emit "repo.maven.apache.org 443")"
has "the name becomes an exact SNI acl" "$out" "acl exact_sni_p443 req.ssl_sni -m str -i repo.maven.apache.org"
has "the name is held to the port the rule names" "$out" "acl exact_port_p443 dst_port 443"
has "the broker resolves the name rather than trust the header" "$out" "do-resolve(txn.hostip,phobosdns,ipv4) req.ssl_sni if exact_port_p443 exact_sni_p443"
has "the destination is set to the resolved address" "$out" "set-dst var(txn.hostip) if exact_port_p443 exact_sni_p443 { var(txn.hostip) -m found }"
has "a name that does not resolve is refused" "$out" "reject if exact_port_p443 exact_sni_p443 !{ var(txn.hostip) -m found }"
has "and marked as unresolved first, so the guard does not word it as a policy refusal" "$out" "set-var(txn.marker) str(PHB-BROKER-UNRESOLVED) if exact_port_p443 exact_sni_p443 !{ var(txn.hostip) -m found }"
has "an allowed SNI routes to the destination backend" "$out" "use_backend to_dst if exact_port_p443 exact_sni_p443"
has "everything else is refused" "$out" "default_backend refuse"
has "the port is tested before the TLS name, so a connection to another port is decided without waiting for a ClientHello" "$out" "!exact_sni_p443 exact_port_p443"

echo
echo "== a wildcard host name is refused, never turned into a rule =="
# Runs a body through build_haproxy_conf in a subshell, so the refusal's exit is captured. The body
# is written with printf %s, which adds no newline, so the last row may be left unterminated.
# Prints "<exit>|<config written?>|<log>".
refuse_conf() {
  local body="$1"
  local out
  rm -f "$WORK/refused.cfg"
  printf '%s' "$body" > "$WORK/net.rules"
  out="$( ( build_haproxy_conf "$WORK/net.rules" "$WORK/refused.cfg" "127.0.0.1:3128" "127.0.0.11:53" ) 2>&1 )"
  local rc=$?
  local written=no
  [[ -e "$WORK/refused.cfg" ]] && written=yes
  printf '%s|%s|%s' "$rc" "$written" "$(tr '\n' ' ' <<<"$out")"
}
for wildcard_body in "*.example.org 443
" "a*b.example 443
" "name.* 443
" "*.example.org 53 udp
" "repo.example.org 443
127.0.0.1 53 udp
*.example.org 53 udp" "*.example.org 443"; do
  r="$(refuse_conf "$wildcard_body")"
  label="$(printf '%s' "$wildcard_body" | tr '\n' ',')"
  if [[ "$(cut -d'|' -f1 <<<"$r")" == "${PHB_EPOLICY}" && "$(cut -d'|' -f2 <<<"$r")" == no && "$(cut -d'|' -f3 <<<"$r")" == *"wildcard host name"* ]]; then
    ok "'$label' is refused with PHB-EPOLICY and no config is written"
  else
    bad "'$label' is refused with PHB-EPOLICY and no config is written" "exit ${PHB_EPOLICY}, no file, a message naming the wildcard" "$r"
  fi
done
has "a wildcard name is classified invalid" "$(classify_connect_host '*.example.org')" "invalid"
has "a star inside a name is invalid" "$(classify_connect_host 'a*b.example')" "invalid"
has "a trailing star is invalid" "$(classify_connect_host 'name.*')" "invalid"
has "a star beside a slash is invalid, not an address" "$(classify_connect_host '*/8')" "invalid"
has "a star beside a colon is invalid, not an address" "$(classify_connect_host '*::1')" "invalid"
has "the bare star is still any" "$(classify_connect_host '*')" "any"
r="$(refuse_conf "repo.example.org 443
*
")"
[[ "$(cut -d'|' -f1 <<<"$r")" == 0 && "$(cut -d'|' -f2 <<<"$r")" == yes ]] && ok "an exact name and a bare star are still accepted" || bad "an exact name and a bare star are still accepted" "exit 0 and a config written" "$r"

echo
echo "== an IP literal and a CIDR range become destination acls, not SNI =="
out="$(emit "192.0.2.10 443
104.16.0.0/12 443")"
has "the literal and the range are destination addresses" "$out" "acl allowed_dst dst -m ip 104.16.0.0/12 192.0.2.10"
has "an allowed destination routes to the destination backend" "$out" "use_backend to_dst if allowed_dst"
has "no SNI acl is emitted for addresses" "$out" "!req.ssl_sni"

echo
echo "== a star host routes every connection to the destination =="
out="$(emit "* 443")"
has "any host routes to the destination backend by default" "$out" "default_backend to_dst"
has "no refuse backend is the default for any-host" "$out" "!default_backend refuse"

echo
echo "== localhost is loopback, not a name the broker resolves =="
out="$(emit "localhost 443")"
has "localhost becomes a destination address acl" "$out" "acl allowed_dst dst -m ip"
has "localhost covers the IPv4 loopback range" "$out" "127.0.0.0/8"
has "localhost covers the IPv6 loopback address" "$out" "::1"
has "localhost is not resolved as an exact name" "$out" "!do-resolve"
has "localhost is not an exact SNI acl" "$out" "!exact_sni"

echo
echo "== exact_connect_names lists the names the broker resolves, and nothing else =="
printf 'a.example 443\n*.b.example 443\n192.0.2.3 443\nlocalhost 443\n* 443\n' > "$WORK/net.rules"
exact_out="$(exact_connect_names "$WORK/net.rules")"
has "an exact name is listed" "$exact_out" "a.example"
has "a wildcard name is not listed" "$exact_out" "!*.b.example"
has "an address is not listed" "$exact_out" "!192.0.2.3"
has "localhost is not listed" "$exact_out" "!localhost"
has "a star is not listed" "$exact_out" "!*"

echo
echo "== an all-digit token is classified as an address, as tests must pin =="
has "1234 is an address, not an exact name (the shell-vs-guard divergence)" "$(classify_connect_host 1234)" "address"
has "a plain name is exact" "$(classify_connect_host repo.example.org)" "exact"

echo
echo "== names and addresses together each get their own allow =="
out="$(emit "repo.example.org 443
192.0.2.10 443")"
has "the name has an SNI acl" "$out" "acl exact_sni_p443 req.ssl_sni -m str -i repo.example.org"
has "the address has a destination acl" "$out" "acl allowed_dst dst -m ip 192.0.2.10"
has "the SNI allow routes to the destination" "$out" "use_backend to_dst if exact_port_p443 exact_sni_p443"
has "the destination allow routes to the destination" "$out" "use_backend to_dst if allowed_dst"

echo
echo "== a name is held to its own port, so a connection allowed on another port cannot carry that port to it =="
out="$(emit "a.example 443
b.example 8443
c.example 443")"
has "the names of one port share an acl" "$out" "acl exact_sni_p443 req.ssl_sni -m str -i a.example c.example"
has "the name of another port has its own acl" "$out" "acl exact_sni_p8443 req.ssl_sni -m str -i b.example"
has "the first port is an acl of its own" "$out" "acl exact_port_p443 dst_port 443"
has "the second port is an acl of its own" "$out" "acl exact_port_p8443 dst_port 8443"
has "a name is not matched on the other name's port" "$out" "!exact_sni_p8443 req.ssl_sni -m str -i a.example"
has "each pair resolves only for its own port" "$out" "do-resolve(txn.hostip,phobosdns,ipv4) req.ssl_sni if exact_port_p8443 exact_sni_p8443"
has "each pair routes only for its own port" "$out" "use_backend to_dst if exact_port_p8443 exact_sni_p8443"
out="$(emit "a.example 443
a.example 8443")"
has "one name on two ports is in both groups" "$out" "acl exact_sni_p8443 req.ssl_sni -m str -i a.example"
out="$(emit "localhost *
example.org 443")"
has "a loopback wildcard beside a name leaves the name held to its port" "$out" "do-resolve(txn.hostip,phobosdns,ipv4) req.ssl_sni if exact_port_p443 exact_sni_p443"
has "the loopback range is still an address allow" "$out" "use_backend to_dst if allowed_dst"
out="$(emit "example.org *")"
has "a name with no port is held to no port, as written" "$out" "acl exact_sni_pany req.ssl_sni -m str -i example.org"
has "and has no port acl" "$out" "!exact_port_pany"

echo
echo "== build_haproxy_conf wraps the rules in a loopback proxy preamble and backends =="
printf 'repo.maven.apache.org 443\n' > "$WORK/net.rules"
build_haproxy_conf "$WORK/net.rules" "$WORK/haproxy.cfg" "127.0.0.1:3128" "127.0.0.11:53"
conf="$(cat "$WORK/haproxy.cfg")"
has "it binds the given loopback endpoint and reads the PROXY header" "$conf" "bind 127.0.0.1:3128 accept-proxy"
has "it sets the destination from the header" "$conf" "tcp-request content set-dst dst"
has "it reads the ClientHello" "$conf" "req.ssl_hello_type 1"
has "it emits the resolver the name is resolved through" "$conf" "nameserver dns1 127.0.0.11:53"
has "it carries the allow-list" "$conf" "use_backend to_dst if exact_port_p443 exact_sni_p443"
has "it has a destination backend" "$conf" "backend to_dst"
has "it has a refuse backend" "$conf" "backend refuse"

echo
echo "== the broker logs its refusals to a descriptor only when it is given one =="
printf 'repo.maven.apache.org 443\n' > "$WORK/net.rules"
build_haproxy_conf "$WORK/net.rules" "$WORK/haproxy.cfg" "127.0.0.1:3128" "127.0.0.11:53" 11
conf="$(cat "$WORK/haproxy.cfg")"
has "it logs raw lines to the descriptor given" "$conf" "log fd@11 format raw local0"
has "it does not log a connection that completed normally" "$conf" "option dontlog-normal"
has "and logs machine fields only: marker, backend, termination state, hex host name, destination" "$conf" 'log-format "%[var(txn.marker)] %b %ts %[var(txn.sni),hex] %[dst] %[dst_port]"'
has "the marker is the broker's own constant" "$conf" "tcp-request content set-var(txn.marker) str(PHB-BROKER)"
has "taking the host name from a variable set while the ClientHello is inspected" "$conf" "tcp-request content set-var(txn.sni) req.ssl_sni"
build_haproxy_conf "$WORK/net.rules" "$WORK/haproxy.cfg" "127.0.0.1:3128" "127.0.0.11:53"
conf="$(cat "$WORK/haproxy.cfg")"
has "with no descriptor it logs nothing at all" "$conf" "!log "
has "and sets no log format" "$conf" "!log-format"
has "nor keeps the host name in a variable" "$conf" "!set-var(txn.sni)"
has "nor dontlog-normal" "$conf" "!dontlog-normal"

echo
echo "== a bare ip resolver gets the default DNS port, and no resolver emits no section =="
build_haproxy_conf "$WORK/net.rules" "$WORK/haproxy.cfg" "127.0.0.1:3128" "192.0.2.53"
has "a bare resolver ip is given the default port" "$(cat "$WORK/haproxy.cfg")" "nameserver dns1 192.0.2.53:53"
printf '203.0.113.9 443\n' > "$WORK/net.rules"
build_haproxy_conf "$WORK/net.rules" "$WORK/haproxy.cfg" "127.0.0.1:3128"
has "an address-only config needs no resolvers section" "$(cat "$WORK/haproxy.cfg")" "!resolvers phobosdns"

echo
if command -v haproxy >/dev/null 2>&1; then
  for body in "" "repo.maven.apache.org 443" "repo.example.org 443
192.0.2.10 443
104.16.0.0/12 443" "* 443"; do
    printf '%s\n' "$body" > "$WORK/net.rules"
    build_haproxy_conf "$WORK/net.rules" "$WORK/haproxy.cfg" "127.0.0.1:3128" "127.0.0.11:53"
    if haproxy -c -f "$WORK/haproxy.cfg" >/dev/null 2>&1; then
      ok "a generated config for '$(printf '%s' "$body" | tr '\n' ',')' is valid to haproxy"
    else
      bad "a generated config for '$(printf '%s' "$body" | tr '\n' ',')' is valid to haproxy" "$(haproxy -c -f "$WORK/haproxy.cfg" 2>&1 | tail -3)"
    fi
  done
  printf 'repo.example.org 443\n192.0.2.10 443\n' > "$WORK/net.rules"
  build_haproxy_conf "$WORK/net.rules" "$WORK/haproxy.cfg" "127.0.0.1:3128" "127.0.0.11:53" 11
  if (exec 11<>/dev/null; haproxy -c -f "$WORK/haproxy.cfg" >/dev/null 2>&1); then
    ok "a generated config that logs its refusals to a descriptor is valid to haproxy"
  else
    bad "a generated config that logs its refusals to a descriptor is valid to haproxy" "$( (exec 11<>/dev/null; haproxy -c -f "$WORK/haproxy.cfg" 2>&1) | tail -3)"
  fi
  printf 'repo.maven.apache.org 443\n' > "$WORK/net.rules"
  build_haproxy_conf "$WORK/net.rules" "$WORK/haproxy.cfg" "127.0.0.1:3128"
  if haproxy -c -f "$WORK/haproxy.cfg" >/dev/null 2>&1; then
    bad "an exact-name config with no resolver is rejected by haproxy" "it was accepted, so the resolvers section is not load-bearing"
  else
    ok "an exact-name config with no resolver is rejected by haproxy, so the network layer must supply one"
  fi
else
  skip "a generated config is valid to haproxy" "haproxy is not installed here; the acceptance suite checks it in the image"
fi

echo
echo "== the names a udp rule holds, and the rules the guard is handed for them =="
printf 'tcp.example 443\nudp.example 53 udp\nudp.example 5353 udp\n8.8.8.8 53 udp\nlocalhost 53 udp\n* 123 udp\n10.0.0.0/8 53 udp\n# c.example 9 udp\n' > "$WORK/udp-names.rules"
got="$(udp_connect_names "$WORK/udp-names.rules" | paste -sd' ')"
[[ "$got" == "udp.example" ]] && ok "only a host name in a udp row is listed, once, and no address, range, star or tcp name" \
  || bad "only a host name in a udp row is listed, once, and no address, range, star or tcp name" "udp.example" "$got"
got="$(exact_connect_names "$WORK/udp-names.rules" | paste -sd' ')"
[[ "$got" == "tcp.example" ]] && ok "the broker's names stay the tcp ones, a udp name does not start the broker" \
  || bad "the broker's names stay the tcp ones, a udp name does not start the broker" "tcp.example" "$got"
printf 'DNS.example 53 udp\ndns.example 123 udp\nOther.Example 9 udp\n' > "$WORK/udp-case.rules"
got="$(udp_connect_names "$WORK/udp-case.rules" | paste -sd' ')"
[[ "$got" == "dns.example other.example" ]] && ok "a name spelled in two cases is one name, listed once in lower case" \
  || bad "a name spelled in two cases is one name, listed once in lower case" "dns.example other.example" "$got"
printf 'dns.example 192.0.2.7\nother.example 192.0.2.8\n' > "$WORK/resolved-case"
expand_udp_name_rules "$WORK/udp-case.rules" "$WORK/resolved-case" "$WORK/guard-case.rules"
got="$(paste -sd'|' "$WORK/guard-case.rules")"
[[ "$got" == "192.0.2.7 53 udp|192.0.2.7 123 udp|192.0.2.8 9 udp" ]] \
  && ok "every spelling of the name gets the one resolved set, on its own port" \
  || bad "every spelling of the name gets the one resolved set, on its own port" "192.0.2.7 53 udp|192.0.2.7 123 udp|192.0.2.8 9 udp" "$got"
got="$(udp_connect_names "$WORK/absent.rules")"
[[ -z "$got" ]] && ok "a missing file names nothing" || bad "a missing file names nothing" "" "$got"

printf 'udp.example 192.0.2.1\nudp.example 2001:db8::1\nother.example 192.0.2.9\n' > "$WORK/resolved"
expand_udp_name_rules "$WORK/udp-names.rules" "$WORK/resolved" "$WORK/guard.rules"
got="$(paste -sd'|' "$WORK/guard.rules")"
want='tcp.example 443|192.0.2.1 53 udp|2001:db8::1 53 udp|192.0.2.1 5353 udp|2001:db8::1 5353 udp|8.8.8.8 53 udp|localhost 53 udp|* 123 udp|10.0.0.0/8 53 udp'
[[ "$got" == "$want" ]] && ok "a udp name row becomes a row per address on its own port, every other row is kept as it was and the comment is dropped" \
  || bad "a udp name row becomes a row per address on its own port, every other row is kept as it was" "$want" "$got"
: > "$WORK/nothing"
expand_udp_name_rules "$WORK/udp-names.rules" "$WORK/nothing" "$WORK/guard-none.rules"
got="$(paste -sd'|' "$WORK/guard-none.rules")"
[[ "$got" == 'tcp.example 443|8.8.8.8 53 udp|localhost 53 udp|* 123 udp|10.0.0.0/8 53 udp' ]] \
  && ok "a udp name with no resolved address yields no row, so it is denied and never read as a port-only rule" \
  || bad "a udp name with no resolved address yields no row, so it is denied and never read as a port-only rule" "" "$got"
expand_udp_name_rules "$WORK/udp-names.rules" "$WORK/resolved" "$WORK/no-such-dir/out"
[[ $? -ne 0 ]] && ok "a rules file that cannot be written is a failure" || bad "a rules file that cannot be written is a failure" "non-zero" "0"

finish
