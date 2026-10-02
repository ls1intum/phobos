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
has "the name becomes an exact SNI acl" "$out" "acl exact_sni req.ssl_sni -m str -i repo.maven.apache.org"
has "the broker resolves the name rather than trust the header" "$out" "do-resolve(txn.hostip,phobosdns,ipv4) req.ssl_sni if exact_sni"
has "the destination is set to the resolved address" "$out" "set-dst var(txn.hostip) if exact_sni { var(txn.hostip) -m found }"
has "a name that does not resolve is refused" "$out" "reject if exact_sni !{ var(txn.hostip) -m found }"
has "an allowed SNI routes to the destination backend" "$out" "use_backend to_dst if exact_sni"
has "everything else is refused" "$out" "default_backend refuse"

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
has "the name has an SNI acl" "$out" "acl exact_sni req.ssl_sni -m str -i repo.example.org"
has "the address has a destination acl" "$out" "acl allowed_dst dst -m ip 192.0.2.10"
has "the SNI allow routes to the destination" "$out" "use_backend to_dst if exact_sni"
has "the destination allow routes to the destination" "$out" "use_backend to_dst if allowed_dst"

echo
echo "== build_haproxy_conf wraps the rules in a loopback proxy preamble and backends =="
printf 'repo.maven.apache.org 443\n' > "$WORK/net.rules"
build_haproxy_conf "$WORK/net.rules" "$WORK/haproxy.cfg" "127.0.0.1:3128" "127.0.0.11:53"
conf="$(cat "$WORK/haproxy.cfg")"
has "it binds the given loopback endpoint and reads the PROXY header" "$conf" "bind 127.0.0.1:3128 accept-proxy"
has "it sets the destination from the header" "$conf" "tcp-request content set-dst dst"
has "it reads the ClientHello" "$conf" "req.ssl_hello_type 1"
has "it emits the resolver the name is resolved through" "$conf" "nameserver dns1 127.0.0.11:53"
has "it carries the allow-list" "$conf" "use_backend to_dst if exact_sni"
has "it has a destination backend" "$conf" "backend to_dst"
has "it has a refuse backend" "$conf" "backend refuse"

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

finish
