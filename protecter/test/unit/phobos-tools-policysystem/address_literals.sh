#!/usr/bin/env bash
# Which spellings of an address, a range and a port a [connect] line may use. The connect guard reads
# only an exact dotted-quad or IPv6 address as an address and treats anything else as a host name, held
# to its port alone, so an address that is almost right would open its port to every address. The
# parser therefore has to refuse each of those spellings, and has to accept every right one, which this
# suite pins in both directions, for the two literal tests and for the whole check a line goes through.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../../src"
# shellcheck source=../../../src/phobos-tools-common/phobos-common.sh
source "${CORE}/phobos-tools-common/phobos-common.sh"
# shellcheck source=../../../src/phobos-tools-policysystem/phobos-policy-parse.sh
source "${CORE}/phobos-tools-policysystem/phobos-policy-parse.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== IPv4 literals =="
for address in 0.0.0.0 1.2.3.4 127.0.0.1 255.255.255.255 10.20.30.40 192.168.1.1 100.64.0.1 9.9.9.9; do
  if is_ipv4_literal "$address"; then ok "${address} is an address"; else bad "${address} is an address" "accepted" "refused"; fi
done
for address in 256.1.1.1 1.2.3 1.2.3.4.5 127.1 2130706433 01.2.3.4 1.2.3.04 1.2.3. .1.2.3 1..2.3 -1.2.3.4 1.2.3.4a 999.0.0.1 1.2.3.256 a.b.c.d "" "1.2.3.4 " 1.2.3.-4 1,2,3,4 ٨.٨.٨.٨ 1.2.3.٤ ١٢٧.٠.٠.١ ١0.0.0.1 25٤.0.0.1 1.2.3.٥٠ ٢55.255.255.255; do
  if is_ipv4_literal "$address"; then bad "'${address}' is not an address" "refused" "accepted"; else ok "'${address}' is not an address"; fi
done

echo
echo "== IPv6 literals =="
for address in ::1 :: 2001:db8::1 2001:db8:0:0:0:0:0:1 fe80::1 ::ffff:127.0.0.1 1:2:3:4:5:6:7:8 1:2:3:4:5:6:7:: ::2:3:4:5:6:7:8 1::8 ABCD::ef01 ::ffff:1.2.3.4 1:2:3:4:5:6:1.2.3.4 64:ff9b::1.2.3.4; do
  if is_ipv6_literal "$address"; then ok "${address} is an IPv6 address"; else bad "${address} is an IPv6 address" "accepted" "refused"; fi
done
for address in ::1::2 1:2:3:4:5:6:7:8:9 1:2:3:4:5:6:7 :1 1: ::1: :::1 1:::2 12345::1 g::1 fe80::1%eth0 1.2.3.4 ::1.2.3 ::256.1.1.1 1:2:3:4:5:6:7:8: 1::2::3 : 1:2:3:4:5:6:7:1.2.3.4 1.2.3.4::1 ::ffff:127.0.0.1.5 "" "::1 " ::٨ ٨::1 ::١2 fe٨0::1; do
  if is_ipv6_literal "$address"; then bad "'${address}' is not an IPv6 address" "refused" "accepted"; else ok "'${address}' is not an IPv6 address"; fi
done

echo
echo "== the whole check a [connect] line goes through =="
# Runs refuse_malformed_address in a subshell, since a refusal exits, and prints "<status>|<message>".
judge() {
  local out
  out="$(refuse_malformed_address "$1" "$2" "allow $1:$2" 2>&1 > /dev/null)"
  printf '%s|%s' "$?" "$out"
}
for case in "127.0.0.1|80" "127.0.0.1|*" "10.0.0.0/8|80" "10.0.0.0/32|80" "10.0.0.0/1|80" "::1|80" "2001:db8::/32|80" "2001:db8::/128|80" "2001:db8::/1|80" "::ffff:127.0.0.1/96|80" "::ffff:127.0.0.1/128|80" "::ffff:1:2:3/64|80" "1::ffff:7f00:1/64|80" "0:0:0:0:ffff:0:7f00:1/64|80" "localhost|80" "*|80" "example.org|443" "1password.example|443" "cafe.example|443" "0x7f.1|80" "under_score.example|80"; do
  host="${case%%|*}"
  port="${case##*|}"
  result="$(judge "$host" "$port")"
  if [[ "${result%%|*}" == 0 ]]; then ok "accepted: ${host}:${port}"; else bad "accepted: ${host}:${port}" "status 0" "${result}"; fi
done
for case in "256.1.1.1|80|not a valid address" "1.2.3|80|not a valid address" "1.2.3.4.5|80|not a valid address" "127.1|80|not a valid address" "2130706433|80|not a valid address" "01.2.3.4|80|not a valid address" "::1::2|80|not a valid address" "fe80::1%eth0|80|not a valid address" "1.2.3.4|(empty)|no port" "::1|(empty)|no port" "10.0.0.0/33|80|prefix length" "10.0.0.0/-1|80|prefix length" "10.0.0.0/abc|80|prefix length" "10.0.0.0/|80|prefix length" "10.0.0.0/0|80|prefix length of 0" "::/0|80|prefix length of 0" "2001:db8::/129|80|prefix length" "2001:db8::/1000|80|prefix length" "300.0.0.0/8|80|not a valid address" "example.org/24|80|not a valid address" "1.2.3/8|80|not a valid address" "localhost/|80|not a valid address" "localhost/8|80|not a valid address" "::ffff:127.0.0.1/95|80|IPv4-mapped" "::ffff:7f00:1/64|80|IPv4-mapped" "0:0:0:0:0:ffff:7f00:1/95|80|IPv4-mapped" "0:0:0:0:0:FFFF:127.0.0.1/1|80|IPv4-mapped" "::FFFF:127.0.0.1/0|80|prefix length of 0"; do
  host="${case%%|*}"
  rest="${case#*|}"
  port="${rest%%|*}"
  message="${rest#*|}"
  [[ "$port" == "(empty)" ]] && port=""
  result="$(judge "$host" "$port")"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"${message}"* ]]; then ok "refused as a policy error, saying '${message}': ${host}:${port}"; else bad "refused as a policy error, saying '${message}': ${host}:${port}" "status ${PHB_EPOLICY}" "${result}"; fi
done

finish
