#!/usr/bin/env bash
# The egress broker binds an exact [connect] name to the address it resolves itself, on a real
# kernel, as the network layer starts it.
#
# For an exact host name the broker does not trust the destination the command aimed at: it reads
# the name from the TLS ClientHello, resolves it through its own resolver, and connects to that
# address. So a command that presents an allowed name but aims at some other address is still sent
# only to where the name resolves. This drives that whole path with a stand-in resolver that maps
# the name to one loopback address while a decoy listens on another: a connection that names the
# allowed host reaches the resolved address; the same name aimed at the decoy still reaches the
# resolved address and never the decoy (the spoof is denied); a forbidden name, and a plain
# connection with no ClientHello, reach neither; a plain loopback connection is forwarded under a
# localhost rule, which is loopback rather than a name to resolve; a broker that cannot start, and
# an exact-name rule with no resolver, each refuse the run; and, end to end through the network
# layer, the name is mapped to a placeholder the command resolves with no DNS before it reaches the
# resolved address. It needs a C compiler, HAProxy, openssl and a kernel with seccomp
# user-notification, and skips itself where any is absent.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=harness.sh
source "${HERE}/harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../core"
# shellcheck source=../core/phobos-common.sh
source "${CORE}/phobos-common.sh"
# shellcheck source=../core/phobos-haproxy.sh
source "${CORE}/phobos-haproxy.sh"

WORK="$(mktemp -d)"
cleanup() {
  [[ -n "${broker_pid:-}" ]] && kill "$broker_pid" 2>/dev/null
  [[ -n "${lh_broker_pid:-}" ]] && kill "$lh_broker_pid" 2>/dev/null
  [[ -n "${e2e_broker_pid:-}" ]] && kill "$e2e_broker_pid" 2>/dev/null
  [[ -n "${real_pid:-}" ]] && kill "$real_pid" 2>/dev/null
  [[ -n "${decoy_pid:-}" ]] && kill "$decoy_pid" 2>/dev/null
  [[ -n "${loopback_pid:-}" ]] && kill "$loopback_pid" 2>/dev/null
  [[ -n "${dns_pid:-}" ]] && kill "$dns_pid" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

compiler=gcc-14
command -v "$compiler" >/dev/null 2>&1 || compiler=gcc
if ! command -v "$compiler" >/dev/null 2>&1; then
  skip "the egress broker" "no C compiler to build the guard"
  finish
fi
if ! command -v haproxy >/dev/null 2>&1; then
  skip "the egress broker" "haproxy is not installed here"
  finish
fi
if ! command -v openssl >/dev/null 2>&1; then
  skip "the egress broker" "openssl is not installed here, so no ClientHello can be sent"
  finish
fi
if ! "$compiler" -std=gnu23 -O2 -Wall -Wextra -Werror -o "$WORK/guard" "${CORE}"/phobos-seccomp-networksystem*.c 2>"$WORK/cc.log"; then
  bad "the connect guard builds" "$(cat "$WORK/cc.log")"
  finish
fi
# The network layer applies the Landlock TCP-port rules itself now, so the end-to-end case below,
# whose [connect] rule names a port, needs the phobos-landlock-filesystem-and-networksystem binary too.
if ! "$compiler" -std=gnu23 -O2 -Wall -Wextra -Werror -o "$WORK/phobos-landlock-filesystem-and-networksystem" "${CORE}"/phobos-landlock-filesystem-and-networksystem*.c 2>"$WORK/cc.log"; then
  bad "phobos-landlock-filesystem-and-networksystem builds" "$(cat "$WORK/cc.log")"
  finish
fi

cat > "$WORK/upstream.c" <<'C'
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
/* The status the upstream ends with when it cannot bind its address. */
enum { UPSTREAM_BIND_FAILED = 3 };
/* How many connections may wait to be accepted. */
enum { LISTEN_BACKLOG = 4 };
/* A tiny server on a given loopback address and port that writes a marker file the moment it
 * accepts a connection, so the suite can tell which address the broker forwarded to. It reads and
 * discards what follows. Arguments: bind address, port, marker path. */
int main(int argc, char **argv) {
    if (argc < 4) {
        return 2;
    }
    int server = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &address.sin_addr) != 1) {
        return 2;
    }
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0) {
        perror("bind");
        return UPSTREAM_BIND_FAILED;
    }
    listen(server, LISTEN_BACKLOG);
    printf("UPSTREAM-LISTENING\n");
    fflush(stdout);
    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client < 0) {
            continue;
        }
        FILE *marker = fopen(argv[3], "w");
        if (marker != NULL) {
            fprintf(marker, "GOT\n");
            fclose(marker);
        }
        char discard[64];
        ssize_t got = read(client, discard, sizeof(discard));
        (void)got;
        close(client);
    }
}
C
if ! "$compiler" -O2 -o "$WORK/upstream" "$WORK/upstream.c" 2>"$WORK/upstream-cc.log"; then
  bad "the upstream builds" "$(cat "$WORK/upstream-cc.log")"
  finish
fi

cat > "$WORK/dns.c" <<'C'
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
/* The status the responder ends with when it cannot bind its port. */
enum { DNS_BIND_FAILED = 3 };
/* A DNS message opens with a twelve-byte header; a question ends with a two-byte type and class. */
enum { HEADER_BYTES = 12 };
enum { QUESTION_TAIL = 4 };
/* A stand-in resolver that answers every A query on a loopback port with one fixed address, so the
 * broker can resolve a name without a real network. It echoes the question and points the answer
 * name back at it. Arguments: port, answer address. */
int main(int argc, char **argv) {
    if (argc < 3) {
        return 2;
    }
    struct in_addr answer;
    if (inet_pton(AF_INET, argv[2], &answer) != 1) {
        return 2;
    }
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons((unsigned short)atoi(argv[1]));
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) != 0) {
        perror("bind");
        return DNS_BIND_FAILED;
    }
    printf("DNS-LISTENING\n");
    fflush(stdout);
    for (;;) {
        unsigned char query[512];
        struct sockaddr_in from;
        socklen_t from_length = sizeof(from);
        ssize_t got = recvfrom(sock, query, sizeof(query), 0, (struct sockaddr *)&from, &from_length);
        if (got < HEADER_BYTES) {
            continue;
        }
        size_t name_end = HEADER_BYTES;
        while (name_end < (size_t)got && query[name_end] != 0) {
            name_end += (size_t)query[name_end] + 1;
        }
        size_t question_end = name_end + 1 + QUESTION_TAIL;
        if (question_end > (size_t)got) {
            continue;
        }
        unsigned char reply[600];
        memcpy(reply, query, question_end);
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply[6] = 0x00;
        reply[7] = 0x01;
        reply[8] = 0x00;
        reply[9] = 0x00;
        reply[10] = 0x00;
        reply[11] = 0x00;
        size_t at = question_end;
        reply[at++] = 0xC0;
        reply[at++] = 0x0C;
        reply[at++] = 0x00;
        reply[at++] = 0x01;
        reply[at++] = 0x00;
        reply[at++] = 0x01;
        reply[at++] = 0x00;
        reply[at++] = 0x00;
        reply[at++] = 0x00;
        reply[at++] = 0x1E;
        reply[at++] = 0x00;
        reply[at++] = 0x04;
        memcpy(&reply[at], &answer, 4);
        at += 4;
        ssize_t sent = sendto(sock, reply, at, 0, (struct sockaddr *)&from, from_length);
        (void)sent;
    }
}
C
if ! "$compiler" -O2 -o "$WORK/dns" "$WORK/dns.c" 2>"$WORK/dns-cc.log"; then
  bad "the stand-in resolver builds" "$(cat "$WORK/dns-cc.log")"
  finish
fi

cat > "$WORK/client.c" <<'C'
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
/* The status the client ends with when it cannot connect. */
enum { CONNECT_FAILED = 7 };
/* A plain TCP client that connects to an address and port and sends one byte, with no TLS
 * ClientHello, so the broker sees a connection carrying no host name. Arguments: address, port. */
int main(int argc, char **argv) {
    if (argc < 3) {
        return 2;
    }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &address.sin_addr) != 1) {
        return 2;
    }
    if (connect(sock, (struct sockaddr *)&address, sizeof(address)) != 0) {
        return CONNECT_FAILED;
    }
    ssize_t sent = write(sock, "x", 1);
    (void)sent;
    close(sock);
    return 0;
}
C
if ! "$compiler" -O2 -o "$WORK/client" "$WORK/client.c" 2>"$WORK/client-cc.log"; then
  bad "the plain client builds" "$(cat "$WORK/client-cc.log")"
  finish
fi

probe_out="$("$WORK/guard" -- /bin/true 2>&1)"
if [[ "$probe_out" == *"NEW_LISTENER"* ]]; then
  skip "the egress broker" "this kernel has no seccomp user-notification"
  finish
fi

UPORT=39511
REAL_IP=127.0.0.3
DECOY_IP=127.0.0.4
DNSPORT=39553
LISTENER_WAIT_ATTEMPTS=100
LISTENER_WAIT_SECONDS=0.05
haproxy_bin="$(command -v haproxy)"

# The map from an exact name to a loopback placeholder is what lets a command resolve the name with
# no DNS. It is appended once, under a marker, and only when not already there.
hosts_probe="$WORK/hosts"
printf '127.0.0.1 localhost\n' > "$hosts_probe"
write_broker_hosts "$hosts_probe" allowed.example
write_broker_hosts "$hosts_probe" allowed.example
if [[ "$(grep -c "^${PHB_BROKER_PLACEHOLDER_IP} allowed.example$" "$hosts_probe")" == "1" ]]; then
  ok "an exact name is mapped to the placeholder once, so the command can resolve it with no DNS"
else
  bad "an exact name is mapped to the placeholder once" "$(cat "$hosts_probe")"
fi

# A broker that cannot even start refuses to be started, so a run that asked for one fails
# rather than losing the enforcement quietly.
spec_fail="$WORK/spec-fail"
mkdir -p "$spec_fail"
printf 'allowed.example %s\n' "$UPORT" > "$spec_fail/net.rules"
if start_egress_broker "$spec_fail" "$spec_fail/net.rules" "/nonexistent/haproxy" "127.0.0.1:${DNSPORT}" > /dev/null 2>&1; then
  bad "a broker whose binary is missing fails to start" "it reported success"
else
  ok "a broker whose binary is missing fails to start rather than run without enforcement"
fi

# The network layer refuses an exact-name rule with no resolver, because the broker could not bind
# the name to its address, rather than run without the host-name enforcement it was asked for.
spec_layer="$WORK/spec-layer"
mkdir -p "$spec_layer"
printf 'allowed.example %s\n' "$UPORT" > "$spec_layer/net.rules"
layer_status=0
"${CORE}/phobos-network.sh" --connect-guard-bin "$WORK/guard" \
  "$spec_layer" -- true > "$WORK/layer.out" 2>&1 \
  || layer_status=$?
if (( layer_status == PHB_ERUNTIME )); then
  ok "the network layer refuses an exact-name rule when no resolver was given"
else
  bad "the network layer refuses an exact-name rule when no resolver was given" \
    "exit was ${layer_status}, expected ${PHB_ERUNTIME}; output: $(cat "$WORK/layer.out")"
fi

# The real path: the resolver maps the name to REAL_IP, a decoy listens on DECOY_IP, and the broker
# resolves the name itself.
spec="$WORK/spec"
mkdir -p "$spec"
printf 'allowed.example %s\n' "$UPORT" > "$spec/net.rules"
"$WORK/upstream" "$REAL_IP" "$UPORT" "$WORK/real.marker" > "$WORK/real.out" 2>&1 &
real_pid=$!
"$WORK/upstream" "$DECOY_IP" "$UPORT" "$WORK/decoy.marker" > "$WORK/decoy.out" 2>&1 &
decoy_pid=$!
"$WORK/dns" "$DNSPORT" "$REAL_IP" > "$WORK/dns.out" 2>&1 &
dns_pid=$!
for _ in $(seq 1 "$LISTENER_WAIT_ATTEMPTS"); do grep -q UPSTREAM-LISTENING "$WORK/real.out" 2>/dev/null && break; sleep "$LISTENER_WAIT_SECONDS"; done
for _ in $(seq 1 "$LISTENER_WAIT_ATTEMPTS"); do grep -q UPSTREAM-LISTENING "$WORK/decoy.out" 2>/dev/null && break; sleep "$LISTENER_WAIT_SECONDS"; done
for _ in $(seq 1 "$LISTENER_WAIT_ATTEMPTS"); do grep -q DNS-LISTENING "$WORK/dns.out" 2>/dev/null && break; sleep "$LISTENER_WAIT_SECONDS"; done

broker_endpoint="$(start_egress_broker "$spec" "$spec/net.rules" "$haproxy_bin" "127.0.0.1:${DNSPORT}")"
if [[ -z "$broker_endpoint" || ! -f "$spec/${PHB_SPEC_BROKER_PID}" ]]; then
  bad "the network layer starts the broker and records it" "endpoint=$broker_endpoint pidfile missing"
  finish
fi
ok "the network layer starts the broker on a loopback port and records its process id"
broker_pid="$(cat "$spec/${PHB_SPEC_BROKER_PID}")"

# Runs one TLS client under the guard, pointed at the started broker, sending the given SNI and
# aiming at the given address, then answers nothing: the caller reads the marker files to see which
# address the broker forwarded to. The client's own exit does not matter, as the upstreams are
# plain and never complete the handshake.
drive() {
  rm -f "$WORK/real.marker" "$WORK/decoy.marker"
  "$WORK/guard" --rules "$spec/net.rules" --broker "$broker_endpoint" -- \
    timeout 3 openssl s_client -connect "$2:$UPORT" -servername "$1" -quiet < /dev/null \
    > "$WORK/client.out" 2>&1 || true
  sleep 0.6
}

drive "allowed.example" "$REAL_IP"
if [[ -f "$WORK/real.marker" ]]; then
  ok "a connection whose ClientHello names an allowed host reaches the address the name resolves to"
else
  bad "a connection whose ClientHello names an allowed host reaches the address the name resolves to" "client=$(cat "$WORK/client.out") broker=$(cat "$spec/${PHB_SPEC_SCRATCH}/broker.log" 2>/dev/null)"
fi

drive "allowed.example" "$DECOY_IP"
if [[ -f "$WORK/real.marker" && ! -f "$WORK/decoy.marker" ]]; then
  ok "an allowed name aimed at another address still reaches only the resolved address, so a spoofed destination is ignored"
else
  bad "an allowed name aimed at another address still reaches only the resolved address" "real=$([[ -f "$WORK/real.marker" ]] && echo yes || echo no) decoy=$([[ -f "$WORK/decoy.marker" ]] && echo yes || echo no); client=$(cat "$WORK/client.out")"
fi

drive "forbidden.example" "$REAL_IP"
if [[ ! -f "$WORK/real.marker" && ! -f "$WORK/decoy.marker" ]]; then
  ok "a connection whose ClientHello names a forbidden host reaches neither address"
else
  bad "a connection whose ClientHello names a forbidden host reaches neither address" "the upstream was reached; client=$(cat "$WORK/client.out")"
fi

# A plain connection carries no ClientHello, so the broker has no host name to check against an
# exact-name rule and refuses it rather than forward a connection it cannot bind to a name.
rm -f "$WORK/real.marker" "$WORK/decoy.marker"
"$WORK/guard" --rules "$spec/net.rules" --broker "$broker_endpoint" -- \
  timeout 3 "$WORK/client" "$REAL_IP" "$UPORT" > "$WORK/client.out" 2>&1 || true
sleep 0.6
if [[ ! -f "$WORK/real.marker" && ! -f "$WORK/decoy.marker" ]]; then
  ok "a plain connection with no ClientHello reaches neither address under an exact-name rule"
else
  bad "a plain connection with no ClientHello reaches neither address under an exact-name rule" "an upstream was reached; client=$(cat "$WORK/client.out")"
fi

# localhost is loopback, not a name to resolve: a plain connection to a loopback address is
# forwarded to it under a localhost rule, which the slice-2 broker refused for want of the SNI
# "localhost". The forbidden direction, a non-loopback destination, is refused by the guard, which
# tests/unit/seccomp_networksystem_unit.c pins, and by the config carrying no exact-name path for localhost,
# which tests/haproxy_conf.sh pins.
LOOPBACK_IP=127.0.0.5
spec_lh="$WORK/spec-lh"
mkdir -p "$spec_lh"
printf 'localhost %s\n' "$UPORT" > "$spec_lh/net.rules"
"$WORK/upstream" "$LOOPBACK_IP" "$UPORT" "$WORK/lh.marker" > "$WORK/lh.out" 2>&1 &
loopback_pid=$!
for _ in $(seq 1 "$LISTENER_WAIT_ATTEMPTS"); do grep -q UPSTREAM-LISTENING "$WORK/lh.out" 2>/dev/null && break; sleep "$LISTENER_WAIT_SECONDS"; done
lh_endpoint="$(start_egress_broker "$spec_lh" "$spec_lh/net.rules" "$haproxy_bin")"
lh_broker_pid="$(cat "$spec_lh/${PHB_SPEC_BROKER_PID}" 2>/dev/null)"
rm -f "$WORK/lh.marker"
"$WORK/guard" --rules "$spec_lh/net.rules" --broker "$lh_endpoint" -- \
  timeout 3 "$WORK/client" "$LOOPBACK_IP" "$UPORT" > "$WORK/lh.client.out" 2>&1 || true
sleep 0.6
if [[ -f "$WORK/lh.marker" ]]; then
  ok "a plain loopback connection is forwarded under a localhost rule, whatever its SNI"
else
  bad "a plain loopback connection is forwarded under a localhost rule" "the loopback upstream was not reached; broker=$(cat "$spec_lh/${PHB_SPEC_SCRATCH}/broker.log" 2>/dev/null)"
fi

# The whole network layer, end to end: it writes the placeholder to /etc/hosts, starts the broker
# with the resolver, and the command then resolves the name with no DNS, connects, and reaches the
# address the broker resolves. The rule names only the host and its port: mixing it with a
# loopback wildcard rule (no port) is refused as unenforceable, because Landlock expresses ports,
# not hosts, so a wildcard alongside a concrete port would be half-enforced. It writes /etc/hosts,
# so it needs that file writable, as the run-phase image the acceptance suite uses gives; where it
# is not, this one case is skipped.
if [[ -w /etc/hosts ]]; then
  spec_e2e="$WORK/spec-e2e"
  mkdir -p "$spec_e2e"
  printf 'allowed.example %s\n' "$UPORT" > "$spec_e2e/net.rules"
  rm -f "$WORK/real.marker"
  "${CORE}/phobos-network.sh" --connect-guard-bin "$WORK/guard" --landlock-bin "$WORK/phobos-landlock-filesystem-and-networksystem" \
    --resolver "127.0.0.1:${DNSPORT}" "$spec_e2e" -- \
    timeout 4 openssl s_client -connect "allowed.example:${UPORT}" -servername allowed.example -quiet < /dev/null \
    > "$WORK/e2e.out" 2>&1 || true
  sleep 0.6
  e2e_broker_pid="$(cat "$spec_e2e/${PHB_SPEC_BROKER_PID}" 2>/dev/null)"
  if grep -qxF "${PHB_BROKER_PLACEHOLDER_IP} allowed.example" /etc/hosts && [[ -f "$WORK/real.marker" ]]; then
    ok "the network layer maps the name, and the command resolves it with no DNS and reaches the resolved address"
  else
    bad "the network layer maps the name, and the command resolves it with no DNS and reaches the resolved address" "hosts=$(grep allowed.example /etc/hosts || echo none) real=$([[ -f "$WORK/real.marker" ]] && echo yes || echo no); out=$(tail -2 "$WORK/e2e.out")"
  fi
else
  skip "the network layer maps the name end to end" "/etc/hosts is not writable here"
fi

stop_recorded_broker "$spec"
sleep 0.2
if kill -0 "$broker_pid" 2>/dev/null; then
  bad "stopping the recorded broker ends it" "the broker is still running"
else
  ok "stopping the recorded broker ends it, and removes the record"
  broker_pid=""
fi
[[ -f "$spec/${PHB_SPEC_BROKER_PID}" ]] && bad "the broker record is removed" "it is still there" || ok "the broker record is removed with it"

finish
