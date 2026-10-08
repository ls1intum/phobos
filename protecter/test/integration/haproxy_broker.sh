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
# localhost rule, which is loopback rather than a name to resolve; a server that speaks first on a
# port no name rule names gets its banner to the client at once rather than after the broker's
# inspect-delay, while a port no rule names stays refused; a broker that cannot start, and
# an exact-name rule with no resolver, each refuse the run; and, end to end through the network
# layer, the name is mapped to a placeholder the command resolves with no DNS before it reaches the
# resolved address, and once the run has ended the mapping and the broker are both gone. It needs
# a C compiler, HAProxy, openssl and a kernel with seccomp user-notification, and skips itself
# where any is absent.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../src"
# shellcheck source=../../src/phobos-tools-common/phobos-common.sh
source "${CORE}/phobos-tools-common/phobos-common.sh"
# shellcheck source=../../src/phobos-tools-networksystem/phobos-haproxy.sh
source "${CORE}/phobos-tools-networksystem/phobos-haproxy.sh"

WORK="$(mktemp -d)"
cleanup() {
  stop_haproxy_child "${broker_pid:-}"
  stop_haproxy_child "${lh_broker_pid:-}"
  stop_haproxy_child "${sf_broker_pid:-}"
  stop_haproxy_child "${log_broker_pid:-}"
  stop_haproxy_child "${flood_broker_pid:-}"
  [[ -n "${speaker_pid:-}" ]] && kill "$speaker_pid" 2>/dev/null
  [[ -n "${ungranted_pid:-}" ]] && kill "$ungranted_pid" 2>/dev/null
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
if ! "$compiler" -std=gnu23 -O2 -Wall -Wextra -Werror -o "$WORK/guard" "${CORE}"/phobos-seccomp-networksystem/phobos-seccomp-networksystem*.c \
  "${CORE}"/phobos-seccomp-filesystem/phobos-seccomp-filesystem-*.c \
  "${CORE}"/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-policy.c \
  "${CORE}"/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-path-rule.c \
  "${CORE}"/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-model.c 2>"$WORK/cc.log"; then
  bad "the connect guard builds" "$(cat "$WORK/cc.log")"
  finish
fi
# The network layer applies the Landlock TCP-port rules itself now, so the end-to-end case below,
# whose [connect] rule names a port, needs the phobos-landlock-filesystem-and-networksystem binary too.
if ! "$compiler" -std=gnu23 -O2 -Wall -Wextra -Werror -o "$WORK/phobos-landlock-filesystem-and-networksystem" "${CORE}"/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem*.c 2>"$WORK/cc.log"; then
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
 * accepts a connection, so the suite can tell which address the broker forwarded to. Given a
 * banner, it sends that line first, before it reads anything, as a server that speaks first does.
 * It reads and discards what follows. Arguments: bind address, port, marker path, optional banner. */
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
        if (argc > 4) {
            ssize_t spoke = write(client, argv[4], strlen(argv[4]));
            (void)spoke;
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

cat > "$WORK/reader.c" <<'C'
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
/* The status the reader ends with when no byte came in time, and when it cannot connect. */
enum { NOTHING_IN_TIME = 1 };
enum { CONNECT_FAILED = 7 };
/* A client for a server that speaks first: it connects to an address and port, sends nothing, and
 * waits at most the given number of milliseconds for the server's first bytes, which it prints after
 * "BANNER ". Arguments: address, port, milliseconds. */
int main(int argc, char **argv) {
    if (argc < 4) {
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
        perror("connect");
        return CONNECT_FAILED;
    }
    struct pollfd readable = { .fd = sock, .events = POLLIN };
    if (poll(&readable, 1, atoi(argv[3])) != 1) {
        printf("NOTHING within %s ms\n", argv[3]);
        return NOTHING_IN_TIME;
    }
    char banner[64];
    ssize_t got = read(sock, banner, sizeof(banner) - 1);
    if (got <= 0) {
        printf("CLOSED before any byte\n");
        return NOTHING_IN_TIME;
    }
    banner[got] = '\0';
    printf("BANNER %s\n", banner);
    close(sock);
    return 0;
}
C
if ! "$compiler" -O2 -o "$WORK/reader" "$WORK/reader.c" 2>"$WORK/reader-cc.log"; then
  bad "the reading client builds" "$(cat "$WORK/reader-cc.log")"
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

# How the map from an exact name to the placeholder is written and removed again is pinned by
# protecter/test/unit/phobos-tools-common/hosts_entries.sh; the end-to-end case below proves it through
# the network layer.

# A broker that cannot even start refuses to be started, so a run that asked for one fails
# rather than losing the enforcement quietly.
spec_fail="$WORK/spec-fail"
mkdir -p "$spec_fail"
printf 'allowed.example %s\n' "$UPORT" > "$spec_fail/net.rules"
if start_egress_broker "$spec_fail" "$spec_fail/net.rules" "/nonexistent/haproxy" "127.0.0.1:${DNSPORT}" fail_endpoint fail_pid > /dev/null 2>&1; then
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
"${CORE}/phobos-networksystem.sh" --connect-guard-bin "$WORK/guard" \
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

broker_endpoint=""
broker_pid=""
start_egress_broker "$spec" "$spec/net.rules" "$haproxy_bin" "127.0.0.1:${DNSPORT}" broker_endpoint broker_pid
if [[ -z "$broker_endpoint" || -z "$broker_pid" ]] || ! kill -0 "$broker_pid" 2>/dev/null; then
  bad "the broker starts on a loopback port and hands back its endpoint and process id" "endpoint=${broker_endpoint} pid=${broker_pid}"
  finish
fi
ok "the broker starts on a loopback port and hands back its endpoint and process id"

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
# protecter/test/unit/seccomp_networksystem_unit.c pins, and by the config carrying no exact-name path for localhost,
# which protecter/test/unit/phobos-tools-networksystem/haproxy_conf.sh pins.
LOOPBACK_IP=127.0.0.5
spec_lh="$WORK/spec-lh"
mkdir -p "$spec_lh"
printf 'localhost %s\n' "$UPORT" > "$spec_lh/net.rules"
"$WORK/upstream" "$LOOPBACK_IP" "$UPORT" "$WORK/lh.marker" > "$WORK/lh.out" 2>&1 &
loopback_pid=$!
for _ in $(seq 1 "$LISTENER_WAIT_ATTEMPTS"); do grep -q UPSTREAM-LISTENING "$WORK/lh.out" 2>/dev/null && break; sleep "$LISTENER_WAIT_SECONDS"; done
lh_endpoint=""
lh_broker_pid=""
start_egress_broker "$spec_lh" "$spec_lh/net.rules" "$haproxy_bin" "" lh_endpoint lh_broker_pid
rm -f "$WORK/lh.marker"
"$WORK/guard" --rules "$spec_lh/net.rules" --broker "$lh_endpoint" -- \
  timeout 3 "$WORK/client" "$LOOPBACK_IP" "$UPORT" > "$WORK/lh.client.out" 2>&1 || true
sleep 0.6
if [[ -f "$WORK/lh.marker" ]]; then
  ok "a plain loopback connection is forwarded under a localhost rule, whatever its SNI"
else
  bad "a plain loopback connection is forwarded under a localhost rule" "the loopback upstream was not reached; broker=$(cat "$spec_lh/${PHB_SPEC_SCRATCH}/broker.log" 2>/dev/null)"
fi

# A name is held to its own port. The guard hands every connection it allows to the broker, which keeps
# the destination port it was given, so a connection the guard let through on another port under a
# loopback rule, with the allowed name in its ClientHello, must not carry that port to the name: here
# the name resolves to REAL_IP, which listens on the other port too, and a bypass would reach it
# instead of the loopback address the command aimed at.
OTHER_PORT=39512
spec_mx="$WORK/spec-mx"
mkdir -p "$spec_mx"
printf 'localhost *\nallowed.example %s\n' "$UPORT" > "$spec_mx/net.rules"
"$WORK/upstream" "$REAL_IP" "$OTHER_PORT" "$WORK/bypass.marker" > "$WORK/bypass.out" 2>&1 &
bypass_pid=$!
"$WORK/upstream" "$LOOPBACK_IP" "$OTHER_PORT" "$WORK/aimed.marker" > "$WORK/aimed.out" 2>&1 &
aimed_pid=$!
for _ in $(seq 1 "$LISTENER_WAIT_ATTEMPTS"); do grep -q UPSTREAM-LISTENING "$WORK/bypass.out" 2>/dev/null && break; sleep "$LISTENER_WAIT_SECONDS"; done
for _ in $(seq 1 "$LISTENER_WAIT_ATTEMPTS"); do grep -q UPSTREAM-LISTENING "$WORK/aimed.out" 2>/dev/null && break; sleep "$LISTENER_WAIT_SECONDS"; done
mx_endpoint=""
mx_broker_pid=""
start_egress_broker "$spec_mx" "$spec_mx/net.rules" "$haproxy_bin" "127.0.0.1:${DNSPORT}" mx_endpoint mx_broker_pid
rm -f "$WORK/bypass.marker" "$WORK/aimed.marker"
"$WORK/guard" --rules "$spec_mx/net.rules" --broker "$mx_endpoint" -- \
  timeout 3 openssl s_client -connect "${LOOPBACK_IP}:${OTHER_PORT}" -servername allowed.example -quiet < /dev/null \
  > "$WORK/mx.client.out" 2>&1 || true
sleep 0.6
if [[ -f "$WORK/aimed.marker" && ! -f "$WORK/bypass.marker" ]]; then
  ok "an allowed name in the ClientHello of a connection allowed on another port does not carry that port to the name"
else
  bad "an allowed name does not carry another port to its address" "aimed=$([[ -f "$WORK/aimed.marker" ]] && echo yes || echo no) bypass=$([[ -f "$WORK/bypass.marker" ]] && echo yes || echo no); broker=$(cat "$spec_mx/${PHB_SPEC_SCRATCH}/broker.log" 2>/dev/null)"
fi
rm -f "$WORK/real.marker" "$WORK/decoy.marker"
"$WORK/guard" --rules "$spec_mx/net.rules" --broker "$mx_endpoint" -- \
  timeout 3 openssl s_client -connect "${DECOY_IP}:${UPORT}" -servername allowed.example -quiet < /dev/null \
  > "$WORK/mx.client.out" 2>&1 || true
sleep 0.6
if [[ -f "$WORK/real.marker" && ! -f "$WORK/decoy.marker" ]]; then
  ok "and on the port the rule names the same name still reaches the address it resolves to"
else
  bad "the name still reaches its address on its own port" "real=$([[ -f "$WORK/real.marker" ]] && echo yes || echo no) decoy=$([[ -f "$WORK/decoy.marker" ]] && echo yes || echo no)"
fi
stop_haproxy_child "$mx_broker_pid"
kill "$bypass_pid" "$aimed_pid" 2> /dev/null || true

# A server that speaks first, as SMTP, MySQL or SSH do, hears nothing from its client before it has
# sent its banner, and the broker connects onward only once it has decided the connection. A
# decision that waited for a ClientHello would therefore hold the banner back until the broker's
# five-second inspect-delay ran out. On a port no name rule names, no ClientHello can change the
# decision, so it is made at once and the banner arrives well within that delay. Beside it the other
# directions are pinned under the same rules: a loopback port no rule names is still refused, the
# allowed name still reaches the address it resolves to, and a forbidden name reaches nothing.
SPEAKER_IP=127.0.0.6
SPEAKER_PORT=39513
UNGRANTED_PORT=39514
BANNER_WAIT_MILLISECONDS=3000
spec_sf="$WORK/spec-sf"
mkdir -p "$spec_sf"
printf '%s %s\nallowed.example %s\n' "$SPEAKER_IP" "$SPEAKER_PORT" "$UPORT" > "$spec_sf/net.rules"
"$WORK/upstream" "$SPEAKER_IP" "$SPEAKER_PORT" "$WORK/speaker.marker" "220 speaker ready" > "$WORK/speaker.out" 2>&1 &
speaker_pid=$!
"$WORK/upstream" "$SPEAKER_IP" "$UNGRANTED_PORT" "$WORK/ungranted.marker" "220 ungranted ready" > "$WORK/ungranted.out" 2>&1 &
ungranted_pid=$!
for _ in $(seq 1 "$LISTENER_WAIT_ATTEMPTS"); do grep -q UPSTREAM-LISTENING "$WORK/speaker.out" 2>/dev/null && break; sleep "$LISTENER_WAIT_SECONDS"; done
for _ in $(seq 1 "$LISTENER_WAIT_ATTEMPTS"); do grep -q UPSTREAM-LISTENING "$WORK/ungranted.out" 2>/dev/null && break; sleep "$LISTENER_WAIT_SECONDS"; done
sf_endpoint=""
sf_broker_pid=""
start_egress_broker "$spec_sf" "$spec_sf/net.rules" "$haproxy_bin" "127.0.0.1:${DNSPORT}" sf_endpoint sf_broker_pid
sf_status=0
"$WORK/guard" --rules "$spec_sf/net.rules" --broker "$sf_endpoint" -- \
  "$WORK/reader" "$SPEAKER_IP" "$SPEAKER_PORT" "$BANNER_WAIT_MILLISECONDS" > "$WORK/sf.client.out" 2>&1 \
  || sf_status=$?
if (( sf_status == 0 )) && grep -q '^BANNER 220 speaker ready' "$WORK/sf.client.out"; then
  ok "a server that speaks first on a port no name rule names gets its banner to the client at once, not after the broker's inspect-delay"
else
  bad "a server that speaks first gets its banner to the client at once" "exit ${sf_status}; client=$(cat "$WORK/sf.client.out"); broker=$(cat "$spec_sf/${PHB_SPEC_SCRATCH}/broker.log" 2>/dev/null)"
fi
rm -f "$WORK/ungranted.marker"
sf_status=0
"$WORK/guard" --rules "$spec_sf/net.rules" --broker "$sf_endpoint" -- \
  "$WORK/reader" "$SPEAKER_IP" "$UNGRANTED_PORT" "$BANNER_WAIT_MILLISECONDS" > "$WORK/sf.client.out" 2>&1 \
  || sf_status=$?
sleep 0.6
if (( sf_status == 7 )) && [[ ! -f "$WORK/ungranted.marker" ]]; then
  ok "beside it, a loopback port no rule names is still refused, and its server is never reached"
else
  bad "a loopback port no rule names is still refused" "exit ${sf_status}, expected 7; reached=$([[ -f "$WORK/ungranted.marker" ]] && echo yes || echo no); client=$(cat "$WORK/sf.client.out")"
fi
rm -f "$WORK/real.marker" "$WORK/decoy.marker"
"$WORK/guard" --rules "$spec_sf/net.rules" --broker "$sf_endpoint" -- \
  timeout 3 openssl s_client -connect "${DECOY_IP}:${UPORT}" -servername allowed.example -quiet < /dev/null \
  > "$WORK/sf.client.out" 2>&1 || true
sleep 0.6
if [[ -f "$WORK/real.marker" && ! -f "$WORK/decoy.marker" ]]; then
  ok "and the allowed name still reaches only the address it resolves to"
else
  bad "the allowed name still reaches only the address it resolves to" "real=$([[ -f "$WORK/real.marker" ]] && echo yes || echo no) decoy=$([[ -f "$WORK/decoy.marker" ]] && echo yes || echo no)"
fi
rm -f "$WORK/real.marker" "$WORK/decoy.marker"
"$WORK/guard" --rules "$spec_sf/net.rules" --broker "$sf_endpoint" -- \
  timeout 3 openssl s_client -connect "${REAL_IP}:${UPORT}" -servername forbidden.example -quiet < /dev/null \
  > "$WORK/sf.client.out" 2>&1 || true
sleep 0.6
if [[ ! -f "$WORK/real.marker" && ! -f "$WORK/decoy.marker" ]]; then
  ok "and a forbidden name still reaches neither address"
else
  bad "a forbidden name still reaches neither address" "the upstream was reached; client=$(cat "$WORK/sf.client.out")"
fi
stop_haproxy_child "$sf_broker_pid"
kill "$speaker_pid" "$ungranted_pid" 2> /dev/null || true
sf_broker_pid=""
speaker_pid=""
ungranted_pid=""

# The whole network layer, end to end: it writes the placeholder to /etc/hosts, starts the broker
# with the resolver, and the command then resolves the name with no DNS, connects, and reaches the
# address the broker resolves. Once the run has ended, the layer has stopped the broker and the
# placeholder line is gone, leaving /etc/hosts as it found it. The rule names only the host and its
# port: beside a loopback wildcard rule (no port) the port would get no Landlock rule, since
# Landlock expresses ports, not hosts, and the connect guard alone would enforce it. The directory is marked as one Phobos owns, as phobos.sh marks its own, so the
# layer's clean-up treats it as the run's. It writes /etc/hosts, so it needs that file writable, as
# the run-phase image the acceptance suite uses gives; where it is not, this one case is skipped.
if [[ -w /etc/hosts ]]; then
  spec_e2e="$WORK/spec-e2e"
  mkdir -p "$spec_e2e"
  mark_owned_spec_dir "$spec_e2e"
  printf 'allowed.example %s\n' "$UPORT" > "$spec_e2e/net.rules"
  hosts_before="$(cat /etc/hosts; printf 'x')"
  rm -f "$WORK/real.marker"
  "${CORE}/phobos-networksystem.sh" --connect-guard-bin "$WORK/guard" --landlock-bin "$WORK/phobos-landlock-filesystem-and-networksystem" \
    --resolver "127.0.0.1:${DNSPORT}" "$spec_e2e" -- \
    timeout 4 openssl s_client -connect "allowed.example:${UPORT}" -servername allowed.example -quiet < /dev/null \
    > "$WORK/e2e.out" 2>&1 || true
  if [[ -f "$WORK/real.marker" ]]; then
    ok "the network layer maps the name, and the command resolves it with no DNS and reaches the resolved address"
  else
    bad "the network layer maps the name, and the command resolves it with no DNS and reaches the resolved address" "real=no; out=$(tail -2 "$WORK/e2e.out")"
  fi
  [[ "$(cat /etc/hosts; printf 'x')" == "$hosts_before" ]] \
    && ok "once the run has ended, /etc/hosts is byte-identical to what it was before" \
    || bad "once the run has ended, /etc/hosts is byte-identical to what it was before" "$(grep allowed.example /etc/hosts)"
  if pgrep -f "${spec_e2e}/${PHB_SPEC_SCRATCH}/broker.cfg" > /dev/null; then
    bad "once the run has ended, the broker the layer started is gone" "$(pgrep -af "${spec_e2e}/${PHB_SPEC_SCRATCH}/broker.cfg")"
  else
    ok "once the run has ended, the broker the layer started is gone"
  fi
  [[ ! -e "$spec_e2e" ]] && ok "and so is the run's specification directory" || bad "and so is the run's specification directory" "$(ls -A "$spec_e2e")"
  spec_e2e2="$WORK/spec-e2e2"
  mkdir -p "$spec_e2e2"
  mark_owned_spec_dir "$spec_e2e2"
  printf 'allowed.example %s\n' "$UPORT" > "$spec_e2e2/net.rules"
  "${CORE}/phobos-networksystem.sh" --connect-guard-bin "$WORK/guard" --landlock-bin "$WORK/phobos-landlock-filesystem-and-networksystem" \
    --resolver "127.0.0.1:${DNSPORT}" "$spec_e2e2" -- \
    timeout 4 openssl s_client -connect "allowed.example:${UPORT}" -servername forbidden.example -quiet < /dev/null \
    > "$WORK/e2e.refused.out" 2>&1 || true
  if [[ "$(grep -cF "illegally connect to the Host 'forbidden.example' on Port ${UPORT}" "$WORK/e2e.refused.out")" == 1 ]]; then
    ok "through the network layer, a ClientHello for a host no rule names is refused and the guard words it once, from the pipe the layer opened"
  else
    bad "through the network layer, a refused host name is worded once" "$(tail -4 "$WORK/e2e.refused.out")"
  fi
else
  skip "the network layer maps the name end to end" "/etc/hosts is not writable here"
fi

# The broker's refusals reach the guard through an anonymous pipe, and the guard words each of them. HAProxy
# logs a refusal to a descriptor it inherited, in the machine fields the guard reads; the host name is hex,
# so a name the program chose cannot inject anything into the line. First what the broker logs for a
# refused host name, a refused plain connection and an allowed name; then that the command inherits no
# descriptor of the pipe and cannot reach it through the guard's descriptors with the filesystem layer on;
# then, with the filesystem layer off, the limit the layer's manual states, that a command running as the
# same user can write to the pipe through /proc and forge a line; last, that a broker whose log nobody
# reads is not stalled by it.
REFUSED_NAME_LINE="Phobos Security Error: the program tried to illegally connect to the Host 'forbidden.example' on Port ${UPORT} but was blocked by Phobos."
REFUSED_PLAIN_LINE="Phobos Security Error: the program tried to illegally connect to the Endpoint ${REAL_IP}:${UPORT} over TCP but was blocked by Phobos."
spec_log="$WORK/spec-log"
mkdir -p "$spec_log"
printf 'allowed.example %s\n' "$UPORT" > "$spec_log/net.rules"
exec {broker_log}<> <(:)
log_endpoint=""
log_broker_pid=""
start_egress_broker "$spec_log" "$spec_log/net.rules" "$haproxy_bin" "127.0.0.1:${DNSPORT}" log_endpoint log_broker_pid "$broker_log"
if [[ -z "$log_endpoint" || -z "$log_broker_pid" ]]; then
  bad "a broker that logs to a descriptor starts" "endpoint=${log_endpoint} pid=${log_broker_pid}"
else
  ok "a broker that logs its refusals to a descriptor starts"
  guard_with_log() {
    "$WORK/guard" --rules "$spec_log/net.rules" --broker "$log_endpoint" --broker-log-fd "$broker_log" "$@"
  }

  rm -f "$WORK/real.marker" "$WORK/decoy.marker"
  guard_with_log -- timeout 3 openssl s_client -connect "${REAL_IP}:${UPORT}" -servername forbidden.example -quiet \
    < /dev/null > "$WORK/log.client.out" 2>&1 || true
  sleep 0.6
  if [[ "$(grep -cxF -- "$REFUSED_NAME_LINE" "$WORK/log.client.out")" == 1 && ! -f "$WORK/real.marker" ]]; then
    ok "a ClientHello for a host no rule names is still refused and prints one line naming the host and the port"
  else
    bad "a ClientHello for a host no rule names is refused and printed once" "$(cat "$WORK/log.client.out"); broker=$(cat "$spec_log/${PHB_SPEC_SCRATCH}/broker.log" 2>/dev/null)"
  fi

  rm -f "$WORK/real.marker" "$WORK/decoy.marker"
  guard_with_log -- timeout 3 openssl s_client -connect "${REAL_IP}:${UPORT}" -servername allowed.example -quiet \
    < /dev/null > "$WORK/log.client.out" 2>&1 || true
  sleep 0.6
  if [[ -f "$WORK/real.marker" && "$(grep -cE 'illegally connect to the (Host|Endpoint)' "$WORK/log.client.out")" == 0 ]]; then
    ok "an allowed host name still connects and prints no connect line (timeout's own setpgid and openssl's netlink socket are worded, being refused too)"
  else
    bad "an allowed host name still connects and prints nothing" "$(cat "$WORK/log.client.out")"
  fi

  guard_with_log -- timeout 3 "$WORK/client" "$REAL_IP" "$UPORT" > "$WORK/log.client.out" 2>&1 || true
  sleep 0.6
  if [[ "$(grep -cxF -- "$REFUSED_PLAIN_LINE" "$WORK/log.client.out")" == 1 ]]; then
    ok "a plain connection to an address no rule names prints one line naming the endpoint"
  else
    bad "a plain connection to an address no rule names prints one line naming the endpoint" "$(cat "$WORK/log.client.out")"
  fi

  # A host a rule names whose address the broker cannot resolve is refused too, but not by the policy, so it
  # is not worded as a blocked connection. The log shows its name field empty, which the guard ignores.
  spec_unres="$WORK/spec-unres"
  mkdir -p "$spec_unres"
  printf 'allowed.example %s\n' "$UPORT" > "$spec_unres/net.rules"
  unres_endpoint=""
  unres_pid=""
  start_egress_broker "$spec_unres" "$spec_unres/net.rules" "$haproxy_bin" "127.0.0.1:9" unres_endpoint unres_pid "$broker_log"
  rm -f "$WORK/real.marker"
  "$WORK/guard" --rules "$spec_unres/net.rules" --broker "$unres_endpoint" --broker-log-fd "$broker_log" -- \
    timeout 8 openssl s_client -connect "${REAL_IP}:${UPORT}" -servername allowed.example -quiet \
    < /dev/null > "$WORK/log.unres.out" 2>&1 || true
  sleep 0.6
  if [[ ! -f "$WORK/real.marker" && "$(grep -cE 'illegally connect to the (Host|Endpoint)' "$WORK/log.unres.out")" == 0 ]]; then
    ok "an allowed host name the broker cannot resolve is refused without a line that blames the policy"
  else
    bad "an allowed host name the broker cannot resolve is refused without a line that blames the policy" "$(cat "$WORK/log.unres.out")"
  fi
  stop_haproxy_child "$unres_pid"

  # Only the broker's pipe is ever written to below, found by its identity: any other descriptor a
  # step holds, a CI runner's own channel among them, must not receive a forged line.
  PIPE_ID="$(readlink "/proc/$$/fd/${broker_log}")"
  export PIPE_ID
  guard_with_log -- bash -c 'for descriptor in /proc/self/fd/*; do readlink "$descriptor"; done' \
    > "$WORK/log.fds.out" 2>&1 || true
  if [[ "$(grep -cxF -- "$PIPE_ID" "$WORK/log.fds.out")" == 0 ]]; then
    ok "the command inherits no descriptor of the broker's pipe (a CI runner's own pipes, which any step holds, are not counted)"
  else
    bad "the command inherits no descriptor of the broker's pipe" "$(cat "$WORK/log.fds.out")"
  fi
  guard_with_log -- bash -c 'held=0
    for descriptor in /proc/self/fd/*; do
      if [[ "$(readlink "$descriptor")" == "$PIPE_ID" ]]; then held=$((held + 1)); echo "PHB-BROKER refuse PR 666f72676564 1.2.3.4 80" >&"${descriptor##*/}"; fi
    done; echo "held=$held"' > "$WORK/log.forge.out" 2>&1 || true
  if [[ "$(grep -c "the Host 'forged'" "$WORK/log.forge.out")" == 0 ]] && grep -qx 'held=0' "$WORK/log.forge.out"; then
    ok "a command holds no descriptor of the pipe, so it can write a forged broker line to none"
  else
    bad "a command holds no descriptor of the pipe, so it can write a forged broker line to none" "$(cat "$WORK/log.forge.out")"
  fi
  guard_with_log -- bash -c 'for descriptor in /proc/$PPID/fd/*; do
      if [[ "$(readlink "$descriptor")" == "$PIPE_ID" ]]; then echo "PHB-BROKER refuse PR 666f72676564 1.2.3.4 80" > "$descriptor" 2>/dev/null; fi
    done; sleep 0.5' > "$WORK/log.reach.out" 2>&1 || true
  if [[ "$(grep -c "the Host 'forged'" "$WORK/log.reach.out")" -ge 1 ]]; then
    ok "the limit the manual states: with no Landlock domain at all a command can reach the pipe through the guard's /proc entry and forge a line"
  else
    bad "the limit the manual states: with no Landlock domain at all a command can forge a line through /proc" "the forged line did not print; $(cat "$WORK/log.reach.out")"
  fi
  ls "$spec_log" "$spec_log/${PHB_SPEC_SCRATCH}" > "$WORK/log.listing" 2>&1
  if ! grep -qE 'broker[-.]?log[^.]|\.pipe|\.fifo' "$WORK/log.listing" && [[ -z "$(find "$spec_log" -type p)" ]]; then
    ok "no file or pipe on a file system carries the log: the specification directory holds none"
  else
    bad "no file or pipe on a file system carries the log" "$(cat "$WORK/log.listing")"
  fi
fi

# A broker whose log nobody reads. The pipe holds 64 KiB, about 1300 lines; the guard makes the shared
# description non-blocking, so HAProxy's write fails with EAGAIN and it drops the line instead of waiting.
# The description is made non-blocking here by a helper, and then 3000 refused connections are made without
# anyone reading, after which an allowed connection and a refused one are both still decided.
cat > "$WORK/nonblock.c" <<'C'
#include <fcntl.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc < 2) {
        return 2;
    }
    int descriptor = atoi(argv[1]);
    int flags = fcntl(descriptor, F_GETFL);
    return flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0;
}
C
if ! "$compiler" -O2 -o "$WORK/nonblock" "$WORK/nonblock.c" 2>"$WORK/nonblock-cc.log"; then
  bad "the non-blocking helper builds" "$(cat "$WORK/nonblock-cc.log")"
else
  spec_flood="$WORK/spec-flood"
  mkdir -p "$spec_flood"
  printf 'allowed.example %s\n' "$UPORT" > "$spec_flood/net.rules"
  exec {flood_log}<> <(:)
  "$WORK/nonblock" "$flood_log"
  flood_endpoint=""
  flood_broker_pid=""
  start_egress_broker "$spec_flood" "$spec_flood/net.rules" "$haproxy_bin" "127.0.0.1:${DNSPORT}" flood_endpoint flood_broker_pid "$flood_log"
  flood_port="${flood_endpoint##*:}"
  FLOOD_REFUSALS=3000
  for _ in $(seq 1 "$FLOOD_REFUSALS"); do
    exec 3<>"/dev/tcp/127.0.0.1/${flood_port}"
    printf 'PROXY TCP4 127.0.0.1 93.184.216.34 40000 443\r\njunk\r\n' >&3
    exec 3>&-
  done
  sleep 1
  rm -f "$WORK/real.marker" "$WORK/decoy.marker"
  "$WORK/guard" --rules "$spec_flood/net.rules" --broker "$flood_endpoint" --broker-log-fd "$flood_log" -- \
    timeout 3 openssl s_client -connect "${REAL_IP}:${UPORT}" -servername allowed.example -quiet < /dev/null \
    > "$WORK/flood.client.out" 2>&1 || true
  sleep 0.6
  if kill -0 "$flood_broker_pid" 2>/dev/null && [[ -f "$WORK/real.marker" ]]; then
    ok "after ${FLOOD_REFUSALS} refusals nobody read, the broker is not stalled: an allowed connection still completes"
  else
    bad "after ${FLOOD_REFUSALS} refusals nobody read, an allowed connection still completes" "broker alive=$(kill -0 "$flood_broker_pid" 2>/dev/null && echo yes || echo no); $(cat "$WORK/flood.client.out")"
  fi
  rm -f "$WORK/real.marker" "$WORK/decoy.marker"
  "$WORK/guard" --rules "$spec_flood/net.rules" --broker "$flood_endpoint" --broker-log-fd "$flood_log" -- \
    timeout 3 openssl s_client -connect "${REAL_IP}:${UPORT}" -servername forbidden.example -quiet < /dev/null \
    > "$WORK/flood.client.out" 2>&1 || true
  sleep 0.6
  if [[ ! -f "$WORK/real.marker" && "$(grep -cxF -- "$REFUSED_NAME_LINE" "$WORK/flood.client.out")" -le 1 ]]; then
    ok "and a refused one is still refused (its line may be lost to the full pipe, never the refusal)"
  else
    bad "a refused connection after the flood is still refused" "$(cat "$WORK/flood.client.out")"
  fi
fi

stopped_pid="$broker_pid"
stop_haproxy_child "$broker_pid"
broker_pid=""
if kill -0 "$stopped_pid" 2>/dev/null; then
  bad "stopping the broker ends it" "the broker is still running"
else
  ok "stopping the broker ends it and collects its status"
fi

finish
