#!/usr/bin/env bash
# The egress broker enforces the [connect] allow-list by TLS host name, on a real kernel.
#
# The connect guard hands every allowed stream connection to HAProxy on loopback with a PROXY
# protocol version 2 header naming the destination (proven by tests/connect_guard.sh). HAProxy,
# started from a config tests/haproxy_conf.sh proves build_haproxy_conf generates, reads the host
# name from the TLS ClientHello, which the guard cannot see, and forwards a permitted name to the
# destination while refusing one the allow-list does not name. This drives that whole path: an
# allowed name reaches an upstream, a forbidden one does not. It needs a C compiler, HAProxy,
# openssl and a kernel with seccomp user-notification, and skips itself where any is absent.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=harness.sh
source "${HERE}/harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../core"
# shellcheck source=../core/phobos-haproxy.sh
source "${CORE}/phobos-haproxy.sh"

WORK="$(mktemp -d)"
cleanup() {
  [[ -n "${haproxy_pid:-}" ]] && kill "$haproxy_pid" 2>/dev/null
  [[ -n "${upstream_pid:-}" ]] && kill "$upstream_pid" 2>/dev/null
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
if ! "$compiler" -std=gnu23 -O2 -Wall -Wextra -Werror -o "$WORK/guard" "${CORE}"/phobos-connect-guard*.c 2>"$WORK/cc.log"; then
  bad "the connect guard builds" "$(cat "$WORK/cc.log")"
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
/* The status the upstream ends with when it cannot bind its port. */
enum { UPSTREAM_BIND_FAILED = 3 };
/* How many connections may wait to be accepted. */
enum { LISTEN_BACKLOG = 4 };
/* A tiny server that writes a marker file the moment it accepts a connection, so the suite can
 * tell whether the broker forwarded one. It reads and discards what follows. */
int main(int argc, char **argv) {
    int server = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)atoi(argv[1]));
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
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
        FILE *marker = fopen(argv[2], "w");
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

probe_out="$("$WORK/guard" -- /bin/true 2>&1)"
if [[ "$probe_out" == *"NEW_LISTENER"* ]]; then
  skip "the egress broker" "this kernel has no seccomp user-notification"
  finish
fi

UPORT=39511
BROKER=39512
LISTENER_WAIT_ATTEMPTS=100
LISTENER_WAIT_SECONDS=0.05

# The allow-list names a host, not the loopback address the upstream really listens on: the guard
# lets any address on the port through to the broker, and the broker decides by the ClientHello.
printf 'allowed.example %s\n' "$UPORT" > "$WORK/rules"
build_haproxy_conf "$WORK/rules" "$WORK/haproxy.cfg" "127.0.0.1:$BROKER"

"$WORK/upstream" "$UPORT" "$WORK/upstream.marker" > "$WORK/upstream.out" 2>&1 &
upstream_pid=$!
haproxy -f "$WORK/haproxy.cfg" -db > "$WORK/haproxy.out" 2>&1 &
haproxy_pid=$!
for _ in $(seq 1 "$LISTENER_WAIT_ATTEMPTS"); do grep -q UPSTREAM-LISTENING "$WORK/upstream.out" 2>/dev/null && break; sleep "$LISTENER_WAIT_SECONDS"; done
sleep 0.5

# Runs one TLS client under the guard, sending the given SNI, and answers whether the upstream
# was reached. The client's own exit does not matter: the upstream is plain and never completes
# the handshake, so what the check reads is whether the broker forwarded the connection at all.
reached_with_sni() {
  rm -f "$WORK/upstream.marker"
  "$WORK/guard" --rules "$WORK/rules" --broker "127.0.0.1:$BROKER" -- \
    timeout 3 openssl s_client -connect "127.0.0.1:$UPORT" -servername "$1" -quiet < /dev/null \
    > "$WORK/client.out" 2>&1
  sleep 0.5
  [[ -f "$WORK/upstream.marker" ]]
}

if reached_with_sni "allowed.example"; then
  ok "a connection whose ClientHello names an allowed host reaches the destination"
else
  bad "a connection whose ClientHello names an allowed host reaches the destination" "client=$(cat "$WORK/client.out") haproxy=$(cat "$WORK/haproxy.out")"
fi

if reached_with_sni "forbidden.example"; then
  bad "a connection whose ClientHello names a forbidden host is refused" "the upstream was reached; client=$(cat "$WORK/client.out")"
else
  ok "a connection whose ClientHello names a forbidden host never reaches the destination"
fi

finish
