#!/usr/bin/env bash
# The egress broker enforces the [connect] allow-list by TLS host name, on a real kernel, as the
# network layer starts it.
#
# start_egress_broker generates the broker's config from the allow-list, binds HAProxy to a free
# loopback port and records its process id for the layer to stop later. The connect guard then
# hands every allowed stream connection to that broker with a PROXY protocol header naming the
# destination (proven by tests/connect_guard.sh). HAProxy reads the host name from the TLS
# ClientHello, which the guard cannot see, and forwards a permitted name to the destination while
# refusing one the allow-list does not name. The broker is started under the same libnetblocker
# preload the network layer imposes on the graded command, so an allowed name reaching the upstream
# also proves the broker forwards from outside that filter rather than being refused by it. This
# drives that whole path: an allowed name reaches an upstream, a forbidden one does not, a broker
# that cannot start refuses the run, and stopping the recorded broker ends it. It needs a C
# compiler, HAProxy, openssl and a kernel with seccomp user-notification, and skips itself where
# any is absent.
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
# The network layer runs the graded command, and so the broker it starts, with libnetblocker
# preloaded. The broker must forward a host-name connection all the same, which it can only do
# outside that filter, so the suite starts it under the real preload environment to prove it
# escapes it rather than is broken by it. A libnetblocker built from the same sources stands in
# for the one the image ships, which the checkout does not carry.
netblocker_so="$WORK/libnetblocker.so"
if ! "$compiler" -std=gnu23 -O2 -fPIC -shared -o "$netblocker_so" "${CORE}"/../ld_preloader/*.c 2>"$WORK/nb.log"; then
  bad "libnetblocker builds for the broker's environment" "$(cat "$WORK/nb.log")"
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
LISTENER_WAIT_ATTEMPTS=100
LISTENER_WAIT_SECONDS=0.05
haproxy_bin="$(command -v haproxy)"

# A broker that cannot even start refuses to be started, so a run that asked for one fails
# rather than losing the enforcement quietly.
spec_fail="$WORK/spec-fail"
mkdir -p "$spec_fail"
printf 'allowed.example %s\n' "$UPORT" > "$spec_fail/net.rules"
if start_egress_broker "$spec_fail" "$spec_fail/net.rules" "/nonexistent/haproxy" > /dev/null 2>&1; then
  bad "a broker whose binary is missing fails to start" "it reported success"
else
  ok "a broker whose binary is missing fails to start rather than run without enforcement"
fi

# The network layer maps that start failure to a refusal: asked for a broker it cannot start, it
# ends the run with PHB-ERUNTIME rather than run the command without the host-name enforcement.
spec_layer="$WORK/spec-layer"
mkdir -p "$spec_layer"
printf 'allowed.example %s\n' "$UPORT" > "$spec_layer/net.rules"
layer_status=0
"${CORE}/phobos-network.sh" --netblocker-so "$netblocker_so" --connect-guard-bin "$WORK/guard" \
  --egress-broker --haproxy-bin /nonexistent/haproxy "$spec_layer" -- true > "$WORK/layer.out" 2>&1 \
  || layer_status=$?
if (( layer_status == PHB_ERUNTIME )); then
  ok "the network layer refuses the run when the broker it was asked for cannot start"
else
  bad "the network layer refuses the run when the broker it was asked for cannot start" \
    "exit was ${layer_status}, expected ${PHB_ERUNTIME}; output: $(cat "$WORK/layer.out")"
fi

# The allow-list names a host, not the loopback address the upstream really listens on: the guard
# lets any address on the port through to the broker, and the broker decides by the ClientHello.
spec="$WORK/spec"
mkdir -p "$spec"
printf 'allowed.example %s\n' "$UPORT" > "$spec/net.rules"
"$WORK/upstream" "$UPORT" "$WORK/upstream.marker" > "$WORK/upstream.out" 2>&1 &
upstream_pid=$!
for _ in $(seq 1 "$LISTENER_WAIT_ATTEMPTS"); do grep -q UPSTREAM-LISTENING "$WORK/upstream.out" 2>/dev/null && break; sleep "$LISTENER_WAIT_SECONDS"; done

export LD_PRELOAD="$netblocker_so"
export NETBLOCKER_CONF="$spec/net.rules"
broker_endpoint="$(start_egress_broker "$spec" "$spec/net.rules" "$haproxy_bin")"
unset LD_PRELOAD NETBLOCKER_CONF
if [[ -z "$broker_endpoint" || ! -f "$spec/${PHB_SPEC_BROKER_PID}" ]]; then
  bad "the network layer starts the broker and records it" "endpoint=$broker_endpoint pidfile missing"
  finish
fi
ok "the network layer starts the broker on a loopback port and records its process id"
broker_pid="$(cat "$spec/${PHB_SPEC_BROKER_PID}")"

# Runs one TLS client under the guard, pointed at the started broker, sending the given SNI, and
# answers whether the upstream was reached. The client's own exit does not matter: the upstream is
# plain and never completes the handshake, so what the check reads is whether the broker forwarded
# the connection at all.
reached_with_sni() {
  rm -f "$WORK/upstream.marker"
  "$WORK/guard" --rules "$spec/net.rules" --broker "$broker_endpoint" -- \
    timeout 3 openssl s_client -connect "127.0.0.1:$UPORT" -servername "$1" -quiet < /dev/null \
    > "$WORK/client.out" 2>&1
  sleep 0.5
  [[ -f "$WORK/upstream.marker" ]]
}

if reached_with_sni "allowed.example"; then
  ok "a connection whose ClientHello names an allowed host reaches the destination"
else
  bad "a connection whose ClientHello names an allowed host reaches the destination" "client=$(cat "$WORK/client.out") broker=$(cat "$spec/${PHB_SPEC_SCRATCH}/broker.log" 2>/dev/null)"
fi

if reached_with_sni "forbidden.example"; then
  bad "a connection whose ClientHello names a forbidden host is refused" "the upstream was reached; client=$(cat "$WORK/client.out")"
else
  ok "a connection whose ClientHello names a forbidden host never reaches the destination"
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
