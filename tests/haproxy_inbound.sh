#!/usr/bin/env bash
# The inbound filter fronts a student's TCP listener on a public port and admits only the source
# addresses an [accept] rule names, on a real HAProxy.
#
# build_inbound_conf turns the "H P src" accept rules phobos-policysystem.sh writes into an haproxy.cfg
# that binds each public port H dual-stack and rejects a connection whose source is not in H's
# source file, forwarding an admitted one to the student's backend port P on loopback.
# start_inbound_haproxy starts it and records its process id for the layer to stop later. This
# drives that path with a backend that counts the connections it accepts and a client that binds a
# chosen loopback source before connecting: an admitted source reaches the backend, a rejected one
# does not, a service with no source admits no one, a filter that cannot start refuses the run, and
# stopping the recorded filter frees the port. It needs a C compiler and HAProxy, and skips itself
# where either is absent. No guard or Landlock is involved, so no special kernel is needed.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=harness.sh
source "${HERE}/harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../core"
# shellcheck source=../core/phobos-tools-common/phobos-common.sh
source "${CORE}/phobos-tools-common/phobos-common.sh"
# shellcheck source=../core/phobos-tools-networksystem/phobos-haproxy.sh
source "${CORE}/phobos-tools-networksystem/phobos-haproxy.sh"

WORK="$(mktemp -d)"
cleanup() {
  [[ -n "${inbound_pid:-}" ]] && kill "$inbound_pid" 2>/dev/null
  [[ -n "${server_pid:-}" ]] && kill "$server_pid" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

compiler=gcc-14
command -v "$compiler" >/dev/null 2>&1 || compiler=gcc
if ! command -v "$compiler" >/dev/null 2>&1; then
  skip "the inbound filter" "no C compiler to build the backend and client"
  finish
fi
if ! command -v haproxy >/dev/null 2>&1; then
  skip "the inbound filter" "haproxy is not installed here"
  finish
fi

cat > "$WORK/server.c" <<'C'
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
/* The status the backend ends with when it cannot bind its port. */
enum { BACKEND_BIND_FAILED = 3 };
/* How many connections may wait to be accepted. */
enum { LISTEN_BACKLOG = 8 };
/* A tiny backend on loopback that appends a line to a log file for every connection it accepts,
 * so the suite can count how many the filter admitted. Arguments: port, log path. */
int main(int argc, char **argv) {
    if (argc < 3) {
        return 2;
    }
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
        return BACKEND_BIND_FAILED;
    }
    listen(server, LISTEN_BACKLOG);
    printf("BACKEND-LISTENING\n");
    fflush(stdout);
    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client < 0) {
            continue;
        }
        FILE *log = fopen(argv[2], "a");
        if (log != NULL) {
            fprintf(log, "ACCEPT\n");
            fclose(log);
        }
        char discard[16];
        ssize_t got = read(client, discard, sizeof(discard));
        (void)got;
        close(client);
    }
}
C
if ! "$compiler" -O2 -o "$WORK/server" "$WORK/server.c" 2>"$WORK/server-cc.log"; then
  bad "the backend builds" "$(cat "$WORK/server-cc.log")"
  finish
fi

cat > "$WORK/srcclient.c" <<'C'
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
/* The status the client ends with when it cannot bind its source or connect. */
enum { SOURCE_BIND_FAILED = 4 };
enum { CONNECT_FAILED = 7 };
/* A client that binds a chosen loopback source address before connecting to a loopback port, so
 * the filter sees that source. Arguments: source address, port. */
int main(int argc, char **argv) {
    if (argc < 3) {
        return 2;
    }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in source;
    memset(&source, 0, sizeof(source));
    source.sin_family = AF_INET;
    if (inet_pton(AF_INET, argv[1], &source.sin_addr) != 1) {
        return 2;
    }
    if (bind(sock, (struct sockaddr *)&source, sizeof(source)) != 0) {
        return SOURCE_BIND_FAILED;
    }
    struct sockaddr_in destination;
    memset(&destination, 0, sizeof(destination));
    destination.sin_family = AF_INET;
    destination.sin_port = htons((unsigned short)atoi(argv[2]));
    destination.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(sock, (struct sockaddr *)&destination, sizeof(destination)) != 0) {
        return CONNECT_FAILED;
    }
    ssize_t sent = write(sock, "x", 1);
    (void)sent;
    close(sock);
    return 0;
}
C
if ! "$compiler" -O2 -o "$WORK/srcclient" "$WORK/srcclient.c" 2>"$WORK/client-cc.log"; then
  bad "the client builds" "$(cat "$WORK/client-cc.log")"
  finish
fi

HPORT=18888
BPORT=18080
ALLOWED=127.0.0.5
FORBIDDEN=127.0.0.6
haproxy_bin="$(command -v haproxy)"

# The generator turns "H P src" rules into a frontend that reads H's source file and a backend to
# the loopback backend port, and gives a service with no source an empty source file.
gen_spec="$WORK/gen"
mkdir -p "$gen_spec/scratch"
printf '%s %s %s\n%s %s %s\n' "$HPORT" "$BPORT" "$ALLOWED" "$HPORT" "$BPORT" "203.0.113.9" > "$gen_spec/accept.rules"
build_inbound_conf "$gen_spec/accept.rules" "$gen_spec/scratch/inbound.cfg" "$gen_spec/scratch"
conf="$(cat "$gen_spec/scratch/inbound.cfg")"
has() {
  local n="$1"
  local b="$2"
  local x="$3"
  if [[ "$x" == "!"* ]]; then
    if grep -qF -- "${x#!}" <<<"$b"; then bad "$n" "absent: ${x#!}" "present"; else ok "$n"; fi
  else
    if grep -qF -- "$x" <<<"$b"; then ok "$n"; else bad "$n" "present: $x" "absent"; fi
  fi
}
has "the frontend binds the public port dual-stack" "$conf" "bind :::${HPORT} v4v6"
has "the frontend rejects a source not in the file" "$conf" "tcp-request connection reject if !{ src -f ${gen_spec}/scratch/in_${HPORT}.src }"
has "the backend forwards to the loopback backend port" "$conf" "server s 127.0.0.1:${BPORT}"
if [[ "$(sort "$gen_spec/scratch/in_${HPORT}.src" | tr '\n' ' ')" == "127.0.0.5 203.0.113.9 " ]]; then
  ok "every source for a public port is collected into its source file"
else
  bad "every source for a public port is collected into its source file" "$(cat "$gen_spec/scratch/in_${HPORT}.src")"
fi

# A filter that cannot start refuses the run, so a run does not lose the inbound enforcement.
fail_spec="$WORK/fail"
mkdir -p "$fail_spec/scratch"
printf '%s %s %s\n' "$HPORT" "$BPORT" "$ALLOWED" > "$fail_spec/accept.rules"
if start_inbound_haproxy "$fail_spec" "$fail_spec/accept.rules" "/nonexistent/haproxy" > /dev/null 2>&1; then
  bad "a filter whose binary is missing fails to start" "it reported success"
else
  ok "a filter whose binary is missing fails to start rather than run without enforcement"
fi

# The real filter: the backend counts accepts, the filter fronts it, and a client binds a chosen
# source before connecting to the public port.
spec="$WORK/spec"
mkdir -p "$spec/scratch"
printf '%s %s %s\n' "$HPORT" "$BPORT" "$ALLOWED" > "$spec/accept.rules"
"$WORK/server" "$BPORT" "$WORK/accepts.log" > "$WORK/server.out" 2>&1 &
server_pid=$!
: > "$WORK/accepts.log"
for _ in $(seq 1 100); do grep -q BACKEND-LISTENING "$WORK/server.out" 2>/dev/null && break; sleep 0.05; done

if start_inbound_haproxy "$spec" "$spec/accept.rules" "$haproxy_bin" && [[ -f "$spec/${PHB_SPEC_INBOUND_PID}" ]]; then
  ok "the filter starts and records its process id"
else
  bad "the filter starts and records its process id" "start failed or pidfile missing; log: $(cat "$spec/scratch/inbound.log" 2>/dev/null)"
  finish
fi
inbound_pid="$(cat "$spec/${PHB_SPEC_INBOUND_PID}")"

# Counts how many connections the backend has accepted so far, as a single number.
accepts() {
  local n
  n="$(grep -c ACCEPT "$WORK/accepts.log" 2>/dev/null || true)"
  printf '%s' "${n:-0}"
}

before="$(accepts)"
"$WORK/srcclient" "$ALLOWED" "$HPORT" || true
sleep 1
after_allowed="$(accepts)"
if (( after_allowed > before )); then
  ok "a connection from an admitted source reaches the backend"
else
  bad "a connection from an admitted source reaches the backend" "the backend accepted nothing; log: $(cat "$spec/scratch/inbound.log" 2>/dev/null)"
fi

before="$(accepts)"
"$WORK/srcclient" "$FORBIDDEN" "$HPORT" || true
sleep 1
after_forbidden="$(accepts)"
if (( after_forbidden == before )); then
  ok "a connection from a source the filter does not name never reaches the backend"
else
  bad "a connection from a source the filter does not name never reaches the backend" "the backend accepted a rejected source"
fi

stop_recorded_inbound "$spec"
sleep 0.2
if kill -0 "$inbound_pid" 2>/dev/null; then
  bad "stopping the recorded filter ends it and frees the port" "the filter is still running"
else
  ok "stopping the recorded filter ends it and frees the port"
  inbound_pid=""
fi
[[ -f "$spec/${PHB_SPEC_INBOUND_PID}" ]] && bad "the filter record is removed" "it is still there" || ok "the filter record is removed with it"

# A service with no source admits no one, the fail-closed default.
closed_spec="$WORK/closed"
mkdir -p "$closed_spec/scratch"
CPORT=18899
printf '%s %s\n' "$CPORT" "$BPORT" > "$closed_spec/accept.rules"
if start_inbound_haproxy "$closed_spec" "$closed_spec/accept.rules" "$haproxy_bin"; then
  closed_pid="$(cat "$closed_spec/${PHB_SPEC_INBOUND_PID}")"
  before="$(accepts)"
  "$WORK/srcclient" "$ALLOWED" "$CPORT" || true
  sleep 1
  if (( "$(accepts)" == before )); then
    ok "a public port with no source admits no one, the fail-closed default"
  else
    bad "a public port with no source admits no one" "the backend accepted a connection"
  fi
  kill "$closed_pid" 2>/dev/null
else
  bad "a public port with no source still starts a filter" "it failed to start"
fi

finish
