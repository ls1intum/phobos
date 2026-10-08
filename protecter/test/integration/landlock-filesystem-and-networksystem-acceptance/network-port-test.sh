#!/usr/bin/env bash
# Proves the network boundary the "both" policy relies on: Landlock's TCP-port rule holds
# against a submission that reaches the network with a raw connect() syscall.
#
# The connect guard interposes at the seccomp boundary and the kernel enforces the port
# through Landlock --connect-tcp, so a raw syscall is caught rather than slipping past a
# libc-level filter. This suite connects with a raw syscall to an allowed port and to a
# denied one and shows the kernel permits the first and refuses the second, and, as a
# control, that with the network layer off (no --connect-tcp) the same connect reaches the
# denied port.
#
# It needs the run-phase image and an ordinary container: no --privileged, no --cap-add,
# no --security-opt. Landlock network rules need ABI 4 (kernel 6.7) or newer.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

CORE="${PHOBOS_HOME:-/var/tmp/opt/core}"
LANDLOCK="${CORE}/phobos-landlock-filesystem-and-networksystem"
# How long the listeners are given to bind their ports before the probes connect.
LISTENER_START_SECONDS=1
# The errno a Landlock denial answers a connect with, as the probe prints it.
EACCES_ERRNO=13
WORK="$(mktemp -d)"
cleanup() {
  [[ -n "${allowed_pid:-}" ]] && kill "$allowed_pid" 2>/dev/null
  [[ -n "${denied_pid:-}" ]] && kill "$denied_pid" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

ALLOWED_PORT=12345
DENIED_PORT=20000

cat > "$WORK/bypass.c" <<'C'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int argc, char **argv) {
    int port = atoi(argv[1]);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    long rc = syscall(SYS_connect, fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        printf("port=%d RAW-CONNECT-OK\n", port);
    } else {
        printf("port=%d RAW-CONNECT-DENIED errno=%d\n", port, errno);
    }
    close(fd);
    return 0;
}
C
compiler=gcc-14
command -v "$compiler" >/dev/null 2>&1 || compiler=gcc
"$compiler" -O2 -o "$WORK/bypass" "$WORK/bypass.c" 2>"$WORK/cc.log"
[[ -x "$WORK/bypass" ]] || { bad "compile the raw-connect probe" "$(cat "$WORK/cc.log")"; finish; }

# How many connections may wait to be accepted on each loopback listener.
LISTEN_BACKLOG=16

# Loopback listeners, so an allowed connect actually completes rather than being refused.
listener() { perl -e '
  use IO::Socket::INET;
  my $s = IO::Socket::INET->new(LocalAddr=>"127.0.0.1", LocalPort=>$ARGV[0],
    Listen=>$ARGV[1], ReuseAddr=>1, Proto=>"tcp") or exit 1;
  while (my $c = $s->accept) { close $c }' "$1" "$LISTEN_BACKLOG"; }
listener "$ALLOWED_PORT" &
allowed_pid=$!
listener "$DENIED_PORT" &
denied_pid=$!
sleep "$LISTENER_START_SECONDS"

# Runs the raw-connect probe under phobos-landlock-filesystem-and-networksystem. Arguments: port, extra landlock args...
run() {
  local port=$1; shift
  "$LANDLOCK" --rights=rx /opt --rights=rx /usr --rights=rx /lib --rights=rx "$WORK" "$@" \
    -- "$WORK/bypass" "$port" 2>&1
}

echo "== with the Landlock network layer on (allow only ${ALLOWED_PORT}) =="
out="$(run "$ALLOWED_PORT" --connect-tcp "$ALLOWED_PORT")"
[[ "$out" == *"RAW-CONNECT-OK"* ]] && ok "the allowed port connects" || bad "the allowed port connects" "$out"
out="$(run "$DENIED_PORT" --connect-tcp "$ALLOWED_PORT")"
[[ "$out" == *"RAW-CONNECT-DENIED errno=${EACCES_ERRNO}"* ]] && ok "the denied port is refused by the kernel, raw syscall and all" \
  || bad "the denied port is refused by the kernel, raw syscall and all" "$out"

echo
echo "== control: with the network layer off, the same bypass reaches the denied port =="
out="$(run "$DENIED_PORT")"
[[ "$out" == *"RAW-CONNECT-OK"* ]] && ok "no --connect-tcp means the raw bypass is not stopped by Landlock" \
  || bad "no --connect-tcp means the raw bypass is not stopped by Landlock" "$out"

finish
