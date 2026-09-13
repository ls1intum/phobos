#!/usr/bin/env bash
# Proves the network boundary the "both" policy relies on: Landlock's TCP-port rule holds
# against a submission that steps around the preload library with a raw connect() syscall.
#
# libnetblocker is defence in depth and bypassable: a raw syscall never calls the hooked
# libc connect, so the library never sees it. The kernel, through Landlock --connect-tcp,
# does. This suite connects with a raw syscall to an allowed port and to a denied one and
# shows the kernel permits the first and refuses the second, and, as a control, that with
# the network layer off (no --connect-tcp) the same bypass reaches the denied port.
#
# It needs the run-phase image and an ordinary container: no --privileged, no --cap-add,
# no --security-opt. Landlock network rules need ABI 4 (kernel 6.7) or newer.
set -uo pipefail

CORE="${PHOBOS_HOME:-/var/tmp/opt/core}"
LANDLOCK="${CORE}/phobos-landlock"
WORK="$(mktemp -d)"
cleanup() {
    [[ -n "${allowed_pid:-}" ]] && kill "$allowed_pid" 2>/dev/null
    [[ -n "${denied_pid:-}" ]] && kill "$denied_pid" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

pass=0
fail=0
ok()  { printf 'ok    %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf 'FAIL  %s\n        %s\n' "$1" "$2"; fail=$((fail + 1)); }

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
[[ -x "$WORK/bypass" ]] || { bad "compile the raw-connect probe" "$(cat "$WORK/cc.log")"; echo; printf '%d passed, %d failed\n' "$pass" "$fail"; exit 1; }

# Loopback listeners, so an allowed connect actually completes rather than being refused.
listener() { perl -e '
    use IO::Socket::INET;
    my $s = IO::Socket::INET->new(LocalAddr=>"127.0.0.1", LocalPort=>$ARGV[0],
        Listen=>16, ReuseAddr=>1, Proto=>"tcp") or exit 1;
    while (my $c = $s->accept) { close $c }' "$1"; }
listener "$ALLOWED_PORT" & allowed_pid=$!
listener "$DENIED_PORT" & denied_pid=$!
sleep 1

run() {  # port, extra landlock args...
    local port=$1; shift
    "$LANDLOCK" --rights=rx /opt --rights=rx /usr --rights=rx /lib --rights=rx "$WORK" "$@" \
        -- "$WORK/bypass" "$port" 2>&1
}

echo "== with the Landlock network layer on (allow only ${ALLOWED_PORT}) =="
out="$(run "$ALLOWED_PORT" --connect-tcp "$ALLOWED_PORT")"
[[ "$out" == *"RAW-CONNECT-OK"* ]] && ok "the allowed port connects" || bad "the allowed port connects" "$out"
out="$(run "$DENIED_PORT" --connect-tcp "$ALLOWED_PORT")"
[[ "$out" == *"RAW-CONNECT-DENIED errno=13"* ]] && ok "the denied port is refused by the kernel, raw syscall and all" \
    || bad "the denied port is refused by the kernel, raw syscall and all" "$out"

echo
echo "== control: with the network layer off, the same bypass reaches the denied port =="
out="$(run "$DENIED_PORT")"
[[ "$out" == *"RAW-CONNECT-OK"* ]] && ok "no --connect-tcp means the raw bypass is not stopped by Landlock" \
    || bad "no --connect-tcp means the raw bypass is not stopped by Landlock" "$out"

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
(( fail == 0 ))
