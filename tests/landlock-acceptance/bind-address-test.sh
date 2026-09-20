#!/usr/bin/env bash
# Proves libnetblocker's bind hook against the library the run-phase image compiled: a TCP
# bind to a local address the [bind] allow-list names passes, one it does not is refused
# (EACCES), a disallowed port is refused, a UDP bind is not filtered, and with no bind rules
# every bind passes. The local-address narrowing is libnetblocker's, not Landlock's, so this
# preloads the library directly rather than going through the whole layer chain.
#
# It needs the run-phase image and an ordinary container: no --privileged, no --cap-add,
# no --security-opt.
set -uo pipefail

CORE="${PHOBOS_HOME:-/var/tmp/opt/core}"
LIB="${CORE}/libnetblocker.so"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
ok()  { printf 'ok    %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf 'FAIL  %s\n        %s\n' "$1" "$2"; fail=$((fail + 1)); }

cat > "$WORK/bind_probe.c" <<'C'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    int is_udp = (argc > 3 && strcmp(argv[3], "udp") == 0);
    int fd = socket(AF_INET, is_udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &addr.sin_addr);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        printf("BIND-OK %s:%s\n", argv[1], argv[2]);
    } else {
        printf("BIND-DENIED %s:%s errno=%d\n", argv[1], argv[2], errno);
    }
    close(fd);
    return 0;
}
C

compiler=gcc-14
command -v "$compiler" >/dev/null 2>&1 || compiler=gcc
"$compiler" -O2 -o "$WORK/bind_probe" "$WORK/bind_probe.c" 2>"$WORK/cc.log" \
  || { bad "compile the bind probe" "$(cat "$WORK/cc.log")"; echo; printf '%d passed, %d failed\n' "$pass" "$fail"; exit 1; }

printf '127.0.0.1 8080\n' > "$WORK/bind.rules"
run() { LD_PRELOAD="$LIB" NETBLOCKER_BIND_CONF="$WORK/bind.rules" "$WORK/bind_probe" "$@" 2>&1; }

out="$(run 127.0.0.1 8080)"
[[ "$out" == *BIND-OK* ]] && ok "the allowed loopback bind passes" || bad "the allowed loopback bind passes" "$out"
out="$(run 0.0.0.0 8080)"
[[ "$out" == *BIND-DENIED* ]] && ok "a wider local address on the same port is refused" || bad "a wider local address on the same port is refused" "$out"
out="$(run 127.0.0.1 9090)"
[[ "$out" == *BIND-DENIED* ]] && ok "a bind to a port no rule names is refused" || bad "a bind to a port no rule names is refused" "$out"
out="$(run 0.0.0.0 8080 udp)"
[[ "$out" == *BIND-OK* ]] && ok "a UDP bind is not filtered (Landlock's bind right is TCP-only)" || bad "a UDP bind is not filtered" "$out"

# Control: with no bind rules the hook does not narrow, matching the absence of a Landlock
# bind-port rule.
out="$(LD_PRELOAD="$LIB" "$WORK/bind_probe" 0.0.0.0 8080 2>&1)"
[[ "$out" == *BIND-OK* ]] && ok "with no bind rules every bind passes" || bad "with no bind rules every bind passes" "$out"

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
(( fail == 0 ))
