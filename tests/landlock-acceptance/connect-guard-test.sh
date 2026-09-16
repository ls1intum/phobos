#!/usr/bin/env bash
# Proves the connect guard the run-phase image compiled: that an unprivileged process can
# install its seccomp user-notification filter under the image's default seccomp profile, and
# that the shipped binary enforces the [connect] allow-list by host and port. An allow-listed
# IP and port is reached and works, a port the list does not name is refused, and a
# UNIX-domain connect is refused rather than made outside the sandbox.
#
# This exercises the guard binary the image ships (/var/tmp/opt/core/phobos-connect-guard),
# which is what the network layer runs, so it is the in-container counterpart of the
# host-side tests/connect_guard.sh. It needs the run-phase image and an ordinary container:
# no --privileged, no --cap-add, no --security-opt.
set -uo pipefail

CORE="${PHOBOS_HOME:-/var/tmp/opt/core}"
GUARD="${CORE}/phobos-connect-guard"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
ok()  { printf 'ok    %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf 'FAIL  %s\n        %s\n' "$1" "$2"; fail=$((fail + 1)); }

if [[ ! -x "$GUARD" ]]; then
  bad "the image ships the connect guard" "no executable at ${GUARD}"
  echo
  printf '%d passed, %d failed\n' "$pass" "$fail"
  exit 1
fi

cat > "$WORK/probe.c" <<'C'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "unix") == 0) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un address;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        snprintf(address.sun_path, sizeof(address.sun_path), "%s", argv[2]);
        if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
            fprintf(stderr, "connect: %s\n", strerror(errno));
            return 10;
        }
        printf("UNIX-OK\n");
        return 0;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)atoi(argv[3]));
    inet_pton(AF_INET, argv[2], &address.sin_addr);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        fprintf(stderr, "connect: %s\n", strerror(errno));
        return 10;
    }
    if (write(fd, "ping", 4) != 4) {
        return 11;
    }
    char reply[8] = { 0 };
    if (read(fd, reply, 4) != 4 || memcmp(reply, "pong", 4) != 0) {
        return 12;
    }
    printf("PROBE-OK\n");
    close(fd);
    return 0;
}
C
cat > "$WORK/listener.c" <<'C'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
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
        return 3;
    }
    listen(server, 4);
    printf("LISTENING\n");
    fflush(stdout);
    int client = accept(server, NULL, NULL);
    char buffer[8] = { 0 };
    if (read(client, buffer, 4) == 4 && memcmp(buffer, "ping", 4) == 0) {
        ssize_t wrote = write(client, "pong", 4);
        (void)wrote;
    }
    close(client);
    close(server);
    return 0;
}
C

compiler=gcc-14
command -v "$compiler" >/dev/null 2>&1 || compiler=gcc
"$compiler" -O2 -o "$WORK/probe" "$WORK/probe.c" 2>"$WORK/cc.log" \
    || { bad "compile the probe" "$(cat "$WORK/cc.log")"; echo; printf '%d passed, %d failed\n' "$pass" "$fail"; exit 1; }
"$compiler" -O2 -o "$WORK/listener" "$WORK/listener.c" 2>"$WORK/cc.log" \
    || { bad "compile the listener" "$(cat "$WORK/cc.log")"; echo; printf '%d passed, %d failed\n' "$pass" "$fail"; exit 1; }

PORT=18091
OTHER=18092
start_listener() {
  "$WORK/listener" "$1" > "$WORK/listener.out" 2>&1 &
  echo $!
  for _ in $(seq 1 100); do grep -q LISTENING "$WORK/listener.out" 2>/dev/null && break; sleep 0.05; done
}

printf '127.0.0.1 %s\n' "$PORT" > "$WORK/rules"

lp=$(start_listener "$PORT")
out="$("$GUARD" --rules "$WORK/rules" -- "$WORK/probe" inet 127.0.0.1 "$PORT" 2>&1)"
rc=$?
kill "$lp" 2>/dev/null
wait "$lp" 2>/dev/null
if [[ $rc -eq 0 && "$out" == *PROBE-OK* ]]; then
  ok "the shipped guard installs its filter under the image's default seccomp and permits an allow-listed connect"
else
  bad "the shipped guard installs its filter under the image's default seccomp and permits an allow-listed connect" "rc=$rc out=$out"
fi

out="$("$GUARD" --rules "$WORK/rules" -- "$WORK/probe" inet 127.0.0.1 "$OTHER" 2>&1)"
rc=$?
if [[ $rc -eq 10 && "$out" == *"Permission denied"* ]]; then
  ok "a connect to a port the allow-list does not name is refused"
else
  bad "a connect to a port the allow-list does not name is refused" "rc=$rc out=$out"
fi

out="$("$GUARD" --rules "$WORK/rules" -- "$WORK/probe" unix "$WORK/nosuch.sock" 2>&1)"
rc=$?
if [[ $rc -eq 10 && "$out" == *"Permission denied"* ]]; then
  ok "a UNIX-domain connect is refused, not made outside the sandbox"
else
  bad "a UNIX-domain connect is refused, not made outside the sandbox" "rc=$rc out=$out"
fi

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
(( fail == 0 ))
