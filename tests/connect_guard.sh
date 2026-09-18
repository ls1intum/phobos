#!/usr/bin/env bash
# The connect guard enforces the [connect] allow-list by host and port, on a real kernel.
#
# The guard traps every connect() with a seccomp user-notification and makes an allowed
# connection itself, so it is the whole connect boundary where it runs. This proves both
# directions: an allow-listed destination is reached and works, a destination the list does not
# name is refused, and a connect of a family the guard does not carry (a UNIX-domain socket) is
# refused rather than made outside the sandbox. It needs a C compiler and a kernel with seccomp
# user-notification; where either is missing the checks skip, saying so, rather than passing
# without having run. No privileges, no container flags.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="${HERE}/../core"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
skipped=0
ok()   { printf 'ok    %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf 'FAIL  %s\n        %s\n' "$1" "$2"; fail=$((fail + 1)); }
skip() { printf 'SKIP  %s\n        reason:   %s\n' "$1" "$2"; skipped=$((skipped + 1)); }
finish() {
  echo
  printf '%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skipped"
  (( fail == 0 )) || exit 1
  exit 0
}

compiler=gcc-14
command -v "$compiler" >/dev/null 2>&1 || compiler=gcc
if ! command -v "$compiler" >/dev/null 2>&1; then
  skip "the connect guard" "no C compiler to build it"
  finish
fi

if ! "$compiler" -std=gnu23 -O2 -Wall -Wextra -Werror -o "$WORK/guard" "${CORE}/phobos-connect-guard.c" 2>"$WORK/cc.log"; then
  bad "the connect guard builds" "$(cat "$WORK/cc.log")"
  finish
fi
ok "the connect guard builds with -Wall -Wextra -Werror"

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
    if (argc >= 2 && strcmp(argv[1], "raw") == 0) {
        int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (fd < 0) { fprintf(stderr, "socket: %s\n", strerror(errno)); return 10; }
        printf("RAW-OK\n");
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "ping") == 0) {
        int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if (fd < 0) { fprintf(stderr, "socket: %s\n", strerror(errno)); return 10; }
        printf("PING-OK\n");
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "setsid") == 0) {
        if (setsid() == (pid_t)-1) { fprintf(stderr, "setsid: %s\n", strerror(errno)); return 10; }
        printf("SETSID-OK\n");
        return 0;
    }
    if (argc >= 4 && strcmp(argv[1], "cudp") == 0) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((unsigned short)atoi(argv[3]));
        inet_pton(AF_INET, argv[2], &address.sin_addr);
        if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
            fprintf(stderr, "connect: %s\n", strerror(errno));
            return 10;
        }
        if (send(fd, "x", 1, 0) < 0) {
            fprintf(stderr, "send: %s\n", strerror(errno));
            return 11;
        }
        printf("CUDP-OK\n");
        return 0;
    }
    if (argc >= 4 && strcmp(argv[1], "udp") == 0) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((unsigned short)atoi(argv[3]));
        inet_pton(AF_INET, argv[2], &address.sin_addr);
        if (sendto(fd, "x", 1, 0, (struct sockaddr *)&address, sizeof(address)) < 0) {
            fprintf(stderr, "sendto: %s\n", strerror(errno));
            return 10;
        }
        printf("UDP-OK\n");
        return 0;
    }
    if (argc >= 4 && strcmp(argv[1], "tfo") == 0) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((unsigned short)atoi(argv[3]));
        inet_pton(AF_INET, argv[2], &address.sin_addr);
        if (sendto(fd, "x", 1, MSG_FASTOPEN, (struct sockaddr *)&address, sizeof(address)) < 0) {
            fprintf(stderr, "sendto: %s\n", strerror(errno));
            return 10;
        }
        printf("TFO-OK\n");
        return 0;
    }
    if (argc >= 4 && strcmp(argv[1], "csend") == 0) {
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
        if (send(fd, "ping", 4, 0) != 4) {
            fprintf(stderr, "send: %s\n", strerror(errno));
            return 11;
        }
        printf("CSEND-OK\n");
        return 0;
    }
    if (argc < 4 || strcmp(argv[1], "inet") != 0) {
        fprintf(stderr, "usage: probe inet <host> <port> | probe unix <path>\n");
        return 2;
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
"$compiler" -O2 -o "$WORK/probe" "$WORK/probe.c" || { bad "the probe builds" "$(cat "$WORK/cc.log" 2>/dev/null)"; finish; }
"$compiler" -O2 -o "$WORK/listener" "$WORK/listener.c" || { bad "the listener builds" ""; finish; }

# Where the kernel has no seccomp user-notification the guard cannot install its filter and
# refuses; skip rather than fail, since that is the environment's limit, not a defect here.
probe_out="$("$WORK/guard" -- /bin/true 2>&1)"
if [[ "$probe_out" == *"NEW_LISTENER"* ]]; then
  skip "the connect guard" "this kernel has no seccomp user-notification"
  finish
fi

PORT=39311
OTHER=39312
start_listener() {
  "$WORK/listener" "$1" > "$WORK/listener.out" 2>&1 &
  echo $!
  for _ in $(seq 1 100); do grep -q LISTENING "$WORK/listener.out" 2>/dev/null && break; sleep 0.05; done
}

echo
echo "== an allow-listed IP and port is reached and works =="
printf '127.0.0.1 %s\n' "$PORT" > "$WORK/rules"
lp=$(start_listener "$PORT")
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" inet 127.0.0.1 "$PORT" 2>&1)"
rc=$?
kill "$lp" 2>/dev/null
wait "$lp" 2>/dev/null
if [[ $rc -eq 0 && "$out" == *PROBE-OK* ]]; then
  ok "a permitted connect is made on the command's behalf and works"
else
  bad "a permitted connect is made on the command's behalf and works" "rc=$rc out=$out"
fi

echo
echo "== a port the allow-list does not name is refused =="
printf '127.0.0.1 %s\n' "$PORT" > "$WORK/rules"
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" inet 127.0.0.1 "$OTHER" 2>&1)"
rc=$?
if [[ $rc -eq 10 && "$out" == *"Permission denied"* ]]; then
  ok "a connect to a non-listed port is refused with EACCES"
else
  bad "a connect to a non-listed port is refused with EACCES" "rc=$rc out=$out"
fi

echo
echo "== an IP literal is enforced exactly: another loopback address is refused =="
printf '127.0.0.2 %s\n' "$PORT" > "$WORK/rules"
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" inet 127.0.0.1 "$PORT" 2>&1)"
rc=$?
if [[ $rc -eq 10 && "$out" == *"Permission denied"* ]]; then
  ok "127.0.0.1 is refused when only 127.0.0.2 is allowed"
else
  bad "127.0.0.1 is refused when only 127.0.0.2 is allowed" "rc=$rc out=$out"
fi

echo
echo "== an empty allow-list denies every connect, the deny-first baseline =="
: > "$WORK/rules"
lp=$(start_listener "$PORT")
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" inet 127.0.0.1 "$PORT" 2>&1)"
rc=$?
kill "$lp" 2>/dev/null
wait "$lp" 2>/dev/null
if [[ $rc -eq 10 && "$out" == *"Permission denied"* ]]; then
  ok "an empty allow-list refuses the connect"
else
  bad "an empty allow-list refuses the connect" "rc=$rc out=$out"
fi

echo
echo "== a hostname rule is held to its port; the host is left to libnetblocker =="
# The guard cannot tie a DNS name to an address at connect time, so a hostname rule enforces
# its port and lets any host through on it: the port is refused elsewhere, the host is not.
printf 'example.invalid %s\n' "$PORT" > "$WORK/rules"
lp=$(start_listener "$PORT")
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" inet 127.0.0.1 "$PORT" 2>&1)"
rc=$?
kill "$lp" 2>/dev/null
wait "$lp" 2>/dev/null
if [[ $rc -eq 0 && "$out" == *PROBE-OK* ]]; then
  ok "a hostname rule permits a host on its port (host not enforced here)"
else
  bad "a hostname rule permits a host on its port (host not enforced here)" "rc=$rc out=$out"
fi
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" inet 127.0.0.1 "$OTHER" 2>&1)"
rc=$?
if [[ $rc -eq 10 && "$out" == *"Permission denied"* ]]; then
  ok "a hostname rule still refuses a port it does not name"
else
  bad "a hostname rule still refuses a port it does not name" "rc=$rc out=$out"
fi

echo
echo "== a UNIX-domain connect is refused, even with an empty list =="
: > "$WORK/rules"
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" unix "$WORK/nosuch.sock" 2>&1)"
rc=$?
if [[ $rc -eq 10 && "$out" == *"Permission denied"* ]]; then
  ok "an AF_UNIX connect is refused (deny non-INET), not made outside the sandbox"
else
  bad "an AF_UNIX connect is refused (deny non-INET), not made outside the sandbox" "rc=$rc out=$out"
fi

echo
echo "== the guard covers the other egress paths, not connect alone =="
printf '127.0.0.1 %s\n' "$PORT" > "$WORK/rules"

lp=$(start_listener "$PORT")
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" csend 127.0.0.1 "$PORT" 2>&1)"
rc=$?
kill "$lp" 2>/dev/null
wait "$lp" 2>/dev/null
if [[ $rc -eq 0 && "$out" == *CSEND-OK* ]]; then
  ok "an ordinary send on a connected socket still works"
else
  bad "an ordinary send on a connected socket still works" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" udp 127.0.0.1 "$PORT" 2>&1)"
rc=$?
if [[ $rc -eq 0 && "$out" == *UDP-OK* ]]; then
  ok "a datagram to a listed destination is allowed"
else
  bad "a datagram to a listed destination is allowed" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" udp 127.0.0.1 "$OTHER" 2>&1)"
rc=$?
if [[ $rc -eq 10 && "$out" == *"Permission denied"* ]]; then
  ok "a datagram to a destination the list does not name is refused"
else
  bad "a datagram to a destination the list does not name is refused" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" tfo 127.0.0.1 "$PORT" 2>&1)"
rc=$?
if [[ $rc -eq 10 && "$out" == *"Permission denied"* ]]; then
  ok "a TCP Fast Open send is refused, so it cannot reach past connect"
else
  bad "a TCP Fast Open send is refused, so it cannot reach past connect" "rc=$rc out=$out"
fi

# No listener runs on $PORT here. A datagram socket's connect only sets the default peer, so it
# succeeds; the old behaviour turned it into a TCP socket, whose connect to a port with no
# listener would fail with a refused connection. So CUDP-OK proves the socket stayed a datagram.
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" cudp 127.0.0.1 "$PORT" 2>&1)"
rc=$?
if [[ $rc -eq 0 && "$out" == *CUDP-OK* ]]; then
  ok "a connected datagram socket stays a datagram, not turned into TCP"
else
  bad "a connected datagram socket stays a datagram, not turned into TCP" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" cudp 127.0.0.1 "$OTHER" 2>&1)"
rc=$?
if [[ $rc -eq 10 && "$out" == *"Permission denied"* ]]; then
  ok "a connected datagram socket to an unlisted destination is refused at connect"
else
  bad "a connected datagram socket to an unlisted destination is refused at connect" "rc=$rc out=$out"
fi

# Prove the guard's own refusal, not the environment's. Each of these calls can also fail
# because the host lacks the capability or setting (a raw socket without CAP_NET_RAW, say). So
# run the probe once WITHOUT the guard: if the environment already refuses it, skip rather than
# claim a guard win; only when it is ambiently allowed does the guarded run have to refuse it,
# and with EACCES, the errno the guard answers, not the EPERM of a missing capability.
guard_refuses_ambiently_allowed() {
  local label="$1"
  shift
  local base_out base_rc g_out g_rc
  base_out="$("$WORK/probe" "$@" 2>&1)"
  base_rc=$?
  if [[ $base_rc -ne 0 ]]; then
    skip "$label" "the environment itself refuses it (rc=$base_rc: $base_out), so the guard cannot be credited"
    return
  fi
  g_out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" "$@" 2>&1)"
  g_rc=$?
  if [[ $g_rc -eq 10 && "$g_out" == *"Permission denied"* ]]; then
    ok "$label"
  else
    bad "$label" "base_rc=$base_rc g_rc=$g_rc out=$g_out"
  fi
}

guard_refuses_ambiently_allowed "a raw socket is refused" raw
guard_refuses_ambiently_allowed "an ICMP datagram socket is refused" ping
guard_refuses_ambiently_allowed "setsid is refused, so a submission cannot leave the timeout's process group" setsid

echo
echo "== an IP range in [connect] enforces the host by network, not by port alone =="
printf '127.0.0.0/8 %s\n' "$PORT" > "$WORK/rules"
lp=$(start_listener "$PORT")
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" inet 127.0.0.1 "$PORT" 2>&1)"
rc=$?
kill "$lp" 2>/dev/null
wait "$lp" 2>/dev/null
if [[ $rc -eq 0 && "$out" == *PROBE-OK* ]]; then
  ok "an address inside the range is reached"
else
  bad "an address inside the range is reached" "rc=$rc out=$out"
fi
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" inet 8.8.8.8 "$PORT" 2>&1)"
rc=$?
if [[ $rc -eq 10 && "$out" == *"Permission denied"* ]]; then
  ok "an address outside the range is refused, though it shares the allowed port"
else
  bad "an address outside the range is refused, though it shares the allowed port" "rc=$rc out=$out"
fi

finish
