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
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../src"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

compiler=gcc-14
command -v "$compiler" >/dev/null 2>&1 || compiler=gcc
if ! command -v "$compiler" >/dev/null 2>&1; then
  skip "the connect guard" "no C compiler to build it"
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
/* The statuses the probe ends with, which the suite reads: the call was refused, the message
 * could not be sent, the reply was not the expected one, or it was called the wrong way. */
enum probe_status { PROBE_USAGE = 2, PROBE_REFUSED = 10, PROBE_SEND_FAILED = 11, PROBE_REPLY_WRONG = 12 };
/* The length of the "ping" the probe sends and the "pong" it expects back. */
enum { MESSAGE_LENGTH = sizeof("ping") - 1 };
int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "unix") == 0) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un address;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        snprintf(address.sun_path, sizeof(address.sun_path), "%s", argv[2]);
        if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
            fprintf(stderr, "connect: %s\n", strerror(errno));
            return PROBE_REFUSED;
        }
        printf("UNIX-OK\n");
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "raw") == 0) {
        int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (fd < 0) { fprintf(stderr, "socket: %s\n", strerror(errno)); return PROBE_REFUSED; }
        printf("RAW-OK\n");
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "ping") == 0) {
        int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if (fd < 0) { fprintf(stderr, "socket: %s\n", strerror(errno)); return PROBE_REFUSED; }
        printf("PING-OK\n");
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "setsid") == 0) {
        if (setsid() == (pid_t)-1) { fprintf(stderr, "setsid: %s\n", strerror(errno)); return PROBE_REFUSED; }
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
            return PROBE_REFUSED;
        }
        if (send(fd, "x", 1, 0) < 0) {
            fprintf(stderr, "send: %s\n", strerror(errno));
            return PROBE_SEND_FAILED;
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
            return PROBE_REFUSED;
        }
        printf("UDP-OK\n");
        return 0;
    }
    if (argc >= 4 && strcmp(argv[1], "msg") == 0) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((unsigned short)atoi(argv[3]));
        inet_pton(AF_INET, argv[2], &address.sin_addr);
        char payload = 'x';
        struct iovec vector = { .iov_base = &payload, .iov_len = 1 };
        struct msghdr header;
        memset(&header, 0, sizeof(header));
        header.msg_name = &address;
        header.msg_namelen = sizeof(address);
        header.msg_iov = &vector;
        header.msg_iovlen = 1;
        if (sendmsg(fd, &header, 0) < 0) {
            fprintf(stderr, "sendmsg: %s\n", strerror(errno));
            return PROBE_REFUSED;
        }
        printf("MSG-OK\n");
        return 0;
    }
    if (argc >= 4 && strcmp(argv[1], "msg2") == 0) {
        int filler = socket(AF_INET, SOCK_DGRAM, 0);
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((unsigned short)atoi(argv[3]));
        inet_pton(AF_INET, argv[2], &address.sin_addr);
        char payload = 'x';
        struct iovec vector = { .iov_base = &payload, .iov_len = 1 };
        struct msghdr header;
        memset(&header, 0, sizeof(header));
        header.msg_name = &address;
        header.msg_namelen = sizeof(address);
        header.msg_iov = &vector;
        header.msg_iovlen = 1;
        if (sendmsg(fd, &header, 0) < 0) {
            fprintf(stderr, "sendmsg: %s\n", strerror(errno));
            return PROBE_REFUSED;
        }
        (void)filler;
        printf("MSG2-OK\n");
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
            return PROBE_REFUSED;
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
            return PROBE_REFUSED;
        }
        if (send(fd, "ping", MESSAGE_LENGTH, 0) != MESSAGE_LENGTH) {
            fprintf(stderr, "send: %s\n", strerror(errno));
            return PROBE_SEND_FAILED;
        }
        printf("CSEND-OK\n");
        return 0;
    }
    if (argc >= 4 && strcmp(argv[1], "inet6") == 0) {
        int fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (fd < 0) {
            fprintf(stderr, "socket: %s\n", strerror(errno));
            return PROBE_SEND_FAILED;
        }
        struct sockaddr_in6 address;
        memset(&address, 0, sizeof(address));
        address.sin6_family = AF_INET6;
        address.sin6_port = htons((unsigned short)atoi(argv[3]));
        inet_pton(AF_INET6, argv[2], &address.sin6_addr);
        if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
            fprintf(stderr, "connect: %s\n", strerror(errno));
            return PROBE_REFUSED;
        }
        printf("INET6-OK\n");
        return 0;
    }
    if (argc < 4 || strcmp(argv[1], "inet") != 0) {
        fprintf(stderr, "usage: probe inet <host> <port> | probe inet6 <host> <port> | probe unix <path>\n");
        return PROBE_USAGE;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)atoi(argv[3]));
    inet_pton(AF_INET, argv[2], &address.sin_addr);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        fprintf(stderr, "connect: %s\n", strerror(errno));
        return PROBE_REFUSED;
    }
    if (write(fd, "ping", MESSAGE_LENGTH) != MESSAGE_LENGTH) {
        return PROBE_SEND_FAILED;
    }
    char reply[MESSAGE_LENGTH + 1] = { 0 };
    if (read(fd, reply, MESSAGE_LENGTH) != MESSAGE_LENGTH || memcmp(reply, "pong", MESSAGE_LENGTH) != 0) {
        return PROBE_REPLY_WRONG;
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
/* The status the listener ends with when it cannot bind its port. */
enum { LISTENER_BIND_FAILED = 3 };
/* How many connections may wait to be accepted. */
enum { LISTEN_BACKLOG = 4 };
/* The length of the "ping" it expects and the "pong" it answers with. */
enum { MESSAGE_LENGTH = sizeof("ping") - 1 };
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
        return LISTENER_BIND_FAILED;
    }
    listen(server, LISTEN_BACKLOG);
    printf("LISTENING\n");
    fflush(stdout);
    int client = accept(server, NULL, NULL);
    char buffer[MESSAGE_LENGTH + 1] = { 0 };
    if (read(client, buffer, MESSAGE_LENGTH) == MESSAGE_LENGTH && memcmp(buffer, "ping", MESSAGE_LENGTH) == 0) {
        ssize_t wrote = write(client, "pong", MESSAGE_LENGTH);
        (void)wrote;
    }
    close(client);
    close(server);
    return 0;
}
C
cat > "$WORK/broker.c" <<'C'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
/* The status the broker ends with when it cannot bind its port. */
enum { BROKER_BIND_FAILED = 3 };
/* How many connections may wait to be accepted. */
enum { LISTEN_BACKLOG = 4 };
/* The PROXY protocol version 2 signature, the sixteen-byte prefix, and the IPv4 address block. */
static const unsigned char PROXY_SIGNATURE[12] = { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };
enum { PROXY_PREFIX = 16 };
enum { PROXY_IPV4_BLOCK = 12 };
/* Reads exactly n bytes or fails. */
static int read_fully(int fd, void *buffer, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buffer + got, n - got);
        if (r <= 0) {
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}
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
        return BROKER_BIND_FAILED;
    }
    listen(server, LISTEN_BACKLOG);
    printf("BROKER-LISTENING\n");
    fflush(stdout);
    int client = accept(server, NULL, NULL);
    if (client < 0) {
        return 1;
    }
    unsigned char prefix[PROXY_PREFIX];
    if (read_fully(client, prefix, PROXY_PREFIX) != 0 || memcmp(prefix, PROXY_SIGNATURE, sizeof(PROXY_SIGNATURE)) != 0) {
        printf("BROKER no-proxy-header\n");
        return 1;
    }
    unsigned char block[PROXY_IPV4_BLOCK];
    if (read_fully(client, block, PROXY_IPV4_BLOCK) != 0) {
        printf("BROKER short-block\n");
        return 1;
    }
    char destination[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &block[4], destination, sizeof(destination));
    unsigned short destination_port = 0;
    memcpy(&destination_port, &block[10], sizeof(destination_port));
    char payload[16] = { 0 };
    ssize_t got = read(client, payload, sizeof(payload) - 1);
    (void)got;
    printf("BROKER dst=%s:%u payload=%s\n", destination, ntohs(destination_port), payload);
    fflush(stdout);
    close(client);
    close(server);
    return 0;
}
C
"$compiler" -O2 -o "$WORK/probe" "$WORK/probe.c" 2>"$WORK/probe-cc.log" \
  || { bad "the probe builds" "$(cat "$WORK/probe-cc.log")"; finish; }
"$compiler" -O2 -o "$WORK/listener" "$WORK/listener.c" 2>"$WORK/listener-cc.log" \
  || { bad "the listener builds" "$(cat "$WORK/listener-cc.log")"; finish; }
"$compiler" -O2 -o "$WORK/broker" "$WORK/broker.c" 2>"$WORK/broker-cc.log" \
  || { bad "the broker builds" "$(cat "$WORK/broker-cc.log")"; finish; }

# Where the kernel has no seccomp user-notification the guard cannot install its filter and
# refuses; skip rather than fail, since that is the environment's limit, not a defect here.
probe_out="$("$WORK/guard" -- /bin/true 2>&1)"
if [[ "$probe_out" == *"NEW_LISTENER"* ]]; then
  skip "the connect guard" "this kernel has no seccomp user-notification"
  finish
fi

# The status the probe ends with when its call was refused; the probe's source names it too.
PROBE_REFUSED=10
# How often, and how far apart, the suite looks for the listener to be ready.
LISTENER_WAIT_ATTEMPTS=100
LISTENER_WAIT_SECONDS=0.05
PORT=39311
OTHER=39312
start_listener() {
  "$WORK/listener" "$1" > "$WORK/listener.out" 2>&1 &
  echo $!
  for _ in $(seq 1 "$LISTENER_WAIT_ATTEMPTS"); do grep -q LISTENING "$WORK/listener.out" 2>/dev/null && break; sleep "$LISTENER_WAIT_SECONDS"; done
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
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
  ok "a connect to a non-listed port is refused with EACCES"
else
  bad "a connect to a non-listed port is refused with EACCES" "rc=$rc out=$out"
fi

echo
echo "== a verbose refusal names the refused endpoint, address and port, and still refuses =="
# The line comes from format_endpoint: an IPv4 address and port, an IPv6 address in brackets,
# an IPv4-mapped address in the IPv6 spelling, and the same for a refused datagram. The refusal
# itself, EACCES, is unchanged.
: > "$WORK/rules"
# Runs the probe with the arguments after the first two under the verbose guard and an empty
# allow-list, and checks it is refused with EACCES and the guard's line names the endpoint $2.
check_named_refusal() {
  local name="$1"
  local endpoint="$2"
  shift 2
  local out
  out="$("$WORK/guard" --verbose --rules "$WORK/rules" -- "$WORK/probe" "$@" 2>&1)"
  local rc=$?
  if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* && "$out" == *"does not name: ${endpoint}"* ]]; then
    ok "$name"
  else
    bad "$name" "rc=$rc out=$out"
  fi
}
check_named_refusal "a refused IPv4 connect names 10.0.0.1:80" "10.0.0.1:80" inet 10.0.0.1 80
check_named_refusal "a refused IPv6 connect names [2001:db8::1]:443" "[2001:db8::1]:443" inet6 2001:db8::1 443
check_named_refusal "a refused IPv4-mapped connect names [::ffff:10.0.0.1]:80" "[::ffff:10.0.0.1]:80" inet6 ::ffff:10.0.0.1 80
check_named_refusal "a refused datagram names 127.0.0.2:${OTHER}" "127.0.0.2:${OTHER}" udp 127.0.0.2 "$OTHER"
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" inet 10.0.0.1 80 2>&1)"
rc=$?
if [[ $rc -eq "$PROBE_REFUSED" && "$out" != *"does not name"* ]]; then
  ok "without --verbose the refusal stays silent"
else
  bad "without --verbose the refusal stays silent" "rc=$rc out=$out"
fi

echo
echo "== an IP literal is enforced exactly: another loopback address is refused =="
printf '127.0.0.2 %s\n' "$PORT" > "$WORK/rules"
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" inet 127.0.0.1 "$PORT" 2>&1)"
rc=$?
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
  ok "127.0.0.1 is refused when only 127.0.0.2 is allowed"
else
  bad "127.0.0.1 is refused when only 127.0.0.2 is allowed" "rc=$rc out=$out"
fi

echo
echo "== an IPv4-mapped destination is the IPv4 endpoint it maps =="
# A program that opens an IPv6 socket and connects to ::ffff:127.0.0.1, as a Java virtual machine does by
# default, reaches the listener on 127.0.0.1. The guard judges it as that IPv4 endpoint: what a rule admits
# as 127.0.0.1 it admits mapped, on the same port, and nothing else. Where this kernel or container has no
# IPv6 socket, the permitted checks skip, saying so, and the refusals still run.
printf '* %s\n' "$PORT" > "$WORK/rules"
lp=$(start_listener "$PORT")
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" inet6 ::ffff:127.0.0.1 "$PORT" 2>&1)"
rc=$?
kill "$lp" 2>/dev/null
wait "$lp" 2>/dev/null
if [[ $rc -eq 0 && "$out" == *INET6-OK* ]]; then
  mapped_reachable=1
else
  mapped_reachable=0
  skip "an IPv4-mapped connect is admitted as the IPv4 endpoint it maps" "this environment cannot reach 127.0.0.1 through an IPv6 socket: rc=$rc out=$out"
fi
if (( mapped_reachable )); then
  for rule in "localhost *" "127.0.0.1 ${PORT}" "127.0.0.1 *" "127.0.0.0/8 ${PORT}"; do
    printf '%s\n' "$rule" > "$WORK/rules"
    lp=$(start_listener "$PORT")
    out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" inet6 ::ffff:127.0.0.1 "$PORT" 2>&1)"
    rc=$?
    kill "$lp" 2>/dev/null
    wait "$lp" 2>/dev/null
    if [[ $rc -eq 0 && "$out" == *INET6-OK* ]]; then
      ok "the rule '${rule}' admits ::ffff:127.0.0.1 on the port it admits for 127.0.0.1"
    else
      bad "the rule '${rule}' admits ::ffff:127.0.0.1 on the port it admits for 127.0.0.1" "rc=$rc out=$out"
    fi
  done
fi
for rule in "localhost *" "127.0.0.1 ${PORT}" "127.0.0.1 *"; do
  printf '%s\n' "$rule" > "$WORK/rules"
  out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" inet6 ::ffff:10.0.0.1 "$PORT" 2>&1)"
  rc=$?
  if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
    ok "the rule '${rule}' still refuses ::ffff:10.0.0.1"
  else
    bad "the rule '${rule}' still refuses ::ffff:10.0.0.1" "rc=$rc out=$out"
  fi
done
printf '127.0.0.1 %s\n' "$PORT" > "$WORK/rules"
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" inet6 ::ffff:127.0.0.1 "$OTHER" 2>&1)"
rc=$?
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
  ok "::ffff:127.0.0.1 on a port no rule names is refused"
else
  bad "::ffff:127.0.0.1 on a port no rule names is refused" "rc=$rc out=$out"
fi
printf '127.0.0.2 %s\n' "$PORT" > "$WORK/rules"
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" inet6 ::ffff:127.0.0.1 "$PORT" 2>&1)"
rc=$?
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
  ok "::ffff:127.0.0.1 is refused when only 127.0.0.2 is allowed"
else
  bad "::ffff:127.0.0.1 is refused when only 127.0.0.2 is allowed" "rc=$rc out=$out"
fi

echo
echo "== an empty allow-list denies every connect, the deny-first baseline =="
: > "$WORK/rules"
lp=$(start_listener "$PORT")
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" inet 127.0.0.1 "$PORT" 2>&1)"
rc=$?
kill "$lp" 2>/dev/null
wait "$lp" 2>/dev/null
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
  ok "an empty allow-list refuses the connect"
else
  bad "an empty allow-list refuses the connect" "rc=$rc out=$out"
fi

echo
echo "== a hostname rule is held to its port; the host is left to the egress broker =="
# The guard cannot tie a DNS name to an address at connect time, so a hostname rule enforces
# its port and lets any host through on it: the port is refused elsewhere, the host is left to
# the egress broker, which the network layer requires such a rule to run under.
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
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
  ok "a hostname rule still refuses a port it does not name"
else
  bad "a hostname rule still refuses a port it does not name" "rc=$rc out=$out"
fi

echo
echo "== a UNIX-domain connect is refused, even with an empty list =="
: > "$WORK/rules"
out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" unix "$WORK/nosuch.sock" 2>&1)"
rc=$?
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
  ok "an AF_UNIX connect is refused (deny non-INET), not made outside the sandbox"
else
  bad "an AF_UNIX connect is refused (deny non-INET), not made outside the sandbox" "rc=$rc out=$out"
fi

echo
echo "== the guard covers the other egress paths, not connect alone =="
# Two allow-lists, because the guard judges the two transports apart: a row with no third word
# is tcp, and a datagram is admitted only by a row that says udp. The stream assertions below
# read the first file and the datagram ones the second, so each names the destination it is
# about. One file naming both would let every assertion here pass whether or not the transport
# were checked, which is what the section further down exists to catch.
printf '127.0.0.1 %s\n' "$PORT" > "$WORK/rules"
printf '127.0.0.1 %s udp\n' "$PORT" > "$WORK/rules-udp"

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

out="$("$WORK/guard" --rules "$WORK/rules-udp" --allow-ephemeral-udp-bind -- "$WORK/probe" udp 127.0.0.1 "$PORT" 2>&1)"
rc=$?
if [[ $rc -eq 0 && "$out" == *UDP-OK* ]]; then
  ok "a datagram to a destination the udp list names is allowed"
else
  bad "a datagram to a destination the udp list names is allowed" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-udp" --allow-ephemeral-udp-bind -- "$WORK/probe" udp 127.0.0.1 "$OTHER" 2>&1)"
rc=$?
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
  ok "a datagram to a destination the udp list does not name is refused"
else
  bad "a datagram to a destination the udp list does not name is refused" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-udp" --allow-ephemeral-udp-bind -- "$WORK/probe" msg 127.0.0.1 "$PORT" 2>&1)"
rc=$?
if [[ $rc -eq 0 && "$out" == *MSG-OK* ]]; then
  ok "a sendmsg datagram to a destination the udp list names is allowed, so the handoff survived trapping sendmsg"
else
  bad "a sendmsg datagram to a destination the udp list names is allowed" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-udp" --allow-ephemeral-udp-bind -- "$WORK/probe" msg 127.0.0.1 "$OTHER" 2>&1)"
rc=$?
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
  ok "a sendmsg datagram to a destination the udp list does not name is refused"
else
  bad "a sendmsg datagram to a destination the udp list does not name is refused" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-udp" --allow-ephemeral-udp-bind -- "$WORK/probe" msg2 127.0.0.1 "$PORT" 2>&1)"
rc=$?
if [[ $rc -eq 0 && "$out" == *MSG2-OK* ]]; then
  ok "a sendmsg on a low reused descriptor is still allowed, so the lockout does not over-deny"
else
  bad "a sendmsg on a low reused descriptor is still allowed, so the lockout does not over-deny" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" tfo 127.0.0.1 "$PORT" 2>&1)"
rc=$?
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
  ok "a TCP Fast Open send is refused, so it cannot reach past connect"
else
  bad "a TCP Fast Open send is refused, so it cannot reach past connect" "rc=$rc out=$out"
fi

# No listener runs on $PORT here. A datagram socket's connect only sets the default peer, so it
# succeeds; the old behaviour turned it into a TCP socket, whose connect to a port with no
# listener would fail with a refused connection. So CUDP-OK proves the socket stayed a datagram.
out="$("$WORK/guard" --rules "$WORK/rules-udp" --allow-ephemeral-udp-bind -- "$WORK/probe" cudp 127.0.0.1 "$PORT" 2>&1)"
rc=$?
if [[ $rc -eq 0 && "$out" == *CUDP-OK* ]]; then
  ok "a connected datagram socket stays a datagram, not turned into TCP"
else
  bad "a connected datagram socket stays a datagram, not turned into TCP" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-udp" --allow-ephemeral-udp-bind -- "$WORK/probe" cudp 127.0.0.1 "$OTHER" 2>&1)"
rc=$?
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
  ok "a connected datagram socket to an unlisted destination is refused at connect"
else
  bad "a connected datagram socket to an unlisted destination is refused at connect" "rc=$rc out=$out"
fi

echo
echo "== a rule for one transport does not admit the other =="
# The two directions of what #121 bought. Every other datagram assertion in this suite passes
# on a guard that ignored the transport altogether, because each names a destination the list
# carries; these two are the only ones that fail on such a guard.
printf '127.0.0.1 %s\n' "$PORT" > "$WORK/rules-tcp-only"
printf '127.0.0.1 %s udp\n' "$PORT" > "$WORK/rules-udp-only"

# No listener is needed: a datagram to a port nothing listens on is sent regardless, so a
# refusal here is the guard's rather than the absence of a peer.
out="$("$WORK/guard" --rules "$WORK/rules-tcp-only" --allow-ephemeral-udp-bind -- "$WORK/probe" udp 127.0.0.1 "$PORT" 2>&1)"
rc=$?
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
  ok "a tcp rule does not admit a datagram to the same host and port"
else
  bad "a tcp rule does not admit a datagram to the same host and port" "rc=$rc out=$out"
fi

# A listener does run here, so an unguarded connect to this port would succeed. The refusal is
# therefore the guard's and not a connection nobody answered.
lp=$(start_listener "$PORT")
out="$("$WORK/guard" --rules "$WORK/rules-udp-only" -- "$WORK/probe" inet 127.0.0.1 "$PORT" 2>&1)"
rc=$?
kill "$lp" 2>/dev/null
wait "$lp" 2>/dev/null
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
  ok "a udp rule does not admit a stream connect to the same host and port"
else
  bad "a udp rule does not admit a stream connect to the same host and port" "rc=$rc out=$out"
fi

echo
echo "== the guard refuses what the environment would otherwise allow =="
# Prove the guard's own refusal, not the environment's. Each of these calls can also fail
# because the host lacks the capability or setting (a raw socket without CAP_NET_RAW, say). So
# run the probe once WITHOUT the guard: if the environment already refuses it, skip rather than
# claim a guard win; only when it is ambiently allowed does the guarded run have to refuse it,
# and with EACCES, the errno the guard answers, not the EPERM of a missing capability.
guard_refuses_ambiently_allowed() {
  local label="$1"
  shift
  local base_out
  local base_rc
  local g_out
  local g_rc
  base_out="$("$WORK/probe" "$@" 2>&1)"
  base_rc=$?
  if [[ $base_rc -ne 0 ]]; then
    skip "$label" "the environment itself refuses it (rc=$base_rc: $base_out), so the guard cannot be credited"
    return
  fi
  g_out="$("$WORK/guard" --rules "$WORK/rules" -- "$WORK/probe" "$@" 2>&1)"
  g_rc=$?
  if [[ $g_rc -eq "$PROBE_REFUSED" && "$g_out" == *"Permission denied"* ]]; then
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
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
  ok "an address outside the range is refused, though it shares the allowed port"
else
  bad "an address outside the range is refused, though it shares the allowed port" "rc=$rc out=$out"
fi

echo
echo "== with a broker configured, an allowed connection is handed to it, destination named =="
BROKERPORT=39313
# A documentation-reserved destination (TEST-NET-1), never routed: the guard redirects the
# connect to the loopback broker, so nothing is sent to it, and it differs from the loopback
# source in the header, so a source/destination mix-up would be caught.
DEST=192.0.2.7
printf '%s %s\n' "$DEST" "$PORT" > "$WORK/rules"
start_broker() {
  "$WORK/broker" "$1" > "$2" 2>&1 &
  echo $!
  for _ in $(seq 1 "$LISTENER_WAIT_ATTEMPTS"); do grep -q BROKER-LISTENING "$2" 2>/dev/null && break; sleep "$LISTENER_WAIT_SECONDS"; done
}
bp=$(start_broker "$BROKERPORT" "$WORK/broker.out")
out="$("$WORK/guard" --rules "$WORK/rules" --broker "127.0.0.1:$BROKERPORT" -- "$WORK/probe" csend "$DEST" "$PORT" 2>&1)"
rc=$?
kill "$bp" 2>/dev/null
wait "$bp" 2>/dev/null
brk="$(cat "$WORK/broker.out")"
if [[ $rc -eq 0 && "$out" == *CSEND-OK* && "$brk" == *"dst=$DEST:$PORT"* && "$brk" == *"payload=ping"* ]]; then
  ok "an allowed connect reaches the broker, which is told the destination and gets the payload"
else
  bad "an allowed connect reaches the broker, which is told the destination and gets the payload" "rc=$rc out=$out brk=$brk"
fi

bp=$(start_broker "$BROKERPORT" "$WORK/broker2.out")
out="$("$WORK/guard" --rules "$WORK/rules" --broker "127.0.0.1:$BROKERPORT" -- "$WORK/probe" csend 127.0.0.1 "$OTHER" 2>&1)"
rc=$?
kill "$bp" 2>/dev/null
wait "$bp" 2>/dev/null
brk="$(cat "$WORK/broker2.out")"
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* && "$brk" != *"dst="* ]]; then
  ok "a forbidden connect is refused before the broker, which receives nothing"
else
  bad "a forbidden connect is refused before the broker, which receives nothing" "rc=$rc out=$out brk=$brk"
fi

echo
echo "== a listen() is run by the guard on a socket it created, so an unbound socket cannot become a listener =="
cat > "$WORK/lprobe.c" <<'C'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
/* How long the probe waits for the closed connection to leave the port before it binds it again. */
enum {
    REBIND_PAUSE_MICROSECONDS = 200000
};
/* The descriptor number the race flips between a bound and an unbound socket, and how many listens
 * the race attempts while it does. */
enum {
    RACE_DESCRIPTOR = 50,
    RACE_LISTENS = 20000,
    BACKLOG = 4,
    INHERITED_DESCRIPTOR = 3
};
static atomic_int race_over;
static int race_bound_socket;
static int race_unbound_socket;

static void loopback(struct sockaddr_in *address, int port) {
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons((unsigned short)port);
    address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}

static int bound_port(int fd) {
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &length) != 0) {
        return -1;
    }
    return ntohs(address.sin_port);
}

/* The thread that puts first the unbound and then the bound socket under the descriptor the main
 * thread is listening on, as fast as it can. */
static void *flip(void *unused) {
    (void)unused;
    while (!atomic_load(&race_over)) {
        dup2(race_unbound_socket, RACE_DESCRIPTOR);
        dup2(race_bound_socket, RACE_DESCRIPTOR);
    }
    return NULL;
}

static int race(void) {
    race_bound_socket = socket(AF_INET, SOCK_STREAM, 0);
    race_unbound_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    loopback(&address, 0);
    if (bind(race_bound_socket, (struct sockaddr *)&address, sizeof(address)) != 0) {
        printf("RACE-BIND-FAILED %s\n", strerror(errno));
        return 1;
    }
    dup2(race_bound_socket, RACE_DESCRIPTOR);
    pthread_t thread;
    pthread_create(&thread, NULL, flip, NULL);
    for (int attempt = 0; attempt < RACE_LISTENS; attempt++) {
        (void)listen(RACE_DESCRIPTOR, BACKLOG);
    }
    atomic_store(&race_over, 1);
    pthread_join(thread, NULL);
    int port = bound_port(race_unbound_socket);
    if (port == 0) {
        printf("RACE-NO-LISTENER\n");
    } else {
        printf("RACE-LISTENER-CREATED port %d\n", port);
    }
    return 0;
}

static int stream_server(int family, const struct sockaddr *address, socklen_t length, const char *label) {
    int server = socket(family, SOCK_STREAM, 0);
    int reuse = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (bind(server, address, length) != 0) {
        printf("%s-BIND-FAILED %s\n", label, strerror(errno));
        return 1;
    }
    if (listen(server, BACKLOG) != 0) {
        printf("%s-LISTEN-FAILED %s\n", label, strerror(errno));
        return 1;
    }
    if (family == AF_UNIX) {
        printf("%s-LISTEN-OK\n", label);
        return 0;
    }
    int client = socket(family, SOCK_STREAM, 0);
    if (family == AF_INET) {
        struct sockaddr_in target;
        socklen_t target_length = sizeof(target);
        getsockname(server, (struct sockaddr *)&target, &target_length);
        if (connect(client, (struct sockaddr *)&target, target_length) != 0) {
            printf("%s-CONNECT-FAILED %s\n", label, strerror(errno));
            return 1;
        }
    }
    int accepted = accept(server, NULL, NULL);
    printf("%s-LISTEN-OK accept %s\n", label, accepted >= 0 ? "ok" : strerror(errno));
    if (accepted >= 0) {
        close(accepted);
    }
    close(client);
    if (family == AF_INET) {
        int port = bound_port(server);
        close(server);
        usleep(REBIND_PAUSE_MICROSECONDS);
        int again = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(again, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in same;
        loopback(&same, port);
        printf("%s-REBIND %s\n", label, bind(again, (struct sockaddr *)&same, sizeof(same)) == 0 ? "ok" : strerror(errno));
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "race") == 0) {
        return race();
    }
    if (argc >= 2 && strcmp(argv[1], "bound") == 0) {
        struct sockaddr_in address;
        loopback(&address, 0);
        return stream_server(AF_INET, (struct sockaddr *)&address, sizeof(address), "BOUND");
    }
    if (argc >= 3 && strcmp(argv[1], "unix") == 0) {
        struct sockaddr_un address;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        snprintf(address.sun_path, sizeof(address.sun_path), "%s", argv[2]);
        unlink(argv[2]);
        return stream_server(AF_UNIX, (struct sockaddr *)&address, sizeof(address), "UNIX");
    }
    if (argc >= 2 && strcmp(argv[1], "twice") == 0) {
        int server = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in address;
        loopback(&address, 0);
        bind(server, (struct sockaddr *)&address, sizeof(address));
        int first = listen(server, BACKLOG);
        int second = listen(server, BACKLOG + 1);
        printf("TWICE first %s second %s\n", first == 0 ? "ok" : strerror(errno), second == 0 ? "ok" : strerror(errno));
        return 0;
    }
    if (argc >= 5 && strcmp(argv[1], "holder") == 0) {
        int outside = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in address;
        loopback(&address, 0);
        bind(outside, (struct sockaddr *)&address, sizeof(address));
        dup2(outside, INHERITED_DESCRIPTOR);
        execl(argv[2], argv[2], "--rules", argv[3], "--", argv[4], "inherited", "3", (char *)NULL);
        return 1;
    }
    if (argc >= 3 && strcmp(argv[1], "inherited") == 0) {
        int rc = listen(atoi(argv[2]), BACKLOG);
        printf("INHERITED %s\n", rc == 0 ? "ok" : strerror(errno));
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "unbound") == 0) {
        int server = socket(AF_INET, SOCK_STREAM, 0);
        int rc = listen(server, BACKLOG);
        if (rc != 0) {
            printf("UNBOUND %s\n", strerror(errno));
            return 0;
        }
        int port = bound_port(server);
        int client = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in target;
        loopback(&target, port);
        printf("UNBOUND ok port %d reachable %s\n", port, connect(client, (struct sockaddr *)&target, sizeof(target)) == 0 ? "yes" : "no");
        return 0;
    }
    fprintf(stderr, "usage: lprobe race|bound|unbound|twice | unix <path> | inherited <fd> | holder <guard> <rules> <lprobe>\n");
    return 2;
}
C
if ! "$compiler" -O2 -pthread -o "$WORK/lprobe" "$WORK/lprobe.c" 2>"$WORK/lprobe-cc.log"; then
  bad "the listen probe builds" "$(cat "$WORK/lprobe-cc.log")"
  finish
fi
printf '127.0.0.1 *\n' > "$WORK/rules-loopback"

out="$("$WORK/guard" --rules "$WORK/rules-loopback" -- "$WORK/lprobe" bound 2>&1)"
if [[ "$out" == *"BOUND-LISTEN-OK accept ok"* ]]; then
  ok "a socket bound to a port listens, a client connects and accept() sees it"
else
  bad "a socket bound to a port listens, a client connects and accept() sees it" "$out"
fi
if [[ "$out" == *"BOUND-REBIND ok"* ]]; then
  ok "the port is free again once the command closes its listener, the guard keeps no copy"
else
  bad "the port is free again once the command closes its listener, the guard keeps no copy" "$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-loopback" -- "$WORK/lprobe" unix "$WORK/listen.sock" 2>&1)"
if [[ "$out" == *"UNIX-LISTEN-OK"* ]]; then
  ok "a UNIX-domain socket still binds and listens under the guard"
else
  bad "a UNIX-domain socket still binds and listens under the guard" "$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-loopback" -- "$WORK/lprobe" twice 2>&1)"
if [[ "$out" == *"TWICE first ok second ok"* ]]; then
  ok "a repeated listen succeeds, without changing anything"
else
  bad "a repeated listen succeeds, without changing anything" "$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-loopback" -- "$WORK/lprobe" unbound 2>&1)"
if [[ "$out" == *"UNBOUND Permission denied"* ]]; then
  ok "a socket that was never bound is refused when it listens, so no listener appears on a port nothing judged"
else
  bad "a socket that was never bound is refused when it listens, so no listener appears on a port nothing judged" "$out"
fi

out="$("$WORK/lprobe" unbound 2>&1)"
if [[ "$out" == *"UNBOUND ok"*"reachable yes"* ]]; then
  ok "control: without the guard the same unbound listen creates a reachable listener"
else
  bad "control: without the guard the same unbound listen creates a reachable listener" "$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-loopback" --allow-ephemeral-listen -- "$WORK/lprobe" unbound 2>&1)"
if [[ "$out" == *"UNBOUND ok"*"reachable yes"* ]]; then
  ok "with --allow-ephemeral-listen the same unbound listen works and is reachable"
else
  bad "with --allow-ephemeral-listen the same unbound listen works and is reachable" "$out"
fi

out="$("$WORK/lprobe" holder "$WORK/guard" "$WORK/rules-loopback" "$WORK/lprobe" 2>&1)"
if [[ "$out" == *"INHERITED Permission denied"* ]]; then
  ok "a socket the guard did not create, here a bound one inherited from outside, cannot listen"
else
  bad "a socket the guard did not create, here a bound one inherited from outside, cannot listen" "$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-loopback" -- "$WORK/lprobe" race 2>&1)"
if [[ "$out" == *"RACE-NO-LISTENER"* ]]; then
  ok "swapping an unbound socket under the descriptor while it listens never creates a listener"
else
  bad "swapping an unbound socket under the descriptor while it listens never creates a listener" "$out"
fi

out="$("$WORK/lprobe" race 2>&1)"
if [[ "$out" == *"RACE-LISTENER-CREATED"* ]]; then
  ok "control: without the guard the same swap does create a listener, so the race really reaches listen()"
else
  bad "control: without the guard the same swap does create a listener, so the race really reaches listen()" "$out"
fi

echo
echo "== every datagram connect and send is made by the guard itself, from copies, never continued in the command =="
cat > "$WORK/dprobe.c" <<'C'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
/* The statuses the probe ends with, which the suite reads: the call was refused, or the probe was
 * called the wrong way. */
enum probe_status { PROBE_USAGE = 2, PROBE_REFUSED = 10 };
/* How often the race drains the receivers, so that their buffers never fill and drop datagrams,
 * how long it waits for the last datagrams to arrive, and how long a receive waits for one. */
enum { DRAIN_EVERY = 20, SETTLE_MICROSECONDS = 100000, RECEIVE_WAIT_MILLISECONDS = 1000 };
/* The descriptor an inherited socket is passed on, and the most a receive reads. */
enum { INHERITED_DESCRIPTOR = 3, RECEIVE_BUFFER = 64 };
/* A datagram one byte beyond the 64 KiB the guard copies. */
enum { OVERSIZE_DATAGRAM = 65536 };

static struct sockaddr_in destination;
static atomic_int race_over;
static in_addr_t allowed_address;
static in_addr_t forbidden_address;

/* The thread that shows the guard one address and the kernel another, as fast as it can: it
 * rewrites the destination in memory while the main thread is sending to it. */
static void *flip(void *unused) {
    (void)unused;
    while (!atomic_load(&race_over)) {
        *(volatile in_addr_t *)&destination.sin_addr.s_addr = forbidden_address;
        *(volatile in_addr_t *)&destination.sin_addr.s_addr = allowed_address;
    }
    return NULL;
}

static void fill(struct sockaddr_in *address, in_addr_t host, int port) {
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons((unsigned short)port);
    address->sin_addr.s_addr = host;
}

static int receiver(in_addr_t host, int port) {
    int descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in local;
    fill(&local, host, port);
    if (bind(descriptor, (struct sockaddr *)&local, sizeof(local)) != 0) {
        printf("RECEIVER-BIND-FAILED %s\n", strerror(errno));
        exit(PROBE_USAGE);
    }
    return descriptor;
}

static int drain(int descriptor) {
    int count = 0;
    char buffer[RECEIVE_BUFFER];
    while (recv(descriptor, buffer, sizeof(buffer), 0) > 0) {
        count++;
    }
    return count;
}

/* One send of one byte to the destination the other thread is flipping, by the named call. */
static int send_once(int sender, const char *mode) {
    char payload = 'x';
    struct iovec vector = { .iov_base = &payload, .iov_len = 1 };
    struct msghdr header;
    memset(&header, 0, sizeof(header));
    header.msg_name = &destination;
    header.msg_namelen = sizeof(destination);
    header.msg_iov = &vector;
    header.msg_iovlen = 1;
    if (strcmp(mode, "sendto") == 0) {
        return (int)sendto(sender, &payload, 1, 0, (struct sockaddr *)&destination, sizeof(destination));
    }
    if (strcmp(mode, "sendmsg") == 0) {
        return (int)sendmsg(sender, &header, 0);
    }
    if (strcmp(mode, "sendmmsg") == 0) {
        struct mmsghdr entry;
        memset(&entry, 0, sizeof(entry));
        entry.msg_hdr = header;
        return sendmmsg(sender, &entry, 1, 0);
    }
    if (connect(sender, (struct sockaddr *)&destination, sizeof(destination)) != 0) {
        return -1;
    }
    return (int)send(sender, &payload, 1, 0);
}

/* The race: two receivers share one port, one on an allowed address and one on a forbidden one, so
 * the port alone cannot tell them apart. Whatever arrives at the forbidden one got past the guard. */
static int race(const char *mode, int port, int attempts) {
    allowed_address = inet_addr("127.0.0.1");
    forbidden_address = inet_addr("127.0.0.2");
    int allowed = receiver(allowed_address, port);
    int forbidden = receiver(forbidden_address, port);
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    fill(&destination, allowed_address, port);
    pthread_t thread;
    pthread_create(&thread, NULL, flip, NULL);
    int refused = 0;
    int to_allowed = 0;
    int to_forbidden = 0;
    for (int attempt = 0; attempt < attempts; attempt++) {
        if (attempt % DRAIN_EVERY == 0) {
            to_allowed += drain(allowed);
            to_forbidden += drain(forbidden);
        }
        if (send_once(sender, mode) < 0) {
            refused++;
        }
    }
    atomic_store(&race_over, 1);
    pthread_join(thread, NULL);
    usleep(SETTLE_MICROSECONDS);
    to_allowed += drain(allowed);
    to_forbidden += drain(forbidden);
    printf("RACE %s attempts=%d refused=%d allowed=%d forbidden=%d\n", mode, attempts, refused,
           to_allowed, to_forbidden);
    return 0;
}

/* Waits for one datagram on the receiver and answers its length, or -1 when none came. */
static int receive_length(int descriptor, char *buffer, size_t size) {
    struct pollfd waiting = { .fd = descriptor, .events = POLLIN, .revents = 0 };
    if (poll(&waiting, 1, RECEIVE_WAIT_MILLISECONDS) <= 0) {
        return -1;
    }
    return (int)recv(descriptor, buffer, size, 0);
}

/* Every call that carries a datagram, used the way ordinary programs use them, and the bytes
 * checked at the other end: that is what the guard must not break. */
static int roundtrip(int port) {
    int listener = receiver(inet_addr("127.0.0.1"), port);
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in target;
    fill(&target, inet_addr("127.0.0.1"), port);
    char got[RECEIVE_BUFFER];
    int length;

    if (sendto(sender, "hello", 5, 0, (struct sockaddr *)&target, sizeof(target)) != 5) {
        printf("ROUNDTRIP-SENDTO-FAILED %s\n", strerror(errno));
        return 1;
    }
    length = receive_length(listener, got, sizeof(got));
    if (length != 5 || memcmp(got, "hello", 5) != 0) {
        printf("ROUNDTRIP-SENDTO-WRONG %d\n", length);
        return 1;
    }

    struct iovec parts[2] = { { .iov_base = "ab", .iov_len = 2 }, { .iov_base = "cd", .iov_len = 2 } };
    struct msghdr header;
    memset(&header, 0, sizeof(header));
    header.msg_name = &target;
    header.msg_namelen = sizeof(target);
    header.msg_iov = parts;
    header.msg_iovlen = 2;
    if (sendmsg(sender, &header, 0) != 4) {
        printf("ROUNDTRIP-SENDMSG-FAILED %s\n", strerror(errno));
        return 1;
    }
    length = receive_length(listener, got, sizeof(got));
    if (length != 4 || memcmp(got, "abcd", 4) != 0) {
        printf("ROUNDTRIP-SENDMSG-WRONG %d\n", length);
        return 1;
    }

    struct iovec first = { .iov_base = "1", .iov_len = 1 };
    struct iovec second = { .iov_base = "22", .iov_len = 2 };
    struct iovec third = { .iov_base = "333", .iov_len = 3 };
    struct mmsghdr batch[3];
    memset(batch, 0, sizeof(batch));
    struct iovec *vectors[3] = { &first, &second, &third };
    for (int index = 0; index < 3; index++) {
        batch[index].msg_hdr.msg_name = &target;
        batch[index].msg_hdr.msg_namelen = sizeof(target);
        batch[index].msg_hdr.msg_iov = vectors[index];
        batch[index].msg_hdr.msg_iovlen = 1;
    }
    int sent = sendmmsg(sender, batch, 3, 0);
    if (sent != 3 || batch[0].msg_len != 1 || batch[1].msg_len != 2 || batch[2].msg_len != 3) {
        printf("ROUNDTRIP-SENDMMSG-FAILED sent=%d lengths=%u,%u,%u %s\n", sent, batch[0].msg_len,
               batch[1].msg_len, batch[2].msg_len, strerror(errno));
        return 1;
    }
    int total = 0;
    for (int index = 0; index < 3; index++) {
        total += receive_length(listener, got, sizeof(got));
    }
    if (total != 6) {
        printf("ROUNDTRIP-SENDMMSG-WRONG %d\n", total);
        return 1;
    }

    int connected = socket(AF_INET, SOCK_DGRAM, 0);
    if (connect(connected, (struct sockaddr *)&target, sizeof(target)) != 0 ||
        send(connected, "conn", 4, 0) != 4) {
        printf("ROUNDTRIP-CONNECT-FAILED %s\n", strerror(errno));
        return 1;
    }
    length = receive_length(listener, got, sizeof(got));
    if (length != 4 || memcmp(got, "conn", 4) != 0) {
        printf("ROUNDTRIP-CONNECT-WRONG %d\n", length);
        return 1;
    }
    printf("ROUNDTRIP-OK\n");
    return 0;
}

/* One datagram on a socket that was never bound, to the destination: the kernel binds a source
 * port for it, which only a policy that grants an ephemeral bind lets through. */
static int unbound(int port) {
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in target;
    fill(&target, inet_addr("127.0.0.1"), port);
    if (sendto(sender, "x", 1, 0, (struct sockaddr *)&target, sizeof(target)) < 0) {
        printf("UNBOUND-REFUSED %s\n", strerror(errno));
        return PROBE_REFUSED;
    }
    printf("UNBOUND-OK\n");
    return 0;
}

/* A sendmsg that carries ancillary data, which can steer a datagram. */
static int ancillary(int port) {
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in target;
    fill(&target, inet_addr("127.0.0.1"), port);
    char payload = 'x';
    struct iovec vector = { .iov_base = &payload, .iov_len = 1 };
    union {
        char buffer[CMSG_SPACE(sizeof(int))];
        struct cmsghdr alignment;
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr header;
    memset(&header, 0, sizeof(header));
    header.msg_name = &target;
    header.msg_namelen = sizeof(target);
    header.msg_iov = &vector;
    header.msg_iovlen = 1;
    header.msg_control = control.buffer;
    header.msg_controllen = sizeof(control.buffer);
    struct cmsghdr *entry = CMSG_FIRSTHDR(&header);
    entry->cmsg_level = IPPROTO_IP;
    entry->cmsg_type = IP_TOS;
    entry->cmsg_len = CMSG_LEN(sizeof(int));
    int tos = 0;
    memcpy(CMSG_DATA(entry), &tos, sizeof(tos));
    if (sendmsg(sender, &header, 0) < 0) {
        printf("ANCILLARY-REFUSED %s\n", strerror(errno));
        return PROBE_REFUSED;
    }
    printf("ANCILLARY-OK\n");
    return 0;
}

/* A sendmsg that names no destination on a socket that was never bound. The kernel binds the
 * socket before it notices there is nowhere to send to, so the port the socket ends up with says
 * whether the call reached the kernel. */
static int nodest(void) {
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    char payload = 'x';
    struct iovec vector = { .iov_base = &payload, .iov_len = 1 };
    struct msghdr header;
    memset(&header, 0, sizeof(header));
    header.msg_iov = &vector;
    header.msg_iovlen = 1;
    ssize_t result = sendmsg(sender, &header, 0);
    int failure = errno;
    struct sockaddr_in bound;
    socklen_t length = sizeof(bound);
    memset(&bound, 0, sizeof(bound));
    getsockname(sender, (struct sockaddr *)&bound, &length);
    printf("NODEST result=%d errno=%s port=%s\n", (int)result, strerror(failure),
           ntohs(bound.sin_port) == 0 ? "none" : "bound");
    return 0;
}

/* A sendmmsg whose vector sits in memory the command can read but not write, so the lengths cannot
 * be written back. The kernel sends the first message and then reports the fault, and the guard
 * has to report the same, and send the same, as the kernel does. */
static int readonly_vector(int port) {
    int listener = receiver(inet_addr("127.0.0.1"), port);
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in target;
    fill(&target, inet_addr("127.0.0.1"), port);
    long page = sysconf(_SC_PAGESIZE);
    struct mmsghdr *batch = mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    static struct iovec parts[3];
    static char payloads[3][2] = { "a", "b", "c" };
    for (int index = 0; index < 3; index++) {
        parts[index].iov_base = payloads[index];
        parts[index].iov_len = 1;
        batch[index].msg_hdr.msg_name = &target;
        batch[index].msg_hdr.msg_namelen = sizeof(target);
        batch[index].msg_hdr.msg_iov = &parts[index];
        batch[index].msg_hdr.msg_iovlen = 1;
    }
    mprotect(batch, (size_t)page, PROT_READ);
    int result = sendmmsg(sender, batch, 3, 0);
    int failure = errno;
    usleep(SETTLE_MICROSECONDS);
    printf("READONLY result=%d errno=%s arrived=%d\n", result, result < 0 ? strerror(failure) : "none",
           drain(listener));
    return 0;
}

/* Sends one datagram to a host name, which the command resolves as any program does, from
 * /etc/hosts, and then one to a decoy address on the same port. The first answers where the name
 * leads, the second shows that a rule for the name is held to its addresses and not to the port. */
static int name_send(const char *name, int port, const char *decoy) {
    struct addrinfo hints;
    struct addrinfo *found = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    char service[16];
    snprintf(service, sizeof(service), "%d", port);
    if (getaddrinfo(name, service, &hints, &found) != 0 || found == NULL) {
        printf("NAME-NOT-RESOLVED\n");
        return PROBE_REFUSED;
    }
    char text[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((struct sockaddr_in *)found->ai_addr)->sin_addr, text, sizeof(text));
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    if (sendto(sender, "x", 1, 0, found->ai_addr, found->ai_addrlen) < 0) {
        printf("NAME-REFUSED %s %s\n", text, strerror(errno));
    } else {
        printf("NAME-SENT %s\n", text);
    }
    struct sockaddr_in other;
    fill(&other, inet_addr(decoy), port);
    if (sendto(sender, "x", 1, 0, (struct sockaddr *)&other, sizeof(other)) < 0) {
        printf("DECOY-REFUSED %s\n", strerror(errno));
    } else {
        printf("DECOY-SENT\n");
    }
    return 0;
}

/* Waits a moment on an address and port and says how many datagrams came. */
static int count_arrivals(const char *address, int port) {
    int listener = receiver(inet_addr(address), port);
    printf("RECEIVER-UP\n");
    fflush(stdout);
    usleep(3 * RECEIVE_WAIT_MILLISECONDS * 1000);
    printf("ARRIVED %d\n", drain(listener));
    return 0;
}

/* A datagram one byte beyond the 64 KiB the guard copies. */
static int oversize(int port) {
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in target;
    fill(&target, inet_addr("127.0.0.1"), port);
    static char data[OVERSIZE_DATAGRAM];
    if (sendto(sender, data, sizeof(data), 0, (struct sockaddr *)&target, sizeof(target)) < 0) {
        printf("OVERSIZE-REFUSED %s\n", strerror(errno));
        return PROBE_REFUSED;
    }
    printf("OVERSIZE-OK\n");
    return 0;
}

/* A datagram to a socket the guard did not create: the descriptor was inherited from outside. */
static int inherited(int descriptor, int port) {
    struct sockaddr_in target;
    fill(&target, inet_addr("127.0.0.1"), port);
    if (sendto(descriptor, "x", 1, 0, (struct sockaddr *)&target, sizeof(target)) < 0) {
        printf("INHERITED-REFUSED %s\n", strerror(errno));
        return PROBE_REFUSED;
    }
    printf("INHERITED-OK\n");
    return 0;
}

/* Creates a bound datagram socket, passes it on as descriptor 3 through the guard to the command,
 * as a socket inherited from outside would be. */
static int holder(char **arguments) {
    int outside = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local;
    fill(&local, inet_addr("127.0.0.1"), 0);
    bind(outside, (struct sockaddr *)&local, sizeof(local));
    dup2(outside, INHERITED_DESCRIPTOR);
    execl(arguments[0], arguments[0], "--rules", arguments[1], "--", arguments[2], "inherited", "3",
          arguments[3], (char *)NULL);
    return 1;
}

int main(int argc, char **argv) {
    if (argc >= 5 && strcmp(argv[1], "race") == 0) {
        return race(argv[2], atoi(argv[3]), atoi(argv[4]));
    }
    if (argc >= 3 && strcmp(argv[1], "roundtrip") == 0) {
        return roundtrip(atoi(argv[2]));
    }
    if (argc >= 3 && strcmp(argv[1], "unbound") == 0) {
        return unbound(atoi(argv[2]));
    }
    if (argc >= 3 && strcmp(argv[1], "ancillary") == 0) {
        return ancillary(atoi(argv[2]));
    }
    if (argc >= 2 && strcmp(argv[1], "nodest") == 0) {
        return nodest();
    }
    if (argc >= 3 && strcmp(argv[1], "readonly") == 0) {
        return readonly_vector(atoi(argv[2]));
    }
    if (argc >= 5 && strcmp(argv[1], "namesend") == 0) {
        return name_send(argv[2], atoi(argv[3]), argv[4]);
    }
    if (argc >= 4 && strcmp(argv[1], "arrivals") == 0) {
        return count_arrivals(argv[2], atoi(argv[3]));
    }
    if (argc >= 3 && strcmp(argv[1], "oversize") == 0) {
        return oversize(atoi(argv[2]));
    }
    if (argc >= 4 && strcmp(argv[1], "inherited") == 0) {
        return inherited(atoi(argv[2]), atoi(argv[3]));
    }
    if (argc >= 6 && strcmp(argv[1], "holder") == 0) {
        return holder(&argv[2]);
    }
    fprintf(stderr, "usage: dprobe race <mode> <port> <attempts> | roundtrip|unbound|ancillary|oversize <port> | "
                    "holder <guard> <rules> <dprobe> <port>\n");
    return PROBE_USAGE;
}
C
if ! "$compiler" -O2 -pthread -o "$WORK/dprobe" "$WORK/dprobe.c" 2>"$WORK/dprobe-cc.log"; then
  bad "the datagram probe builds" "$(cat "$WORK/dprobe-cc.log")"
  finish
fi
DGRAM_PORT=39320
RACE_PORT=39321
RACE_ATTEMPTS=20000
printf '127.0.0.1 %s udp\n' "$DGRAM_PORT" > "$WORK/rules-dgram"
printf '127.0.0.1 %s udp\n' "$RACE_PORT" > "$WORK/rules-race"

out="$("$WORK/guard" --rules "$WORK/rules-dgram" --allow-ephemeral-udp-bind -- "$WORK/dprobe" roundtrip "$DGRAM_PORT" 2>&1)"
if [[ "$out" == *ROUNDTRIP-OK* ]]; then
  ok "sendto, sendmsg with two segments, sendmmsg with three messages and a connected send all arrive intact, and sendmmsg reports each length"
else
  bad "sendto, sendmsg with two segments, sendmmsg with three messages and a connected send all arrive intact" "$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-dgram" -- "$WORK/dprobe" unbound "$DGRAM_PORT" 2>&1)"
rc=$?
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"UNBOUND-REFUSED Permission denied"* ]]; then
  ok "a datagram on a socket that was never bound is refused when the policy grants no ephemeral bind"
else
  bad "a datagram on a socket that was never bound is refused when the policy grants no ephemeral bind" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-dgram" --allow-ephemeral-udp-bind -- "$WORK/dprobe" unbound "$DGRAM_PORT" 2>&1)"
if [[ "$out" == *UNBOUND-OK* ]]; then
  ok "with --allow-ephemeral-udp-bind the same datagram is sent"
else
  bad "with --allow-ephemeral-udp-bind the same datagram is sent" "$out"
fi

control="$("$WORK/dprobe" nodest 2>&1)"
out="$("$WORK/guard" --rules "$WORK/rules-dgram" -- "$WORK/dprobe" nodest 2>&1)"
granted="$("$WORK/guard" --rules "$WORK/rules-dgram" --allow-ephemeral-udp-bind -- "$WORK/dprobe" nodest 2>&1)"
if [[ "$control" == *"errno=Destination address required port=bound"* ]]; then
  if [[ "$out" == *"errno=Permission denied port=none"* && "$granted" == *"errno=Destination address required port=bound"* ]]; then
    ok "a send that names no destination still cannot give an unbound socket a port nobody granted, though the kernel would (control: $control)"
  else
    bad "a send that names no destination still cannot give an unbound socket a port nobody granted" "control: $control; guarded: $out; granted: $granted"
  fi
else
  skip "a send that names no destination still cannot give an unbound socket a port nobody granted" "without the guard the kernel did not bind it either (${control})"
fi

control="$("$WORK/dprobe" readonly "$DGRAM_PORT" 2>&1)"
out="$("$WORK/guard" --rules "$WORK/rules-dgram" --allow-ephemeral-udp-bind -- "$WORK/dprobe" readonly "$DGRAM_PORT" 2>&1)"
if [[ "$control" == "READONLY result=-1 errno=Bad address arrived=1" && "$out" == "$control" ]]; then
  ok "a sendmmsg whose lengths cannot be written back sends one message and reports EFAULT, exactly as the kernel does"
else
  bad "a sendmmsg whose lengths cannot be written back sends one message and reports EFAULT, exactly as the kernel does" "control: $control; guarded: $out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-dgram" --allow-ephemeral-udp-bind -- "$WORK/dprobe" ancillary "$DGRAM_PORT" 2>&1)"
rc=$?
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"ANCILLARY-REFUSED Permission denied"* ]]; then
  ok "a sendmsg with ancillary data is refused, it can steer a datagram past the destination check"
else
  bad "a sendmsg with ancillary data is refused, it can steer a datagram past the destination check" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-dgram" --allow-ephemeral-udp-bind -- "$WORK/dprobe" oversize "$DGRAM_PORT" 2>&1)"
rc=$?
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"OVERSIZE-REFUSED Message too long"* ]]; then
  ok "a datagram beyond 64 KiB is refused with EMSGSIZE, as the kernel would"
else
  bad "a datagram beyond 64 KiB is refused with EMSGSIZE, as the kernel would" "rc=$rc out=$out"
fi

out="$("$WORK/dprobe" holder "$WORK/guard" "$WORK/rules-dgram" "$WORK/dprobe" "$DGRAM_PORT" 2>&1)"
if [[ "$out" == *"INHERITED-REFUSED Permission denied"* ]]; then
  ok "a datagram socket the guard did not create, here one inherited from outside, cannot send to a destination"
else
  bad "a datagram socket the guard did not create, here one inherited from outside, cannot send to a destination" "$out"
fi

# The race. A second thread rewrites the destination in memory while the main thread sends, and
# two receivers share the port, one on the allowed address and one on a forbidden one, so only
# the guard can keep a datagram from the second. Each call is measured without the guard first:
# where that run never reaches the forbidden receiver, this machine cannot show the race at all
# (a single processor, say) and the guarded run would prove nothing, so it is skipped, as the
# checks above skip what the environment refuses by itself.
race_count() {
  sed -n "s/.*$2=\([0-9][0-9]*\).*/\1/p" <<<"$1"
}
for mode in sendto sendmsg sendmmsg connect; do
  control="$("$WORK/dprobe" race "$mode" "$RACE_PORT" "$RACE_ATTEMPTS" 2>&1)"
  leaked="$(race_count "$control" forbidden)"
  if [[ -z "$leaked" || "$leaked" -eq 0 ]]; then
    skip "a rewritten destination never reaches the forbidden receiver by $mode" "without the guard it never did either (${control}), so the race is not reachable here"
    continue
  fi
  out="$("$WORK/guard" --rules "$WORK/rules-race" --allow-ephemeral-udp-bind -- "$WORK/dprobe" race "$mode" "$RACE_PORT" "$RACE_ATTEMPTS" 2>&1)"
  forbidden="$(race_count "$out" forbidden)"
  allowed="$(race_count "$out" allowed)"
  refused="$(race_count "$out" refused)"
  if [[ "$forbidden" == "0" && -n "$allowed" && "$allowed" -gt 0 && -n "$refused" && "$refused" -gt 0 ]]; then
    ok "by $mode, a destination rewritten while the call runs never reaches the forbidden receiver, and the allowed one still receives (control without the guard leaked $leaked)"
  else
    bad "by $mode, a destination rewritten while the call runs never reaches the forbidden receiver, and the allowed one still receives" "control: $control; guarded: $out"
  fi
done

echo
echo "== the guard's resolve mode gives the addresses of the names a udp rule holds =="
cat > "$WORK/stubdns.c" <<'C'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
/* A stub name server for the suite: it answers by the first label of the question, so each name
 * names the behaviour it wants. The record types it knows are A (1) and AAAA (28). */
enum { A = 1, AAAA = 28, HEADER = 12, PACKET = 1500, MANY = 20 };

static size_t question_end(const unsigned char *query, size_t length) {
    size_t at = HEADER;
    while (at < length && query[at] != 0) {
        at += (size_t)query[at] + 1;
    }
    return at + 5;
}

static size_t add_record_owned(unsigned char *out, size_t at, const unsigned char *owner, size_t owner_length,
                               int type, const unsigned char *data, size_t data_length) {
    if (owner != NULL) {
        memcpy(out + at, owner, owner_length);
        at += owner_length;
    } else {
        out[at++] = 0xc0;
        out[at++] = HEADER;
    }
    out[at++] = 0;
    out[at++] = (unsigned char)type;
    out[at++] = 0;
    out[at++] = 1;
    memset(out + at, 0, 3);
    at += 3;
    out[at++] = 60;
    out[at++] = 0;
    out[at++] = (unsigned char)data_length;
    memcpy(out + at, data, data_length);
    return at + data_length;
}

static size_t add_record(unsigned char *out, size_t at, int type, const unsigned char *data, size_t data_length) {
    return add_record_owned(out, at, NULL, 0, type, data, data_length);
}

int main(int argc, char **argv) {
    int port = atoi(argv[1]);
    int server = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local = { .sin_family = AF_INET, .sin_port = htons((unsigned short)port) };
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(server, (struct sockaddr *)&local, sizeof(local)) != 0) {
        perror("bind");
        return 1;
    }
    printf("STUB-UP\n");
    fflush(stdout);
    int late_seen = 0;
    for (;;) {
        unsigned char query[PACKET];
        struct sockaddr_in from;
        socklen_t from_length = sizeof(from);
        ssize_t length = recvfrom(server, query, sizeof(query), 0, (struct sockaddr *)&from, &from_length);
        if (length < HEADER + 5) {
            continue;
        }
        char label[64] = { 0 };
        memcpy(label, query + HEADER + 1, query[HEADER] < 63 ? query[HEADER] : 63);
        int type = query[question_end(query, (size_t)length) - 4] * 256 + query[question_end(query, (size_t)length) - 3];
        size_t end = question_end(query, (size_t)length);
        unsigned char out[PACKET];
        memcpy(out, query, end);
        out[2] = (unsigned char)(0x81 | (query[2] & 0x01));
        out[3] = 0x80;
        out[6] = out[7] = out[8] = out[9] = out[10] = out[11] = 0;
        size_t at = end;
        int answers = 0;
        if (strcmp(label, "slow") == 0) {
            continue;
        }
        if (strcmp(label, "late") == 0 && !late_seen) {
            late_seen = 1;
            continue;
        }
        if (strcmp(label, "wrongid") == 0) {
            out[1] ^= 0xff;
        } else if (strcmp(label, "fail") == 0) {
            out[3] = 0x82;
        } else if (strcmp(label, "nx") == 0) {
            out[3] = 0x83;
        } else if (strcmp(label, "trunc") == 0) {
            out[2] |= 0x02;
        } else if (strcmp(label, "garbage") == 0) {
            at = end;
            out[7] = 5;
            out[at++] = 0xc0;
        } else if (strcmp(label, "badlength") == 0 && type == A) {
            unsigned char data[3] = { 1, 2, 3 };
            at = add_record(out, at, A, data, sizeof(data));
            answers = 1;
        } else if (strcmp(label, "many") == 0 && type == A) {
            for (int index = 0; index < MANY; index++) {
                unsigned char data[4] = { 198, 51, 100, (unsigned char)(index + 1) };
                at = add_record(out, at, A, data, sizeof(data));
                answers++;
            }
        } else if (strcmp(label, "cname") == 0 && type == A) {
            unsigned char alias[] = { 5, 'a', 'l', 'i', 'a', 's', 0 };
            at = add_record(out, at, 5, alias, sizeof(alias));
            unsigned char data[4] = { 192, 0, 2, 4 };
            at = add_record_owned(out, at, alias, sizeof(alias), A, data, sizeof(data));
            answers = 2;
        } else if (strcmp(label, "foreign") == 0 && type == A) {
            unsigned char other[] = { 5, 'o', 't', 'h', 'e', 'r', 0 };
            unsigned char data[4] = { 192, 0, 2, 99 };
            at = add_record_owned(out, at, other, sizeof(other), A, data, sizeof(data));
            answers = 1;
        } else if (strcmp(label, "plain") == 0 || strcmp(label, "case") == 0) {
            if (type == A) {
                unsigned char first[4] = { 192, 0, 2, 1 };
                unsigned char second[4] = { 192, 0, 2, 2 };
                at = add_record(out, at, A, first, sizeof(first));
                at = add_record(out, at, A, second, sizeof(second));
                answers = 2;
            } else if (type == AAAA) {
                unsigned char data[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
                at = add_record(out, at, AAAA, data, sizeof(data));
                answers = 1;
            }
            if (strcmp(label, "case") == 0) {
                for (size_t index = HEADER; index < end - 4; index++) {
                    out[index] = (unsigned char)toupper(out[index]);
                }
            }
        } else if (strcmp(label, "loop") == 0 && type == A) {
            unsigned char data[4] = { 127, 0, 0, 1 };
            at = add_record(out, at, A, data, sizeof(data));
            answers = 1;
        } else if ((strcmp(label, "v4only") == 0 || strcmp(label, "late") == 0) && type == A) {
            unsigned char data[4] = { 192, 0, 2, 3 };
            at = add_record(out, at, A, data, sizeof(data));
            answers = 1;
        }
        out[7] = out[7] ? out[7] : (unsigned char)answers;
        sendto(server, out, at, 0, (struct sockaddr *)&from, from_length);
    }
}
C
if ! "$compiler" -O2 -o "$WORK/stubdns" "$WORK/stubdns.c" 2>"$WORK/stubdns-cc.log"; then
  bad "the stub name server builds" "$(cat "$WORK/stubdns-cc.log")"
  finish
fi
DNS_PORT=39340
"$WORK/stubdns" "$DNS_PORT" > "$WORK/stubdns.out" 2>&1 &
stub_pid=$!
for _ in $(seq 1 "$LISTENER_WAIT_ATTEMPTS"); do grep -q STUB-UP "$WORK/stubdns.out" 2>/dev/null && break; sleep "$LISTENER_WAIT_SECONDS"; done

# The status the resolve mode ends with when it cannot give every name an address.
RESOLVE_REFUSED=125
resolve() {
  "$WORK/guard" --resolve --resolver "127.0.0.1:${DNS_PORT}" -- "$@" 2>"$WORK/resolve.err"
}
resolve_fails_with() {
  local label="$1"
  local wanted="$2"
  shift 2
  local out
  local rc
  out="$(resolve "$@")"
  rc=$?
  if [[ $rc -eq "$RESOLVE_REFUSED" && -z "$out" && "$(cat "$WORK/resolve.err")" == *"$wanted"* ]]; then
    ok "$label"
  else
    bad "$label" "rc=$rc out=$out err=$(cat "$WORK/resolve.err")"
  fi
}

out="$(resolve plain.test)"
if [[ "$out" == $'plain.test 192.0.2.1\nplain.test 192.0.2.2\nplain.test 2001:db8::1' ]]; then
  ok "a name with two IPv4 addresses and one IPv6 address gives all three"
else
  bad "a name with two IPv4 addresses and one IPv6 address gives all three" "$out"
fi
out="$(resolve v4only.test)"
if [[ "$out" == "v4only.test 192.0.2.3" ]]; then
  ok "an empty answer for one record type is not a failure when the other type gave an address"
else
  bad "an empty answer for one record type is not a failure when the other type gave an address" "$out"
fi
out="$(resolve cname.test)"
if [[ "$out" == "cname.test 192.0.2.4" ]]; then
  ok "an alias in the answer is stepped over and the address after it is kept"
else
  bad "an alias in the answer is stepped over and the address after it is kept" "$out"
fi
out="$(resolve case.test)"
if [[ "$out" == *"case.test 192.0.2.1"* && "$out" == *"case.test 2001:db8::1"* ]]; then
  ok "a resolver that changes the case of the question is still understood"
else
  bad "a resolver that changes the case of the question is still understood" "$out"
fi
out="$(resolve late.test)"
if [[ "$out" == "late.test 192.0.2.3" ]]; then
  ok "a first query that is not answered is asked again"
else
  bad "a first query that is not answered is asked again" "$out"
fi
out="$(resolve plain.test v4only.test)"
if [[ "$(wc -l <<<"$out")" -eq 4 && "$out" == *"v4only.test 192.0.2.3"* ]]; then
  ok "several names are resolved in one call, each line naming its name"
else
  bad "several names are resolved in one call, each line naming its name" "$out"
fi
out="$(resolve many.test)"
if [[ "$(wc -l <<<"$out")" -eq 16 ]]; then
  ok "a name with twenty addresses keeps sixteen of them"
else
  bad "a name with twenty addresses keeps sixteen of them" "$(wc -l <<<"$out") lines"
fi

resolve_fails_with "a name that does not exist is refused" "no address was found" nx.test
resolve_fails_with "a resolver that answers with an error is refused" "answered with an error" fail.test
resolve_fails_with "a truncated answer is refused rather than used in part" "truncated" trunc.test
resolve_fails_with "an address that belongs to another name is not taken for the name asked" "no address was found" foreign.test
resolve_fails_with "an answer that cannot be read is refused" "could not be read" garbage.test
resolve_fails_with "an address record of the wrong length is refused" "could not be read" badlength.test
resolve_fails_with "a name that is not answered is refused after the wait" "did not answer in time" slow.test
resolve_fails_with "an answer with the wrong id is not taken for the answer" "did not answer in time" wrongid.test
resolve_fails_with "a name that cannot be a DNS question is refused" "cannot be sent" 'bad!name.test'
resolve_fails_with "one name that fails makes the whole call print nothing, the ones before it included" "cannot resolve nx.test" plain.test nx.test

out="$("$WORK/guard" --resolve --resolver 127.0.0.1:1 -- plain.test 2>&1)"
rc=$?
if [[ $rc -eq "$RESOLVE_REFUSED" && "$out" == *"did not answer in time"* ]]; then
  ok "a resolver nothing listens on is refused after the wait"
else
  bad "a resolver nothing listens on is refused after the wait" "rc=$rc out=$out"
fi
out="$("$WORK/guard" --resolve --resolver not-an-address -- plain.test 2>&1)"
rc=$?
if [[ $rc -eq "$RESOLVE_REFUSED" && "$out" == *"is not an address"* ]]; then
  ok "a resolver that is a host name is refused"
else
  bad "a resolver that is a host name is refused" "rc=$rc out=$out"
fi

echo
echo "== through the network layer, a udp rule that names a host is held to the addresses it had at the start =="
# The layer writes /etc/hosts, so it needs that file writable, as the run-phase image the acceptance
# suite uses gives; where it is not, these cases are skipped. The Landlock enforcer is a stand-in
# that runs the command: a udp rule naming a port needs Landlock version 10, which no kernel the
# project's CI or local runs use has, and the guard is what is being proven here, not the port rules.
if [[ -w /etc/hosts ]]; then
  stub_landlock="$WORK/stub-landlock"
  printf '#!/bin/sh\nwhile [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done\nshift\nexec "$@"\n' > "$stub_landlock"
  chmod +x "$stub_landlock"
  NAME_PORT=39350
  owned_spec_for() {
    local directory
    directory="$(mktemp -d "$WORK/udp-name-spec.XXXXXX")"
    ( source "${CORE}/phobos-tools-common/phobos-common.sh"; mark_owned_spec_dir "$directory" )
    printf '%s\n' "$directory"
  }
  hosts_before="$(cat /etc/hosts; printf 'x')"

  spec="$(owned_spec_for)"
  printf 'loop.test %s udp\n' "$NAME_PORT" > "$spec/net.rules"
  "$WORK/dprobe" arrivals 127.0.0.1 "$NAME_PORT" > "$WORK/arrive-real.out" 2>&1 &
  real_pid=$!
  "$WORK/dprobe" arrivals 127.0.0.2 "$NAME_PORT" > "$WORK/arrive-decoy.out" 2>&1 &
  decoy_pid=$!
  for _ in $(seq 1 "$LISTENER_WAIT_ATTEMPTS"); do
    grep -q RECEIVER-UP "$WORK/arrive-real.out" 2>/dev/null && grep -q RECEIVER-UP "$WORK/arrive-decoy.out" 2>/dev/null && break
    sleep "$LISTENER_WAIT_SECONDS"
  done
  out="$("${CORE}/phobos-networksystem.sh" --connect-guard-bin "$WORK/guard" --landlock-bin "$stub_landlock" \
    --resolver "127.0.0.1:${DNS_PORT}" "$spec" -- "$WORK/dprobe" namesend loop.test "$NAME_PORT" 127.0.0.2 2>&1)"
  wait "$real_pid" "$decoy_pid" 2>/dev/null
  if [[ "$out" == *"NAME-SENT 127.0.0.1"* && "$(cat "$WORK/arrive-real.out")" == *"ARRIVED 1"* ]]; then
    ok "the command resolves the name from /etc/hosts to the address the layer resolved, and a datagram to it arrives"
  else
    bad "the command resolves the name from /etc/hosts to the address the layer resolved, and a datagram to it arrives" "out=$out real=$(cat "$WORK/arrive-real.out")"
  fi
  if [[ "$out" == *"DECOY-REFUSED Permission denied"* && "$(cat "$WORK/arrive-decoy.out")" == *"ARRIVED 0"* ]]; then
    ok "another address on the same port is refused and nothing reaches it, so the rule is held to the name's addresses and not to its port"
  else
    bad "another address on the same port is refused and nothing reaches it" "out=$out decoy=$(cat "$WORK/arrive-decoy.out")"
  fi
  [[ "$(cat /etc/hosts; printf 'x')" == "$hosts_before" ]] \
    && ok "once the run has ended, /etc/hosts is byte-identical to what it was before" \
    || bad "once the run has ended, /etc/hosts is byte-identical to what it was before" "$(grep loop.test /etc/hosts)"
  [[ ! -e "$spec" ]] && ok "and the run's specification directory is gone, the guard's rules file with it" \
    || bad "and the run's specification directory is gone, the guard's rules file with it" "$(ls -A "$spec")"

  spec="$(owned_spec_for)"
  printf 'loop.test %s udp\n' "$NAME_PORT" > "$spec/net.rules"
  rm -f "$WORK/ran.marker"
  out="$("${CORE}/phobos-networksystem.sh" --connect-guard-bin "$WORK/guard" --landlock-bin "$stub_landlock" \
    --resolver 127.0.0.1:1 "$spec" -- touch "$WORK/ran.marker" 2>&1)"
  rc=$?
  if [[ $rc -eq 15 && ! -e "$WORK/ran.marker" && "$out" == *"could not be resolved"* ]]; then
    ok "a resolver that does not answer refuses the run and the command never starts"
  else
    bad "a resolver that does not answer refuses the run and the command never starts" "rc=$rc out=$out"
  fi
  [[ "$(cat /etc/hosts; printf 'x')" == "$hosts_before" ]] \
    && ok "a refused run leaves /etc/hosts as it found it" \
    || bad "a refused run leaves /etc/hosts as it found it" "$(grep loop.test /etc/hosts)"

  if command -v haproxy >/dev/null 2>&1; then
    spec="$(owned_spec_for)"
    printf 'LOOP.test 443\nloop.test %s udp\n' "$NAME_PORT" > "$spec/net.rules"
    out="$("${CORE}/phobos-networksystem.sh" --connect-guard-bin "$WORK/guard" --landlock-bin "$stub_landlock" \
      --resolver "127.0.0.1:${DNS_PORT}" "$spec" -- grep -i loop.test /etc/hosts 2>&1)"
    if [[ "$out" == *"127.0.0.1 loop.test"* && "$out" != *"127.0.0.2"* ]]; then
      ok "a name held by both a tcp and a udp rule, written in another case, is mapped to its real address and gets no placeholder"
    else
      bad "a name held by both a tcp and a udp rule, written in another case, is mapped to its real address and gets no placeholder" "$out"
    fi
  else
    skip "a name held by both a tcp and a udp rule gets no placeholder" "haproxy is not installed here"
  fi
else
  skip "the network layer holds a udp name rule to the addresses it resolved to" "/etc/hosts is not writable here"
fi

kill "$stub_pid" 2>/dev/null
wait "$stub_pid" 2>/dev/null

finish
