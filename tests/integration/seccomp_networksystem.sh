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
CORE="${HERE}/../../core"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

compiler=gcc-14
command -v "$compiler" >/dev/null 2>&1 || compiler=gcc
if ! command -v "$compiler" >/dev/null 2>&1; then
  skip "the connect guard" "no C compiler to build it"
  finish
fi

if ! "$compiler" -std=gnu23 -O2 -Wall -Wextra -Werror -o "$WORK/guard" "${CORE}"/phobos-seccomp-networksystem/phobos-seccomp-networksystem*.c 2>"$WORK/cc.log"; then
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
    if (argc < 4 || strcmp(argv[1], "inet") != 0) {
        fprintf(stderr, "usage: probe inet <host> <port> | probe unix <path>\n");
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

out="$("$WORK/guard" --rules "$WORK/rules-udp" -- "$WORK/probe" udp 127.0.0.1 "$PORT" 2>&1)"
rc=$?
if [[ $rc -eq 0 && "$out" == *UDP-OK* ]]; then
  ok "a datagram to a destination the udp list names is allowed"
else
  bad "a datagram to a destination the udp list names is allowed" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-udp" -- "$WORK/probe" udp 127.0.0.1 "$OTHER" 2>&1)"
rc=$?
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
  ok "a datagram to a destination the udp list does not name is refused"
else
  bad "a datagram to a destination the udp list does not name is refused" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-udp" -- "$WORK/probe" msg 127.0.0.1 "$PORT" 2>&1)"
rc=$?
if [[ $rc -eq 0 && "$out" == *MSG-OK* ]]; then
  ok "a sendmsg datagram to a destination the udp list names is allowed, so the handoff survived trapping sendmsg"
else
  bad "a sendmsg datagram to a destination the udp list names is allowed" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-udp" -- "$WORK/probe" msg 127.0.0.1 "$OTHER" 2>&1)"
rc=$?
if [[ $rc -eq "$PROBE_REFUSED" && "$out" == *"Permission denied"* ]]; then
  ok "a sendmsg datagram to a destination the udp list does not name is refused"
else
  bad "a sendmsg datagram to a destination the udp list does not name is refused" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-udp" -- "$WORK/probe" msg2 127.0.0.1 "$PORT" 2>&1)"
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
out="$("$WORK/guard" --rules "$WORK/rules-udp" -- "$WORK/probe" cudp 127.0.0.1 "$PORT" 2>&1)"
rc=$?
if [[ $rc -eq 0 && "$out" == *CUDP-OK* ]]; then
  ok "a connected datagram socket stays a datagram, not turned into TCP"
else
  bad "a connected datagram socket stays a datagram, not turned into TCP" "rc=$rc out=$out"
fi

out="$("$WORK/guard" --rules "$WORK/rules-udp" -- "$WORK/probe" cudp 127.0.0.1 "$OTHER" 2>&1)"
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
out="$("$WORK/guard" --rules "$WORK/rules-tcp-only" -- "$WORK/probe" udp 127.0.0.1 "$PORT" 2>&1)"
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

finish
