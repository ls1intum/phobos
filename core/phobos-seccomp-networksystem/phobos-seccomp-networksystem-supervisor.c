#define _GNU_SOURCE
#include "phobos-seccomp-networksystem-supervisor.h"

#include "phobos-seccomp-networksystem-broker-log.h"
#include "phobos-seccomp-networksystem-child.h"
#include "phobos-seccomp-networksystem-datagram.h"
#include "phobos-seccomp-networksystem-destination.h"
#include "phobos-seccomp-networksystem-diagnostics.h"
#include "phobos-seccomp-networksystem-handoff.h"
#include "phobos-seccomp-networksystem-held-sockets.h"
#include "phobos-seccomp-networksystem-report.h"
#include "phobos-seccomp-networksystem-rules.h"
#include "phobos-seccomp-networksystem-seccomp-compat.h"
#include "phobos-seccomp-networksystem-socket-types.h"

#include "../phobos-seccomp-filesystem/phobos-seccomp-filesystem-refusals.h"
#include "../phobos-seccomp-filesystem/phobos-seccomp-filesystem-reporter.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>

/* The bits of socket()'s type argument that name the type itself, the rest being
 * SOCK_CLOEXEC and SOCK_NONBLOCK. Defined by glibc; kept here for an older header. */
#ifndef SOCK_TYPE_MASK
#define SOCK_TYPE_MASK 0xf
#endif

/* How long the supervisor waits for one connection it makes on the command's behalf. */
static constexpr int CONNECT_TIMEOUT_MS = 10000;
/* Where each trapped syscall keeps the arguments the supervisor reads, as the kernel numbers
 * them in struct seccomp_data: connect(fd, address, length) and socket(domain, type, protocol).
 * The arguments of the sends are read in the datagram module. */
static constexpr int CONNECT_ARGUMENT_DESCRIPTOR = 0;
static constexpr int CONNECT_ARGUMENT_ADDRESS = 1;
static constexpr int CONNECT_ARGUMENT_LENGTH = 2;
static constexpr int SOCKET_ARGUMENT_DOMAIN = 0;
static constexpr int SOCKET_ARGUMENT_TYPE = 1;
static constexpr int SOCKET_ARGUMENT_PROTOCOL = 2;
/* listen(fd, backlog). */
static constexpr int LISTEN_ARGUMENT_DESCRIPTOR = 0;
static constexpr int LISTEN_ARGUMENT_BACKLOG = 1;

void answer(int notify_descriptor, struct seccomp_notif_resp *response, __u64 id,
            __s64 value, __s32 error) {
    memset(response, 0, sizeof(*response));
    response->id = id;
    response->val = value;
    response->error = error;
    response->flags = 0;
    if (!send_notification_response(notify_descriptor, response) && errno != ENOENT) {
        log_verbose("notify send: %s", strerror(errno));
    }
}

/* Let the kernel run the child's own syscall unchanged. Used only for a socket() the guard does
 * not govern. CONTINUE re-runs the syscall against the child's registers, so it is sound only for
 * a decision made from scalar arguments, which a second thread cannot rewrite; nothing that
 * names a destination behind a pointer is ever continued. */
static void answer_continue(int notify_descriptor, struct seccomp_notif_resp *response, __u64 id) {
    memset(response, 0, sizeof(*response));
    response->id = id;
    response->val = 0;
    response->error = 0;
    response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    if (!send_notification_response(notify_descriptor, response) && errno != ENOENT) {
        log_verbose("notify continue: %s", strerror(errno));
    }
}

/* Whether the calls the guard's filter refuses outright, other than io_uring, are counted for the
 * timeout layer: its group lock is above the guard and its signature was found. Otherwise the
 * network layer is the only one that refuses them (A.5.8, point 9). */
static bool group_lock_counted_for_timeout = false;

/* The descriptor of the pipe the egress broker logs its refusals to, or NO_BROKER_LOG. */
static int broker_log_descriptor = -1;

void configure_group_lock_attribution(bool timeout_layer) {
    group_lock_counted_for_timeout = timeout_layer;
}

void configure_broker_log(int descriptor) {
    broker_log_descriptor = descriptor;
}

/* The transport of one of the command's sockets, for the reporter's judgement of a bind: the type
 * this guard recorded for the socket behind the descriptor, or -1 for a socket it never saw. */
int tracked_socket_type(pid_t owner, int descriptor) {
    uint8_t type = lookup_socket_type(fd_socket_inode(owner, descriptor));
    if (type == FD_TYPE_STREAM) {
        return SOCK_STREAM;
    }
    return type == FD_TYPE_DGRAM ? SOCK_DGRAM : -1;
}

void configure_reporting(const char *landlock_bin, int landlock_version) {
    if (landlock_bin != nullptr) {
        reporter_configure(landlock_bin, landlock_version);
    }
    reporter_use_socket_types(tracked_socket_type);
}

/* The layer a refused call is counted for: io_uring for the network layer, which refuses it alone,
 * and setsid, setpgid and every foreign-ABI call for the timeout layer when its group lock refuses
 * them too, and for the network layer otherwise. */
static enum report_layer refusal_layer(const struct seccomp_data *data) {
    bool io_uring = data->arch == GUARD_NATIVE_AUDIT_ARCH
                    && (data->nr == __NR_io_uring_setup || data->nr == __NR_io_uring_enter
                        || data->nr == __NR_io_uring_register);
    if (io_uring || !group_lock_counted_for_timeout) {
        return REPORT_LAYER_NETWORK;
    }
    return REPORT_LAYER_TIMEOUT;
}

int connect_within_deadline(int family, const struct sockaddr *address, socklen_t length) {
    int outward = socket(family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (outward < 0) {
        return -errno;
    }
    if (connect(outward, address, length) == 0) {
        (void)fcntl(outward, F_SETFL, fcntl(outward, F_GETFL) & ~O_NONBLOCK);
        return outward;
    }
    if (errno != EINPROGRESS) {
        int failure = errno;
        close(outward);
        return -failure;
    }
    struct pollfd waiting = { .fd = outward, .events = POLLOUT, .revents = 0 };
    int ready;
    do {
        ready = poll(&waiting, 1, CONNECT_TIMEOUT_MS);
    } while (ready < 0 && errno == EINTR);
    if (ready <= 0) {
        int failure = errno;
        close(outward);
        return ready == 0 ? -ETIMEDOUT : -failure;
    }
    int socket_error = 0;
    socklen_t error_length = sizeof(socket_error);
    if (getsockopt(outward, SOL_SOCKET, SO_ERROR, &socket_error, &error_length) != 0) {
        int failure = errno;
        close(outward);
        return -failure;
    }
    if (socket_error != 0) {
        close(outward);
        return -socket_error;
    }
    (void)fcntl(outward, F_SETFL, fcntl(outward, F_GETFL) & ~O_NONBLOCK);
    return outward;
}

/* The twelve bytes a PROXY protocol version 2 header opens with, the marker a broker reads to
 * know a header follows. */
static const uint8_t PROXY_V2_SIGNATURE[] = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
};
/* Version 2, command PROXY: the header describes a proxied connection rather than the proxy's own. */
static constexpr uint8_t PROXY_V2_VERSION_COMMAND = 0x21;
/* The transport byte: a TCP stream over IPv4, and over IPv6. */
static constexpr uint8_t PROXY_V2_TCP_OVER_IPV4 = 0x11;
static constexpr uint8_t PROXY_V2_TCP_OVER_IPV6 = 0x21;
/* The address block that follows the sixteen-byte prefix: two addresses and two ports. */
static constexpr uint16_t PROXY_V2_IPV4_BLOCK = 12;
static constexpr uint16_t PROXY_V2_IPV6_BLOCK = 36;
/* The prefix length and the largest header, prefix plus the IPv6 block. */
static constexpr size_t PROXY_V2_PREFIX = 16;
static constexpr size_t PROXY_V2_HEADER_MAXIMUM = PROXY_V2_PREFIX + PROXY_V2_IPV6_BLOCK;
/* Room for a broker's host text, an IP literal at most, IPv6's forty-five characters and a null. */
static constexpr size_t BROKER_HOST_TEXT = 64;

/* The broker every allowed stream connection is pointed at, when one is configured. */
static struct sockaddr_storage broker_address;
static socklen_t broker_length = 0;
static bool broker_set = false;

bool configure_broker(const char *endpoint) {
    char host[BROKER_HOST_TEXT];
    const char *port_text = nullptr;
    if (endpoint[0] == '[') {
        const char *closing = strchr(endpoint, ']');
        if (closing == nullptr || closing[1] != ':') {
            return false;
        }
        size_t host_length = (size_t)(closing - endpoint - 1);
        if (host_length == 0 || host_length >= sizeof(host)) {
            return false;
        }
        memcpy(host, endpoint + 1, host_length);
        host[host_length] = '\0';
        port_text = closing + 2;
    } else {
        const char *colon = strrchr(endpoint, ':');
        if (colon == nullptr || (size_t)(colon - endpoint) >= sizeof(host)) {
            return false;
        }
        memcpy(host, endpoint, (size_t)(colon - endpoint));
        host[colon - endpoint] = '\0';
        port_text = colon + 1;
    }
    char *unconverted = nullptr;
    unsigned long port = strtoul(port_text, &unconverted, 10);
    if (*port_text == '\0' || *unconverted != '\0' || port == 0 || port > UINT16_MAX) {
        return false;
    }
    memset(&broker_address, 0, sizeof(broker_address));
    struct in_addr v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, host, &v4) == 1) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&broker_address;
        sin->sin_family = AF_INET;
        sin->sin_port = htons((uint16_t)port);
        sin->sin_addr = v4;
        broker_length = sizeof(*sin);
    } else if (inet_pton(AF_INET6, host, &v6) == 1) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&broker_address;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((uint16_t)port);
        sin6->sin6_addr = v6;
        broker_length = sizeof(*sin6);
    } else {
        return false;
    }
    broker_set = true;
    return true;
}

/* Builds into buffer a PROXY protocol version 2 header that names the original destination, so
 * the broker connects onward to it although the guard connected to the broker. The source is the
 * loopback of the destination's family with port zero: the broker routes by the destination, and
 * the guard has no source of the command's to name. Returns the header length. Assumes buffer
 * holds PROXY_V2_HEADER_MAXIMUM bytes and that the destination is IPv4 or IPv6, which service_connect
 * has already established before any connection is made on the command's behalf. */
static size_t build_proxy_v2_header(uint8_t *buffer, const struct sockaddr_storage *destination) {
    memcpy(buffer, PROXY_V2_SIGNATURE, sizeof(PROXY_V2_SIGNATURE));
    buffer[12] = PROXY_V2_VERSION_COMMAND;
    uint16_t source_port = 0;
    if (destination->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)destination;
        buffer[13] = PROXY_V2_TCP_OVER_IPV4;
        buffer[14] = (uint8_t)(PROXY_V2_IPV4_BLOCK >> 8);
        buffer[15] = (uint8_t)(PROXY_V2_IPV4_BLOCK & 0xff);
        uint32_t loopback = htonl(INADDR_LOOPBACK);
        memcpy(&buffer[16], &loopback, 4);
        memcpy(&buffer[20], &sin->sin_addr, 4);
        memcpy(&buffer[24], &source_port, 2);
        memcpy(&buffer[26], &sin->sin_port, 2);
        return PROXY_V2_PREFIX + PROXY_V2_IPV4_BLOCK;
    }
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)destination;
    buffer[13] = PROXY_V2_TCP_OVER_IPV6;
    buffer[14] = (uint8_t)(PROXY_V2_IPV6_BLOCK >> 8);
    buffer[15] = (uint8_t)(PROXY_V2_IPV6_BLOCK & 0xff);
    memcpy(&buffer[16], &in6addr_loopback, 16);
    memcpy(&buffer[32], &sin6->sin6_addr, 16);
    memcpy(&buffer[48], &source_port, 2);
    memcpy(&buffer[50], &sin6->sin6_port, 2);
    return PROXY_V2_PREFIX + PROXY_V2_IPV6_BLOCK;
}

/* Sends the whole PROXY header on the socket before the command's own bytes, retrying a short
 * write and an interruption. Returns whether all of it was sent. */
static bool send_proxy_v2_header(int socket_descriptor, const struct sockaddr_storage *destination) {
    uint8_t header[PROXY_V2_HEADER_MAXIMUM];
    size_t length = build_proxy_v2_header(header, destination);
    size_t sent = 0;
    while (sent < length) {
        ssize_t wrote = send(socket_descriptor, header + sent, length - sent, MSG_NOSIGNAL);
        if (wrote < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        sent += (size_t)wrote;
    }
    return true;
}

bool connect_on_behalf(int notify_descriptor, struct seccomp_notif_resp *response,
                       __u64 id, int target_descriptor, int family,
                       const struct sockaddr *address, socklen_t length) {
    int outward;
    if (broker_set) {
        outward = connect_within_deadline(broker_address.ss_family,
                                          (const struct sockaddr *)&broker_address, broker_length);
    } else {
        outward = connect_within_deadline(family, address, length);
    }
    if (outward < 0) {
        answer(notify_descriptor, response, id, 0, outward);
        return false;
    }
    if (broker_set) {
        struct sockaddr_storage destination;
        memset(&destination, 0, sizeof(destination));
        memcpy(&destination, address, length < sizeof(destination) ? length : sizeof(destination));
        if (!send_proxy_v2_header(outward, &destination)) {
            close(outward);
            answer(notify_descriptor, response, id, 0, -ECONNREFUSED);
            return false;
        }
    }
    struct seccomp_notif_addfd addfd;
    memset(&addfd, 0, sizeof(addfd));
    addfd.id = id;
    addfd.flags = SECCOMP_ADDFD_FLAG_SETFD;
    addfd.srcfd = (__u32)outward;
    addfd.newfd = (__u32)target_descriptor;
    addfd.newfd_flags = 0;
    if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd) < 0) {
        if (errno != ENOENT) {
            answer(notify_descriptor, response, id, 0, -errno);
        }
        close(outward);
        return false;
    }
    close(outward);
    answer(notify_descriptor, response, id, 0, 0);
    return true;
}

/* Decide one trapped connect: read the destination from the child, confirm the notification is
 * still valid so the read belongs to this call, and refuse a family this guard does not carry. A
 * refused connect to a UNIX socket is worded only for a task of the filesystem domain, the command
 * and what it started: every layer's shell runs under this guard's filter before the domain exists
 * and asks the name service cache for the user at start-up, a connect the guard refuses, and worded
 * it would blame the program for Phobos's own helpers. With the filesystem layer off there is no
 * domain, and no such line is worded.
 * The socket's provenance is then resolved before the allow-list check, because the transport is
 * part of the decision: a stream socket is TCP and a datagram socket is UDP, and the allow-list
 * holds each transport apart, so a UDP-only rule must not admit a TCP connection to the same host
 * and port. A socket of unknown provenance is refused first: one the guard never recorded, one
 * evicted from a full table, an injected replacement being reconnected, or a descriptor /proc
 * cannot name. Letting such a call continue would run the child's own unmediated connect(), the
 * very boundary a raw connect must not reach, so an unknown provenance fails closed. For a stream
 * socket, make the connection here and inject it, so the child's connect() returns already
 * connected to the address the check read and a second thread cannot redirect it. For a datagram
 * socket connect() only sets the default peer, which cannot be injected, so the datagram module
 * makes the connect itself on the descriptor it holds for that socket. */
static void service_connect(int notify_descriptor, struct seccomp_notif *request,
                            struct seccomp_notif_resp *response) {
    int target_descriptor = (int)request->data.args[CONNECT_ARGUMENT_DESCRIPTOR];
    uintptr_t address_pointer = (uintptr_t)request->data.args[CONNECT_ARGUMENT_ADDRESS];
    socklen_t claimed_length = (socklen_t)request->data.args[CONNECT_ARGUMENT_LENGTH];

    struct sockaddr_storage storage;
    memset(&storage, 0, sizeof(storage));
    socklen_t length = read_peer_address(request->pid, address_pointer, claimed_length, &storage);

    if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_ID_VALID, &request->id) != 0) {
        return;
    }
    if (length == 0) {
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }

    struct destination where = read_destination(&storage);
    if (where.family != AF_INET && where.family != AF_INET6) {
        log_verbose("refusing connect of family %d, which this guard does not carry", where.family);
        if (where.family == AF_UNIX && reporter_task_in_domain(notify_descriptor, request)) {
            report_refused_socket_file(&storage, length);
        }
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }
    uint64_t inode = fd_socket_inode(request->pid, target_descriptor);
    uint8_t provenance = lookup_socket_type(inode);
    if (provenance != FD_TYPE_STREAM && provenance != FD_TYPE_DGRAM) {
        log_verbose("refusing connect on a socket of unknown provenance, fd %d", target_descriptor);
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }
    if (!connection_permitted(where.family, where.address, where.port,
                              provenance == FD_TYPE_DGRAM)) {
        char endpoint[ENDPOINT_TEXT_SIZE];
        format_endpoint(&where, endpoint, sizeof(endpoint));
        log_verbose("refusing connect to a destination the allow-list does not name: %s", endpoint);
        bool datagram = provenance == FD_TYPE_DGRAM;
        report_refused_endpoint(datagram ? "send to" : "connect to", &where, datagram);
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }
    if (provenance == FD_TYPE_STREAM) {
        if (connect_on_behalf(notify_descriptor, response, request->id, target_descriptor,
                              where.family, (const struct sockaddr *)&storage, length)) {
            release_held_socket(inode);
        }
        return;
    }
    service_datagram_connect(notify_descriptor, response, request->id, inode, &storage, length);
}

/* Decide one trapped socket(): refuse the socket kinds that reach the network outside the
 * connect and send hooks, a packet socket, a raw socket and an ICMP datagram socket (which any
 * user may open here because the container's ping_group_range spans every group). An INET
 * stream or datagram socket is created here and injected, so its type is tracked. A datagram
 * socket is held, because every datagram connect and send is made by this supervisor on it. A
 * stream or sequenced-packet socket of the INET, INET6 or UNIX family is held too: it is the only
 * kind that can listen, and a listen() is only ever run by this supervisor, on a socket it made
 * and still holds. Any other socket is left to the kernel. The arguments are the kernel's own scalar
 * copy in the notification, so there is nothing to read from the child and nothing a second
 * thread could rewrite. */
static void service_socket(int notify_descriptor, struct seccomp_notif *request,
                           struct seccomp_notif_resp *response) {
    int domain = (int)request->data.args[SOCKET_ARGUMENT_DOMAIN];
    int type = (int)request->data.args[SOCKET_ARGUMENT_TYPE];
    int protocol = (int)request->data.args[SOCKET_ARGUMENT_PROTOCOL];
    int base_type = type & SOCK_TYPE_MASK;
    bool icmp = protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6;
    if (domain == AF_PACKET || base_type == SOCK_RAW
        || ((domain == AF_INET || domain == AF_INET6) && icmp)) {
        log_verbose("refusing socket(domain=%d, type=%d, protocol=%d)", domain, type, protocol);
        report_refused_socket_kind(domain, type);
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }
    bool tracked = (domain == AF_INET || domain == AF_INET6)
                   && (base_type == SOCK_STREAM || base_type == SOCK_DGRAM);
    bool may_listen = (domain == AF_INET || domain == AF_INET6 || domain == AF_UNIX)
                      && (base_type == SOCK_STREAM || base_type == SOCK_SEQPACKET);
    if (!tracked && !may_listen) {
        answer_continue(notify_descriptor, response, request->id);
        return;
    }
    int made = socket(domain, base_type | SOCK_CLOEXEC, protocol);
    if (made < 0) {
        answer(notify_descriptor, response, request->id, 0, -errno);
        return;
    }
    if (type & SOCK_NONBLOCK) {
        int flags = fcntl(made, F_GETFL);
        if (flags >= 0) {
            (void)fcntl(made, F_SETFL, flags | O_NONBLOCK);
        }
    }
    struct seccomp_notif_addfd addfd;
    memset(&addfd, 0, sizeof(addfd));
    addfd.id = request->id;
    addfd.flags = 0;
    addfd.srcfd = (__u32)made;
    addfd.newfd = 0;
    addfd.newfd_flags = (type & SOCK_CLOEXEC) ? O_CLOEXEC : 0;
    int allocated = ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
    if (allocated < 0) {
        if (errno != ENOENT) {
            answer(notify_descriptor, response, request->id, 0, -errno);
        }
        close(made);
        return;
    }
    uint64_t inode = fd_socket_inode(getpid(), made);
    if (tracked) {
        record_socket_type(inode, base_type == SOCK_STREAM ? FD_TYPE_STREAM : FD_TYPE_DGRAM);
    }
    hold_socket(inode, made);
    answer(notify_descriptor, response, request->id, allocated, 0);
}

/* Whether the guard allows a socket that was never bound to listen: a kernel that is asked to
 * listen on an unbound socket binds it to a port of its own choosing, which no bind rule judged. */
static bool ephemeral_listen_allowed = false;

void configure_ephemeral_listen(bool allowed) {
    ephemeral_listen_allowed = allowed;
}

/* Whether a socket the supervisor holds may be put into the listening state: a UNIX socket
 * always may, because Landlock's filesystem rules and scoping judged where it was bound; an INET
 * or INET6 socket may when it is bound to an explicit port, which Landlock's bind rules already
 * judged, or when it is unbound and an ephemeral bind is allowed. Reads the socket's own address
 * from the supervisor's descriptor, which is the command's socket, so nothing the command can
 * rewrite is read. Any other family, or an address the kernel cannot report, is refused. */
static bool listen_permitted(int held_descriptor) {
    int family;
    uint16_t port;
    if (!socket_local_port(held_descriptor, &family, &port)) {
        return false;
    }
    if (family == AF_UNIX) {
        return true;
    }
    if (family != AF_INET && family != AF_INET6) {
        return false;
    }
    return port != 0 || ephemeral_listen_allowed;
}

/* Decide one trapped listen(). The call is never continued: whatever the check saw, the command
 * could have swapped another socket onto the descriptor before the kernel ran it, one that was
 * never bound, so the supervisor runs listen() itself, on the descriptor it holds for the socket
 * the command's descriptor named when it was read, and answers with the result. A socket this
 * supervisor never created (an inherited descriptor, an accepted socket, one evicted from the
 * table) is refused. A socket it has already let listen is answered 0 without calling the kernel:
 * that covers a listen() repeated to change the backlog and one the command retries after a
 * signal cancelled the notification once the supervisor had already listened; if the command had
 * swapped another socket onto the descriptor, that socket simply is not listening. The listening
 * socket is then let go of, so the port is free again when the command closes its descriptor. */
static void service_listen(int notify_descriptor, struct seccomp_notif *request,
                           struct seccomp_notif_resp *response) {
    int target_descriptor = (int)request->data.args[LISTEN_ARGUMENT_DESCRIPTOR];
    int backlog = (int)request->data.args[LISTEN_ARGUMENT_BACKLOG];
    uint64_t inode = fd_socket_inode(request->pid, target_descriptor);
    if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_ID_VALID, &request->id) != 0) {
        return;
    }
    if (was_listened(inode)) {
        answer(notify_descriptor, response, request->id, 0, 0);
        return;
    }
    int held = held_socket_descriptor(inode);
    if (held < 0) {
        log_verbose("refusing listen on a socket this guard did not create, fd %d", target_descriptor);
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }
    if (!listen_permitted(held)) {
        log_verbose("refusing listen on a socket bound to no port, fd %d", target_descriptor);
        report_refused_listen();
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }
    if (listen(held, backlog) != 0) {
        answer(notify_descriptor, response, request->id, 0, -errno);
        return;
    }
    remember_listened(inode);
    release_held_socket(inode);
    answer(notify_descriptor, response, request->id, 0, 0);
}

void service_one(int notify_descriptor, struct seccomp_notif *request,
                 struct seccomp_notif_resp *response, size_t request_size) {
    memset(request, 0, request_size);
    if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_RECV, request) != 0) {
        return;
    }
    if (is_filter_refusal(&request->data)) {
        answer_filter_refusal(notify_descriptor, request, response, refusal_layer(&request->data));
        return;
    }
    if (reporter_handles(request)) {
        reporter_service(notify_descriptor, request, response);
        return;
    }
    if (request->data.nr == __NR_connect) {
        service_connect(notify_descriptor, request, response);
        return;
    }
    if (request->data.nr == __NR_socket) {
        service_socket(notify_descriptor, request, response);
        return;
    }
    if (request->data.nr == __NR_listen) {
        service_listen(notify_descriptor, request, response);
        return;
    }
    if (request->data.nr == __NR_sendto || request->data.nr == __NR_sendmmsg
        || request->data.nr == __NR_sendmsg) {
        service_datagram_send(notify_descriptor, request, response);
        return;
    }
    answer(notify_descriptor, response, request->id, 0, -EACCES);
}

void supervise(int notify_descriptor) {
    struct seccomp_notif_sizes sizes;
    memset(&sizes, 0, sizeof(sizes));
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0) {
        sizes.seccomp_notif = sizeof(struct seccomp_notif);
        sizes.seccomp_notif_resp = sizeof(struct seccomp_notif_resp);
    }
    size_t request_size = sizes.seccomp_notif;
    if (request_size < sizeof(struct seccomp_notif)) {
        request_size = sizeof(struct seccomp_notif);
    }
    size_t response_size = sizes.seccomp_notif_resp;
    if (response_size < sizeof(struct seccomp_notif_resp)) {
        response_size = sizeof(struct seccomp_notif_resp);
    }
    struct seccomp_notif *request = calloc(1, request_size);
    struct seccomp_notif_resp *response = calloc(1, response_size);
    if (request == nullptr || response == nullptr) {
        free(request);
        free(response);
        return;
    }

    for (;;) {
        struct pollfd watch[2] = {
            { .fd = notify_descriptor, .events = POLLIN, .revents = 0 },
            { .fd = broker_log_descriptor, .events = POLLIN, .revents = 0 },
        };
        int ready = poll(watch, 2, -1);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (watch[1].revents & POLLIN) {
            drain_broker_log(broker_log_descriptor);
        }
        if (watch[1].revents & (POLLERR | POLLNVAL)) {
            broker_log_descriptor = -1;
        }
        if (watch[0].revents & POLLIN) {
            service_one(notify_descriptor, request, response, request_size);
        }
        if (watch[0].revents & (POLLHUP | POLLERR)) {
            break;
        }
    }
    if (broker_log_descriptor >= 0) {
        drain_broker_log(broker_log_descriptor);
    }
    free(request);
    free(response);
}

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
void broker_reset_for_tests(void) {
    broker_set = false;
    broker_length = 0;
}

void ephemeral_listen_reset_for_tests(void) {
    ephemeral_listen_allowed = false;
}

void reporting_reset_for_tests(void) {
    group_lock_counted_for_timeout = false;
    broker_log_descriptor = -1;
}
#endif
