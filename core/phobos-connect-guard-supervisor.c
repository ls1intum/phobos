#define _GNU_SOURCE
#include "phobos-connect-guard-supervisor.h"

#include "phobos-connect-guard-destination.h"
#include "phobos-connect-guard-diagnostics.h"
#include "phobos-connect-guard-rules.h"
#include "phobos-connect-guard-seccomp-compat.h"
#include "phobos-connect-guard-socket-types.h"

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

/* The send flag that opens a connection with the first datagram (TCP Fast Open). It
 * carries a destination past connect(), so the guard refuses it rather than let a send
 * reach a host connect() never vetted. */
#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN 0x20000000
#endif

/* How long the supervisor waits for one connection it makes on the command's behalf. */
static constexpr int CONNECT_TIMEOUT_MS = 10000;
/* Where each trapped syscall keeps the arguments the supervisor reads, as the kernel numbers
 * them in struct seccomp_data: connect(fd, address, length), socket(domain, type, protocol),
 * sendto(fd, buffer, length, flags, address, address_length) and
 * sendmmsg(fd, vector, count, flags). */
static constexpr int CONNECT_ARGUMENT_DESCRIPTOR = 0;
static constexpr int CONNECT_ARGUMENT_ADDRESS = 1;
static constexpr int CONNECT_ARGUMENT_LENGTH = 2;
static constexpr int SOCKET_ARGUMENT_DOMAIN = 0;
static constexpr int SOCKET_ARGUMENT_TYPE = 1;
static constexpr int SOCKET_ARGUMENT_PROTOCOL = 2;
static constexpr int SEND_ARGUMENT_FLAGS = 3;
static constexpr int SENDTO_ARGUMENT_ADDRESS = 4;
static constexpr int SENDTO_ARGUMENT_ADDRESS_LENGTH = 5;
static constexpr int SENDMMSG_ARGUMENT_VECTOR = 1;
static constexpr int SENDMMSG_ARGUMENT_COUNT = 2;
static constexpr int SENDMSG_ARGUMENT_HEADER = 1;
static constexpr int SENDMSG_ARGUMENT_FLAGS = 2;
/* The most messages the kernel sends in one sendmmsg call (UIO_MAXIOV); a larger count is
 * cut down to it, so no more entries than it would send are read. */
static constexpr unsigned int SENDMMSG_MAXIMUM_BATCH = 1024;
/* A shell reports a command killed by a signal as this plus the signal's number. */
static constexpr int SIGNALLED_EXIT_BASE = 128;

int receive_descriptor(int socket_descriptor) {
    char payload = 0;
    struct iovec vector = { .iov_base = &payload, .iov_len = 1 };
    union {
        char buffer[CMSG_SPACE(sizeof(int))];
        struct cmsghdr alignment;
    } control;
    memset(&control, 0, sizeof(control));

    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.buffer;
    message.msg_controllen = sizeof(control.buffer);

    ssize_t received;
    do {
        received = recvmsg(socket_descriptor, &message, MSG_CMSG_CLOEXEC);
    } while (received < 0 && errno == EINTR);
    if (received != 1) {
        return -1;
    }
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (header == nullptr || header->cmsg_level != SOL_SOCKET ||
        header->cmsg_type != SCM_RIGHTS || header->cmsg_len != CMSG_LEN(sizeof(int))) {
        return -1;
    }
    int descriptor = -1;
    memcpy(&descriptor, CMSG_DATA(header), sizeof(int));
    return descriptor;
}

void answer(int notify_descriptor, struct seccomp_notif_resp *response, __u64 id,
            __s64 value, __s32 error) {
    memset(response, 0, sizeof(*response));
    response->id = id;
    response->val = value;
    response->error = error;
    response->flags = 0;
    if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_SEND, response) != 0 && errno != ENOENT) {
        log_verbose("notify send: %s", strerror(errno));
    }
}

/* Let the kernel run the child's own syscall unchanged. Used where the call is outside what
 * this guard governs, so the guard adds nothing: a bare send on a connected socket the connect
 * already vetted, a send to a non-INET address, or an allowed socket(). CONTINUE re-runs the
 * syscall against the child's registers, so for a scalar-only decision (socket, the send flag)
 * there is nothing a second thread could rewrite; a destination behind a pointer is the one
 * case where CONTINUE is best-effort, which is why the send guard is defence in depth beside a
 * no-network container, not a boundary. */
static void answer_continue(int notify_descriptor, struct seccomp_notif_resp *response, __u64 id) {
    memset(response, 0, sizeof(*response));
    response->id = id;
    response->val = 0;
    response->error = 0;
    response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_SEND, response) != 0 && errno != ENOENT) {
        log_verbose("notify continue: %s", strerror(errno));
    }
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

void connect_on_behalf(int notify_descriptor, struct seccomp_notif_resp *response,
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
        return;
    }
    if (broker_set) {
        struct sockaddr_storage destination;
        memset(&destination, 0, sizeof(destination));
        memcpy(&destination, address, length < sizeof(destination) ? length : sizeof(destination));
        if (!send_proxy_v2_header(outward, &destination)) {
            close(outward);
            answer(notify_descriptor, response, id, 0, -ECONNREFUSED);
            return;
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
        return;
    }
    close(outward);
    answer(notify_descriptor, response, id, 0, 0);
}

/* Decide one trapped connect: read the destination from the child, confirm the notification is
 * still valid so the read belongs to this call, and refuse a family this guard does not carry.
 * The socket's provenance is then resolved before the allow-list check, because the transport is
 * part of the decision: a stream socket is TCP and a datagram socket is UDP, and the allow-list
 * holds each transport apart, so a UDP-only rule must not admit a TCP connection to the same host
 * and port. A socket of unknown provenance is refused first: one the guard never recorded, one
 * evicted from a full table, an injected replacement being reconnected, or a descriptor /proc
 * cannot name. Letting such a call continue would run the child's own unmediated connect(), the
 * very boundary a raw connect must not reach, so an unknown provenance fails closed. For a stream
 * socket, make the connection here and inject it, so the child's connect() returns already
 * connected to the address the check read and a second thread cannot redirect it. For a datagram
 * socket connect() only sets the default peer, which cannot be injected, so the checked call is
 * let through. */
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
        log_verbose("refusing connect to a destination the allow-list does not name, port %u",
                    (unsigned)where.port);
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }
    if (provenance == FD_TYPE_STREAM) {
        connect_on_behalf(notify_descriptor, response, request->id, target_descriptor,
                          where.family, (const struct sockaddr *)&storage, length);
        return;
    }
    answer_continue(notify_descriptor, response, request->id);
}

/* Decide one trapped socket(): refuse the socket kinds that reach the network outside the
 * connect and send hooks, a packet socket, a raw socket and an ICMP datagram socket (which any
 * user may open here because the container's ping_group_range spans every group), and otherwise
 * let the kernel create it. The arguments are the kernel's own scalar copy in the notification,
 * so there is nothing to read from the child and nothing a second thread could rewrite. */
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
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }
    bool tracked = (domain == AF_INET || domain == AF_INET6)
                   && (base_type == SOCK_STREAM || base_type == SOCK_DGRAM);
    if (!tracked) {
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
    close(made);
    record_socket_type(inode, base_type == SOCK_STREAM ? FD_TYPE_STREAM : FD_TYPE_DGRAM);
    answer(notify_descriptor, response, request->id, allocated, 0);
}

/* Answer one send whose destination has already been read: let a non-INET destination through
 * (a UNIX or netlink address is not the network this guard governs), refuse an INET destination
 * the allow-list does not name or one that could not be read, and otherwise let the kernel run
 * the send. A send that carries its own destination is judged as UDP: the destination-bearing
 * sends are the datagram calls, so the allow-list is consulted for the UDP transport. A sendto
 * with a destination on a stream socket is unusual and is deliberately judged the same way, so it
 * is refused unless a UDP rule names the destination rather than passing on a TCP rule. */
static void forward_or_refuse(int notify_descriptor, struct seccomp_notif *request,
                              struct seccomp_notif_resp *response,
                              const struct sockaddr_storage *storage, socklen_t length) {
    if (length == 0) {
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }
    struct destination where = read_destination(storage);
    if (where.family != AF_INET && where.family != AF_INET6) {
        answer_continue(notify_descriptor, response, request->id);
        return;
    }
    if (!connection_permitted(where.family, where.address, where.port, true)) {
        log_verbose("refusing a datagram to a destination the allow-list does not name, port %u",
                    (unsigned)where.port);
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }
    answer_continue(notify_descriptor, response, request->id);
}

/* The flags argument of the two send syscalls the guard traps, sendto and sendmmsg, is the
 * fourth. sendmsg is not trapped (see the filter), so it is not among them. */
static unsigned int send_flags(const struct seccomp_notif *request) {
    return (unsigned int)request->data.args[SEND_ARGUMENT_FLAGS];
}

/* Decide one trapped sendto: a call with no destination is a send on an already-connected
 * socket, whose connect() the guard decided when it was made, so it is not re-examined here; a
 * call carrying a destination has that destination read and judged. */
static void service_sendto(int notify_descriptor, struct seccomp_notif *request,
                           struct seccomp_notif_resp *response) {
    uintptr_t address_pointer = (uintptr_t)request->data.args[SENDTO_ARGUMENT_ADDRESS];
    socklen_t claimed_length = (socklen_t)request->data.args[SENDTO_ARGUMENT_ADDRESS_LENGTH];
    if (address_pointer == 0 || claimed_length == 0) {
        answer_continue(notify_descriptor, response, request->id);
        return;
    }
    struct sockaddr_storage storage;
    memset(&storage, 0, sizeof(storage));
    socklen_t length = read_peer_address(request->pid, address_pointer, claimed_length, &storage);
    if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_ID_VALID, &request->id) != 0) {
        return;
    }
    forward_or_refuse(notify_descriptor, request, response, &storage, length);
}

/* Decide one trapped sendmmsg: every message in the batch is judged, because one CONTINUE
 * lets the kernel send them all, so a batch is refused whole if any entry names an INET
 * destination the allow-list does not name. The count is capped at the kernel's own limit. */
static void service_sendmmsg(int notify_descriptor, struct seccomp_notif *request,
                             struct seccomp_notif_resp *response) {
    uintptr_t vector = (uintptr_t)request->data.args[SENDMMSG_ARGUMENT_VECTOR];
    unsigned int count = (unsigned int)request->data.args[SENDMMSG_ARGUMENT_COUNT];
    if (count > SENDMMSG_MAXIMUM_BATCH) {
        count = SENDMMSG_MAXIMUM_BATCH;
    }
    for (unsigned int index = 0; index < count; index++) {
        struct mmsghdr entry;
        memset(&entry, 0, sizeof(entry));
        uintptr_t entry_pointer = vector + (uintptr_t)index * sizeof(struct mmsghdr);
        bool read_ok = read_child_bytes(request->pid, entry_pointer, &entry, sizeof(entry));
        if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_ID_VALID, &request->id) != 0) {
            return;
        }
        if (!read_ok) {
            answer(notify_descriptor, response, request->id, 0, -EACCES);
            return;
        }
        if (entry.msg_hdr.msg_name == NULL || entry.msg_hdr.msg_namelen == 0) {
            continue;
        }
        struct sockaddr_storage storage;
        memset(&storage, 0, sizeof(storage));
        socklen_t length = read_peer_address(request->pid, (uintptr_t)entry.msg_hdr.msg_name,
                                             (socklen_t)entry.msg_hdr.msg_namelen, &storage);
        if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_ID_VALID, &request->id) != 0) {
            return;
        }
        if (length == 0) {
            answer(notify_descriptor, response, request->id, 0, -EACCES);
            return;
        }
        struct destination where = read_destination(&storage);
        if ((where.family == AF_INET || where.family == AF_INET6)
            && !connection_permitted(where.family, where.address, where.port, true)) {
            log_verbose("refusing a sendmmsg batch: entry %u names a disallowed destination", index);
            answer(notify_descriptor, response, request->id, 0, -EACCES);
            return;
        }
    }
    answer_continue(notify_descriptor, response, request->id);
}

/* Decide one trapped sendmsg: refuse TCP Fast Open, which carries a destination past connect(),
 * then read the destination out of the message header and judge it as a datagram send. A header
 * with no name is a send on a connected socket, whose connect the guard already decided, so it
 * continues; a header naming an INET destination the allow-list does not name is refused. The
 * flags of sendmsg are its third argument, unlike sendto and sendmmsg whose flags are the
 * fourth, so this reads them itself rather than through send_flags. */
static void service_sendmsg(int notify_descriptor, struct seccomp_notif *request,
                            struct seccomp_notif_resp *response) {
    if ((unsigned int)request->data.args[SENDMSG_ARGUMENT_FLAGS] & MSG_FASTOPEN) {
        log_verbose("refusing a sendmsg with MSG_FASTOPEN, which opens a connection past connect()");
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }
    struct msghdr header;
    memset(&header, 0, sizeof(header));
    uintptr_t header_pointer = (uintptr_t)request->data.args[SENDMSG_ARGUMENT_HEADER];
    bool read_ok = read_child_bytes(request->pid, header_pointer, &header, sizeof(header));
    if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_ID_VALID, &request->id) != 0) {
        return;
    }
    if (!read_ok) {
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }
    if (header.msg_name == NULL || header.msg_namelen == 0) {
        answer_continue(notify_descriptor, response, request->id);
        return;
    }
    struct sockaddr_storage storage;
    memset(&storage, 0, sizeof(storage));
    socklen_t length = read_peer_address(request->pid, (uintptr_t)header.msg_name,
                                         (socklen_t)header.msg_namelen, &storage);
    if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_ID_VALID, &request->id) != 0) {
        return;
    }
    forward_or_refuse(notify_descriptor, request, response, &storage, length);
}

/* Decide one trapped send: refuse TCP Fast Open outright, since it carries a destination past
 * connect(), then judge the destination by the send syscall it came from. */
static void service_send(int notify_descriptor, struct seccomp_notif *request,
                         struct seccomp_notif_resp *response) {
    if (send_flags(request) & MSG_FASTOPEN) {
        log_verbose("refusing a send with MSG_FASTOPEN, which opens a connection past connect()");
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }
    if (request->data.nr == __NR_sendto) {
        service_sendto(notify_descriptor, request, response);
        return;
    }
    service_sendmmsg(notify_descriptor, request, response);
}

void service_one(int notify_descriptor, struct seccomp_notif *request,
                 struct seccomp_notif_resp *response, size_t request_size) {
    memset(request, 0, request_size);
    if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_RECV, request) != 0) {
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
    if (request->data.nr == __NR_sendto || request->data.nr == __NR_sendmmsg) {
        service_send(notify_descriptor, request, response);
        return;
    }
    if (request->data.nr == __NR_sendmsg) {
        service_sendmsg(notify_descriptor, request, response);
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
        struct pollfd watch = { .fd = notify_descriptor, .events = POLLIN, .revents = 0 };
        int ready = poll(&watch, 1, -1);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (watch.revents & POLLIN) {
            service_one(notify_descriptor, request, response, request_size);
        }
        if (watch.revents & (POLLHUP | POLLERR)) {
            break;
        }
    }
    free(request);
    free(response);
}

int exit_code_from_status(int status) {
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return SIGNALLED_EXIT_BASE + WTERMSIG(status);
    }
    return EXIT_CODE_SETUP_ERROR;
}

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
void broker_reset_for_tests(void) {
    broker_set = false;
    broker_length = 0;
}
#endif
