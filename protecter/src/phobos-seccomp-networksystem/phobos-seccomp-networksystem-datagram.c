#define _GNU_SOURCE
#include "phobos-seccomp-networksystem-datagram.h"

#include "phobos-seccomp-networksystem-destination.h"
#include "phobos-seccomp-networksystem-diagnostics.h"
#include "phobos-seccomp-networksystem-held-sockets.h"
#include "phobos-seccomp-networksystem-report.h"
#include "phobos-seccomp-networksystem-rules.h"
#include "phobos-seccomp-networksystem-seccomp-compat.h"
#include "phobos-seccomp-networksystem-socket-types.h"
#include "phobos-seccomp-networksystem-supervisor.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>

/* The send flag that opens a connection with the first datagram (TCP Fast Open). It carries a
 * destination past connect(), so the guard refuses it rather than let a send reach a host
 * connect() never vetted. */
#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN 0x20000000
#endif

/* Where each trapped syscall keeps the arguments the supervisor reads, as the kernel numbers them
 * in struct seccomp_data: sendto(fd, buffer, length, flags, address, address_length),
 * sendmsg(fd, header, flags) and sendmmsg(fd, vector, count, flags). */
static constexpr int SEND_ARGUMENT_DESCRIPTOR = 0;
static constexpr int SENDTO_ARGUMENT_BUFFER = 1;
static constexpr int SENDTO_ARGUMENT_LENGTH = 2;
static constexpr int SENDTO_ARGUMENT_FLAGS = 3;
static constexpr int SENDTO_ARGUMENT_ADDRESS = 4;
static constexpr int SENDTO_ARGUMENT_ADDRESS_LENGTH = 5;
static constexpr int SENDMSG_ARGUMENT_HEADER = 1;
static constexpr int SENDMSG_ARGUMENT_FLAGS = 2;
static constexpr int SENDMMSG_ARGUMENT_VECTOR = 1;
static constexpr int SENDMMSG_ARGUMENT_COUNT = 2;
static constexpr int SENDMMSG_ARGUMENT_FLAGS = 3;

/* The largest datagram the supervisor copies: a UDP payload cannot exceed it, so a larger
 * request is one the kernel would refuse with EMSGSIZE too. */
static constexpr size_t DATAGRAM_MAXIMUM = 65535;
/* The most segments one message may gather and the most messages one sendmmsg may carry, the
 * kernel's own limit (UIO_MAXIOV): a larger sendmmsg count is cut down to it. */
static constexpr size_t SEGMENT_MAXIMUM = 1024;
static constexpr unsigned int BATCH_MAXIMUM = 1024;
/* How long a blocking socket that cannot take a datagram is waited on, so that one slow socket
 * cannot stall every other notification the supervisor has to answer. */
static constexpr int SEND_WAIT_MS = 1000;

/* The flags the supervisor passes on to its own send: do not block, do not signal, the
 * corking and confirmation hints, and do not route. Every other bit is one it cannot honour on
 * the command's behalf: MSG_ZEROCOPY would pin the supervisor's copy buffer, which it reuses. */
static constexpr unsigned int PASSED_SEND_FLAGS =
    MSG_DONTWAIT | MSG_NOSIGNAL | MSG_MORE | MSG_CONFIRM | MSG_DONTROUTE;

/* The result of a send that the command no longer waits for, because its notification was
 * cancelled. Nothing is answered for it. No errno is this large. */
static constexpr int64_t NOTIFICATION_GONE = INT64_MIN;

/* Whether the guard allows a socket that was never bound to be bound by the kernel to a source
 * port of its own choosing, which a connect or a send on it does. */
static bool ephemeral_udp_bind_allowed = false;

/* The supervisor's buffers, shared by every send because it serves one notification at a time:
 * the datagram being gathered and the segments that describe it. */
static unsigned char datagram_buffer[DATAGRAM_MAXIMUM];
static struct iovec segment_vector[SEGMENT_MAXIMUM];

/* What a send needs to know about the notification it serves. */
struct send_context {
    int notify_descriptor;
    const struct seccomp_notif *request;
};

void configure_ephemeral_udp_bind(bool allowed) {
    ephemeral_udp_bind_allowed = allowed;
}

/* Whether the notification is still the call the supervisor read: false once the command was
 * interrupted or has gone, when what was read no longer belongs to a pending call. */
static bool notification_alive(const struct send_context *context) {
    return ioctl(context->notify_descriptor, SECCOMP_IOCTL_NOTIF_ID_VALID, &context->request->id) == 0;
}

/* Whether the socket, which the supervisor holds, may take a connect or a send: it has a source
 * port already, or the policy grants the kernel to choose one. The
 * port is read from the supervisor's own descriptor, which is the command's socket, so nothing
 * the command can rewrite is read. A socket whose address the kernel cannot report, or that is
 * neither IPv4 nor IPv6, is refused. */
static bool source_port_permitted(int held_descriptor) {
    int family;
    uint16_t port;
    if (!socket_local_port(held_descriptor, &family, &port)) {
        return false;
    }
    if (family != AF_INET && family != AF_INET6) {
        return false;
    }
    return port != 0 || ephemeral_udp_bind_allowed;
}

/* Whether the socket would block the command on a send that cannot go at once, which is the
 * descriptor's own mode and is shared with the command's descriptor. A mode the kernel cannot
 * report counts as non-blocking, so the supervisor never waits on it. */
static bool descriptor_blocks(int descriptor) {
    int mode = fcntl(descriptor, F_GETFL);
    return mode >= 0 && !(mode & O_NONBLOCK);
}

/* One non-blocking send on the supervisor's descriptor, repeated while the kernel interrupts it.
 * Answers the byte count the kernel reported, or a negative errno. */
static int64_t send_without_blocking(int descriptor, const void *data, size_t length, int flags,
                                     const struct sockaddr *destination, socklen_t name_length) {
    for (;;) {
        ssize_t sent = sendto(descriptor, data, length, flags, destination, name_length);
        if (sent >= 0) {
            return sent;
        }
        if (errno != EINTR) {
            return -errno;
        }
    }
}

/* Sends one datagram on the supervisor's descriptor and returns the byte count the kernel
 * reported, or a negative errno. The send never blocks the supervisor beyond SEND_WAIT_MS: a
 * socket the command left blocking is waited on once, for room, and then sent on once more, whose
 * answer stands even when it is EAGAIN again. A name of length zero sends to the peer the socket
 * is connected to. */
static int64_t send_datagram(int descriptor, const void *data, size_t length, unsigned int flags,
                             const struct sockaddr_storage *name, socklen_t name_length) {
    bool may_wait = !(flags & MSG_DONTWAIT) && descriptor_blocks(descriptor);
    const struct sockaddr *destination = name_length == 0 ? nullptr : (const struct sockaddr *)name;
    int effective = (int)(flags | MSG_NOSIGNAL | MSG_DONTWAIT);
    int64_t result = send_without_blocking(descriptor, data, length, effective, destination, name_length);
    if (result != -EAGAIN || !may_wait) {
        return result;
    }
    struct pollfd waiting = { .fd = descriptor, .events = POLLOUT, .revents = 0 };
    if (poll(&waiting, 1, SEND_WAIT_MS) <= 0) {
        return -EAGAIN;
    }
    return send_without_blocking(descriptor, data, length, effective, destination, name_length);
}

/* Reports a datagram refused because its socket is bound to no port the policy lets the kernel
 * choose, as a send to the destination the command named. A send that named none has no object to
 * report, and stays a --verbose line. */
static void report_refused_unbound_send(const struct sockaddr_storage *name, socklen_t name_length) {
    if (name_length == 0) {
        return;
    }
    struct destination where = read_destination(name);
    report_refused_endpoint("send to", &where, true);
}

/* Reads the destination the command named, or leaves no name at all when it named none: a null
 * pointer or a length of zero, which the kernel also takes for a send on a connected socket.
 * Answers 0, or a negative errno: EINVAL for a length no socket address has, and EACCES where the
 * memory cannot be read, which the guard refuses rather than guess. */
static int read_name(const struct send_context *context, uintptr_t pointer, socklen_t claimed,
                     struct sockaddr_storage *name, socklen_t *name_length) {
    *name_length = 0;
    if (pointer == 0 || claimed == 0) {
        return 0;
    }
    if (claimed > sizeof(*name)) {
        return -EINVAL;
    }
    *name_length = read_peer_address(context->request->pid, pointer, claimed, name);
    return *name_length == 0 ? -EACCES : 0;
}

/* Whether the allow-list names the destination, as a datagram: a family other than IPv4 and
 * IPv6, which this guard does not carry, is refused, and so is an address no UDP rule names. */
static bool destination_permitted(const struct sockaddr_storage *name) {
    struct destination where = read_destination(name);
    if (where.family != AF_INET && where.family != AF_INET6) {
        log_verbose("refusing a datagram of family %d, which this guard does not carry", where.family);
        return false;
    }
    if (!connection_permitted(where.family, where.address, where.port, true)) {
        char endpoint[ENDPOINT_TEXT_SIZE];
        format_endpoint(&where, endpoint, sizeof(endpoint));
        log_verbose("refusing a datagram to a destination the allow-list does not name: %s", endpoint);
        report_refused_endpoint("send to", &where, true);
        return false;
    }
    return true;
}

/* Copies the segments of one message out of the command into the buffer, one after the other.
 * Answers 0 and the byte count, EMSGSIZE for a message beyond DATAGRAM_MAXIMUM, or EACCES where
 * the memory cannot be read. */
static int gather(const struct send_context *context, const struct iovec *segments, size_t count,
                  size_t *total) {
    *total = 0;
    for (size_t index = 0; index < count; index++) {
        size_t length = segments[index].iov_len;
        if (length > DATAGRAM_MAXIMUM - *total) {
            return -EMSGSIZE;
        }
        if (length == 0) {
            continue;
        }
        if (!read_child_bytes(context->request->pid, (uintptr_t)segments[index].iov_base,
                              datagram_buffer + *total, length)) {
            return -EACCES;
        }
        *total += length;
    }
    return 0;
}

/* Judges and sends one message the command described, from copies the supervisor made. Answers
 * the bytes sent, a negative errno, or NOTIFICATION_GONE when the command is no longer waiting.
 * The order matters: the destination is read and judged before the data is, so a refused
 * destination costs nothing, and the notification is checked after each read, before anything
 * leaves the machine. The source port is judged whether or not a destination was named, because
 * the kernel binds an unbound socket before it notices there is nowhere to send to, so even a
 * send that fails would leave the socket holding a port nobody granted. */
static int64_t deliver(const struct send_context *context, int held, uintptr_t name_pointer,
                       socklen_t name_claimed, const struct iovec *segments, size_t count,
                       unsigned int flags) {
    struct sockaddr_storage name;
    memset(&name, 0, sizeof(name));
    socklen_t name_length;
    int status = read_name(context, name_pointer, name_claimed, &name, &name_length);
    if (!notification_alive(context)) {
        return NOTIFICATION_GONE;
    }
    if (status < 0) {
        return status;
    }
    if (name_length != 0 && !destination_permitted(&name)) {
        return -EACCES;
    }
    if (!source_port_permitted(held)) {
        log_verbose("refusing a datagram on a socket bound to no port, which the policy does "
                    "not allow the kernel to bind");
        report_refused_unbound_send(&name, name_length);
        return -EACCES;
    }
    size_t total;
    status = gather(context, segments, count, &total);
    if (!notification_alive(context)) {
        return NOTIFICATION_GONE;
    }
    if (status < 0) {
        return status;
    }
    return send_datagram(held, datagram_buffer, total, flags, &name, name_length);
}

/* Refuses the flags the supervisor cannot honour on the command's behalf: MSG_FASTOPEN with
 * EACCES, because it carries a destination past connect(), and any other flag it does not pass on
 * with EOPNOTSUPP. Answers 0 when every flag is one it passes. */
static int refuse_unsupported_flags(unsigned int flags) {
    if (flags & MSG_FASTOPEN) {
        log_verbose("refusing a send with MSG_FASTOPEN, which opens a connection past connect()");
        return -EACCES;
    }
    if (flags & ~PASSED_SEND_FLAGS) {
        log_verbose("refusing a send with flags the guard cannot pass on: %#x", flags);
        return -EOPNOTSUPP;
    }
    return 0;
}

/* The supervisor's descriptor for the datagram socket the command's descriptor names, or a
 * negative errno. Only a socket the guard created as a datagram socket and still holds has one,
 * so a send on an inherited, received, evicted or stream socket is refused: the supervisor cannot
 * send on it, and letting the call run in the command is the race this module closes. */
static int held_datagram_descriptor(const struct send_context *context) {
    int target = (int)context->request->data.args[SEND_ARGUMENT_DESCRIPTOR];
    uint64_t inode = fd_socket_inode((pid_t)context->request->pid, target);
    if (lookup_socket_type(inode) != FD_TYPE_DGRAM) {
        log_verbose("refusing a send on a socket that is not a datagram socket this guard created, fd %d",
                    target);
        return -EACCES;
    }
    int held = use_held_socket(inode);
    if (held < 0) {
        log_verbose("refusing a send on a socket this guard no longer holds, fd %d", target);
        return -EACCES;
    }
    return held;
}

/* Sends the message a msghdr describes: refuses ancillary data, which can steer a datagram
 * (IP_PKTINFO, IP_RETOPTS, a routing header), and a segment count beyond the kernel's, then
 * reads the segments and delivers. */
static int64_t deliver_header(const struct send_context *context, int held,
                              const struct msghdr *header, unsigned int flags) {
    if (header->msg_controllen != 0) {
        log_verbose("refusing a send with ancillary data");
        return -EACCES;
    }
    if (header->msg_iovlen > SEGMENT_MAXIMUM) {
        return -EMSGSIZE;
    }
    size_t count = header->msg_iovlen;
    if (count != 0 && !read_child_bytes(context->request->pid, (uintptr_t)header->msg_iov,
                                        segment_vector, count * sizeof(struct iovec))) {
        return notification_alive(context) ? -EACCES : NOTIFICATION_GONE;
    }
    return deliver(context, held, (uintptr_t)header->msg_name, header->msg_namelen,
                   segment_vector, count, flags);
}

/* One trapped sendto. A call with no destination never arrives here from the filter, which lets
 * it through, but one that does is a send on the connected socket and is handled as such. */
static int64_t service_sendto(const struct send_context *context) {
    const unsigned long long *arguments = context->request->data.args;
    unsigned int flags = (unsigned int)arguments[SENDTO_ARGUMENT_FLAGS];
    int status = refuse_unsupported_flags(flags);
    if (status < 0) {
        return status;
    }
    int held = held_datagram_descriptor(context);
    if (held < 0) {
        return held;
    }
    struct iovec segment = { .iov_base = (void *)(uintptr_t)arguments[SENDTO_ARGUMENT_BUFFER],
                             .iov_len = (size_t)arguments[SENDTO_ARGUMENT_LENGTH] };
    return deliver(context, held, (uintptr_t)arguments[SENDTO_ARGUMENT_ADDRESS],
                   (socklen_t)arguments[SENDTO_ARGUMENT_ADDRESS_LENGTH], &segment, 1, flags);
}

/* One trapped sendmsg: reads the header out of the command and delivers it. */
static int64_t service_sendmsg(const struct send_context *context) {
    const unsigned long long *arguments = context->request->data.args;
    unsigned int flags = (unsigned int)arguments[SENDMSG_ARGUMENT_FLAGS];
    int status = refuse_unsupported_flags(flags);
    if (status < 0) {
        return status;
    }
    int held = held_datagram_descriptor(context);
    if (held < 0) {
        return held;
    }
    struct msghdr header;
    memset(&header, 0, sizeof(header));
    bool read_ok = read_child_bytes(context->request->pid,
                                    (uintptr_t)arguments[SENDMSG_ARGUMENT_HEADER], &header,
                                    sizeof(header));
    if (!notification_alive(context)) {
        return NOTIFICATION_GONE;
    }
    if (!read_ok) {
        return -EACCES;
    }
    return deliver_header(context, held, &header, flags);
}

/* Writes the length of one sent message back into the msg_len field of its entry in the
 * command's vector, as the kernel does, and answers whether all of it was written. The datagram has
 * gone either way; what a failed write changes is how many messages the command is told went. */
static bool write_back_length(const struct send_context *context, uintptr_t entry_pointer,
                              unsigned int length) {
    struct iovec local = { .iov_base = &length, .iov_len = sizeof(length) };
    struct iovec remote = { .iov_base = (void *)(entry_pointer + offsetof(struct mmsghdr, msg_len)),
                            .iov_len = sizeof(length) };
    ssize_t written = process_vm_writev(context->request->pid, &local, 1, &remote, 1, 0);
    if (written != (ssize_t)sizeof(length)) {
        log_verbose("could not write a message length back into the command");
        return false;
    }
    return true;
}

/* One trapped sendmmsg: sends the messages in order, each judged on its own, and answers with how
 * many went, as the kernel does. A message that fails after another went ends the batch there
 * and the count stands; one that fails first is the error. A message whose length cannot be
 * written back ends the batch too, and is not counted, as in the kernel, which answers EFAULT
 * when it is the first. */
static int64_t service_sendmmsg(const struct send_context *context) {
    const unsigned long long *arguments = context->request->data.args;
    unsigned int flags = (unsigned int)arguments[SENDMMSG_ARGUMENT_FLAGS];
    int status = refuse_unsupported_flags(flags);
    if (status < 0) {
        return status;
    }
    int held = held_datagram_descriptor(context);
    if (held < 0) {
        return held;
    }
    uintptr_t vector = (uintptr_t)arguments[SENDMMSG_ARGUMENT_VECTOR];
    unsigned int count = (unsigned int)arguments[SENDMMSG_ARGUMENT_COUNT];
    if (count > BATCH_MAXIMUM) {
        count = BATCH_MAXIMUM;
    }
    unsigned int sent = 0;
    for (; sent < count; sent++) {
        struct mmsghdr entry;
        memset(&entry, 0, sizeof(entry));
        uintptr_t entry_pointer = vector + (uintptr_t)sent * sizeof(struct mmsghdr);
        bool read_ok = read_child_bytes(context->request->pid, entry_pointer, &entry, sizeof(entry));
        if (!notification_alive(context)) {
            return NOTIFICATION_GONE;
        }
        int64_t result = read_ok ? deliver_header(context, held, &entry.msg_hdr, flags) : -EACCES;
        if (result == NOTIFICATION_GONE) {
            return NOTIFICATION_GONE;
        }
        if (result < 0) {
            return sent == 0 ? result : (int64_t)sent;
        }
        if (!write_back_length(context, entry_pointer, (unsigned int)result)) {
            return sent == 0 ? -EFAULT : (int64_t)sent;
        }
    }
    return sent;
}

void service_datagram_send(int notify_descriptor, struct seccomp_notif *request,
                           struct seccomp_notif_resp *response) {
    struct send_context context = { .notify_descriptor = notify_descriptor, .request = request };
    int64_t result;
    if (request->data.nr == __NR_sendto) {
        result = service_sendto(&context);
    } else if (request->data.nr == __NR_sendmsg) {
        result = service_sendmsg(&context);
    } else {
        result = service_sendmmsg(&context);
    }
    if (result == NOTIFICATION_GONE) {
        return;
    }
    if (result < 0) {
        answer(notify_descriptor, response, request->id, 0, (__s32)result);
        return;
    }
    answer(notify_descriptor, response, request->id, result, 0);
}

void service_datagram_connect(int notify_descriptor, struct seccomp_notif_resp *response,
                              __u64 id, uint64_t inode, const struct sockaddr_storage *address,
                              socklen_t length) {
    int held = use_held_socket(inode);
    if (held < 0) {
        log_verbose("refusing a datagram connect on a socket this guard no longer holds");
        answer(notify_descriptor, response, id, 0, -EACCES);
        return;
    }
    if (!source_port_permitted(held)) {
        log_verbose("refusing a datagram connect on a socket bound to no port, which the policy "
                    "does not allow the kernel to bind");
        report_refused_unbound_send(address, length);
        answer(notify_descriptor, response, id, 0, -EACCES);
        return;
    }
    if (connect(held, (const struct sockaddr *)address, length) != 0) {
        answer(notify_descriptor, response, id, 0, -errno);
        return;
    }
    answer(notify_descriptor, response, id, 0, 0);
}

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
void ephemeral_udp_bind_reset_for_tests(void) {
    ephemeral_udp_bind_allowed = false;
}
#endif
