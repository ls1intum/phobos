#define _GNU_SOURCE
#include "phobos-seccomp-networksystem-socket-types.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* The loopback device every network namespace has, which a listener is pinned to. */
static const char LOOPBACK_DEVICE[] = "lo";

/* Long enough for "/proc/<pid>/fd/<descriptor>" and for the "socket:[<inode>]" it points to. */
static constexpr size_t PROC_FD_LINK_LENGTH = 64;

/* One remembered socket: its inode and its type. */
struct socket_type_entry {
    uint64_t inode;
    uint8_t type;
};
static struct socket_type_entry socket_type_table[SOCKET_TYPE_TABLE_SIZE];

void record_socket_type(uint64_t inode, uint8_t type) {
    if (inode == 0) {
        return;
    }
    size_t start = (size_t)(inode % SOCKET_TYPE_TABLE_SIZE);
    for (size_t probe = 0; probe < SOCKET_TYPE_TABLE_SIZE; probe++) {
        size_t slot = (start + probe) % SOCKET_TYPE_TABLE_SIZE;
        if (socket_type_table[slot].inode == inode || socket_type_table[slot].inode == 0) {
            socket_type_table[slot].inode = inode;
            socket_type_table[slot].type = type;
            return;
        }
    }
    socket_type_table[start].inode = inode;
    socket_type_table[start].type = type;
}

uint8_t lookup_socket_type(uint64_t inode) {
    if (inode == 0) {
        return FD_TYPE_UNKNOWN;
    }
    size_t start = (size_t)(inode % SOCKET_TYPE_TABLE_SIZE);
    for (size_t probe = 0; probe < SOCKET_TYPE_TABLE_SIZE; probe++) {
        size_t slot = (start + probe) % SOCKET_TYPE_TABLE_SIZE;
        if (socket_type_table[slot].inode == inode) {
            return socket_type_table[slot].type;
        }
        if (socket_type_table[slot].inode == 0) {
            return FD_TYPE_UNKNOWN;
        }
    }
    return FD_TYPE_UNKNOWN;
}

uint64_t fd_socket_inode(pid_t owner_pid, int descriptor) {
    char link_path[PROC_FD_LINK_LENGTH];
    char target[PROC_FD_LINK_LENGTH];
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%d", (int)owner_pid, descriptor);
    ssize_t length = readlink(link_path, target, sizeof(target) - 1);
    if (length < 0) {
        return 0;
    }
    target[length] = '\0';
    unsigned long long inode = 0;
    if (sscanf(target, "socket:[%llu]", &inode) != 1) {
        return 0;
    }
    return (uint64_t)inode;
}

bool socket_local_port(int descriptor, int *family, uint16_t *port) {
    struct sockaddr_storage bound;
    memset(&bound, 0, sizeof(bound));
    socklen_t length = sizeof(bound);
    if (getsockname(descriptor, (struct sockaddr *)&bound, &length) != 0) {
        return false;
    }
    *port = 0;
    if (bound.ss_family == AF_INET) {
        *port = ntohs(((const struct sockaddr_in *)&bound)->sin_port);
    } else if (bound.ss_family == AF_INET6) {
        *port = ntohs(((const struct sockaddr_in6 *)&bound)->sin6_port);
    }
    *family = bound.ss_family;
    return true;
}

/* Whether an IPv6 address can only be bound together with a device, as the kernel reads it: a
 * link-local unicast address, and a link-local or interface-local multicast one. */
static bool address_needs_scope(const struct in6_addr *address) {
    return IN6_IS_ADDR_LINKLOCAL(address) || IN6_IS_ADDR_MC_LINKLOCAL(address)
           || IN6_IS_ADDR_MC_NODELOCAL(address);
}

/* Binds a socket that has no port to the address it holds and a port the kernel picks, with the
 * option that would leave the port out cleared, and answers whether it then has a port. */
static bool bind_kernel_port(int descriptor) {
    struct sockaddr_storage local;
    int keep_port = 0;
    int family;
    uint16_t port = 0;
    memset(&local, 0, sizeof(local));
    socklen_t length = sizeof(local);
    if (getsockname(descriptor, (struct sockaddr *)&local, &length) != 0
        || setsockopt(descriptor, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &keep_port, sizeof(keep_port)) != 0) {
        return false;
    }
    if (local.ss_family == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&local;
        if (address_needs_scope(&v6->sin6_addr)) {
            return false;
        }
        v6->sin6_scope_id = 0;
    }
    if (bind(descriptor, (const struct sockaddr *)&local, length) != 0) {
        return false;
    }
    return socket_local_port(descriptor, &family, &port) && port != 0;
}

bool pin_listener_to_loopback(int descriptor) {
    char device[IFNAMSIZ];
    int family;
    uint16_t port = 0;
    memset(device, 0, sizeof(device));
    socklen_t device_length = sizeof(device);
    if (!socket_local_port(descriptor, &family, &port)) {
        return false;
    }
    if (family != AF_INET && family != AF_INET6) {
        return true;
    }
    if (port == 0 && !bind_kernel_port(descriptor)) {
        return false;
    }
    if (setsockopt(descriptor, SOL_SOCKET, SO_BINDTODEVICE, LOOPBACK_DEVICE, sizeof(LOOPBACK_DEVICE)) != 0
        || getsockopt(descriptor, SOL_SOCKET, SO_BINDTODEVICE, device, &device_length) != 0) {
        return false;
    }
    return strcmp(device, LOOPBACK_DEVICE) == 0;
}

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
void socket_types_reset_for_tests(void) {
    memset(socket_type_table, 0, sizeof(socket_type_table));
}
#endif
