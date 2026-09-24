#define _GNU_SOURCE
#include "phobos-seccomp-networksystem-socket-types.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
void socket_types_reset_for_tests(void) {
    memset(socket_type_table, 0, sizeof(socket_type_table));
}
#endif
