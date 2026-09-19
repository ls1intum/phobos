#define _GNU_SOURCE
#include "phobos-connect-guard-destination.h"

#include <netinet/in.h>
#include <sys/uio.h>

struct destination read_destination(const struct sockaddr_storage *storage) {
    struct destination where = { .family = storage->ss_family, .address = nullptr, .port = 0 };
    if (storage->ss_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)storage;
        where.address = &v4->sin_addr;
        where.port = ntohs(v4->sin_port);
    } else if (storage->ss_family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)storage;
        where.address = &v6->sin6_addr;
        where.port = ntohs(v6->sin6_port);
    }
    return where;
}

bool read_child_bytes(pid_t command_pid, uintptr_t remote_pointer, void *out, size_t size) {
    struct iovec local = { .iov_base = out, .iov_len = size };
    struct iovec remote = { .iov_base = (void *)remote_pointer, .iov_len = size };
    ssize_t read_count = process_vm_readv(command_pid, &local, 1, &remote, 1, 0);
    return read_count >= 0 && (size_t)read_count == size;
}

socklen_t read_peer_address(pid_t command_pid, uintptr_t address_pointer,
                            socklen_t claimed_length, struct sockaddr_storage *out) {
    socklen_t length = claimed_length;
    if (length > sizeof(*out)) {
        length = sizeof(*out);
    }
    if (length < sizeof(sa_family_t)) {
        return 0;
    }
    struct iovec local = { .iov_base = out, .iov_len = length };
    struct iovec remote = { .iov_base = (void *)address_pointer, .iov_len = length };
    ssize_t read_count = process_vm_readv(command_pid, &local, 1, &remote, 1, 0);
    if (read_count < 0 || (socklen_t)read_count != length) {
        return 0;
    }
    return length;
}
