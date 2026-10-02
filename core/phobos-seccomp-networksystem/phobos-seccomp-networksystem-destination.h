/*
 * A destination the sandboxed command named, read out of its memory: the socket address
 * behind a pointer, and the family, address and port the allow-list is asked about.
 */
#ifndef PHOBOS_CONNECT_GUARD_DESTINATION_H
#define PHOBOS_CONNECT_GUARD_DESTINATION_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

/* The family, address pointer and port of a destination read from the command. */
struct destination {
    int family;
    const void *address;
    uint16_t port;
};

/* The destination a socket address names; any family but IPv4 and IPv6 leaves no address. */
struct destination read_destination(const struct sockaddr_storage *storage);

/* Read a fixed-size structure out of the command's memory. Returns whether the whole of it
 * was read; a short or failed read leaves the destination partly written and answers false,
 * so the caller refuses rather than act on half a structure. */
bool read_child_bytes(pid_t command_pid, uintptr_t remote_pointer, void *out, size_t size);

/* Read the peer address out of the command's memory. Returns the length read, or 0
 * if it could not be read or is too short to carry a family. */
socklen_t read_peer_address(pid_t command_pid, uintptr_t address_pointer,
                            socklen_t claimed_length, struct sockaddr_storage *out);

#endif
