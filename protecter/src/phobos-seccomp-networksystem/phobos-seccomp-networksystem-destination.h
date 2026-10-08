/*
 * A destination the sandboxed command named, read out of its memory: the socket address
 * behind a pointer, and the family, address and port the allow-list is asked about.
 */
#ifndef PHOBOS_CONNECT_GUARD_DESTINATION_H
#define PHOBOS_CONNECT_GUARD_DESTINATION_H

#include <netinet/in.h>
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

/* Room for the longest text format_endpoint writes, its terminating NUL included: an IPv6
 * address in brackets, a colon and a five-digit port. */
static constexpr size_t ENDPOINT_TEXT_SIZE = INET6_ADDRSTRLEN + sizeof("[]:65535");

/* The destination a socket address names; any family but IPv4 and IPv6 leaves no address. */
struct destination read_destination(const struct sockaddr_storage *storage);

/* Writes a destination as text for a log line: "203.0.113.7:443" for IPv4, "[2001:db8::1]:443"
 * for IPv6 (an IPv4-mapped address as "[::ffff:203.0.113.7]:443", so the brackets keep the port
 * separator unambiguous), and "family <n>" for any other family or a destination without an
 * address. The text comes only from inet_ntop and the numeric port and family, never from a byte
 * of the command's memory copied verbatim, so it needs no escaping. It is always NUL-terminated
 * when size is not zero, cut short where size is too small, and the length written is returned. */
size_t format_endpoint(const struct destination *where, char *text, size_t size);

/* Read a fixed-size structure out of the command's memory. Returns whether the whole of it
 * was read; a short or failed read leaves the destination partly written and answers false,
 * so the caller refuses rather than act on half a structure. */
bool read_child_bytes(pid_t command_pid, uintptr_t remote_pointer, void *out, size_t size);

/* Read the peer address out of the command's memory. Returns the length read, or 0
 * if it could not be read or is too short to carry a family. */
socklen_t read_peer_address(pid_t command_pid, uintptr_t address_pointer,
                            socklen_t claimed_length, struct sockaddr_storage *out);

#endif
