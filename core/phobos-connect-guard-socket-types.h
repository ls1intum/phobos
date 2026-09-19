/*
 * The type of every socket the sandboxed lineage opened, remembered by inode, so a connect
 * can tell a stream socket from a datagram socket.
 */
#ifndef PHOBOS_CONNECT_GUARD_SOCKET_TYPES_H
#define PHOBOS_CONNECT_GUARD_SOCKET_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* The socket type the guard tracks, so that a connect can tell a stream socket (connected here
 * and injected, a boundary a raw syscall cannot step around) from a datagram socket (whose
 * connect only sets a default peer and is let through after the peer is checked). The guard
 * governs a whole forking lineage through one listener, so a child descriptor number is not
 * unique across it: two processes each hold their own descriptor N. A socket inode is unique
 * among the live sockets of the system, so the type is keyed by inode instead. The table is
 * open-addressed; an entry is overwritten when an inode is reused, because every socket()
 * re-records it, and one evicted under pressure reads back as unknown, which the connect path
 * then handles best-effort. */
static constexpr size_t SOCKET_TYPE_TABLE_SIZE = 65536;
static constexpr uint8_t FD_TYPE_UNKNOWN = 0;
static constexpr uint8_t FD_TYPE_STREAM = 1;
static constexpr uint8_t FD_TYPE_DGRAM = 2;

/* Records the type of a socket by its inode, overwriting any earlier entry for that inode. A
 * full table evicts the entry at the hash slot, which then reads back as unknown. Inode zero is
 * not a socket and is ignored. */
void record_socket_type(uint64_t inode, uint8_t type);

/* Answers the tracked type of a socket by its inode, or UNKNOWN for one the guard never
 * recorded or one evicted from a full table. */
uint8_t lookup_socket_type(uint64_t inode);

/* The socket inode behind a descriptor of the process named, read from /proc. It serves two
 * callers: the supervisor's own fresh socket at socket() time, to record its type, and a child
 * descriptor parked on a trapped connect, to recall it. Answers 0 when the descriptor is not a
 * socket or /proc cannot answer; only a live socket yields an inode, so a descriptor since
 * reused for something that is not a socket reads back 0 and is treated as untracked, which the
 * connect path handles best-effort rather than injecting a socket over it. */
uint64_t fd_socket_inode(pid_t owner_pid, int descriptor);

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
/* Forgets every recorded socket, so each test case starts from an empty table. */
void socket_types_reset_for_tests(void);
#endif

#endif
