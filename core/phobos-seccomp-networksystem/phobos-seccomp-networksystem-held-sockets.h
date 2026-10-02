/*
 * The sockets the supervisor created for the command and still holds, and the ones it has
 * already let listen, so that every listen() is run by the supervisor on a socket it made.
 */
#ifndef PHOBOS_CONNECT_GUARD_HELD_SOCKETS_H
#define PHOBOS_CONNECT_GUARD_HELD_SOCKETS_H

#include <stddef.h>
#include <stdint.h>

/* How many listen-capable sockets the supervisor holds at once. A socket the supervisor holds
 * is one descriptor of its own, so this stays well under the descriptor limit a container
 * starts a process with, 1024 in the narrowest ordinary case. When the table is full the
 * oldest entry is closed to make room, and a socket evicted that way can never listen: the
 * command's listen() on it is refused, which fails closed. */
static constexpr size_t HELD_SOCKET_CAPACITY = 512;

/* How many sockets the supervisor remembers having let listen. It keeps no descriptor for
 * them, only the inode, in a ring that overwrites its oldest entry. */
static constexpr size_t LISTENED_SOCKET_CAPACITY = 4096;

/* Takes ownership of a descriptor the supervisor created for the command, keyed by the socket's
 * inode. The descriptor refers to the same open file description the command's own descriptor
 * does, because the kernel installed that one from this one, so anything the supervisor does on
 * it is done to the command's socket. A new socket also starts un-listened, so the inode is
 * removed from the listened set in case it was recycled. An existing entry for the same inode is
 * closed and replaced. When the table is full the oldest entry is closed first. Inode zero names
 * no socket, so the descriptor is closed and nothing is held. */
void hold_socket(uint64_t inode, int descriptor);

/* The supervisor's descriptor for the socket with this inode, or -1 when none is held: the
 * socket was never created by the supervisor (an inherited descriptor, an accepted socket), was
 * evicted, was released after it listened or after a connect replaced it. The descriptor stays
 * held and owned by the table. */
int held_socket_descriptor(uint64_t inode);

/* Closes the supervisor's descriptor for this inode and forgets it. Nothing happens when none is
 * held. Releasing a socket after it listens, rather than keeping it, is what lets the port be
 * free again when the command closes its own descriptor. */
void release_held_socket(uint64_t inode);

/* Remembers that the supervisor has let the socket with this inode listen. */
void remember_listened(uint64_t inode);

/* Answers whether the supervisor has let the socket with this inode listen. */
bool was_listened(uint64_t inode);

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
/* Closes nothing and forgets everything, so each test case starts from empty tables. The
 * descriptors a case hands in are stand-ins, so they are not closed here. */
void held_sockets_reset_for_tests(void);

/* How many sockets are held now. */
size_t held_sockets_count_for_tests(void);
#endif

#endif
