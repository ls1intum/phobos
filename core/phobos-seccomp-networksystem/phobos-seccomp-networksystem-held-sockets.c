#define _GNU_SOURCE
#include "phobos-seccomp-networksystem-held-sockets.h"

#include <stdbool.h>
#include <string.h>
#include <unistd.h>

/* One held socket: its inode, the supervisor's descriptor, and when it last arrived or was used,
 * so that the least recently used can be found. An inode of zero marks a free slot. */
struct held_entry {
    uint64_t inode;
    int descriptor;
    uint64_t age;
};

static struct held_entry held_entries[HELD_SOCKET_CAPACITY];
static uint64_t next_age = 1;

static uint64_t listened_inodes[LISTENED_SOCKET_CAPACITY];
static size_t listened_next = 0;

static struct held_entry *find_held(uint64_t inode) {
    for (size_t slot = 0; slot < HELD_SOCKET_CAPACITY; slot++) {
        if (held_entries[slot].inode == inode) {
            return &held_entries[slot];
        }
    }
    return nullptr;
}

/* The slot to fill: a free one, or, when none is, the least recently used entry, closed and
 * emptied. */
static struct held_entry *slot_for_new_entry(void) {
    struct held_entry *oldest = &held_entries[0];
    for (size_t slot = 0; slot < HELD_SOCKET_CAPACITY; slot++) {
        if (held_entries[slot].inode == 0) {
            return &held_entries[slot];
        }
        if (held_entries[slot].age < oldest->age) {
            oldest = &held_entries[slot];
        }
    }
    close(oldest->descriptor);
    memset(oldest, 0, sizeof(*oldest));
    return oldest;
}

static void forget_listened(uint64_t inode) {
    for (size_t slot = 0; slot < LISTENED_SOCKET_CAPACITY; slot++) {
        if (listened_inodes[slot] == inode) {
            listened_inodes[slot] = 0;
        }
    }
}

void hold_socket(uint64_t inode, int descriptor) {
    if (inode == 0) {
        close(descriptor);
        return;
    }
    forget_listened(inode);
    release_held_socket(inode);
    struct held_entry *entry = slot_for_new_entry();
    entry->inode = inode;
    entry->descriptor = descriptor;
    entry->age = next_age++;
}

int held_socket_descriptor(uint64_t inode) {
    struct held_entry *entry = inode == 0 ? nullptr : find_held(inode);
    return entry == nullptr ? -1 : entry->descriptor;
}

int use_held_socket(uint64_t inode) {
    struct held_entry *entry = inode == 0 ? nullptr : find_held(inode);
    if (entry == nullptr) {
        return -1;
    }
    entry->age = next_age++;
    return entry->descriptor;
}

void release_held_socket(uint64_t inode) {
    struct held_entry *entry = inode == 0 ? nullptr : find_held(inode);
    if (entry == nullptr) {
        return;
    }
    close(entry->descriptor);
    memset(entry, 0, sizeof(*entry));
}

void remember_listened(uint64_t inode) {
    if (inode == 0) {
        return;
    }
    listened_inodes[listened_next] = inode;
    listened_next = (listened_next + 1) % LISTENED_SOCKET_CAPACITY;
}

bool was_listened(uint64_t inode) {
    if (inode == 0) {
        return false;
    }
    for (size_t slot = 0; slot < LISTENED_SOCKET_CAPACITY; slot++) {
        if (listened_inodes[slot] == inode) {
            return true;
        }
    }
    return false;
}

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
void held_sockets_reset_for_tests(void) {
    memset(held_entries, 0, sizeof(held_entries));
    memset(listened_inodes, 0, sizeof(listened_inodes));
    next_age = 1;
    listened_next = 0;
}

size_t held_sockets_count_for_tests(void) {
    size_t count = 0;
    for (size_t slot = 0; slot < HELD_SOCKET_CAPACITY; slot++) {
        if (held_entries[slot].inode != 0) {
            count++;
        }
    }
    return count;
}
#endif
