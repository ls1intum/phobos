/*
 * The Landlock ruleset: the kernel object that says what a process may still
 * reach, and the operations on it.
 *
 * This is the module that will become a class: a ruleset is a descriptor plus
 * the operations that add rules to it and finally apply it. The three
 * attribute structures below stay raw data, because their layout is fixed by
 * the kernel and they exist only to be handed to a system call.
 *
 * Names are spelled out here, while the kernel abbreviates them. The mapping,
 * so that the kernel documentation stays searchable from this file:
 *
 *   here                                 kernel
 *   LANDLOCK_ACCESS_FILESYSTEM_*         LANDLOCK_ACCESS_FS_*
 *   LANDLOCK_ACCESS_NETWORK_*            LANDLOCK_ACCESS_NET_*
 *   ..._READ_DIRECTORY, ..._MAKE_SOCKET  ..._READ_DIR, ..._MAKE_SOCK
 *   struct landlock_*_attributes         struct landlock_*_attr
 *   SYSCALL_NUMBER_LANDLOCK_*            __NR_landlock_*
 *   Landlock version                     Landlock ABI version
 *
 * TCP keeps its abbreviation, because that is the name of the protocol.
 */
#ifndef PHOBOS_LANDLOCK_RULESET_H
#define PHOBOS_LANDLOCK_RULESET_H

#include <stddef.h>
#include <stdint.h>

struct path_rule;

/* Landlock has no wrapper in the C library, so the numbers are given here.
 * They are the same on every architecture that supports Landlock. */
#ifdef __NR_landlock_create_ruleset
#define SYSCALL_NUMBER_LANDLOCK_CREATE_RULESET __NR_landlock_create_ruleset
#else
#define SYSCALL_NUMBER_LANDLOCK_CREATE_RULESET 444
#endif
#ifdef __NR_landlock_add_rule
#define SYSCALL_NUMBER_LANDLOCK_ADD_RULE __NR_landlock_add_rule
#else
#define SYSCALL_NUMBER_LANDLOCK_ADD_RULE 445
#endif
#ifdef __NR_landlock_restrict_self
#define SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF __NR_landlock_restrict_self
#else
#define SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF 446
#endif

#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#define LANDLOCK_RULE_PATH_BENEATH 1
#define LANDLOCK_RULE_NETWORK_PORT 2

/* Filesystem access rights, available since Landlock version 1 unless noted. */
#define LANDLOCK_ACCESS_FILESYSTEM_EXECUTE (1ULL << 0)
#define LANDLOCK_ACCESS_FILESYSTEM_WRITE_FILE (1ULL << 1)
#define LANDLOCK_ACCESS_FILESYSTEM_READ_FILE (1ULL << 2)
#define LANDLOCK_ACCESS_FILESYSTEM_READ_DIRECTORY (1ULL << 3)
#define LANDLOCK_ACCESS_FILESYSTEM_REMOVE_DIRECTORY (1ULL << 4)
#define LANDLOCK_ACCESS_FILESYSTEM_REMOVE_FILE (1ULL << 5)
#define LANDLOCK_ACCESS_FILESYSTEM_MAKE_CHARACTER_DEVICE (1ULL << 6)
#define LANDLOCK_ACCESS_FILESYSTEM_MAKE_DIRECTORY (1ULL << 7)
#define LANDLOCK_ACCESS_FILESYSTEM_MAKE_REGULAR_FILE (1ULL << 8)
#define LANDLOCK_ACCESS_FILESYSTEM_MAKE_SOCKET (1ULL << 9)
#define LANDLOCK_ACCESS_FILESYSTEM_MAKE_NAMED_PIPE (1ULL << 10)
#define LANDLOCK_ACCESS_FILESYSTEM_MAKE_BLOCK_DEVICE (1ULL << 11)
#define LANDLOCK_ACCESS_FILESYSTEM_MAKE_SYMBOLIC_LINK (1ULL << 12)
#define LANDLOCK_ACCESS_FILESYSTEM_REFER (1ULL << 13)        /* since version 2 */
#define LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE (1ULL << 14)     /* since version 3 */
#define LANDLOCK_ACCESS_FILESYSTEM_IOCTL_DEVICE (1ULL << 15) /* since version 5 */

/* Network access rights, available since Landlock version 4. */
#define LANDLOCK_ACCESS_NETWORK_BIND_TCP (1ULL << 0)
#define LANDLOCK_ACCESS_NETWORK_CONNECT_TCP (1ULL << 1)

/* Rights that only make sense on a directory. */
#define DIRECTORY_ONLY_ACCESS_RIGHTS                                                           \
    (LANDLOCK_ACCESS_FILESYSTEM_READ_DIRECTORY | LANDLOCK_ACCESS_FILESYSTEM_REMOVE_DIRECTORY |  \
     LANDLOCK_ACCESS_FILESYSTEM_REMOVE_FILE |                                                   \
     LANDLOCK_ACCESS_FILESYSTEM_MAKE_CHARACTER_DEVICE |                                         \
     LANDLOCK_ACCESS_FILESYSTEM_MAKE_DIRECTORY |                                                \
     LANDLOCK_ACCESS_FILESYSTEM_MAKE_REGULAR_FILE | LANDLOCK_ACCESS_FILESYSTEM_MAKE_SOCKET |    \
     LANDLOCK_ACCESS_FILESYSTEM_MAKE_NAMED_PIPE |                                               \
     LANDLOCK_ACCESS_FILESYSTEM_MAKE_BLOCK_DEVICE |                                             \
     LANDLOCK_ACCESS_FILESYSTEM_MAKE_SYMBOLIC_LINK | LANDLOCK_ACCESS_FILESYSTEM_REFER)

/* Highest Landlock version whose access rights this tool enumerates. A newer
 * kernel may define rights we do not list, which would leave them
 * unrestricted, so say so loudly rather than pretending the policy is whole. */
#define HIGHEST_KNOWN_LANDLOCK_VERSION 8

/* Layout fixed by the kernel. Raw data, never a class. */
struct landlock_ruleset_attributes {
    uint64_t handled_access_filesystem;
    uint64_t handled_access_network;
    uint64_t scoped;
};

struct landlock_path_beneath_attributes {
    uint64_t allowed_access;
    int32_t parent_fd;
} __attribute__((packed));

struct landlock_network_port_attributes {
    uint64_t allowed_access;
    uint64_t port;
};

/* Rights available at the given Landlock version. */
uint64_t filesystem_rights_for_version(int landlock_version);

/* Size of the attribute structure the given version understands. */
size_t ruleset_attributes_size_for_version(int landlock_version);

/* Asks the kernel for its Landlock version and refuses anything below the
 * demanded minimum, so an unsupported kernel stops the run instead of quietly
 * running it unprotected. */
int detect_landlock_version(int minimum_landlock_version, int network_rules_wanted);

/* Creates a ruleset that denies everything it handles unless a rule allows it. */
int create_ruleset(int landlock_version, int network_rules_wanted);

/* Adds one allow-listed path. */
void add_path_rule(int ruleset_descriptor, int landlock_version, const struct path_rule *rule);

/* Adds one allowed TCP port. */
void add_port_rule(int ruleset_descriptor, uint64_t port, uint64_t allowed_access,
                   const char *what);

/* The one-way door: after this the process, and everything it starts, can only
 * lose access, never regain it. */
void apply_restriction(int ruleset_descriptor);

#endif
