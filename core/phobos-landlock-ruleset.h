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
 * They are the same on every architecture that supports Landlock. These stay
 * macros: the fallback below is a preprocessor decision, and a constant cannot
 * be tested with #ifdef. */
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

static constexpr uint32_t LANDLOCK_CREATE_RULESET_VERSION = 1U << 0;
static constexpr int LANDLOCK_RULE_PATH_BENEATH = 1;
static constexpr int LANDLOCK_RULE_NETWORK_PORT = 2;

/* Filesystem access rights, available since Landlock version 1 unless noted.
 * An enumeration rather than one constant each, so that a translation unit
 * using none of them still compiles clean under -Wall -Wextra -Werror. */
enum landlock_filesystem_access : uint64_t {
    LANDLOCK_ACCESS_FILESYSTEM_EXECUTE = 1ULL << 0,
    LANDLOCK_ACCESS_FILESYSTEM_WRITE_FILE = 1ULL << 1,
    LANDLOCK_ACCESS_FILESYSTEM_READ_FILE = 1ULL << 2,
    LANDLOCK_ACCESS_FILESYSTEM_READ_DIRECTORY = 1ULL << 3,
    LANDLOCK_ACCESS_FILESYSTEM_REMOVE_DIRECTORY = 1ULL << 4,
    LANDLOCK_ACCESS_FILESYSTEM_REMOVE_FILE = 1ULL << 5,
    LANDLOCK_ACCESS_FILESYSTEM_MAKE_CHARACTER_DEVICE = 1ULL << 6,
    LANDLOCK_ACCESS_FILESYSTEM_MAKE_DIRECTORY = 1ULL << 7,
    LANDLOCK_ACCESS_FILESYSTEM_MAKE_REGULAR_FILE = 1ULL << 8,
    LANDLOCK_ACCESS_FILESYSTEM_MAKE_SOCKET = 1ULL << 9,
    LANDLOCK_ACCESS_FILESYSTEM_MAKE_NAMED_PIPE = 1ULL << 10,
    LANDLOCK_ACCESS_FILESYSTEM_MAKE_BLOCK_DEVICE = 1ULL << 11,
    LANDLOCK_ACCESS_FILESYSTEM_MAKE_SYMBOLIC_LINK = 1ULL << 12,
    LANDLOCK_ACCESS_FILESYSTEM_REFER = 1ULL << 13,        /* since version 2 */
    LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE = 1ULL << 14,     /* since version 3 */
    LANDLOCK_ACCESS_FILESYSTEM_IOCTL_DEVICE = 1ULL << 15, /* since version 5 */
};

/* Network access rights, available since Landlock version 4. */
enum landlock_network_access : uint64_t {
    LANDLOCK_ACCESS_NETWORK_BIND_TCP = 1ULL << 0,
    LANDLOCK_ACCESS_NETWORK_CONNECT_TCP = 1ULL << 1,
};

/* Rights that only make sense on a directory, out of the ones this tool ever
 * grants. Device nodes and symbolic links are not in it because they are never
 * granted at all. */
static constexpr uint64_t DIRECTORY_ONLY_ACCESS_RIGHTS =
    LANDLOCK_ACCESS_FILESYSTEM_READ_DIRECTORY | LANDLOCK_ACCESS_FILESYSTEM_REMOVE_DIRECTORY |
    LANDLOCK_ACCESS_FILESYSTEM_REMOVE_FILE | LANDLOCK_ACCESS_FILESYSTEM_MAKE_DIRECTORY |
    LANDLOCK_ACCESS_FILESYSTEM_MAKE_REGULAR_FILE | LANDLOCK_ACCESS_FILESYSTEM_MAKE_SOCKET |
    LANDLOCK_ACCESS_FILESYSTEM_MAKE_NAMED_PIPE | LANDLOCK_ACCESS_FILESYSTEM_REFER;

/* Highest Landlock version whose access rights this tool enumerates. A newer
 * kernel may define rights we do not list, which would leave them
 * unrestricted, so say so loudly rather than pretending the policy is whole. */
static constexpr int HIGHEST_KNOWN_LANDLOCK_VERSION = 8;

/* Versions at which a right first exists. Below them the kernel does not
 * handle the right at all, so it is neither granted nor denied to anyone. */
static constexpr int FIRST_VERSION_WITH_REFER = 2;
static constexpr int FIRST_VERSION_WITH_TRUNCATE = 3;
static constexpr int FIRST_VERSION_WITH_NETWORK = 4;
static constexpr int FIRST_VERSION_WITH_IOCTL_DEVICE = 5;
static constexpr int FIRST_VERSION_WITH_SCOPED = 6;

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

/* The kernel reads these by offset, so a compiler that padded them would send
 * it something else entirely. Checked here rather than trusted. */
static_assert(sizeof(struct landlock_path_beneath_attributes) == 12,
              "landlock_path_beneath_attributes must be packed to 12 bytes");
static_assert(offsetof(struct landlock_ruleset_attributes, handled_access_network) == 8,
              "the kernel expects handled_access_network as the second member");
static_assert(offsetof(struct landlock_ruleset_attributes, scoped) == 16,
              "the kernel expects scoped as the third member");

/* Rights available at the given Landlock version. */
uint64_t filesystem_rights_for_version(int landlock_version);

/* Size of the attribute structure the given version understands. */
size_t ruleset_attributes_size_for_version(int landlock_version);

/* Asks the kernel for its Landlock version and refuses anything below the
 * demanded minimum, so an unsupported kernel stops the run instead of quietly
 * running it unprotected. */
int detect_landlock_version(int minimum_landlock_version, bool network_rules_wanted);

/* Names every right this kernel cannot handle, and what that means in
 * practice. Landlock offers no hook below those versions, so there is nothing
 * to enforce in their place and the gap can only be reported. */
void report_unenforceable_rights(int landlock_version);

/* Creates a ruleset that denies everything it handles unless a rule allows it. */
int create_ruleset(int landlock_version, bool network_rules_wanted);

/* Adds one allow-listed path. */
void add_path_rule(int ruleset_descriptor, int landlock_version, const struct path_rule *rule);

/* Adds one allowed TCP port. */
void add_port_rule(int ruleset_descriptor, uint64_t port, uint64_t allowed_access,
                   const char *what);

/* The one-way door: after this the process, and everything it starts, can only
 * lose access, never regain it. */
void apply_restriction(int ruleset_descriptor);

#endif
