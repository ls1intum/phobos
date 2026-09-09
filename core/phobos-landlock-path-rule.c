/* O_PATH and the other GNU extensions used below need this first. */
#define _GNU_SOURCE
#include "phobos-landlock-path-rule.h"

#include "phobos-landlock-ruleset.h"

#include <fcntl.h>

uint64_t rights_granted_for(const struct path_rule *rule, int landlock_version) {
    uint64_t granted_rights =
        LANDLOCK_ACCESS_FILESYSTEM_READ_FILE | LANDLOCK_ACCESS_FILESYSTEM_READ_DIRECTORY;
    if (rule->executable) {
        granted_rights |= LANDLOCK_ACCESS_FILESYSTEM_EXECUTE;
    }
    if (rule->writable) {
        granted_rights |=
            LANDLOCK_ACCESS_FILESYSTEM_WRITE_FILE | LANDLOCK_ACCESS_FILESYSTEM_REMOVE_DIRECTORY |
            LANDLOCK_ACCESS_FILESYSTEM_REMOVE_FILE |
            LANDLOCK_ACCESS_FILESYSTEM_MAKE_CHARACTER_DEVICE |
            LANDLOCK_ACCESS_FILESYSTEM_MAKE_DIRECTORY |
            LANDLOCK_ACCESS_FILESYSTEM_MAKE_REGULAR_FILE | LANDLOCK_ACCESS_FILESYSTEM_MAKE_SOCKET |
            LANDLOCK_ACCESS_FILESYSTEM_MAKE_NAMED_PIPE |
            LANDLOCK_ACCESS_FILESYSTEM_MAKE_BLOCK_DEVICE |
            LANDLOCK_ACCESS_FILESYSTEM_MAKE_SYMBOLIC_LINK;
        if (landlock_version >= 2) {
            granted_rights |= LANDLOCK_ACCESS_FILESYSTEM_REFER;
        }
        if (landlock_version >= 3) {
            granted_rights |= LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE;
        }
    }
    if (landlock_version >= 5) {
        granted_rights |= LANDLOCK_ACCESS_FILESYSTEM_IOCTL_DEVICE;
    }
    return granted_rights & filesystem_rights_for_version(landlock_version);
}

/* Writable paths are the ones an attacker profits from redirecting, and they
 * are the ones that may sit in a directory the supervised code can write. So
 * refuse a symlink as the final component there. Read-only paths still follow
 * symlinks, because system paths legitimately are ones (/lib -> /usr/lib). */
int open_flags_for_rule(const struct path_rule *rule) {
    int flags = O_PATH | O_CLOEXEC;
    if (rule->writable) {
        flags |= O_NOFOLLOW;
    }
    return flags;
}
