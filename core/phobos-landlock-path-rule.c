/* O_PATH and the other GNU extensions used below need this first. */
#define _GNU_SOURCE
#include "phobos-landlock-path-rule.h"

#include "phobos-landlock-ruleset.h"

#include <fcntl.h>

/* Creating device nodes and symbolic links is deliberately absent from the
 * "makeable" set. No build tool needs either, a device node is a way to reach
 * hardware the policy never named, and a symbolic link is a way to point a
 * later write somewhere the policy never named. They stay in the handled set,
 * so they are denied rather than unregulated. */
uint64_t rights_granted_for(const struct path_rule *rule, int landlock_version) {
    uint64_t granted_rights = 0;
    if (rule->readable) {
        granted_rights |=
            LANDLOCK_ACCESS_FILESYSTEM_READ_FILE | LANDLOCK_ACCESS_FILESYSTEM_READ_DIRECTORY;
    }
    if (rule->executable) {
        granted_rights |= LANDLOCK_ACCESS_FILESYSTEM_EXECUTE;
    }
    if (rule->writable) {
        granted_rights |= LANDLOCK_ACCESS_FILESYSTEM_WRITE_FILE;
        if (landlock_version >= 3) {
            granted_rights |= LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE;
        }
    }
    if (rule->makeable) {
        granted_rights |=
            LANDLOCK_ACCESS_FILESYSTEM_MAKE_REGULAR_FILE |
            LANDLOCK_ACCESS_FILESYSTEM_MAKE_DIRECTORY | LANDLOCK_ACCESS_FILESYSTEM_MAKE_SOCKET |
            LANDLOCK_ACCESS_FILESYSTEM_MAKE_NAMED_PIPE;
    }
    if (rule->removable) {
        granted_rights |=
            LANDLOCK_ACCESS_FILESYSTEM_REMOVE_FILE | LANDLOCK_ACCESS_FILESYSTEM_REMOVE_DIRECTORY;
    }
    /* Moving a file into or out of a directory is creating it on one side and
     * deleting it on the other, so it is granted only where both are. Without
     * it the kernel answers EXDEV, which makes a copying tool succeed quietly
     * and an atomic move fail. */
    if (rule->makeable && rule->removable && landlock_version >= 2) {
        granted_rights |= LANDLOCK_ACCESS_FILESYSTEM_REFER;
    }
    if (rule->ioctl_device && landlock_version >= 5) {
        granted_rights |= LANDLOCK_ACCESS_FILESYSTEM_IOCTL_DEVICE;
    }
    return granted_rights & filesystem_rights_for_version(landlock_version);
}

/* ioctl counts as changing: an ioctl on a device can alter its state, so a rule
 * carrying it deserves the same protection against being pointed somewhere else
 * as a writing one. */
bool rule_can_change_anything(const struct path_rule *rule) {
    return rule->writable || rule->makeable || rule->removable || rule->ioctl_device;
}

/* A rule that may change something is the one worth redirecting, and it may
 * sit in a directory the supervised code can write. So refuse to follow a
 * symbolic link as the final component there. Purely reading rules still
 * follow them, because system paths legitimately are links (/lib -> /usr/lib). */
int open_flags_for_rule(const struct path_rule *rule) {
    int flags = O_PATH | O_CLOEXEC;
    if (rule_can_change_anything(rule)) {
        flags |= O_NOFOLLOW;
    }
    return flags;
}
