/* O_PATH and the other GNU extensions used below need this first. */
#define _GNU_SOURCE
#include "phobos-landlock-filesystem-and-networksystem-path-rule.h"

#include "phobos-landlock-filesystem-and-networksystem-ruleset.h"

#include <fcntl.h>

/* Each make right has its own field, because the risks differ. Creating regular
 * files and directories (makeable) is the ordinary case; creating sockets and
 * named pipes (makeable_ipc) is benign local IPC but separable; creating a
 * symbolic link (makeable_symlink) is a distinct right a policy opts into
 * deliberately. Creating device nodes has no field at all: a character or block
 * device is a way to reach hardware the policy never named, and no build tool
 * needs one, so it stays in the handled set and is denied rather than
 * unregulated.
 *
 * REFER is its own right (referable), not derived from makeable and removable
 * together. It governs moving or renaming across directories, which is the
 * link/rename privilege-escalation surface Landlock guards, so a policy grants it
 * on its own where a workspace needs moves rather than gaining it as a side
 * effect of create plus delete. Without it the kernel answers EXDEV, which makes
 * a copying tool succeed quietly and an atomic move fail.
 *
 * RESOLVE_UNIX (since version 9) gates connecting or sending to a pathname UNIX
 * socket whose server was created outside this Landlock domain. It is granted
 * with the read right, because reaching such a socket by its pathname is a
 * read-like resolution: a path a policy may read, it may also reach the sockets
 * beneath, and a path it may not read, it may not. It is not a directory-only
 * right, so it holds on a socket-file rule as well as on a directory rule, and
 * the mask by filesystem_rights_for_version keeps it off a kernel below 9. */
uint64_t rights_granted_for(const struct path_rule *rule, int landlock_version) {
    uint64_t granted_rights = 0;
    if (rule->readable) {
        granted_rights |=
            LANDLOCK_ACCESS_FILESYSTEM_READ_FILE | LANDLOCK_ACCESS_FILESYSTEM_READ_DIRECTORY;
        if (landlock_version >= FIRST_VERSION_WITH_RESOLVE_UNIX) {
            granted_rights |= LANDLOCK_ACCESS_FILESYSTEM_RESOLVE_UNIX;
        }
    }
    if (rule->executable) {
        granted_rights |= LANDLOCK_ACCESS_FILESYSTEM_EXECUTE;
    }
    if (rule->writable) {
        granted_rights |= LANDLOCK_ACCESS_FILESYSTEM_WRITE_FILE;
        if (landlock_version >= FIRST_VERSION_WITH_TRUNCATE) {
            granted_rights |= LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE;
        }
    }
    if (rule->makeable) {
        granted_rights |=
            LANDLOCK_ACCESS_FILESYSTEM_MAKE_REGULAR_FILE | LANDLOCK_ACCESS_FILESYSTEM_MAKE_DIRECTORY;
    }
    if (rule->makeable_ipc) {
        granted_rights |=
            LANDLOCK_ACCESS_FILESYSTEM_MAKE_SOCKET | LANDLOCK_ACCESS_FILESYSTEM_MAKE_NAMED_PIPE;
    }
    if (rule->makeable_symlink) {
        granted_rights |= LANDLOCK_ACCESS_FILESYSTEM_MAKE_SYMBOLIC_LINK;
    }
    if (rule->removable) {
        granted_rights |=
            LANDLOCK_ACCESS_FILESYSTEM_REMOVE_FILE | LANDLOCK_ACCESS_FILESYSTEM_REMOVE_DIRECTORY;
    }
    if (rule->referable && landlock_version >= FIRST_VERSION_WITH_REFER) {
        granted_rights |= LANDLOCK_ACCESS_FILESYSTEM_REFER;
    }
    if (rule->ioctl_device && landlock_version >= FIRST_VERSION_WITH_IOCTL_DEVICE) {
        granted_rights |= LANDLOCK_ACCESS_FILESYSTEM_IOCTL_DEVICE;
    }
    return granted_rights & filesystem_rights_for_version(landlock_version);
}

/* ioctl counts as changing: an ioctl on a device can alter its state, so a rule
 * carrying it deserves the same protection against being pointed somewhere else
 * as a writing one. */
bool rule_can_change_anything(const struct path_rule *rule) {
    return rule->writable || rule->makeable || rule->makeable_ipc || rule->makeable_symlink ||
           rule->referable || rule->removable || rule->ioctl_device;
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
