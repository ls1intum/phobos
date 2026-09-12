/* O_PATH and the other GNU extensions used below need this first. */
#define _GNU_SOURCE
#include "phobos-landlock-ruleset.h"

#include "phobos-landlock-diagnostics.h"
#include "phobos-landlock-path-rule.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

uint64_t filesystem_rights_for_version(int landlock_version) {
    uint64_t rights =
        LANDLOCK_ACCESS_FILESYSTEM_EXECUTE | LANDLOCK_ACCESS_FILESYSTEM_WRITE_FILE |
        LANDLOCK_ACCESS_FILESYSTEM_READ_FILE | LANDLOCK_ACCESS_FILESYSTEM_READ_DIRECTORY |
        LANDLOCK_ACCESS_FILESYSTEM_REMOVE_DIRECTORY | LANDLOCK_ACCESS_FILESYSTEM_REMOVE_FILE |
        LANDLOCK_ACCESS_FILESYSTEM_MAKE_CHARACTER_DEVICE |
        LANDLOCK_ACCESS_FILESYSTEM_MAKE_DIRECTORY | LANDLOCK_ACCESS_FILESYSTEM_MAKE_REGULAR_FILE |
        LANDLOCK_ACCESS_FILESYSTEM_MAKE_SOCKET | LANDLOCK_ACCESS_FILESYSTEM_MAKE_NAMED_PIPE |
        LANDLOCK_ACCESS_FILESYSTEM_MAKE_BLOCK_DEVICE |
        LANDLOCK_ACCESS_FILESYSTEM_MAKE_SYMBOLIC_LINK;
    if (landlock_version >= FIRST_VERSION_WITH_REFER) {
        rights |= LANDLOCK_ACCESS_FILESYSTEM_REFER;
    }
    if (landlock_version >= FIRST_VERSION_WITH_TRUNCATE) {
        rights |= LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE;
    }
    if (landlock_version >= FIRST_VERSION_WITH_IOCTL_DEVICE) {
        rights |= LANDLOCK_ACCESS_FILESYSTEM_IOCTL_DEVICE;
    }
    return rights;
}

/* Older kernels reject the larger structure, so send only the part they know. */
size_t ruleset_attributes_size_for_version(int landlock_version) {
    if (landlock_version < FIRST_VERSION_WITH_NETWORK) {
        return offsetof(struct landlock_ruleset_attributes, handled_access_network);
    }
    if (landlock_version < FIRST_VERSION_WITH_SCOPED) {
        return offsetof(struct landlock_ruleset_attributes, scoped);
    }
    return sizeof(struct landlock_ruleset_attributes);
}

int detect_landlock_version(int minimum_landlock_version, bool network_rules_wanted) {
    long landlock_version =
        syscall(SYSCALL_NUMBER_LANDLOCK_CREATE_RULESET, nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (landlock_version < 0) {
        exit_with_message("Landlock is not available on this kernel (refusing to run "
                          "unprotected)");
    }
    log_verbose("Landlock version %ld", landlock_version);
    if (landlock_version > HIGHEST_KNOWN_LANDLOCK_VERSION) {
        fprintf(stderr,
                "[phobos-landlock] warning: kernel offers Landlock version %ld but this build "
                "only enumerates rights up to version %d; rights added after that are NOT "
                "restricted\n",
                landlock_version, HIGHEST_KNOWN_LANDLOCK_VERSION);
    }
    if (landlock_version < minimum_landlock_version) {
        fprintf(stderr,
                "[phobos-landlock] kernel offers Landlock version %ld but version %d is required "
                "(refusing to run unprotected)\n",
                landlock_version, minimum_landlock_version);
        exit(EXIT_CODE_POLICY_ERROR);
    }
    if (network_rules_wanted && landlock_version < FIRST_VERSION_WITH_NETWORK) {
        exit_with_message("network rules require Landlock version 4 (kernel 6.7)");
    }
    return (int)landlock_version;
}

/* Landlock grew over the years. A right the running kernel does not know is
 * not merely ungranted, it is not handled at all, so it is free for every path
 * including the ones this policy calls read-only. There is no hook to enforce
 * it in its place, so the only honest thing left is to say so. Always, not
 * only under --verbose: nobody reads detail they did not ask for, and this is
 * the difference between a guarantee and the appearance of one. */
void report_unenforceable_rights(int landlock_version) {
    if (landlock_version < FIRST_VERSION_WITH_TRUNCATE) {
        warn_always("warning: Landlock version %d does not handle TRUNCATE; a file on a "
                    "read-only path can still be emptied with truncate(2) by anyone the "
                    "ordinary file permissions allow to write it. Pass "
                    "--minimum-landlock-version %d to refuse such a kernel instead.",
                    landlock_version, FIRST_VERSION_WITH_TRUNCATE);
    }
    if (landlock_version < FIRST_VERSION_WITH_IOCTL_DEVICE) {
        warn_always("warning: Landlock version %d does not handle IOCTL_DEVICE; ioctl on a "
                    "character or block device is unrestricted on every allowed path. Pass "
                    "--minimum-landlock-version %d to refuse such a kernel instead.",
                    landlock_version, FIRST_VERSION_WITH_IOCTL_DEVICE);
    }
    /* The other direction, and not a gap: without REFER the kernel denies every
     * rename across directories rather than leaving it free. That breaks builds
     * loudly instead of weakening the sandbox quietly, so it is worth naming but
     * it is not a hole. */
    if (landlock_version < FIRST_VERSION_WITH_REFER) {
        warn_always("note: Landlock version %d has no REFER; moving a file between two "
                    "allowed directories is refused with EXDEV even where the policy permits "
                    "both sides.",
                    landlock_version);
    }
}

int create_ruleset(int landlock_version, uint64_t handled_network) {
    struct landlock_ruleset_attributes attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.handled_access_filesystem = filesystem_rights_for_version(landlock_version);
    attributes.handled_access_network = handled_network;

    int ruleset_descriptor =
        (int)syscall(SYSCALL_NUMBER_LANDLOCK_CREATE_RULESET, &attributes,
                     ruleset_attributes_size_for_version(landlock_version), 0);
    if (ruleset_descriptor < 0) {
        exit_with_system_error("landlock_create_ruleset");
    }
    return ruleset_descriptor;
}

void add_path_rule(int ruleset_descriptor, int landlock_version, const struct path_rule *rule) {
    int path_descriptor = open(rule->path, open_flags_for_rule(rule));
    if (path_descriptor < 0) {
        fprintf(stderr, "[phobos-landlock] cannot open %s: %s\n", rule->path, strerror(errno));
        exit(EXIT_CODE_POLICY_ERROR);
    }

    struct stat file_status;
    if (fstat(path_descriptor, &file_status) != 0) {
        exit_with_system_error("fstat");
    }
    /* O_PATH|O_NOFOLLOW opens the link itself instead of failing, so the
     * symlink has to be rejected here. A rule anchored on a link is at best
     * useless and at worst points somewhere the policy never named. */
    if (rule_can_change_anything(rule) && S_ISLNK(file_status.st_mode)) {
        fprintf(stderr,
                "[phobos-landlock] refusing changeable path %s: it is a symbolic link and could "
                "redirect the rule\n",
                rule->path);
        exit(EXIT_CODE_POLICY_ERROR);
    }

    struct landlock_path_beneath_attributes path_rule_attributes;
    memset(&path_rule_attributes, 0, sizeof(path_rule_attributes));
    path_rule_attributes.allowed_access = rights_granted_for(rule, landlock_version);
    if (!S_ISDIR(file_status.st_mode)) {
        path_rule_attributes.allowed_access &= ~DIRECTORY_ONLY_ACCESS_RIGHTS;
    }
    path_rule_attributes.parent_fd = path_descriptor;

    if (syscall(SYSCALL_NUMBER_LANDLOCK_ADD_RULE, ruleset_descriptor, LANDLOCK_RULE_PATH_BENEATH,
                &path_rule_attributes, 0) != 0) {
        fprintf(stderr, "[phobos-landlock] add_rule failed for %s: %s\n", rule->path,
                strerror(errno));
        exit(EXIT_CODE_POLICY_ERROR);
    }
    log_verbose("allow %s%s%s%s%s%s%s", rule->path, rule->readable ? " +r" : "",
                rule->writable ? " +w" : "", rule->executable ? " +x" : "",
                rule->makeable ? " +m" : "", rule->removable ? " +d" : "",
                rule->ioctl_device ? " +i" : "");
    close(path_descriptor);
}

void add_port_rule(int ruleset_descriptor, uint64_t port, uint64_t allowed_access,
                   const char *what) {
    struct landlock_network_port_attributes port_rule_attributes;
    memset(&port_rule_attributes, 0, sizeof(port_rule_attributes));
    port_rule_attributes.allowed_access = allowed_access;
    port_rule_attributes.port = port;
    if (syscall(SYSCALL_NUMBER_LANDLOCK_ADD_RULE, ruleset_descriptor, LANDLOCK_RULE_NETWORK_PORT,
                &port_rule_attributes, 0) != 0) {
        exit_with_system_error(what);
    }
    log_verbose("allow %s tcp/%llu", what, (unsigned long long)port);
}

void apply_restriction(int ruleset_descriptor) {
    /* no_new_privs first, because Landlock requires it and it also closes the
     * setuid route out of the sandbox. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        exit_with_system_error("prctl(PR_SET_NO_NEW_PRIVS)");
    }
    if (syscall(SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF, ruleset_descriptor, 0) != 0) {
        exit_with_system_error("landlock_restrict_self");
    }
    close(ruleset_descriptor);
}
