/*
 * Asks whether this machine can actually enforce a Landlock policy.
 *
 * The version number alone does not answer that. A kernel can report a
 * Landlock version and still refuse to apply a ruleset, so this walks the
 * whole path: prove both fixture files are readable to begin with, create a
 * ruleset, allow one directory, restrict itself, and then prove the permitted
 * file is still readable and the forbidden one is not.
 *
 * The opening baseline is what makes the answer trustworthy. Without it a file
 * that some other mechanism had already made unreadable, a mount option or a
 * container's user mapping, would look exactly like Landlock working.
 *
 * Exit codes are three-valued, because "cannot enforce" and "cannot tell" are
 * different answers: 0 enforced, 1 not enforced, 2 misused, 3 indeterminate.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PROBE_OK 0
#define PROBE_NOT_ENFORCED 1
#define PROBE_USAGE 2
#define PROBE_INDETERMINATE 3

/*
 * Phobos refuses to start with network rules below this version, in
 * detect_landlock_version, and the acceptance suite passes --connect-tcp. A
 * kernel below it can enforce filesystem rules and still not carry the suite,
 * so the probe answers the question the suite will ask, not an easier one.
 */
#define REQUIRED_LANDLOCK_ABI 4

/* glibc ships no wrapper for this call, so it goes through syscall directly. */
static long create_ruleset(const struct landlock_ruleset_attr *attributes, size_t size, uint32_t flags) {
    return syscall(__NR_landlock_create_ruleset, attributes, size, flags);
}

/* glibc ships no wrapper for this call, so it goes through syscall directly. */
static long add_rule(int ruleset_fd, enum landlock_rule_type type, const void *attributes, uint32_t flags) {
    return syscall(__NR_landlock_add_rule, ruleset_fd, type, attributes, flags);
}

/* glibc ships no wrapper for this call, so it goes through syscall directly. */
static long restrict_self(int ruleset_fd, uint32_t flags) {
    return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

/* The Landlock version this kernel offers, or -1 where it offers none. */
static int landlock_version(void) {
    long version = create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (version < 0) {
        return -1;
    }
    return (int) version;
}

/* Prints the Landlock version on one line, for a caller that only wants the number. */
static int report_version(void) {
    int version = landlock_version();
    if (version < 0) {
        fprintf(stderr, "landlock unavailable: %s\n", strerror(errno));
        return PROBE_NOT_ENFORCED;
    }
    printf("%d\n", version);
    return PROBE_OK;
}

/* Whether a file can be opened for reading right now. */
static int is_readable(const char *file) {
    int fd = open(file, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return 0;
    }
    close(fd);
    return 1;
}

/*
 * Establishes that both fixture files start out readable.
 *
 * Anything else means the probe would be measuring whatever already denied
 * them, so it reports that it cannot answer rather than claiming a denial it
 * has not caused.
 */
static int fixture_is_sound(const char *permitted_file, const char *forbidden_file) {
    if (!is_readable(permitted_file)) {
        fprintf(stderr, "the permitted file is unreadable before any restriction: %s\n", permitted_file);
        return 0;
    }
    if (!is_readable(forbidden_file)) {
        fprintf(stderr, "the forbidden file is unreadable before any restriction: %s\n", forbidden_file);
        return 0;
    }
    return 1;
}

/* Anchors a read-only rule on one directory, which is what the probe permits. */
static int allow_reading_beneath(int ruleset_fd, const char *directory) {
    struct landlock_path_beneath_attr rule;
    memset(&rule, 0, sizeof(rule));
    rule.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    rule.parent_fd = open(directory, O_PATH | O_CLOEXEC);
    if (rule.parent_fd < 0) {
        fprintf(stderr, "cannot open the permitted directory %s: %s\n", directory, strerror(errno));
        return PROBE_INDETERMINATE;
    }
    long added = add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
    int add_rule_errno = errno;
    close(rule.parent_fd);
    if (added != 0) {
        fprintf(stderr, "cannot add the rule: %s\n", strerror(add_rule_errno));
        return PROBE_INDETERMINATE;
    }
    return PROBE_OK;
}

/*
 * Confines this process's reads to one directory tree.
 *
 * Reads only. Writing is not among the handled rights, so this is not a
 * read-only sandbox and nothing here says anything about writes.
 */
static int restrict_reads_to(const char *directory) {
    struct landlock_ruleset_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

    long ruleset_fd = create_ruleset(&attributes, sizeof(attributes), 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "cannot create a ruleset: %s\n", strerror(errno));
        return PROBE_INDETERMINATE;
    }
    int result = allow_reading_beneath((int) ruleset_fd, directory);
    if (result == PROBE_OK && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "cannot set no_new_privs: %s\n", strerror(errno));
        result = PROBE_INDETERMINATE;
    }
    if (result == PROBE_OK && restrict_self((int) ruleset_fd, 0) != 0) {
        fprintf(stderr, "cannot restrict this process: %s\n", strerror(errno));
        result = PROBE_INDETERMINATE;
    }
    close((int) ruleset_fd);
    return result;
}

/* Reports whether a file the ruleset permits can still be opened for reading. */
static int permitted_read_succeeds(const char *file) {
    if (!is_readable(file)) {
        printf("  FAIL  the permitted file cannot be opened for reading: %s\n", strerror(errno));
        return PROBE_NOT_ENFORCED;
    }
    printf("  ok    the permitted file can still be opened for reading\n");
    return PROBE_OK;
}

/*
 * Reports whether a file outside the ruleset is refused, and refused for the
 * right reason. The baseline has already shown it was readable a moment ago,
 * so an EACCES here can only have come from the ruleset.
 */
static int forbidden_read_is_refused(const char *file) {
    int fd = open(file, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        close(fd);
        printf("  FAIL  the forbidden file was readable, so nothing is being enforced\n");
        return PROBE_NOT_ENFORCED;
    }
    if (errno != EACCES) {
        printf("  FAIL  the forbidden file was refused with %s, which is not Landlock\n", strerror(errno));
        return PROBE_NOT_ENFORCED;
    }
    printf("  ok    the forbidden file is refused with EACCES\n");
    return PROBE_OK;
}

/* Runs the whole path and fails unless both halves of the verdict hold. */
static int probe_enforcement(const char *permitted_directory, const char *permitted_file, const char *forbidden_file) {
    int version = landlock_version();
    if (version < 0) {
        fprintf(stderr, "landlock unavailable: %s\n", strerror(errno));
        return PROBE_NOT_ENFORCED;
    }
    if (version < REQUIRED_LANDLOCK_ABI) {
        fprintf(stderr, "landlock ABI %d is below the %d that phobos needs for network rules\n",
                version, REQUIRED_LANDLOCK_ABI);
        return PROBE_NOT_ENFORCED;
    }
    printf("  ok    landlock reports ABI %d, at or above the %d phobos needs\n", version, REQUIRED_LANDLOCK_ABI);
    if (!fixture_is_sound(permitted_file, forbidden_file)) {
        return PROBE_INDETERMINATE;
    }
    printf("  ok    both fixture files are readable before any restriction\n");
    int restricted = restrict_reads_to(permitted_directory);
    if (restricted != PROBE_OK) {
        return restricted;
    }
    printf("  ok    the ruleset was applied to this process\n");
    int permitted = permitted_read_succeeds(permitted_file);
    int forbidden = forbidden_read_is_refused(forbidden_file);
    if (permitted != PROBE_OK || forbidden != PROBE_OK) {
        return PROBE_NOT_ENFORCED;
    }
    return PROBE_OK;
}

static void print_usage(void) {
    fprintf(stderr, "usage: landlock-capability-probe --version\n");
    fprintf(stderr, "       landlock-capability-probe --enforce DIR PERMITTED_FILE FORBIDDEN_FILE\n");
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        return report_version();
    }
    if (argc == 5 && strcmp(argv[1], "--enforce") == 0) {
        return probe_enforcement(argv[2], argv[3], argv[4]);
    }
    print_usage();
    return PROBE_USAGE;
}
