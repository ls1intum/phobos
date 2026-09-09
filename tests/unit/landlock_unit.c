/*
 * Unit tests for phobos-landlock.
 *
 * The integration suites under tests/landlock-acceptance exercise the sandbox
 * against a real kernel, which is what proves it works. They cannot reach the
 * failure paths, though: a kernel that refuses a rule, an version older than the
 * one this machine has, an exec that fails. Those decide whether the tool
 * fails closed, so they are the ones that must not go untested.
 *
 * The source is included rather than linked, so the static functions are
 * reachable, and main is renamed so this file can provide its own. Every
 * syscall the tool makes is interposed through the linker's --wrap, so a
 * failure can be injected without a special kernel. Cases that end in exit()
 * run in a forked child and are judged by the exit status.
 */
/* The system headers this file needs itself. They used to arrive indirectly,
 * through the single large source file; now that it is split, the test states
 * its own. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Only the stage sequence is included, so that its main can be called from
 * here under another name. The modules beside it are linked in the normal way,
 * which is what the split into files bought: their functions no longer have to
 * be reached through an include. */
#define main sut_main
#include "../../core/phobos-landlock.c"
#undef main

#include "../../core/phobos-landlock-diagnostics.h"
#include "../../core/phobos-landlock-options.h"
#include "../../core/phobos-landlock-path-rule.h"
#include "../../core/phobos-landlock-ruleset.h"

#include <sys/wait.h>

/* -------------------------------------------------------------- the record */

/* What the wrapped calls were actually handed. Until this existed the suite
 * asserted only that a call happened, never what it carried, so the policy
 * itself could be changed at will and every case stayed green: a file could be
 * given the rights that only directories may hold, a port rule could be
 * dropped, the whole rule loop could be cut to its first turn.
 *
 * It lives in shared memory because a case that ends in exit() runs in a
 * forked child while the assertions are made by the parent. */
#define RECORDED_RULE_LIMIT 8
#define RECORDED_PATH_LENGTH 256

struct syscall_record {
    size_t ruleset_attributes_size;
    uint64_t handled_access_filesystem;
    uint64_t handled_access_network;
    size_t path_rule_count;
    uint64_t path_rule_allowed_access[RECORDED_RULE_LIMIT];
    int path_rule_parent_fd[RECORDED_RULE_LIMIT];
    size_t port_rule_count;
    uint64_t port_rule_allowed_access[RECORDED_RULE_LIMIT];
    uint64_t port_rule_port[RECORDED_RULE_LIMIT];
    int rule_ruleset_descriptor;
    int restricted_ruleset_descriptor;
    size_t opened_path_count;
    char opened_path[RECORDED_RULE_LIMIT][RECORDED_PATH_LENGTH];
    char entered_directory[RECORDED_PATH_LENGTH];
    size_t closed_descriptor_count;
    int closed_descriptor[RECORDED_RULE_LIMIT];
};

static struct syscall_record *record;

static void remember_string(char *destination, const char *value) {
    snprintf(destination, RECORDED_PATH_LENGTH, "%s", value == NULL ? "(none)" : value);
}

/* ------------------------------------------------------------------- mocks */

static long mock_landlock_version = 8; /* what the kernel reports */
static int mock_ruleset_descriptor = 42;
static int fail_create = 0;
static int fail_add_path = 0;
static int fail_add_port = 0;
static int fail_restrict = 0;
static int fail_open = 0;
static int fail_fstat = 0;
static int fail_prctl = 0;
static int fail_chdir = 0;
static int fail_exec = 0;
static int force_symlink = 0;
static int force_regular_file = 0;
/* Descriptor 0 is a descriptor like any other. The tool must not read it as a
 * failure, and handing it out costs no real file, which is what lets the case
 * with a full rule table run without exhausting the process. */
static int force_path_descriptor_zero = 0;

int __real_open(const char *path, int flags, ...);
int __wrap_open(const char *path, int flags, ...) {
    if (record->opened_path_count < RECORDED_RULE_LIMIT) {
        remember_string(record->opened_path[record->opened_path_count], path);
    }
    record->opened_path_count++;
    if (fail_open) {
        errno = EACCES;
        return -1;
    }
    if (force_path_descriptor_zero) {
        return 0;
    }
    return __real_open(path, flags);
}

int __real___fxstat(int ver, int fd, struct stat *st);
int __wrap_fstat(int fd, struct stat *st) {
    if (fail_fstat) {
        errno = EIO;
        return -1;
    }
    memset(st, 0, sizeof(*st));
    st->st_mode = force_symlink ? S_IFLNK : (force_regular_file ? S_IFREG : S_IFDIR);
    (void)fd;
    return 0;
}

/* Each of the three calls takes its own arguments, so they are read inside the
 * branch that knows their types rather than once with a guess. Reading the
 * attribute pointer as anything narrower is how it stayed unexamined. */
static long mock_landlock_version_probe(size_t attributes_size, unsigned flags) {
    if (attributes_size != 0 || flags != LANDLOCK_CREATE_RULESET_VERSION) {
        errno = EINVAL; /* a null ruleset is only ever the version probe */
        return -1;
    }
    if (mock_landlock_version < 0) {
        errno = ENOSYS;
        return -1;
    }
    return mock_landlock_version;
}

static long mock_create_ruleset(const struct landlock_ruleset_attributes *attributes,
                                size_t attributes_size) {
    record->ruleset_attributes_size = attributes_size;
    record->handled_access_filesystem = attributes->handled_access_filesystem;
    record->handled_access_network = attributes->handled_access_network;
    if (fail_create) {
        errno = EINVAL;
        return -1;
    }
    return mock_ruleset_descriptor;
}

static long mock_add_rule(int ruleset_descriptor, int rule_type, const void *rule_attributes) {
    record->rule_ruleset_descriptor = ruleset_descriptor;
    if (rule_type == LANDLOCK_RULE_PATH_BENEATH) {
        const struct landlock_path_beneath_attributes *attributes = rule_attributes;
        if (record->path_rule_count < RECORDED_RULE_LIMIT) {
            record->path_rule_allowed_access[record->path_rule_count] =
                attributes->allowed_access;
            record->path_rule_parent_fd[record->path_rule_count] = attributes->parent_fd;
        }
        record->path_rule_count++;
        if (fail_add_path) {
            errno = EINVAL;
            return -1;
        }
        return 0;
    }
    if (rule_type == LANDLOCK_RULE_NETWORK_PORT) {
        const struct landlock_network_port_attributes *attributes = rule_attributes;
        if (record->port_rule_count < RECORDED_RULE_LIMIT) {
            record->port_rule_allowed_access[record->port_rule_count] =
                attributes->allowed_access;
            record->port_rule_port[record->port_rule_count] = attributes->port;
        }
        record->port_rule_count++;
        if (fail_add_port) {
            errno = EINVAL;
            return -1;
        }
        return 0;
    }
    return 0;
}

static long mock_restrict_self(int ruleset_descriptor) {
    record->restricted_ruleset_descriptor = ruleset_descriptor;
    if (fail_restrict) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

long __wrap_syscall(long number, ...) {
    va_list arguments;
    va_start(arguments, number);
    long result = 0;
    if (number == SYSCALL_NUMBER_LANDLOCK_CREATE_RULESET) {
        /* The version probe passes a null pointer followed by a plain 0, which
         * is an int, so the size is only read once it is known to be a size_t.
         * Reading it unconditionally would read a wider type than was passed. */
        const struct landlock_ruleset_attributes *attributes =
            va_arg(arguments, const struct landlock_ruleset_attributes *);
        if (attributes == NULL) {
            /* The probe passes them as an int and an unsigned, so they are read
             * as those and not as the size_t a real create call passes. */
            int probe_size = va_arg(arguments, int);
            unsigned probe_flags = va_arg(arguments, unsigned);
            result = mock_landlock_version_probe((size_t)probe_size, probe_flags);
        }
        else {
            result = mock_create_ruleset(attributes, va_arg(arguments, size_t));
        }
    }
    else if (number == SYSCALL_NUMBER_LANDLOCK_ADD_RULE) {
        int ruleset_descriptor = va_arg(arguments, int);
        int rule_type = va_arg(arguments, int);
        const void *rule_attributes = va_arg(arguments, const void *);
        result = mock_add_rule(ruleset_descriptor, rule_type, rule_attributes);
    }
    else if (number == SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF) {
        result = mock_restrict_self(va_arg(arguments, int));
    }
    va_end(arguments);
    return result;
}

int __wrap_prctl(int option, ...) {
    (void)option;
    if (fail_prctl) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

int __wrap_chdir(const char *path) {
    remember_string(record->entered_directory, path);
    if (fail_chdir) {
        errno = ENOENT;
        return -1;
    }
    return 0;
}

int __wrap_execvp(const char *file, char *const argv[]) {
    (void)file;
    (void)argv;
    if (fail_exec) {
        errno = ENOENT;
        return -1;
    }
    _exit(0); /* stands in for a successful exec */
}

int __wrap_close(int fd) {
    if (record->closed_descriptor_count < RECORDED_RULE_LIMIT) {
        record->closed_descriptor[record->closed_descriptor_count] = fd;
    }
    record->closed_descriptor_count++;
    return 0;
}

/* ------------------------------------------------------------- test driver */

static int passed = 0;
static int failed = 0;

/* Cleared before a case rather than after it, so that the parent can still
 * read what the child handed over. */
static void reset_record(void) {
    memset(record, 0, sizeof(*record));
}

/* The child's diagnostics used to go to /dev/null, so a case could only judge
 * how a run ended, never what it said. Several mutations changed nothing else:
 * a warning that appears one version too early, a refusal that names the wrong
 * reason. The message is what a person reads when a policy is turned down, so
 * it is worth as much as the exit code. */
static FILE *captured_stderr;
static char captured_stderr_text[8192];

static void reset_captured_stderr(void) {
    captured_stderr_text[0] = '\0';
    rewind(captured_stderr);
    if (ftruncate(fileno(captured_stderr), 0) != 0) {
        perror("ftruncate");
        exit(1);
    }
}

static void collect_captured_stderr(void) {
    rewind(captured_stderr);
    size_t length =
        fread(captured_stderr_text, 1, sizeof(captured_stderr_text) - 1, captured_stderr);
    captured_stderr_text[length] = '\0';
}

static int stderr_says(const char *fragment) {
    return strstr(captured_stderr_text, fragment) != NULL;
}

/* Asked about one descriptor rather than about the whole list. A coverage build
 * links libgcov into the same binary, and the dump it makes on the way out adds
 * eight closes of its own behind the tool's. Those come last, so the tool's own
 * closes are the ones the record keeps, but the count is not the tool's to
 * promise. */
static int descriptor_was_closed(int descriptor) {
    size_t limit = record->closed_descriptor_count < RECORDED_RULE_LIMIT
                       ? record->closed_descriptor_count
                       : RECORDED_RULE_LIMIT;
    for (size_t index = 0; index < limit; index++) {
        if (record->closed_descriptor[index] == descriptor) {
            return 1;
        }
    }
    return 0;
}

static void reset_mocks(void) {
    mock_landlock_version = 8;
    mock_ruleset_descriptor = 42;
    fail_create = 0;
    fail_add_path = 0;
    fail_add_port = 0;
    fail_restrict = 0;
    fail_open = 0;
    fail_fstat = 0;
    fail_prctl = 0;
    fail_chdir = 0;
    fail_exec = 0;
    force_symlink = 0;
    force_regular_file = 0;
    force_path_descriptor_zero = 0;
    verbose = 0;
}

/* Runs sut_main in a child so that a case ending in exit() can be judged. */
static void expect_exit(const char *what, int want, char **argv) {
    reset_record();
    reset_captured_stderr();
    int argc = 0;
    while (argv[argc] != NULL) {
        argc++;
    }
    /* One child per case. gcov accumulates into the same data file, and the
     * parent adds its own counters on top when it exits, so nothing is lost.
     * longjmp would be simpler but loses counters, because it leaves the
     * normal control flow that gcov updates them on. */
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {
        if (dup2(fileno(captured_stderr), STDERR_FILENO) < 0) {
            _exit(98); /* cannot collect the child's output, so do not judge it */
        }
        sut_main(argc, argv);
        _exit(99);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    collect_captured_stderr();
    int got = WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
    if (got == want) {
        printf("  ok    %-58s exit=%d\n", what, got);
        passed++;
    } else {
        printf("  FAIL  %-58s exit=%d, expected %d\n", what, got, want);
        failed++;
    }
    reset_mocks();
}

static void check(const char *what, int condition) {
    if (condition) {
        printf("  ok    %s\n", what);
        passed++;
    } else {
        printf("  FAIL  %s\n", what);
        failed++;
    }
}

/* --------------------------------------------------------------- the cases */

/* The rights tables are pure functions of the Landlock version, so they are checked
 * directly. This is the only way to reach the branches for an version older than
 * the one this machine happens to run. */
static void test_rights_tables(void) {
    printf("\nAccess rights per Landlock version\n");
    check("version 1 has neither REFER nor TRUNCATE nor IOCTL_DEV",
          (filesystem_rights_for_version(1) &
           (LANDLOCK_ACCESS_FILESYSTEM_REFER | LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE |
            LANDLOCK_ACCESS_FILESYSTEM_IOCTL_DEVICE)) == 0);
    check("version 2 adds REFER",
          (filesystem_rights_for_version(2) & LANDLOCK_ACCESS_FILESYSTEM_REFER) != 0);
    check("version 3 adds TRUNCATE",
          (filesystem_rights_for_version(3) & LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE) != 0);
    check("version 4 adds nothing over version 3",
          filesystem_rights_for_version(4) == filesystem_rights_for_version(3));
    check("version 5 adds IOCTL_DEV",
          (filesystem_rights_for_version(5) & LANDLOCK_ACCESS_FILESYSTEM_IOCTL_DEVICE) != 0);
    check("version 8 equals version 5",
          filesystem_rights_for_version(8) == filesystem_rights_for_version(5));

    struct path_rule ro = {.path = "/x", .writable = 0, .executable = 0};
    struct path_rule rox = {.path = "/x", .writable = 0, .executable = 1};
    struct path_rule rw = {.path = "/x", .writable = 1, .executable = 0};
    check("read-only grants no write",
          (rights_granted_for(&ro, 8) & LANDLOCK_ACCESS_FILESYSTEM_WRITE_FILE) == 0);
    check("read-only grants no execute",
          (rights_granted_for(&ro, 8) & LANDLOCK_ACCESS_FILESYSTEM_EXECUTE) == 0);
    check("rox grants execute",
          (rights_granted_for(&rox, 8) & LANDLOCK_ACCESS_FILESYSTEM_EXECUTE) != 0);
    check("rw grants write", (rights_granted_for(&rw, 8) & LANDLOCK_ACCESS_FILESYSTEM_WRITE_FILE) != 0);
    check("a writable rule on version 1 grants neither REFER nor TRUNCATE",
          (rights_granted_for(&rw, 1) &
           (LANDLOCK_ACCESS_FILESYSTEM_REFER | LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE)) == 0);
    check("a writable rule on version 2 grants REFER",
          (rights_granted_for(&rw, 2) & LANDLOCK_ACCESS_FILESYSTEM_REFER) != 0);
    check("a writable rule on version 3 grants TRUNCATE",
          (rights_granted_for(&rw, 3) & LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE) != 0);
    check("a rule on version 4 is granted no IOCTL_DEV",
          (rights_granted_for(&ro, 4) & LANDLOCK_ACCESS_FILESYSTEM_IOCTL_DEVICE) == 0);
    check("a rule on version 5 is granted IOCTL_DEV",
          (rights_granted_for(&ro, 5) & LANDLOCK_ACCESS_FILESYSTEM_IOCTL_DEVICE) != 0);
    check("a granted_rights never exceeds what the version handles",
          (rights_granted_for(&rw, 1) & ~filesystem_rights_for_version(1)) == 0);

    check("version below 4 sends the smallest struct",
          ruleset_attributes_size_for_version(3) ==
              offsetof(struct landlock_ruleset_attributes, handled_access_network));
    check("version 4 and 5 send the middle struct",
          ruleset_attributes_size_for_version(4) ==
                  offsetof(struct landlock_ruleset_attributes, scoped) &&
              ruleset_attributes_size_for_version(5) == ruleset_attributes_size_for_version(4));
    check("version 6 and above send the whole struct",
          ruleset_attributes_size_for_version(6) == sizeof(struct landlock_ruleset_attributes) &&
              ruleset_attributes_size_for_version(8) == ruleset_attributes_size_for_version(6));

    check("a writable path is opened without following a symlink",
          (open_flags_for_rule(&rw) & O_NOFOLLOW) != 0);
    check("a read-only path still follows symlinks",
          (open_flags_for_rule(&ro) & O_NOFOLLOW) == 0);
}

static void test_usage_errors(void) {
    printf("\nCalls that are refused before anything is applied\n");
    char *no_args[] = {"phobos-landlock", NULL};
    expect_exit("no arguments at all", 2, no_args);
    check("a call with no arguments says how to call it", stderr_says("Usage: phobos-landlock"));

    char *unknown[] = {"phobos-landlock", "--nonsense", "x", "--", "/bin/true", NULL};
    expect_exit("an unknown option", 2, unknown);

    char *dangling[] = {"phobos-landlock", "--ro", NULL};
    expect_exit("an option whose value is missing", 2, dangling);

    /* The bounds check on the arguments is what keeps an option that reads its
     * value from reading past the end of them. */
    char *dangling_port[] = {"phobos-landlock", "--ro", "/usr", "--connect-tcp", NULL};
    expect_exit("an option that reads a value, with nothing after it", 2, dangling_port);

    char *no_cmd[] = {"phobos-landlock", "--ro", "/usr", "--", NULL};
    expect_exit("nothing to run after --", 2, no_cmd);

    char *only_verbose[] = {"phobos-landlock", "--verbose", NULL};
    expect_exit("--verbose but no command", 2, only_verbose);
}

static void test_limits(void) {
    printf("\nLimits of the fixed-size tables\n");
    static char *many[MAXIMUM_PATH_RULES * 2 + 8];
    size_t n = 0;
    many[n++] = "phobos-landlock";
    for (int r = 0; r <= MAXIMUM_PATH_RULES; r++) {
        many[n++] = "--ro";
        many[n++] = "/usr";
    }
    many[n++] = "--";
    many[n++] = "/bin/true";
    many[n] = NULL;
    expect_exit("one path rule more than the table holds", EXIT_CODE_POLICY_ERROR, many);
    /* The exit code alone did not say why. With the guard moved by one the run
     * wrote past the table and failed later, for another reason entirely, and
     * the case stayed green. */
    check("a refused table hands no rule to the kernel", record->path_rule_count == 0);

    static char *ports[MAXIMUM_PORT_RULES * 2 + 8];
    n = 0;
    ports[n++] = "phobos-landlock";
    for (int p = 0; p <= MAXIMUM_PORT_RULES; p++) {
        ports[n++] = "--connect-tcp";
        ports[n++] = "443";
    }
    ports[n++] = "--";
    ports[n++] = "/bin/true";
    ports[n] = NULL;
    expect_exit("one connect port more than the table holds", EXIT_CODE_POLICY_ERROR, ports);

    static char *binds[MAXIMUM_PORT_RULES * 2 + 8];
    n = 0;
    binds[n++] = "phobos-landlock";
    for (int p = 0; p <= MAXIMUM_PORT_RULES; p++) {
        binds[n++] = "--bind-tcp";
        binds[n++] = "8080";
    }
    binds[n++] = "--";
    binds[n++] = "/bin/true";
    binds[n] = NULL;
    expect_exit("one bind port more than the table holds", EXIT_CODE_POLICY_ERROR, binds);
}

static void test_version_gate(void) {
    printf("\nWhat the kernel can enforce\n");
    char *plain[] = {"phobos-landlock", "--ro", "/usr", "--", "/bin/true", NULL};

    mock_landlock_version = -1;
    expect_exit("no Landlock at all refuses to run", EXIT_CODE_POLICY_ERROR, plain);
    check("a kernel without Landlock is named as the reason",
          stderr_says("[phobos-landlock] Landlock is not available on this kernel"));

    /* Version 0 is a kernel that answers the question but has nothing to
     * offer. It is too old, which is not the same as having no Landlock, and
     * the two must not be reported as one another. */
    mock_landlock_version = 0;
    expect_exit("a kernel offering version 0 refuses to run", EXIT_CODE_POLICY_ERROR, plain);
    check("version 0 is reported as too old rather than as absent",
          stderr_says("kernel offers Landlock version 0 but version 1 is required"));

    /* The demanded version has to be one this build knows, otherwise it is
     * refused while the arguments are read and the comparison below is never
     * reached. */
    char *demanding[] = {"phobos-landlock",
                         "--minimum-landlock-version",
                         "5",
                         "--ro",
                         "/usr",
                         "--",
                         "/bin/true",
                         NULL};
    mock_landlock_version = 3;
    expect_exit("a kernel below the demanded version refuses to run", EXIT_CODE_POLICY_ERROR,
                demanding);
    check("the refusal names both the version there is and the one that was asked for",
          stderr_says("kernel offers Landlock version 3 but version 5 is required"));

    char *lenient[] = {"phobos-landlock",
                       "--minimum-landlock-version",
                       "1",
                       "--ro",
                       "/usr",
                       "--",
                       "/bin/true",
                       NULL};
    mock_landlock_version = 8;
    expect_exit("--minimum-landlock-version below the kernel runs", 0, lenient);

    mock_landlock_version = 99;
    expect_exit("a version newer than this build warns but runs", 0, plain);
    check("a newer kernel is reported as only partly restricted",
          stderr_says("warning: kernel offers Landlock version 99"));

    char *net[] = {
        "phobos-landlock", "--connect-tcp", "443", "--ro", "/usr", "--", "/bin/true", NULL};
    mock_landlock_version = 3;
    expect_exit("network rules on an version below 4 refuse to run", EXIT_CODE_POLICY_ERROR,
                net);

    mock_landlock_version = 3;
    expect_exit("an old version without network rules still runs", 0, plain);
}

/* Numbers that are not numbers, or outside what the option can mean. Before
 * these were checked, atoi answered 0 and a typo quietly weakened the policy. */
static void test_number_parsing(void) {
    printf("\nValues that are not usable numbers\n");
    char *not_a_number[] = {"phobos-landlock", "--connect-tcp", "https", "--ro",
                            "/usr", "--", "/bin/true", NULL};
    expect_exit("a port that is not a number", EXIT_CODE_POLICY_ERROR, not_a_number);
    check("the refusal quotes what was given", stderr_says("not a TCP port: 'https'"));

    char *empty[] = {"phobos-landlock", "--connect-tcp", "", "--ro",
                     "/usr", "--", "/bin/true", NULL};
    expect_exit("an empty port value", EXIT_CODE_POLICY_ERROR, empty);
    /* Only that message. Without the abort behind it the value would fall
     * through to the conversion, which reports the same input a second time
     * and as something else. */
    check("an empty value is named as empty, and only that",
          stderr_says("not a TCP port: empty value") && !stderr_says("not a TCP port: ''"));

    char *trailing[] = {"phobos-landlock", "--connect-tcp", "443x", "--ro",
                        "/usr", "--", "/bin/true", NULL};
    expect_exit("a port with something after the digits", EXIT_CODE_POLICY_ERROR, trailing);

    char *too_low[] = {"phobos-landlock", "--connect-tcp", "0", "--ro",
                       "/usr", "--", "/bin/true", NULL};
    expect_exit("port zero", EXIT_CODE_POLICY_ERROR, too_low);

    char *too_high[] = {"phobos-landlock", "--connect-tcp", "65536", "--ro",
                        "/usr", "--", "/bin/true", NULL};
    expect_exit("a port above 65535", EXIT_CODE_POLICY_ERROR, too_high);

    char *overflowing[] = {"phobos-landlock", "--connect-tcp", "99999999999999999999",
                           "--ro", "/usr", "--", "/bin/true", NULL};
    expect_exit("a port that overflows the conversion", EXIT_CODE_POLICY_ERROR, overflowing);

    char *bad_version[] = {"phobos-landlock", "--minimum-landlock-version", "none",
                           "--ro", "/usr", "--", "/bin/true", NULL};
    expect_exit("a version that is not a number", EXIT_CODE_POLICY_ERROR, bad_version);
    check("the refusal names the option it came from",
          stderr_says("not a usable Landlock version: 'none'"));

    char *unknown_version[] = {"phobos-landlock", "--minimum-landlock-version", "99",
                               "--ro", "/usr", "--", "/bin/true", NULL};
    expect_exit("a version this build does not know", EXIT_CODE_POLICY_ERROR, unknown_version);
}

/* The four path flags are all at least four characters, so a shorter one can
 * only come from a future edit. The guard says so rather than reading before
 * the start of the string. */
static void test_short_flag_guard(void) {
    printf("\nA path rule flag that is too short\n");
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {
        if (freopen("/dev/null", "w", stderr) == NULL) {
            _exit(98);
        }
        static struct options options;
        memset(&options, 0, sizeof(options));
        remember_path_rule(&options, "--r", "/usr");
        _exit(99);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    int got = WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
    check("a flag shorter than --ro is refused", got == EXIT_CODE_POLICY_ERROR);
}

static void test_syscall_failures(void) {
    printf("\nEvery syscall that can fail, failing\n");
    char *plain[] = {"phobos-landlock", "--ro", "/usr", "--", "/bin/true", NULL};
    char *writable[] = {"phobos-landlock", "--rw", "/tmp", "--", "/bin/true", NULL};
    char *net[] = {"phobos-landlock",
                   "--connect-tcp",
                   "443",
                   "--bind-tcp",
                   "8080",
                   "--ro",
                   "/usr",
                   "--",
                   "/bin/true",
                   NULL};
    char *moving[] = {"phobos-landlock", "--chdir", "/tmp", "--ro", "/usr", "--",
                      "/bin/true",       NULL};

    fail_create = 1;
    expect_exit("creating the ruleset fails", EXIT_CODE_POLICY_ERROR, plain);
    check("the failing call and the reason are both named",
          stderr_says("[phobos-landlock] landlock_create_ruleset: Invalid argument"));

    char *missing[] = {"phobos-landlock", "--ro", "/no/such/path/at/all", "--",
                       "/bin/true",       NULL};
    expect_exit("a path on the allow-list does not exist", EXIT_CODE_POLICY_ERROR, missing);
    check("the path that could not be opened is named",
          stderr_says("cannot open /no/such/path/at/all: No such file or directory"));

    fail_fstat = 1;
    expect_exit("stat on an opened path fails", EXIT_CODE_POLICY_ERROR, plain);
    check("a failing fstat is named", stderr_says("[phobos-landlock] fstat: Input/output error"));

    force_symlink = 1;
    expect_exit("a writable path that is a symlink is refused", EXIT_CODE_POLICY_ERROR,
                writable);
    check("the refusal explains that a link could redirect the rule",
          stderr_says("refusing writable path /tmp: it is a symbolic link"));

    fail_add_path = 1;
    expect_exit("the kernel rejects a path rule", EXIT_CODE_POLICY_ERROR, plain);
    check("the rejected rule is named with its path",
          stderr_says("add_rule failed for /usr: Invalid argument"));

    fail_add_port = 1;
    expect_exit("the kernel rejects a port rule", EXIT_CODE_POLICY_ERROR, net);
    check("the rejected port rule is named by its direction",
          stderr_says("[phobos-landlock] connect: Invalid argument"));

    fail_chdir = 1;
    expect_exit("--chdir names a directory that cannot be entered", EXIT_CODE_POLICY_ERROR,
                moving);
    check("the directory that could not be entered is named",
          stderr_says("chdir /tmp: No such file or directory"));

    fail_prctl = 1;
    expect_exit("no_new_privs cannot be set", EXIT_CODE_POLICY_ERROR, plain);
    check("the call that could not be made is named",
          stderr_says("prctl(PR_SET_NO_NEW_PRIVS): Operation not permitted"));

    fail_restrict = 1;
    expect_exit("the restriction itself is refused", EXIT_CODE_POLICY_ERROR, plain);
    check("the refused restriction is named",
          stderr_says("landlock_restrict_self: Operation not permitted"));

    fail_exec = 1;
    expect_exit("the command cannot be executed", 127, plain);
    check("the command that could not be run is named",
          stderr_says("exec /bin/true: No such file or directory"));
}

static void test_success_paths(void) {
    printf("\nCalls that go all the way through\n");
    char *ro[] = {"phobos-landlock", "--ro", "/usr", "--", "/bin/true", NULL};
    expect_exit("a read-only rule", 0, ro);
    /* Nothing at all, which is also how a kernel exactly at the highest known
     * version proves it triggers no warning about unrestricted rights. */
    check("a run that goes through says nothing", captured_stderr_text[0] == '\0');

    char *rox[] = {"phobos-landlock", "--rox", "/usr", "--", "/bin/true", NULL};
    expect_exit("a read-and-execute rule", 0, rox);

    char *rw[] = {"phobos-landlock", "--rw", "/tmp", "--", "/bin/true", NULL};
    expect_exit("a writable rule", 0, rw);

    char *rwx[] = {"phobos-landlock", "--rwx", "/tmp", "--", "/bin/true", NULL};
    expect_exit("a writable-and-executable rule", 0, rwx);

    char *ports[] = {"phobos-landlock",
                     "--connect-tcp",
                     "443",
                     "--bind-tcp",
                     "8080",
                     "--ro",
                     "/usr",
                     "--",
                     "/bin/true",
                     NULL};
    expect_exit("both kinds of port rule", 0, ports);

    /* Only a bind rule: the network handling must switch on for that alone,
     * not just when a connect rule is present. */
    char *bind_only[] = {"phobos-landlock", "--bind-tcp", "8080", "--ro", "/usr", "--",
                         "/bin/true",       NULL};
    expect_exit("a bind rule on its own", 0, bind_only);

    char *chdir_ok[] = {"phobos-landlock", "--chdir", "/tmp", "--ro", "/usr", "--",
                        "/bin/true",       NULL};
    expect_exit("a working directory that can be entered", 0, chdir_ok);

    char *loud[] = {"phobos-landlock",
                    "--verbose",
                    "--ro",
                    "/usr",
                    "--rw",
                    "/tmp",
                    "--connect-tcp",
                    "443",
                    "--bind-tcp",
                    "8080",
                    "--",
                    "/bin/true",
                    NULL};
    expect_exit("--verbose reports every rule", 0, loud);
    check("--verbose names the version that was found", stderr_says("Landlock version 8"));
    check("--verbose names each path rule with its rights",
          stderr_says("allow /usr\n") && stderr_says("allow /tmp +w"));
    check("--verbose names each port rule with its direction",
          stderr_says("allow connect tcp/443") && stderr_says("allow bind tcp/8080"));

    char *bare[] = {"phobos-landlock", "--", "/bin/true", NULL};
    expect_exit("no rules at all, only a command", 0, bare);

    /* A rule on a file must drop the rights that only exist for directories,
     * or the kernel rejects it. */
    force_regular_file = 1;
    char *on_file[] = {"phobos-landlock", "--ro", "/etc/hostname", "--", "/bin/true", NULL};
    expect_exit("a rule on a file rather than a directory", 0, on_file);
}

/* Whether the calls happen was already covered. What they carry was not, and
 * that is the policy itself: mutation testing could give a file the rights only
 * a directory may hold, drop a port rule, or cut the rule loop to its first
 * turn, and every case stayed green. */
static void test_what_reaches_the_kernel(void) {
    printf("\nWhat the kernel is actually handed\n");
    char *read_only[] = {"phobos-landlock", "--ro", "/usr", "--", "/bin/true", NULL};
    struct path_rule read_only_rule = {.path = "/usr", .writable = 0, .executable = 0};

    expect_exit("a read-only rule runs", 0, read_only);
    check("the ruleset handles everything version 8 knows",
          record->handled_access_filesystem == filesystem_rights_for_version(8));
    check("the ruleset is sent at the size version 8 expects",
          record->ruleset_attributes_size == ruleset_attributes_size_for_version(8));
    check("without a port rule the ruleset handles no network access",
          record->handled_access_network == 0);
    check("exactly one rule reaches the kernel", record->path_rule_count == 1);
    check("the rule carries the read-only rights and nothing besides",
          record->path_rule_allowed_access[0] == rights_granted_for(&read_only_rule, 8));
    check("the rule is opened on the path that was asked for",
          strcmp(record->opened_path[0], "/usr") == 0);
    check("rule and restriction use the ruleset the kernel handed out",
          record->rule_ruleset_descriptor == 42 && record->restricted_ruleset_descriptor == 42);

    char *three[] = {"phobos-landlock", "--ro", "/usr",       "--rw", "/tmp", "--rox",
                     "/bin",            "--",   "/bin/true",  NULL};
    struct path_rule writable_rule = {.path = "/tmp", .writable = 1, .executable = 0};
    struct path_rule executable_rule = {.path = "/bin", .writable = 0, .executable = 1};
    expect_exit("three rules of three kinds run", 0, three);
    check("every rule reaches the kernel", record->path_rule_count == 3);
    check("each rule carries its own rights, in the order they were given",
          record->path_rule_allowed_access[0] == rights_granted_for(&read_only_rule, 8) &&
              record->path_rule_allowed_access[1] == rights_granted_for(&writable_rule, 8) &&
              record->path_rule_allowed_access[2] == rights_granted_for(&executable_rule, 8));

    force_regular_file = 1;
    char *on_file[] = {"phobos-landlock", "--rwx", "/etc/hostname", "--", "/bin/true", NULL};
    struct path_rule file_rule = {.path = "/etc/hostname", .writable = 1, .executable = 1};
    expect_exit("a rule on a file runs", 0, on_file);
    check("a file is granted no right that only a directory can hold",
          (record->path_rule_allowed_access[0] & DIRECTORY_ONLY_ACCESS_RIGHTS) == 0);
    check("a file is granted every other right the rule asked for",
          record->path_rule_allowed_access[0] ==
              (rights_granted_for(&file_rule, 8) & ~DIRECTORY_ONLY_ACCESS_RIGHTS));
    check("a file still keeps the rights it can use",
          (record->path_rule_allowed_access[0] & LANDLOCK_ACCESS_FILESYSTEM_READ_FILE) != 0);

    char *ports[] = {"phobos-landlock", "--connect-tcp", "443", "--bind-tcp", "8080",
                     "--ro",            "/usr",          "--",  "/bin/true",  NULL};
    expect_exit("a connect and a bind rule run", 0, ports);
    check("both port rules reach the kernel", record->port_rule_count == 2);
    check("the connect rule names the port that was asked for",
          record->port_rule_port[0] == 443 &&
              record->port_rule_allowed_access[0] == LANDLOCK_ACCESS_NETWORK_CONNECT_TCP);
    check("the bind rule names the port that was asked for",
          record->port_rule_port[1] == 8080 &&
              record->port_rule_allowed_access[1] == LANDLOCK_ACCESS_NETWORK_BIND_TCP);
    check("the ruleset handles both directions of network access",
          record->handled_access_network ==
              (LANDLOCK_ACCESS_NETWORK_BIND_TCP | LANDLOCK_ACCESS_NETWORK_CONNECT_TCP));

    char *two_connects[] = {"phobos-landlock", "--connect-tcp", "443", "--connect-tcp",
                            "8443",            "--ro",          "/usr", "--",
                            "/bin/true",       NULL};
    expect_exit("two connect rules run", 0, two_connects);
    check("both connect ports reach the kernel, in the order they were given",
          record->port_rule_count == 2 && record->port_rule_port[0] == 443 &&
              record->port_rule_port[1] == 8443);

    char *two_binds[] = {"phobos-landlock", "--bind-tcp", "8080", "--bind-tcp",
                         "9090",            "--ro",       "/usr", "--",
                         "/bin/true",       NULL};
    expect_exit("two bind rules run", 0, two_binds);
    check("both bind ports reach the kernel, in the order they were given",
          record->port_rule_count == 2 && record->port_rule_port[0] == 8080 &&
              record->port_rule_port[1] == 9090);

    mock_landlock_version = 3;
    expect_exit("an older kernel runs", 0, read_only);
    check("the ruleset handles only what version 3 knows",
          record->handled_access_filesystem == filesystem_rights_for_version(3));
    check("the ruleset is sent at the size version 3 expects",
          record->ruleset_attributes_size == ruleset_attributes_size_for_version(3));
    check("the rule carries only rights version 3 knows",
          record->path_rule_allowed_access[0] == rights_granted_for(&read_only_rule, 3));

    char *moving[] = {"phobos-landlock", "--chdir", "/tmp", "--ro", "/usr", "--",
                      "/bin/true",       NULL};
    expect_exit("a working directory is entered", 0, moving);
    check("the directory that was asked for is the one entered",
          strcmp(record->entered_directory, "/tmp") == 0);
}

/* Each of these sits exactly on a limit. A comparison moved by one is invisible
 * everywhere else, and descriptor 0 is the value most easily mistaken for a
 * failure. */
static void test_boundaries(void) {
    printf("\nValues that sit exactly on a limit\n");
    char *read_only[] = {"phobos-landlock", "--ro", "/usr", "--", "/bin/true", NULL};

    char *highest_port[] = {"phobos-landlock", "--connect-tcp", "65535",     "--ro",
                            "/usr",            "--",            "/bin/true", NULL};
    expect_exit("the highest port there is", 0, highest_port);
    check("the highest port reaches the kernel unchanged",
          record->port_rule_count == 1 && record->port_rule_port[0] == 65535);

    /* Written out from the header rather than as a literal, so that raising the
     * highest known version keeps testing the boundary rather than a number
     * that has fallen below it. */
    static char highest_version_text[16];
    snprintf(highest_version_text, sizeof(highest_version_text), "%d",
             HIGHEST_KNOWN_LANDLOCK_VERSION);
    char *highest_version[] = {"phobos-landlock",     "--minimum-landlock-version",
                               highest_version_text,  "--ro",
                               "/usr",                "--",
                               "/bin/true",           NULL};
    mock_landlock_version = HIGHEST_KNOWN_LANDLOCK_VERSION;
    expect_exit("a kernel exactly at the demanded version", 0, highest_version);

    char *network[] = {"phobos-landlock", "--connect-tcp", "443",       "--ro",
                       "/usr",            "--",            "/bin/true", NULL};
    mock_landlock_version = 4;
    expect_exit("version 4 is new enough for network rules", 0, network);

    mock_ruleset_descriptor = 0;
    expect_exit("a ruleset created as descriptor 0", 0, read_only);
    check("descriptor 0 is used rather than read as a failure",
          record->rule_ruleset_descriptor == 0 && record->restricted_ruleset_descriptor == 0);

    force_path_descriptor_zero = 1;
    expect_exit("a path opened as descriptor 0", 0, read_only);
    check("the rule points at the descriptor the path was opened with",
          record->path_rule_parent_fd[0] == 0);
    check("the path descriptor is closed again", descriptor_was_closed(0));
    check("the ruleset descriptor is closed again", descriptor_was_closed(42));

    /* A table filled to the brim must still be accepted whole. Handing out
     * descriptor 0 keeps this from opening four thousand real files. */
    static char *full[MAXIMUM_PATH_RULES * 2 + 4];
    size_t word_count = 0;
    full[word_count++] = "phobos-landlock";
    for (int rule_index = 0; rule_index < MAXIMUM_PATH_RULES; rule_index++) {
        full[word_count++] = "--ro";
        full[word_count++] = "/usr";
    }
    full[word_count++] = "--";
    full[word_count++] = "/bin/true";
    full[word_count] = NULL;
    force_path_descriptor_zero = 1;
    expect_exit("exactly as many path rules as the table holds", 0, full);
    check("every rule of a full table reaches the kernel",
          record->path_rule_count == MAXIMUM_PATH_RULES);
}

/* A non-directory has to lose the rights that only apply to directories, or
 * the kernel rejects the rule. */
static void test_file_versus_directory(void) {
    printf("\nA file is not a directory\n");
    check("directory-only rights are named",
          (DIRECTORY_ONLY_ACCESS_RIGHTS & LANDLOCK_ACCESS_FILESYSTEM_READ_DIRECTORY) != 0 &&
              (DIRECTORY_ONLY_ACCESS_RIGHTS & LANDLOCK_ACCESS_FILESYSTEM_MAKE_DIRECTORY) != 0);
    check("directory-only rights exclude reading a file",
          (DIRECTORY_ONLY_ACCESS_RIGHTS & LANDLOCK_ACCESS_FILESYSTEM_READ_FILE) == 0);
    check("directory-only rights exclude executing",
          (DIRECTORY_ONLY_ACCESS_RIGHTS & LANDLOCK_ACCESS_FILESYSTEM_EXECUTE) == 0);
}

int main(void) {
    record = mmap(NULL, sizeof(*record), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (record == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    reset_record();
    captured_stderr = tmpfile();
    if (captured_stderr == NULL) {
        perror("tmpfile");
        return 1;
    }
    printf("phobos-landlock unit tests\n");
    test_rights_tables();
    test_file_versus_directory();
    test_usage_errors();
    test_limits();
    test_version_gate();
    test_number_parsing();
    test_short_flag_guard();
    test_syscall_failures();
    test_success_paths();
    test_what_reaches_the_kernel();
    test_boundaries();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
