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
#define main sut_main
#include "../../core/phobos-landlock.c"
#undef main

#include <sys/wait.h>

/* ------------------------------------------------------------------- mocks */

static long mock_abi = 8; /* what the kernel reports */
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

int __real_open(const char *path, int flags, ...);
int __wrap_open(const char *path, int flags, ...) {
    if (fail_open) {
        errno = EACCES;
        return -1;
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

long __wrap_syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    void *a1 = va_arg(ap, void *);
    size_t a2 = va_arg(ap, size_t);
    unsigned a3 = va_arg(ap, unsigned);
    va_end(ap);

    if (number == __NR_landlock_create_ruleset) {
        if (a1 == NULL && a2 == 0 && a3 == LANDLOCK_CREATE_RULESET_VERSION) {
            if (mock_abi < 0) {
                errno = ENOSYS;
                return -1;
            }
            return mock_abi;
        }
        if (fail_create) {
            errno = EINVAL;
            return -1;
        }
        return 42; /* a plausible descriptor */
    }
    if (number == __NR_landlock_add_rule) {
        int type = (int)(size_t)a2;
        if (type == LANDLOCK_RULE_PATH_BENEATH && fail_add_path) {
            errno = EINVAL;
            return -1;
        }
        if (type == LANDLOCK_RULE_NET_PORT && fail_add_port) {
            errno = EINVAL;
            return -1;
        }
        return 0;
    }
    if (number == __NR_landlock_restrict_self) {
        if (fail_restrict) {
            errno = EPERM;
            return -1;
        }
        return 0;
    }
    return 0;
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
    (void)path;
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
    (void)fd;
    return 0;
}

/* ------------------------------------------------------------- test driver */

static int passed = 0;
static int failed = 0;

static void reset_mocks(void) {
    mock_abi = 8;
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
    verbose = 0;
}

/* Runs sut_main in a child so that a case ending in exit() can be judged. */
static void expect_exit(const char *what, int want, char **argv) {
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
        if (freopen("/dev/null", "w", stderr) == NULL) {
            _exit(98); /* cannot silence the child, so do not judge its output */
        }
        sut_main(argc, argv);
        _exit(99);
    }
    int status = 0;
    waitpid(pid, &status, 0);
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
           (LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE |
            LANDLOCK_ACCESS_FS_IOCTL_DEV)) == 0);
    check("version 2 adds REFER",
          (filesystem_rights_for_version(2) & LANDLOCK_ACCESS_FS_REFER) != 0);
    check("version 3 adds TRUNCATE",
          (filesystem_rights_for_version(3) & LANDLOCK_ACCESS_FS_TRUNCATE) != 0);
    check("version 4 adds nothing over version 3",
          filesystem_rights_for_version(4) == filesystem_rights_for_version(3));
    check("version 5 adds IOCTL_DEV",
          (filesystem_rights_for_version(5) & LANDLOCK_ACCESS_FS_IOCTL_DEV) != 0);
    check("version 8 equals version 5",
          filesystem_rights_for_version(8) == filesystem_rights_for_version(5));

    struct path_rule ro = {.path = "/x", .writable = 0, .executable = 0};
    struct path_rule rox = {.path = "/x", .writable = 0, .executable = 1};
    struct path_rule rw = {.path = "/x", .writable = 1, .executable = 0};
    check("read-only grants no write",
          (rights_granted_for(&ro, 8) & LANDLOCK_ACCESS_FS_WRITE_FILE) == 0);
    check("read-only grants no execute",
          (rights_granted_for(&ro, 8) & LANDLOCK_ACCESS_FS_EXECUTE) == 0);
    check("rox grants execute",
          (rights_granted_for(&rox, 8) & LANDLOCK_ACCESS_FS_EXECUTE) != 0);
    check("rw grants write", (rights_granted_for(&rw, 8) & LANDLOCK_ACCESS_FS_WRITE_FILE) != 0);
    check("a writable rule on version 1 grants neither REFER nor TRUNCATE",
          (rights_granted_for(&rw, 1) &
           (LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE)) == 0);
    check("a writable rule on version 2 grants REFER",
          (rights_granted_for(&rw, 2) & LANDLOCK_ACCESS_FS_REFER) != 0);
    check("a writable rule on version 3 grants TRUNCATE",
          (rights_granted_for(&rw, 3) & LANDLOCK_ACCESS_FS_TRUNCATE) != 0);
    check("a granted_rights never exceeds what the version handles",
          (rights_granted_for(&rw, 1) & ~filesystem_rights_for_version(1)) == 0);

    check("version below 4 sends the smallest struct",
          ruleset_attributes_size_for_version(3) ==
              offsetof(struct landlock_ruleset_attr, handled_access_net));
    check("version 4 and 5 send the middle struct",
          ruleset_attributes_size_for_version(4) ==
                  offsetof(struct landlock_ruleset_attr, scoped) &&
              ruleset_attributes_size_for_version(5) == ruleset_attributes_size_for_version(4));
    check("version 6 and above send the whole struct",
          ruleset_attributes_size_for_version(6) == sizeof(struct landlock_ruleset_attr) &&
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

    char *unknown[] = {"phobos-landlock", "--nonsense", "x", "--", "/bin/true", NULL};
    expect_exit("an unknown option", 2, unknown);

    char *dangling[] = {"phobos-landlock", "--ro", NULL};
    expect_exit("an option whose value is missing", 2, dangling);

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

static void test_abi_gate(void) {
    printf("\nWhat the kernel can enforce\n");
    char *plain[] = {"phobos-landlock", "--ro", "/usr", "--", "/bin/true", NULL};

    mock_abi = -1;
    expect_exit("no Landlock at all refuses to run", EXIT_CODE_POLICY_ERROR, plain);

    char *demanding[] = {"phobos-landlock",
                         "--minimum-landlock-version",
                         "9",
                         "--ro",
                         "/usr",
                         "--",
                         "/bin/true",
                         NULL};
    mock_abi = 8;
    expect_exit("--minimum-landlock-version above the kernel refuses to run",
                EXIT_CODE_POLICY_ERROR, demanding);

    char *lenient[] = {"phobos-landlock",
                       "--minimum-landlock-version",
                       "1",
                       "--ro",
                       "/usr",
                       "--",
                       "/bin/true",
                       NULL};
    mock_abi = 8;
    expect_exit("--minimum-landlock-version below the kernel runs", 0, lenient);

    mock_abi = 99;
    expect_exit("a version newer than this build warns but runs", 0, plain);

    char *net[] = {
        "phobos-landlock", "--connect-tcp", "443", "--ro", "/usr", "--", "/bin/true", NULL};
    mock_abi = 3;
    expect_exit("network rules on an version below 4 refuse to run", EXIT_CODE_POLICY_ERROR,
                net);

    mock_abi = 3;
    expect_exit("an old version without network rules still runs", 0, plain);
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

    char *missing[] = {"phobos-landlock", "--ro", "/no/such/path/at/all", "--",
                       "/bin/true",       NULL};
    expect_exit("a path on the allow-list does not exist", EXIT_CODE_POLICY_ERROR, missing);

    fail_fstat = 1;
    expect_exit("stat on an opened path fails", EXIT_CODE_POLICY_ERROR, plain);

    force_symlink = 1;
    expect_exit("a writable path that is a symlink is refused", EXIT_CODE_POLICY_ERROR,
                writable);

    fail_add_path = 1;
    expect_exit("the kernel rejects a path rule", EXIT_CODE_POLICY_ERROR, plain);

    fail_add_port = 1;
    expect_exit("the kernel rejects a port rule", EXIT_CODE_POLICY_ERROR, net);

    fail_chdir = 1;
    expect_exit("--chdir names a directory that cannot be entered", EXIT_CODE_POLICY_ERROR,
                moving);

    fail_prctl = 1;
    expect_exit("no_new_privs cannot be set", EXIT_CODE_POLICY_ERROR, plain);

    fail_restrict = 1;
    expect_exit("the restriction itself is refused", EXIT_CODE_POLICY_ERROR, plain);

    fail_exec = 1;
    expect_exit("the command cannot be executed", 127, plain);
}

static void test_success_paths(void) {
    printf("\nCalls that go all the way through\n");
    char *ro[] = {"phobos-landlock", "--ro", "/usr", "--", "/bin/true", NULL};
    expect_exit("a read-only rule", 0, ro);

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

    char *bare[] = {"phobos-landlock", "--", "/bin/true", NULL};
    expect_exit("no rules at all, only a command", 0, bare);

    /* A rule on a file must drop the rights that only exist for directories,
     * or the kernel rejects it. */
    force_regular_file = 1;
    char *on_file[] = {"phobos-landlock", "--ro", "/etc/hostname", "--", "/bin/true", NULL};
    expect_exit("a rule on a file rather than a directory", 0, on_file);
}

/* A non-directory has to lose the rights that only apply to directories, or
 * the kernel rejects the rule. */
static void test_file_versus_directory(void) {
    printf("\nA file is not a directory\n");
    check("directory-only rights are named",
          (DIRECTORY_ONLY_ACCESS_RIGHTS & LANDLOCK_ACCESS_FS_READ_DIR) != 0 &&
              (DIRECTORY_ONLY_ACCESS_RIGHTS & LANDLOCK_ACCESS_FS_MAKE_DIR) != 0);
    check("directory-only rights exclude reading a file",
          (DIRECTORY_ONLY_ACCESS_RIGHTS & LANDLOCK_ACCESS_FS_READ_FILE) == 0);
    check("directory-only rights exclude executing",
          (DIRECTORY_ONLY_ACCESS_RIGHTS & LANDLOCK_ACCESS_FS_EXECUTE) == 0);
}

int main(void) {
    printf("phobos-landlock unit tests\n");
    test_rights_tables();
    test_file_versus_directory();
    test_usage_errors();
    test_limits();
    test_abi_gate();
    test_syscall_failures();
    test_success_paths();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
