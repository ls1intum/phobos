/*
 * phobos-landlock -- apply a Landlock filesystem policy, then exec a command.
 *
 * Replaces bubblewrap as the enforcement mechanism of the Phobos filesystem
 * layer. Needs no privileges, no capabilities and no container flags: a task
 * may always restrict itself further.
 *
 * Usage:
 *   phobos-landlock [--ro P] [--rox P] [--rw P] [--rwx P]
 *                   [--connect-tcp N] [--bind-tcp N]
 *                   [--chdir D] [--min-abi N] [--verbose] -- CMD [ARGS...]
 *
 * Exits 125 on any policy error. It never degrades silently: if the running
 * kernel cannot enforce the requested minimum, it refuses to run the command.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#define LANDLOCK_RULE_PATH_BENEATH 1
#define LANDLOCK_RULE_NET_PORT 2

/* Filesystem access rights, ABI 1 unless noted. */
#define LL_FS_EXECUTE (1ULL << 0)
#define LL_FS_WRITE_FILE (1ULL << 1)
#define LL_FS_READ_FILE (1ULL << 2)
#define LL_FS_READ_DIR (1ULL << 3)
#define LL_FS_REMOVE_DIR (1ULL << 4)
#define LL_FS_REMOVE_FILE (1ULL << 5)
#define LL_FS_MAKE_CHAR (1ULL << 6)
#define LL_FS_MAKE_DIR (1ULL << 7)
#define LL_FS_MAKE_REG (1ULL << 8)
#define LL_FS_MAKE_SOCK (1ULL << 9)
#define LL_FS_MAKE_FIFO (1ULL << 10)
#define LL_FS_MAKE_BLOCK (1ULL << 11)
#define LL_FS_MAKE_SYM (1ULL << 12)
#define LL_FS_REFER (1ULL << 13)    /* ABI 2 */
#define LL_FS_TRUNCATE (1ULL << 14) /* ABI 3 */
#define LL_FS_IOCTL_DEV (1ULL << 15) /* ABI 5 */

/* Network access rights, ABI 4. */
#define LL_NET_BIND_TCP (1ULL << 0)
#define LL_NET_CONNECT_TCP (1ULL << 1)

/* Rights that only make sense on a directory. */
#define LL_DIR_ONLY                                                            \
    (LL_FS_READ_DIR | LL_FS_REMOVE_DIR | LL_FS_REMOVE_FILE | LL_FS_MAKE_CHAR |  \
     LL_FS_MAKE_DIR | LL_FS_MAKE_REG | LL_FS_MAKE_SOCK | LL_FS_MAKE_FIFO |      \
     LL_FS_MAKE_BLOCK | LL_FS_MAKE_SYM | LL_FS_REFER)

#define EXIT_POLICY 125
#define MAX_RULES 4096
#define MAX_PORTS 64

/* Highest ABI whose access rights this tool enumerates. A newer kernel may
 * define rights we do not list in handled_access_fs, which would leave them
 * unrestricted, so say so loudly rather than pretending the policy is whole. */
#define LANDLOCK_ABI_KNOWN 8

struct landlock_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
    uint64_t scoped;
};

struct landlock_path_beneath_attr {
    uint64_t allowed_access;
    int32_t parent_fd;
} __attribute__((packed));

struct landlock_net_port_attr {
    uint64_t allowed_access;
    uint64_t port;
};

struct path_rule {
    const char *path;
    int write;
    int exec;
};

/* Writable paths are the ones an attacker profits from redirecting, and they
 * are the ones that may sit in a directory the supervised code can write. So
 * refuse a symlink as the final component there. Read-only paths still follow
 * symlinks, because system paths legitimately are ones (/lib -> /usr/lib). */
static int open_flags_for(const struct path_rule *rule) {
    int flags = O_PATH | O_CLOEXEC;
    if (rule->write) {
        flags |= O_NOFOLLOW;
    }
    return flags;
}

static int verbose = 0;

static void vlog(const char *fmt, ...) {
    if (!verbose) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[phobos-landlock] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static void fail(const char *msg) {
    fprintf(stderr, "[phobos-landlock] %s: %s\n", msg, strerror(errno));
    exit(EXIT_POLICY);
}

static void fail_msg(const char *msg) {
    fprintf(stderr, "[phobos-landlock] %s\n", msg);
    exit(EXIT_POLICY);
}

/* Rights available at the given ABI level. */
static uint64_t fs_rights_for_abi(int abi) {
    uint64_t rights = LL_FS_EXECUTE | LL_FS_WRITE_FILE | LL_FS_READ_FILE |
                   LL_FS_READ_DIR | LL_FS_REMOVE_DIR | LL_FS_REMOVE_FILE |
                   LL_FS_MAKE_CHAR | LL_FS_MAKE_DIR | LL_FS_MAKE_REG |
                   LL_FS_MAKE_SOCK | LL_FS_MAKE_FIFO | LL_FS_MAKE_BLOCK |
                   LL_FS_MAKE_SYM;
    if (abi >= 2) {
        rights |= LL_FS_REFER;
    }
    if (abi >= 3) {
        rights |= LL_FS_TRUNCATE;
    }
    if (abi >= 5) {
        rights |= LL_FS_IOCTL_DEV;
    }
    return rights;
}

/* Rights granted for one allow-listed path. */
static uint64_t grant_for(const struct path_rule *rule, int abi) {
    uint64_t grant = LL_FS_READ_FILE | LL_FS_READ_DIR;
    if (rule->exec) {
        grant |= LL_FS_EXECUTE;
    }
    if (rule->write) {
        grant |= LL_FS_WRITE_FILE | LL_FS_REMOVE_DIR | LL_FS_REMOVE_FILE |
                 LL_FS_MAKE_CHAR | LL_FS_MAKE_DIR | LL_FS_MAKE_REG |
                 LL_FS_MAKE_SOCK | LL_FS_MAKE_FIFO | LL_FS_MAKE_BLOCK |
                 LL_FS_MAKE_SYM;
        if (abi >= 2) {
            grant |= LL_FS_REFER;
        }
        if (abi >= 3) {
            grant |= LL_FS_TRUNCATE;
        }
    }
    if (abi >= 5) {
        grant |= LL_FS_IOCTL_DEV;
    }
    return grant & fs_rights_for_abi(abi);
}

static void usage(void) {
    fprintf(stderr,
            "Usage: phobos-landlock [--ro P] [--rox P] [--rw P] [--rwx P]\n"
            "                       [--connect-tcp N] [--bind-tcp N]\n"
            "                       [--chdir D] [--min-abi N] [--verbose]\n"
            "                       -- CMD [ARGS...]\n");
    exit(2);
}

int main(int argc, char *argv[]) {
    struct path_rule rules[MAX_RULES];
    size_t rule_count = 0;
    uint64_t connect_ports[MAX_PORTS];
    size_t connect_count = 0;
    uint64_t bind_ports[MAX_PORTS];
    size_t bind_count = 0;
    const char *chdir_to = NULL;
    int min_abi = 1;
    int i = 1;

    while (i < argc) {
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }
        if (i + 1 >= argc) {
            usage();
        }
        if (strcmp(argv[i], "--ro") == 0 || strcmp(argv[i], "--rox") == 0 ||
            strcmp(argv[i], "--rw") == 0 || strcmp(argv[i], "--rwx") == 0) {
            if (rule_count >= MAX_RULES) {
                fail_msg("too many path rules");
            }
            rules[rule_count].path = argv[i + 1];
            rules[rule_count].write = (argv[i][3] == 'w' || argv[i][4] == 'w');
            rules[rule_count].exec = (argv[i][strlen(argv[i]) - 1] == 'x');
            rule_count++;
        } else if (strcmp(argv[i], "--connect-tcp") == 0) {
            if (connect_count >= MAX_PORTS) {
                fail_msg("too many --connect-tcp ports");
            }
            connect_ports[connect_count++] = (uint64_t)strtoull(argv[i + 1], NULL, 10);
        } else if (strcmp(argv[i], "--bind-tcp") == 0) {
            if (bind_count >= MAX_PORTS) {
                fail_msg("too many --bind-tcp ports");
            }
            bind_ports[bind_count++] = (uint64_t)strtoull(argv[i + 1], NULL, 10);
        } else if (strcmp(argv[i], "--chdir") == 0) {
            chdir_to = argv[i + 1];
        } else if (strcmp(argv[i], "--min-abi") == 0) {
            min_abi = atoi(argv[i + 1]);
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
            i++;
            continue;
        } else {
            usage();
        }
        i += 2;
    }
    if (i >= argc) {
        usage();
    }

    long abi = syscall(__NR_landlock_create_ruleset, NULL, 0,
                       LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        fail_msg("Landlock is not available on this kernel (refusing to run "
                 "unprotected)");
    }
    vlog("Landlock ABI %ld", abi);
    if (abi > LANDLOCK_ABI_KNOWN) {
        fprintf(stderr,
                "[phobos-landlock] warning: kernel offers Landlock ABI %ld but "
                "this build only enumerates rights up to ABI %d; rights added "
                "after that are NOT restricted\n",
                abi, LANDLOCK_ABI_KNOWN);
    }
    if (abi < min_abi) {
        fprintf(stderr,
                "[phobos-landlock] kernel offers Landlock ABI %ld but ABI %d "
                "is required (refusing to run unprotected)\n",
                abi, min_abi);
        exit(EXIT_POLICY);
    }

    int want_net = (connect_count > 0 || bind_count > 0);
    if (want_net && abi < 4) {
        fail_msg("network rules require Landlock ABI 4 (kernel 6.7)");
    }

    struct landlock_ruleset_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.handled_access_fs = fs_rights_for_abi((int)abi);
    if (want_net) {
        attr.handled_access_net = LL_NET_BIND_TCP | LL_NET_CONNECT_TCP;
    }
    /* Older kernels reject the larger struct, so send only what they know. */
    size_t attr_size = sizeof(attr);
    if (abi < 6) {
        attr_size = offsetof(struct landlock_ruleset_attr, scoped);
    }
    if (abi < 4) {
        attr_size = offsetof(struct landlock_ruleset_attr, handled_access_net);
    }

    int ruleset_fd = (int)syscall(__NR_landlock_create_ruleset, &attr, attr_size, 0);
    if (ruleset_fd < 0) {
        fail("landlock_create_ruleset");
    }

    for (size_t r = 0; r < rule_count; r++) {
        int path_fd = open(rules[r].path, open_flags_for(&rules[r]));
        if (path_fd < 0) {
            if (errno == ELOOP && rules[r].write) {
                fprintf(stderr,
                        "[phobos-landlock] refusing writable path %s: it is a "
                        "symbolic link and could redirect the rule\n",
                        rules[r].path);
            }
            else {
                fprintf(stderr, "[phobos-landlock] cannot open %s: %s\n",
                        rules[r].path, strerror(errno));
            }
            exit(EXIT_POLICY);
        }
        struct stat st;
        if (fstat(path_fd, &st) != 0) {
            fail("fstat");
        }
        /* O_PATH|O_NOFOLLOW opens the link itself instead of failing, so the
         * symlink has to be rejected here. A rule anchored on a link is at
         * best useless and at worst points somewhere the policy never named. */
        if (rules[r].write && S_ISLNK(st.st_mode)) {
            fprintf(stderr,
                    "[phobos-landlock] refusing writable path %s: it is a "
                    "symbolic link and could redirect the rule\n",
                    rules[r].path);
            exit(EXIT_POLICY);
        }
        struct landlock_path_beneath_attr beneath;
        memset(&beneath, 0, sizeof(beneath));
        beneath.allowed_access = grant_for(&rules[r], (int)abi);
        if (!S_ISDIR(st.st_mode)) {
            beneath.allowed_access &= ~LL_DIR_ONLY;
        }
        beneath.parent_fd = path_fd;
        if (syscall(__NR_landlock_add_rule, ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH, &beneath, 0) != 0) {
            fprintf(stderr, "[phobos-landlock] add_rule failed for %s: %s\n",
                    rules[r].path, strerror(errno));
            exit(EXIT_POLICY);
        }
        vlog("allow %s%s%s", rules[r].path, rules[r].write ? " +w" : "",
             rules[r].exec ? " +x" : "");
        close(path_fd);
    }

    for (size_t p = 0; p < connect_count; p++) {
        struct landlock_net_port_attr net;
        memset(&net, 0, sizeof(net));
        net.allowed_access = LL_NET_CONNECT_TCP;
        net.port = connect_ports[p];
        if (syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_NET_PORT,
                    &net, 0) != 0) {
            fail("add_rule connect-tcp");
        }
        vlog("allow connect tcp/%llu", (unsigned long long)connect_ports[p]);
    }
    for (size_t p = 0; p < bind_count; p++) {
        struct landlock_net_port_attr net;
        memset(&net, 0, sizeof(net));
        net.allowed_access = LL_NET_BIND_TCP;
        net.port = bind_ports[p];
        if (syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_NET_PORT,
                    &net, 0) != 0) {
            fail("add_rule bind-tcp");
        }
        vlog("allow bind tcp/%llu", (unsigned long long)bind_ports[p]);
    }

    if (chdir_to != NULL && chdir(chdir_to) != 0) {
        fprintf(stderr, "[phobos-landlock] chdir %s: %s\n", chdir_to,
                strerror(errno));
        exit(EXIT_POLICY);
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fail("prctl(PR_SET_NO_NEW_PRIVS)");
    }
    if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) != 0) {
        fail("landlock_restrict_self");
    }
    close(ruleset_fd);

    execvp(argv[i], &argv[i]);
    fprintf(stderr, "[phobos-landlock] exec %s: %s\n", argv[i], strerror(errno));
    return 127;
}
