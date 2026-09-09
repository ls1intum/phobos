/*
 * phobos-landlock -- apply a Landlock filesystem policy, then exec a command.
 *
 * Replaces bubblewrap as the enforcement mechanism of the Phobos filesystem
 * layer. Needs no privileges, no capabilities and no container flags: a task
 * may always restrict itself further.
 *
 * Usage:
 *   phobos-landlock [--ro PATH] [--rox PATH] [--rw PATH] [--rwx PATH]
 *                   [--connect-tcp PORT] [--bind-tcp PORT]
 *                   [--chdir DIRECTORY] [--minimum-landlock-version NUMBER]
 *                   [--verbose] -- COMMAND [ARGUMENTS...]
 *
 * The kernel documents the Landlock version numbers used here as "ABI
 * versions", short for application binary interface. This file spells them out
 * as versions throughout, so searching the kernel documentation for "ABI"
 * finds the same numbers.
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

/* Filesystem access rights, available since Landlock version 1 unless noted. */
#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)     /* since version 2 */
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)  /* since version 3 */
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15) /* since version 5 */

/* Network access rights, available since Landlock version 4. */
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)

/* Rights that only make sense on a directory. */
#define DIRECTORY_ONLY_ACCESS_RIGHTS                                                           \
    (LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |                             \
     LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |                           \
     LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |                               \
     LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |                             \
     LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER)

#define EXIT_CODE_POLICY_ERROR 125
#define MAXIMUM_PATH_RULES 4096
#define MAXIMUM_PORT_RULES 64

/* Highest Landlock version whose access rights this tool enumerates. A newer kernel may
 * define rights we do not list in handled_access_fs, which would leave them
 * unrestricted, so say so loudly rather than pretending the policy is whole. */
#define HIGHEST_KNOWN_LANDLOCK_VERSION 8

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
    int writable;
    int executable;
};

/* Everything the command line asked for, so that each stage below takes one
 * argument and main reads as the sequence of stages it performs. */
struct options {
    struct path_rule rules[MAXIMUM_PATH_RULES];
    size_t path_rule_count;
    uint64_t connect_tcp_ports[MAXIMUM_PORT_RULES];
    size_t connect_tcp_port_count;
    uint64_t bind_tcp_ports[MAXIMUM_PORT_RULES];
    size_t bind_tcp_port_count;
    const char *working_directory;
    int minimum_landlock_version;
    char **command;
};

static int verbose = 0;

/* ------------------------------------------------------------------ output */

static void log_verbose(const char *format, ...) {
    if (!verbose) {
        return;
    }
    va_list argument_list;
    va_start(argument_list, format);
    fprintf(stderr, "[phobos-landlock] ");
    vfprintf(stderr, format, argument_list);
    fprintf(stderr, "\n");
    va_end(argument_list);
}

_Noreturn static void exit_with_system_error(const char *message) {
    fprintf(stderr, "[phobos-landlock] %s: %s\n", message, strerror(errno));
    exit(EXIT_CODE_POLICY_ERROR);
}

_Noreturn static void exit_with_message(const char *message) {
    fprintf(stderr, "[phobos-landlock] %s\n", message);
    exit(EXIT_CODE_POLICY_ERROR);
}

_Noreturn static void print_usage_and_exit(void) {
    fprintf(stderr, "Usage: phobos-landlock [--ro PATH] [--rox PATH] [--rw PATH] [--rwx PATH]\n"
                    "                       [--connect-tcp PORT] [--bind-tcp PORT]\n"
                    "                       [--chdir DIRECTORY]\n"
                    "                       [--minimum-landlock-version NUMBER] [--verbose]\n"
                    "                       -- COMMAND [ARGUMENTS...]\n");
    exit(2);
}

/* ------------------------------------------------------- access-right rules */

/* Rights available at the given Landlock version. */
static uint64_t filesystem_rights_for_version(int landlock_version) {
    uint64_t rights = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                      LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                      LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                      LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
                      LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                      LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                      LANDLOCK_ACCESS_FS_MAKE_SYM;
    if (landlock_version >= 2) {
        rights |= LANDLOCK_ACCESS_FS_REFER;
    }
    if (landlock_version >= 3) {
        rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    if (landlock_version >= 5) {
        rights |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }
    return rights;
}

/* Rights granted for one allow-listed path. */
static uint64_t rights_granted_for(const struct path_rule *rule, int landlock_version) {
    uint64_t granted_rights = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    if (rule->executable) {
        granted_rights |= LANDLOCK_ACCESS_FS_EXECUTE;
    }
    if (rule->writable) {
        granted_rights |= LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
                          LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
                          LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
                          LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
                          LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM;
        if (landlock_version >= 2) {
            granted_rights |= LANDLOCK_ACCESS_FS_REFER;
        }
        if (landlock_version >= 3) {
            granted_rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
        }
    }
    if (landlock_version >= 5) {
        granted_rights |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }
    return granted_rights & filesystem_rights_for_version(landlock_version);
}

/* Writable paths are the ones an attacker profits from redirecting, and they
 * are the ones that may sit in a directory the supervised code can write. So
 * refuse a symlink as the final component there. Read-only paths still follow
 * symlinks, because system paths legitimately are ones (/lib -> /usr/lib). */
static int open_flags_for_rule(const struct path_rule *rule) {
    int flags = O_PATH | O_CLOEXEC;
    if (rule->writable) {
        flags |= O_NOFOLLOW;
    }
    return flags;
}

/* ---------------------------------------------------- stage: parse the call */

/* Records one --ro/--rox/--rw/--rwx option. The suffix decides the rights:
 * a "w" makes it writable, a trailing "x" adds execute. */
static void remember_path_rule(struct options *options, const char *flag_name,
                               const char *path) {
    if (options->path_rule_count >= MAXIMUM_PATH_RULES) {
        exit_with_message("too many path rules");
    }
    struct path_rule *rule = &options->rules[options->path_rule_count];
    rule->path = path;
    /* The flags are --ro, --rox, --rw and --rwx, so position 3 is the one that
     * says writable and a trailing x says executable. */
    rule->writable = (flag_name[3] == 'w');
    rule->executable = (flag_name[strlen(flag_name) - 1] == 'x');
    options->path_rule_count++;
}

static void remember_port(uint64_t *ports, size_t *count, const char *value, const char *what) {
    if (*count >= MAXIMUM_PORT_RULES) {
        exit_with_message(what);
    }
    ports[*count] = (uint64_t)strtoull(value, NULL, 10);
    (*count)++;
}

static void parse_arguments(int argument_count, char *arguments[], struct options *options) {
    memset(options, 0, sizeof(*options));
    options->minimum_landlock_version = 1;

    int argument_index = 1;
    while (argument_index < argument_count) {
        if (strcmp(arguments[argument_index], "--") == 0) {
            argument_index++;
            break;
        }
        if (strcmp(arguments[argument_index], "--verbose") == 0) {
            verbose = 1;
            argument_index++;
            continue;
        }
        /* Every remaining option takes a value, so it must not be the last word. */
        if (argument_index + 1 >= argument_count) {
            print_usage_and_exit();
        }
        if (strcmp(arguments[argument_index], "--ro") == 0 ||
            strcmp(arguments[argument_index], "--rox") == 0 ||
            strcmp(arguments[argument_index], "--rw") == 0 ||
            strcmp(arguments[argument_index], "--rwx") == 0) {
            remember_path_rule(options, arguments[argument_index],
                               arguments[argument_index + 1]);
        } else if (strcmp(arguments[argument_index], "--connect-tcp") == 0) {
            remember_port(options->connect_tcp_ports, &options->connect_tcp_port_count,
                          arguments[argument_index + 1], "too many --connect-tcp ports");
        } else if (strcmp(arguments[argument_index], "--bind-tcp") == 0) {
            remember_port(options->bind_tcp_ports, &options->bind_tcp_port_count,
                          arguments[argument_index + 1], "too many --bind-tcp ports");
        } else if (strcmp(arguments[argument_index], "--chdir") == 0) {
            options->working_directory = arguments[argument_index + 1];
        } else if (strcmp(arguments[argument_index], "--minimum-landlock-version") == 0) {
            options->minimum_landlock_version = atoi(arguments[argument_index + 1]);
        } else {
            print_usage_and_exit();
        }
        argument_index += 2;
    }
    if (argument_index >= argument_count) {
        print_usage_and_exit();
    }
    options->command = &arguments[argument_index];
}

/* ------------------------------------------------- stage: what can we enforce */

/* Asks the kernel for its Landlock version and refuses anything below what the
 * caller demanded, so an unsupported kernel stops the run instead of quietly
 * running it unprotected. */
static int detect_abi(const struct options *options) {
    long landlock_version =
        syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (landlock_version < 0) {
        exit_with_message("Landlock is not available on this kernel (refusing to run "
                          "unprotected)");
    }
    log_verbose("Landlock version %ld", landlock_version);
    if (landlock_version > HIGHEST_KNOWN_LANDLOCK_VERSION) {
        fprintf(stderr,
                "[phobos-landlock] warning: kernel offers Landlock version %ld but "
                "this build only enumerates rights up to version %d; rights added "
                "after that are NOT restricted\n",
                landlock_version, HIGHEST_KNOWN_LANDLOCK_VERSION);
    }
    if (landlock_version < options->minimum_landlock_version) {
        fprintf(stderr,
                "[phobos-landlock] kernel offers Landlock version %ld but version %d "
                "is required (refusing to run unprotected)\n",
                landlock_version, options->minimum_landlock_version);
        exit(EXIT_CODE_POLICY_ERROR);
    }
    if (options->connect_tcp_port_count > 0 || options->bind_tcp_port_count > 0) {
        if (landlock_version < 4) {
            exit_with_message("network rules require Landlock version 4 (kernel 6.7)");
        }
    }
    return (int)landlock_version;
}

/* ----------------------------------------------------- stage: create ruleset */

/* Older kernels reject the larger struct, so send only the part they know. */
static size_t ruleset_attributes_size_for_version(int landlock_version) {
    if (landlock_version < 4) {
        return offsetof(struct landlock_ruleset_attr, handled_access_net);
    }
    if (landlock_version < 6) {
        return offsetof(struct landlock_ruleset_attr, scoped);
    }
    return sizeof(struct landlock_ruleset_attr);
}

/* Everything named in handled_access_fs is denied unless a rule allows it, so
 * this is what makes the ruleset deny by default. */
static int create_ruleset(int landlock_version, const struct options *options) {
    struct landlock_ruleset_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.handled_access_fs = filesystem_rights_for_version(landlock_version);
    if (options->connect_tcp_port_count > 0 || options->bind_tcp_port_count > 0) {
        attributes.handled_access_net =
            LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
    }

    int ruleset_descriptor =
        (int)syscall(__NR_landlock_create_ruleset, &attributes,
                     ruleset_attributes_size_for_version(landlock_version), 0);
    if (ruleset_descriptor < 0) {
        exit_with_system_error("landlock_create_ruleset");
    }
    return ruleset_descriptor;
}

/* -------------------------------------------------- stage: add the path rules */

static void add_path_rule(int ruleset_descriptor, int landlock_version,
                          const struct path_rule *rule) {
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
    if (rule->writable && S_ISLNK(file_status.st_mode)) {
        fprintf(stderr,
                "[phobos-landlock] refusing writable path %s: it is a symbolic "
                "link and could redirect the rule\n",
                rule->path);
        exit(EXIT_CODE_POLICY_ERROR);
    }

    struct landlock_path_beneath_attr path_rule_attributes;
    memset(&path_rule_attributes, 0, sizeof(path_rule_attributes));
    path_rule_attributes.allowed_access = rights_granted_for(rule, landlock_version);
    if (!S_ISDIR(file_status.st_mode)) {
        path_rule_attributes.allowed_access &= ~DIRECTORY_ONLY_ACCESS_RIGHTS;
    }
    path_rule_attributes.parent_fd = path_descriptor;

    if (syscall(__NR_landlock_add_rule, ruleset_descriptor, LANDLOCK_RULE_PATH_BENEATH,
                &path_rule_attributes, 0) != 0) {
        fprintf(stderr, "[phobos-landlock] add_rule failed for %s: %s\n", rule->path,
                strerror(errno));
        exit(EXIT_CODE_POLICY_ERROR);
    }
    log_verbose("allow %s%s%s", rule->path, rule->writable ? " +w" : "",
                rule->executable ? " +x" : "");
    close(path_descriptor);
}

static void add_path_rules(int ruleset_descriptor, int landlock_version,
                           const struct options *options) {
    for (size_t rule_index = 0; rule_index < options->path_rule_count; rule_index++) {
        add_path_rule(ruleset_descriptor, landlock_version, &options->rules[rule_index]);
    }
}

/* -------------------------------------------------- stage: add the port rules */

static void add_port_rule(int ruleset_descriptor, uint64_t port, uint64_t access,
                          const char *what) {
    struct landlock_net_port_attr port_rule_attributes;
    memset(&port_rule_attributes, 0, sizeof(port_rule_attributes));
    port_rule_attributes.allowed_access = access;
    port_rule_attributes.port = port;
    if (syscall(__NR_landlock_add_rule, ruleset_descriptor, LANDLOCK_RULE_NET_PORT,
                &port_rule_attributes, 0) != 0) {
        exit_with_system_error(what);
    }
    log_verbose("allow %s tcp/%llu", what, (unsigned long long)port);
}

static void add_port_rules(int ruleset_descriptor, const struct options *options) {
    for (size_t port_index = 0; port_index < options->connect_tcp_port_count; port_index++) {
        add_port_rule(ruleset_descriptor, options->connect_tcp_ports[port_index],
                      LANDLOCK_ACCESS_NET_CONNECT_TCP, "connect");
    }
    for (size_t port_index = 0; port_index < options->bind_tcp_port_count; port_index++) {
        add_port_rule(ruleset_descriptor, options->bind_tcp_ports[port_index],
                      LANDLOCK_ACCESS_NET_BIND_TCP, "bind");
    }
}

/* ------------------------------------------------ stage: move, then restrict */

/* Before the restriction, because the working directory itself may be outside
 * the allow-list while the paths reached from it are inside it. */
static void enter_working_directory(const struct options *options) {
    if (options->working_directory == NULL) {
        return;
    }
    if (chdir(options->working_directory) != 0) {
        fprintf(stderr, "[phobos-landlock] chdir %s: %s\n", options->working_directory,
                strerror(errno));
        exit(EXIT_CODE_POLICY_ERROR);
    }
}

/* One-way door: after this the process, and everything it starts, can only
 * lose access, never regain it. no_new_privs first, because Landlock requires
 * it and it also closes the setuid route out of the sandbox. */
static void apply_restriction(int ruleset_descriptor) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        exit_with_system_error("prctl(PR_SET_NO_NEW_PRIVS)");
    }
    if (syscall(__NR_landlock_restrict_self, ruleset_descriptor, 0) != 0) {
        exit_with_system_error("landlock_restrict_self");
    }
    close(ruleset_descriptor);
}

/* ------------------------------------------------------- stage: run the build */

_Noreturn static void exec_command(const struct options *options) {
    execvp(options->command[0], options->command);
    fprintf(stderr, "[phobos-landlock] exec %s: %s\n", options->command[0], strerror(errno));
    exit(127);
}

/* ------------------------------------------------------------------ the call */

int main(int argc, char *argv[]) {
    static struct options options;

    parse_arguments(argc, argv, &options);
    int landlock_version = detect_abi(&options);
    int ruleset_descriptor = create_ruleset(landlock_version, &options);
    add_path_rules(ruleset_descriptor, landlock_version, &options);
    add_port_rules(ruleset_descriptor, &options);
    enter_working_directory(&options);
    apply_restriction(ruleset_descriptor);
    exec_command(&options);
}
