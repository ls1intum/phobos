/*
 * denial-report-spike -- a throwaway measurement prototype for the denial-reporting plan
 * (docs/superpowers/plans/2026-10-05-denial-reporting.md). It is not part of Phobos and is never
 * built into an image: it exists so the plan's numbers can be reproduced.
 *
 * It runs a command under a Landlock filesystem ruleset in one of four modes:
 *
 *   plain     exec the command, nothing applied (the baseline)
 *   landlock  apply the ruleset, then exec
 *   trap      as landlock, plus a seccomp user-notification filter on the file syscalls whose
 *             supervisor answers every notification with CONTINUE at once (the floor cost)
 *   report    as trap, but once armed the supervisor reads the path out of the command, resolves
 *             it, mirrors the Landlock decision by walking the ancestors' inodes against the rules,
 *             prints one Phobos Security Error line per distinct denial, and only then CONTINUEs
 *
 * The supervisor never allows or refuses anything: every notification is answered with
 * SECCOMP_USER_NOTIF_FLAG_CONTINUE, so the kernel, and Landlock in it, makes every decision.
 *
 * The supervisor is the parent. The child installs the filter and hands the listener up over a
 * socket pair with SCM_RIGHTS, as the connect guard does; clone(CLONE_FILES) with unshare() was
 * tried first and is refused by Docker's default seccomp profile (unshare needs CAP_SYS_ADMIN). Arming
 * follows the plan: the filter also traps landlock_restrict_self, the supervisor arms on it and
 * records the child's seccomp filter count, the child then installs a no-op marker filter, and a
 * notification is only reported for a task whose filter count is above the recorded one, which is
 * exactly the tasks forked after the marker. --helper forks a process before the restriction that
 * keeps opening a path the ruleset denies, standing in for the layer's tee and counter, which must
 * never be reported.
 *
 * Usage:
 *   denial-report-spike --mode plain|landlock|trap|report [--read PATH]... [--write PATH]...
 *                       [--helper PATH] [--sync-wakeup] -- COMMAND [ARGUMENTS...]
 *   denial-report-spike --probe-nested-listener
 *   denial-report-spike --probe-continue
 *   denial-report-spike --probe-kernel-refusal
 *   denial-report-spike --quote VALUE
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
#define SPIKE_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SPIKE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "the spike knows x86_64 and aarch64 only"
#endif

#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif
/* Linux 6.6: wake the supervisor synchronously, so the trapped thread and the supervisor swap on
 * one CPU instead of each waiting for the scheduler. Older headers lack the names. */
#ifndef SECCOMP_IOCTL_NOTIF_SET_FLAGS
#define SECCOMP_IOCTL_NOTIF_SET_FLAGS SECCOMP_IOW(4, __u64)
#endif
#ifndef SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP
#define SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP (1UL << 0)
#endif

enum spike_mode {
    MODE_PLAIN,
    MODE_LANDLOCK,
    MODE_TRAP,
    MODE_REPORT,
};

static constexpr size_t MAXIMUM_RULES = 64;
static constexpr size_t MAXIMUM_SEEN = 4096;

struct spike_rule {
    const char *path;
    uint64_t rights;
    dev_t device;
    ino_t inode;
};

static struct spike_rule rules[MAXIMUM_RULES];
static size_t rule_count = 0;
static uint64_t seen_keys[MAXIMUM_SEEN];
static size_t seen_count = 0;
static unsigned long denials_total = 0;
static unsigned long denials_suppressed = 0;
static unsigned long notifications_total = 0;
static constexpr size_t CALLS_COUNTED = 512;
static unsigned long notifications_by_call[CALLS_COUNTED];

static constexpr uint64_t READ_RIGHTS = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
static constexpr uint64_t EXECUTE_RIGHTS = LANDLOCK_ACCESS_FS_EXECUTE;
static constexpr uint64_t WRITE_RIGHTS = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE
                                         | LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_DIR
                                         | LANDLOCK_ACCESS_FS_REMOVE_FILE
                                         | LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REFER
                                         | LANDLOCK_ACCESS_FS_MAKE_SOCK
                                         | LANDLOCK_ACCESS_FS_MAKE_FIFO
                                         | LANDLOCK_ACCESS_FS_MAKE_SYM;
static constexpr uint64_t HANDLED_RIGHTS = READ_RIGHTS | EXECUTE_RIGHTS | WRITE_RIGHTS
                                           | LANDLOCK_ACCESS_FS_MAKE_CHAR
                                           | LANDLOCK_ACCESS_FS_MAKE_BLOCK;

/* Prints a failure and ends the process. */
[[noreturn]] static void fail(const char *what) {
    fprintf(stderr, "denial-report-spike: %s: %s\n", what, strerror(errno));
    exit(125);
}

/* Records one allow-listed path with its rights. */
static void add_rule(const char *path, uint64_t rights) {
    if (rule_count == MAXIMUM_RULES) {
        fprintf(stderr, "denial-report-spike: too many rules\n");
        exit(2);
    }
    rules[rule_count].path = path;
    rules[rule_count].rights = rights;
    rule_count++;
}

/* Builds and applies the Landlock ruleset from the rules, recording each rule's inode. */
static void apply_landlock(void) {
    struct landlock_ruleset_attr attributes = {.handled_access_fs = HANDLED_RIGHTS};
    int ruleset = (int)syscall(SYS_landlock_create_ruleset, &attributes, sizeof(attributes), 0);
    if (ruleset < 0) {
        fail("landlock_create_ruleset");
    }
    for (size_t index = 0; index < rule_count; index++) {
        int descriptor = open(rules[index].path, O_PATH | O_CLOEXEC);
        if (descriptor < 0) {
            fail(rules[index].path);
        }
        struct stat status;
        if (fstat(descriptor, &status) != 0) {
            fail("fstat rule");
        }
        uint64_t rights = rules[index].rights;
        if (!S_ISDIR(status.st_mode)) {
            rights &= LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE
                      | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_TRUNCATE;
        }
        rules[index].rights = rights;
        rules[index].device = status.st_dev;
        rules[index].inode = status.st_ino;
        struct landlock_path_beneath_attr beneath = {.allowed_access = rights, .parent_fd = descriptor};
        if (syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &beneath, 0) != 0) {
            fail("landlock_add_rule");
        }
        close(descriptor);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fail("no_new_privs");
    }
    if (syscall(SYS_landlock_restrict_self, ruleset, 0) != 0) {
        fail("landlock_restrict_self");
    }
    close(ruleset);
}

/* Records the rules' inodes in the supervisor, which never applies the ruleset itself. */
static void remember_rule_inodes(void) {
    for (size_t index = 0; index < rule_count; index++) {
        struct stat status;
        if (stat(rules[index].path, &status) != 0) {
            fail("stat rule");
        }
        if (!S_ISDIR(status.st_mode)) {
            rules[index].rights &= LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE
                                   | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_TRUNCATE;
        }
        rules[index].device = status.st_dev;
        rules[index].inode = status.st_ino;
    }
}

#define TRAP(number) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)

/* Installs the reporting filter and answers its listener. It traps the path syscalls of both
 * architectures and landlock_restrict_self, and allows everything else. */
static int install_report_filter(void) {
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SPIKE_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#ifdef __NR_open
        TRAP(__NR_open),
        TRAP(__NR_creat),
        TRAP(__NR_mkdir),
        TRAP(__NR_rmdir),
        TRAP(__NR_unlink),
        TRAP(__NR_rename),
        TRAP(__NR_link),
        TRAP(__NR_symlink),
        TRAP(__NR_mknod),
#endif
        TRAP(__NR_openat),
        TRAP(__NR_openat2),
        TRAP(__NR_execve),
        TRAP(__NR_execveat),
        TRAP(__NR_mkdirat),
        TRAP(__NR_mknodat),
        TRAP(__NR_unlinkat),
        TRAP(__NR_renameat2),
        TRAP(__NR_linkat),
        TRAP(__NR_symlinkat),
        TRAP(__NR_truncate),
        TRAP(SYS_landlock_restrict_self),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
        .filter = instructions,
    };
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER,
                        &program);
}

/* Installs the marker: a filter that allows everything, so only the tasks forked after the
 * restriction carry one filter more than the tasks beside them. */
static void install_marker_filter(void) {
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {.len = 1, .filter = instructions};
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) != 0) {
        fail("marker filter");
    }
}

/* The number of seccomp filters a task carries, from /proc, or -1. */
static int filter_count(pid_t pid) {
    char name[64];
    char buffer[4096];
    snprintf(name, sizeof(name), "/proc/%d/status", (int)pid);
    int descriptor = open(name, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        return -1;
    }
    ssize_t length = read(descriptor, buffer, sizeof(buffer) - 1);
    close(descriptor);
    if (length <= 0) {
        return -1;
    }
    buffer[length] = '\0';
    const char *field = strstr(buffer, "Seccomp_filters:");
    if (field == nullptr) {
        return -1;
    }
    return atoi(field + strlen("Seccomp_filters:"));
}

/* Reads a NUL-terminated string out of the command's memory, page by page. */
static bool read_child_string(pid_t pid, uint64_t address, char *out, size_t size) {
    size_t done = 0;
    while (done < size - 1) {
        uint64_t here = address + done;
        size_t page_left = 4096 - (size_t)(here % 4096);
        size_t want = page_left < size - 1 - done ? page_left : size - 1 - done;
        struct iovec local = {.iov_base = out + done, .iov_len = want};
        struct iovec remote = {.iov_base = (void *)(uintptr_t)here, .iov_len = want};
        ssize_t got = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (got <= 0) {
            return false;
        }
        if (memchr(out + done, '\0', (size_t)got) != nullptr) {
            return true;
        }
        done += (size_t)got;
    }
    out[size - 1] = '\0';
    return false;
}

/* Turns a path the command named relative to a directory descriptor into an absolute one. */
static bool absolute_path(pid_t pid, int directory, const char *path, char *out, size_t size) {
    if (path[0] == '/') {
        snprintf(out, size, "%s", path);
        return true;
    }
    char link[64];
    char base[PATH_MAX];
    if (directory == AT_FDCWD) {
        snprintf(link, sizeof(link), "/proc/%d/cwd", (int)pid);
    } else {
        snprintf(link, sizeof(link), "/proc/%d/fd/%d", (int)pid, directory);
    }
    ssize_t length = readlink(link, base, sizeof(base) - 1);
    if (length <= 0) {
        return false;
    }
    base[length] = '\0';
    int written = path[0] == '\0' ? snprintf(out, size, "%s", base)
                                  : snprintf(out, size, "%s/%s", base, path);
    return written > 0 && (size_t)written < size;
}

/* The rights the rules grant along the ancestors of a resolved path, walked by inode the way
 * Landlock walks its dentries. */
static uint64_t granted_along(const char *resolved) {
    char walk[PATH_MAX];
    uint64_t granted = 0;
    snprintf(walk, sizeof(walk), "%s", resolved);
    for (;;) {
        struct stat status;
        if (stat(walk, &status) == 0) {
            for (size_t index = 0; index < rule_count; index++) {
                if (rules[index].device == status.st_dev && rules[index].inode == status.st_ino) {
                    granted |= rules[index].rights;
                }
            }
        }
        if (strcmp(walk, "/") == 0) {
            return granted;
        }
        char *slash = strrchr(walk, '/');
        if (slash == walk) {
            walk[1] = '\0';
        } else if (slash != nullptr) {
            *slash = '\0';
        } else {
            return granted;
        }
    }
}

/* Resolves the object itself when it exists, or its parent plus the last name when it does not. */
static bool resolve(const char *absolute, bool parent, char *out, size_t size) {
    char copy[PATH_MAX];
    snprintf(copy, sizeof(copy), "%s", absolute);
    if (!parent) {
        return realpath(copy, out) != nullptr;
    }
    char *slash = strrchr(copy, '/');
    if (slash == nullptr) {
        return false;
    }
    if (slash == copy) {
        snprintf(out, size, "/");
        return true;
    }
    *slash = '\0';
    return realpath(copy, out) != nullptr;
}

/* The ANSI-C escape bash writes for one byte inside $'...', or nullptr for a byte it writes in
 * octal or as it is. */
static const char *ansi_c_escape(unsigned char byte) {
    switch (byte) {
    case '\'':
        return "\\'";
    case '\\':
        return "\\\\";
    case '\a':
        return "\\a";
    case '\b':
        return "\\b";
    case '\t':
        return "\\t";
    case '\n':
        return "\\n";
    case '\v':
        return "\\v";
    case '\f':
        return "\\f";
    case '\r':
        return "\\r";
    case 0x1b:
        return "\\E";
    default:
        return nullptr;
    }
}

/* Quotes a value the way bash 5.2 ${value@Q} does under LC_ALL=C, so no control byte or non-text
 * byte ever reaches the terminal raw: single quotes, a quote inside written as '\'', when every
 * byte is printable ASCII, otherwise $'...' with ANSI-C escapes and octal for every other byte. */
static void quote(const char *value, char *out, size_t size) {
    bool plain = true;
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; cursor++) {
        if (*cursor < 0x20 || *cursor > 0x7e) {
            plain = false;
        }
    }
    size_t used = (size_t)snprintf(out, size, plain ? "'" : "$'");
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0' && used + 8 < size;
         cursor++) {
        const char *escape = nullptr;
        if (plain && *cursor == '\'') {
            escape = "'\\''";
        } else if (!plain) {
            escape = ansi_c_escape(*cursor);
        }
        if (escape != nullptr) {
            used += (size_t)snprintf(out + used, size - used, "%s", escape);
        } else if (!plain && (*cursor < 0x20 || *cursor > 0x7e)) {
            used += (size_t)snprintf(out + used, size - used, "\\%03o", *cursor);
        } else {
            out[used] = (char)*cursor;
            used++;
            out[used] = '\0';
        }
    }
    snprintf(out + used, size - used, "'");
}

/* FNV-1a over the verb, the noun and the path: the de-duplication key. */
static uint64_t key_of(const char *verb, const char *noun, const char *path) {
    uint64_t hash = 1469598103934665603ULL;
    const char *parts[] = {verb, noun, path};
    for (size_t part = 0; part < 3; part++) {
        for (const unsigned char *cursor = (const unsigned char *)parts[part]; *cursor != '\0'; cursor++) {
            hash = (hash ^ *cursor) * 1099511628211ULL;
        }
        hash = (hash ^ 0xff) * 1099511628211ULL;
    }
    return hash;
}

/* Prints one Phobos Security Error line, the first time a verb, noun and path come together. */
static void report(const char *verb, const char *noun, const char *path) {
    denials_total++;
    uint64_t key = key_of(verb, noun, path);
    for (size_t index = 0; index < seen_count; index++) {
        if (seen_keys[index] == key) {
            denials_suppressed++;
            return;
        }
    }
    if (seen_count < MAXIMUM_SEEN) {
        seen_keys[seen_count++] = key;
    }
    char quoted[PATH_MAX * 4 + 8];
    quote(path, quoted, sizeof(quoted));
    fprintf(stderr,
            "Phobos Security Error: the program tried to illegally %s the %s %s but was blocked by "
            "Phobos.\n",
            verb, noun, quoted);
}

/* Decides, for one armed notification, whether Landlock refuses it, and reports it if so. */
static void mirror(const struct seccomp_notif *request) {
    const unsigned long long *arguments = request->data.args;
    int directory = AT_FDCWD;
    uint64_t path_address = 0;
    int flags = 0;
    int nr = request->data.nr;
    if (nr == __NR_openat || nr == __NR_openat2) {
        directory = (int)arguments[0];
        path_address = arguments[1];
        flags = (int)arguments[2];
        if (nr == __NR_openat2) {
            struct open_how how;
            struct iovec local = {.iov_base = &how, .iov_len = sizeof(how)};
            struct iovec remote = {.iov_base = (void *)(uintptr_t)arguments[2], .iov_len = sizeof(how)};
            if (process_vm_readv(request->pid, &local, 1, &remote, 1, 0) != (ssize_t)sizeof(how)) {
                return;
            }
            flags = (int)how.flags;
        }
#ifdef __NR_open
    } else if (nr == __NR_open) {
        path_address = arguments[0];
        flags = (int)arguments[1];
#endif
    } else if (nr == __NR_execve) {
        path_address = arguments[0];
    } else if (nr == __NR_mkdirat || nr == __NR_unlinkat) {
        directory = (int)arguments[0];
        path_address = arguments[1];
        flags = (int)arguments[2];
    } else {
        return;
    }
    char path[PATH_MAX];
    char absolute[PATH_MAX];
    char resolved[PATH_MAX];
    if (!read_child_string(request->pid, path_address, path, sizeof(path))) {
        return;
    }
    if (!absolute_path(request->pid, directory, path, absolute, sizeof(absolute))) {
        return;
    }
    struct stat status;
    bool exists = stat(absolute, &status) == 0;
    uint64_t wanted = 0;
    const char *verb = nullptr;
    const char *noun = "File";
    bool on_parent = false;
    if (nr == __NR_execve) {
        if (!exists) {
            return;
        }
        wanted = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE;
        verb = "execute";
    } else if (nr == __NR_mkdirat) {
        if (exists) {
            return;
        }
        wanted = LANDLOCK_ACCESS_FS_MAKE_DIR;
        verb = "create";
        noun = "Directory";
        on_parent = true;
    } else if (nr == __NR_unlinkat) {
        if (!exists) {
            return;
        }
        bool directory_removal = (flags & AT_REMOVEDIR) != 0;
        wanted = directory_removal ? LANDLOCK_ACCESS_FS_REMOVE_DIR : LANDLOCK_ACCESS_FS_REMOVE_FILE;
        verb = "delete";
        noun = directory_removal ? "Directory" : "File";
        on_parent = true;
    } else {
        if ((flags & O_PATH) != 0) {
            return;
        }
        if (!exists && (flags & O_CREAT) == 0) {
            return;
        }
        if (!exists) {
            wanted = LANDLOCK_ACCESS_FS_MAKE_REG;
            verb = "create";
            on_parent = true;
        } else {
            bool is_directory = S_ISDIR(status.st_mode);
            int access = flags & O_ACCMODE;
            if (access == O_WRONLY || access == O_RDWR || (flags & O_TRUNC) != 0) {
                wanted = LANDLOCK_ACCESS_FS_WRITE_FILE;
                verb = "write";
            }
            if (access == O_RDONLY || access == O_RDWR) {
                wanted |= is_directory ? LANDLOCK_ACCESS_FS_READ_DIR : LANDLOCK_ACCESS_FS_READ_FILE;
                if (verb == nullptr) {
                    verb = "read";
                }
            }
            noun = is_directory ? "Directory" : "File";
        }
    }
    if (!resolve(absolute, on_parent, resolved, sizeof(resolved))) {
        return;
    }
    uint64_t granted = granted_along(resolved);
    if ((wanted & HANDLED_RIGHTS & ~granted) != 0) {
        report(verb, noun, absolute);
    }
}

/* Answers one notification with CONTINUE: the kernel, not this process, decides. */
static void answer_continue(int listener, uint64_t identifier) {
    struct seccomp_notif_resp response;
    memset(&response, 0, sizeof(response));
    response.id = identifier;
    response.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response) != 0 && errno != ENOENT) {
        fprintf(stderr, "denial-report-spike: notify send: %s\n", strerror(errno));
    }
}

/* Services the listener until every task under the filter has gone. */
static void supervise(int listener, enum spike_mode mode) {
    bool armed = false;
    int armed_filter_count = INT_MAX;
    struct seccomp_notif request;
    for (;;) {
        struct pollfd watch = {.fd = listener, .events = POLLIN, .revents = 0};
        int ready = poll(&watch, 1, -1);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready < 0) {
            return;
        }
        if ((watch.revents & POLLIN) != 0) {
            memset(&request, 0, sizeof(request));
            if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &request) == 0) {
                notifications_total++;
                if ((size_t)request.data.nr < CALLS_COUNTED) {
                    notifications_by_call[request.data.nr]++;
                }
                if (request.data.nr == SYS_landlock_restrict_self && !armed) {
                    armed = true;
                    armed_filter_count = filter_count((pid_t)request.pid);
                } else if (mode == MODE_REPORT && armed
                           && filter_count((pid_t)request.pid) > armed_filter_count) {
                    mirror(&request);
                }
                answer_continue(listener, request.id);
            }
        }
        if ((watch.revents & (POLLHUP | POLLERR)) != 0) {
            return;
        }
    }
}

/* Keeps opening a path the ruleset denies, from a process forked before the restriction. */
static void run_helper(const char *path) {
    for (int round = 0; round < 50; round++) {
        int descriptor = open(path, O_RDONLY | O_CLOEXEC);
        if (descriptor >= 0) {
            close(descriptor);
        }
        usleep(20000);
    }
    _exit(0);
}

/* Shows that a second listener cannot be installed beneath a first one. */
static int probe_nested_listener(void) {
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        TRAP(__NR_getppid),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
        .filter = instructions,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fail("no_new_privs");
    }
    long first = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
    printf("first listener: %ld (%s)\n", first, first < 0 ? strerror(errno) : "ok");
    long second = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
    printf("second listener: %ld (%s)\n", second, second < 0 ? strerror(errno) : "ok");
    long plain = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program);
    printf("filter without listener beneath it: %ld (%s)\n", plain, plain < 0 ? strerror(errno) : "ok");
    printf("filters now: %d\n", filter_count(getpid()));
    return second < 0 && errno == EBUSY ? 0 : 1;
}

/* Hands one descriptor to the supervisor over the socket pair, as the connect guard does. */
static bool send_descriptor(int socket_descriptor, int descriptor) {
    char payload = 'N';
    struct iovec vector = {.iov_base = &payload, .iov_len = 1};
    union {
        char buffer[CMSG_SPACE(sizeof(int))];
        struct cmsghdr alignment;
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.buffer;
    message.msg_controllen = sizeof(control.buffer);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &descriptor, sizeof(int));
    return sendmsg(socket_descriptor, &message, 0) == 1;
}

/* Receives the one descriptor the child sends, or -1. */
static int receive_descriptor(int socket_descriptor) {
    char payload;
    struct iovec vector = {.iov_base = &payload, .iov_len = 1};
    union {
        char buffer[CMSG_SPACE(sizeof(int))];
        struct cmsghdr alignment;
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.buffer;
    message.msg_controllen = sizeof(control.buffer);
    if (recvmsg(socket_descriptor, &message, MSG_CMSG_CLOEXEC) != 1) {
        return -1;
    }
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (header == nullptr || header->cmsg_type != SCM_RIGHTS) {
        return -1;
    }
    int descriptor = -1;
    memcpy(&descriptor, CMSG_DATA(header), sizeof(int));
    return descriptor;
}

/* Proves SECCOMP_USER_NOTIF_FLAG_CONTINUE directly: a throwaway child traps its own getppid, the
 * parent continues that one notification, and the child reports what getppid returned. */
static int probe_continue(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) {
        printf("probe could not make its socket pair; supported: no\n");
        return 1;
    }
    pid_t child = fork();
    if (child < 0) {
        close(pair[0]);
        close(pair[1]);
        printf("probe could not fork; supported: no\n");
        return 1;
    }
    if (child == 0) {
        close(pair[0]);
        struct sock_filter instructions[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            TRAP(__NR_getppid),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog program = {
            .len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
            .filter = instructions,
        };
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            _exit(2);
        }
        int listener = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                                    SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
        if (listener < 0 || !send_descriptor(pair[1], listener)) {
            _exit(3);
        }
        close(listener);
        pid_t parent = getppid();
        if (write(pair[1], &parent, sizeof(parent)) != (ssize_t)sizeof(parent)) {
            _exit(4);
        }
        _exit(0);
    }
    close(pair[1]);
    int listener = receive_descriptor(pair[0]);
    if (listener < 0) {
        close(pair[0]);
        int ended = 0;
        while (waitpid(child, &ended, 0) < 0 && errno == EINTR) {
        }
        printf("probe could not install or hand over a listener (status %d); supported: no\n",
               WIFEXITED(ended) ? WEXITSTATUS(ended) : 128 + WTERMSIG(ended));
        return 1;
    }
    struct pollfd watch = {.fd = listener, .events = POLLIN, .revents = 0};
    int sent = -1;
    int send_error = ETIMEDOUT;
    if (poll(&watch, 1, 1000) == 1 && (watch.revents & POLLIN) != 0) {
        struct seccomp_notif request;
        memset(&request, 0, sizeof(request));
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &request) == 0) {
            struct seccomp_notif_resp response;
            memset(&response, 0, sizeof(response));
            response.id = request.id;
            response.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            sent = ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response);
            send_error = errno;
        }
    }
    /* Closing the listener releases a probe still waiting in its trapped getppid (it then gets
     * ENOSYS), so a refused CONTINUE, a lost notification or a timed-out wait can never hang the
     * check; the probe writes what it got and exits either way. */
    close(listener);
    pid_t seen = 0;
    ssize_t got = read(pair[0], &seen, sizeof(seen));
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
    bool supported = sent == 0 && got == (ssize_t)sizeof(seen) && seen == getpid();
    printf("continue send: %s; probe's getppid: %d; supervisor: %d; supported: %s\n",
           sent == 0 ? "ok" : strerror(send_error), (int)seen, (int)getpid(), supported ? "yes" : "no");
    return supported ? 0 : 1;
}

/* Installs a listener filter that traps one call, and answers the listener. */
static int install_listener_for(int number) {
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)number, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
        .filter = instructions,
    };
    int listener = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER,
                                &program);
    if (listener < 0) {
        fail("listener filter");
    }
    return listener;
}

/* Installs a filter without a listener that answers one call with the given action. */
static void install_plain_filter(int number, unsigned int action) {
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)number, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, action),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
        .filter = instructions,
    };
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) != 0) {
        fail("plain filter");
    }
}

/* Calls setpgid(0, getpgrp()), a no-op when allowed, and prints the result. */
static void show_setpgid(const char *label) {
    long result = syscall(SYS_setpgid, 0, getpgrp());
    printf("%s: setpgid -> %ld (%s)\n", label, result, result < 0 ? strerror(errno) : "allowed");
    fflush(stdout);
}

/* Shows how a filter refusal can become a reported refusal without depending on the supervisor:
 * an older listener-less filter answering USER_NOTIF refuses on its own with ENOSYS; a newer
 * listener filter answering USER_NOTIF for the same call wins the tie and gets the notification;
 * when that listener is gone the call is refused with ENOSYS again; and an older ERRNO still
 * beats a newer USER_NOTIF, which is why an ERRNO refusal can never be reported. */
static int probe_kernel_refusal(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fail("no_new_privs");
    }
    pid_t errno_child = fork();
    if (errno_child == 0) {
        install_plain_filter(SYS_setpgid, SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA));
        int listener = install_listener_for(SYS_setpgid);
        show_setpgid("older ERRNO, newer USER_NOTIF with a listener nobody serves");
        close(listener);
        _exit(0);
    }
    waitpid(errno_child, nullptr, 0);
    install_plain_filter(SYS_setpgid, SECCOMP_RET_USER_NOTIF);
    show_setpgid("listener-less USER_NOTIF alone");
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) {
        fail("socketpair");
    }
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        int listener = install_listener_for(SYS_setpgid);
        if (!send_descriptor(pair[1], listener)) {
            _exit(3);
        }
        close(listener);
        show_setpgid("newer listener filter, supervisor answers EACCES");
        char go;
        if (read(pair[1], &go, 1) != 1) {
            _exit(4);
        }
        show_setpgid("newer listener filter, supervisor gone");
        _exit(0);
    }
    close(pair[1]);
    int listener = receive_descriptor(pair[0]);
    if (listener < 0) {
        fail("no listener");
    }
    struct seccomp_notif request;
    memset(&request, 0, sizeof(request));
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &request) == 0) {
        struct seccomp_notif_resp response;
        memset(&response, 0, sizeof(response));
        response.id = request.id;
        response.error = -EACCES;
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response) != 0) {
            fail("answer");
        }
    }
    close(listener);
    if (write(pair[0], "g", 1) != 1) {
        fail("go");
    }
    waitpid(child, nullptr, 0);
    return 0;
}

int main(int argument_count, char *arguments[]) {
    enum spike_mode mode = MODE_PLAIN;
    const char *helper_path = nullptr;
    bool synchronous_wake_up = false;
    int index = 1;
    for (; index < argument_count; index++) {
        if (strcmp(arguments[index], "--probe-nested-listener") == 0) {
            return probe_nested_listener();
        } else if (strcmp(arguments[index], "--probe-continue") == 0) {
            return probe_continue();
        } else if (strcmp(arguments[index], "--probe-kernel-refusal") == 0) {
            return probe_kernel_refusal();
        } else if (strcmp(arguments[index], "--quote") == 0 && index + 1 < argument_count) {
            char quoted[PATH_MAX * 4 + 8];
            quote(arguments[index + 1], quoted, sizeof(quoted));
            printf("%s\n", quoted);
            return 0;
        } else if (strcmp(arguments[index], "--mode") == 0 && index + 1 < argument_count) {
            const char *name = arguments[++index];
            mode = strcmp(name, "landlock") == 0 ? MODE_LANDLOCK
                   : strcmp(name, "trap") == 0   ? MODE_TRAP
                   : strcmp(name, "report") == 0 ? MODE_REPORT
                                                 : MODE_PLAIN;
        } else if (strcmp(arguments[index], "--read") == 0 && index + 1 < argument_count) {
            add_rule(arguments[++index], READ_RIGHTS | EXECUTE_RIGHTS);
        } else if (strcmp(arguments[index], "--write") == 0 && index + 1 < argument_count) {
            add_rule(arguments[++index], READ_RIGHTS | EXECUTE_RIGHTS | WRITE_RIGHTS);
        } else if (strcmp(arguments[index], "--sync-wakeup") == 0) {
            synchronous_wake_up = true;
        } else if (strcmp(arguments[index], "--helper") == 0 && index + 1 < argument_count) {
            helper_path = arguments[++index];
        } else if (strcmp(arguments[index], "--") == 0) {
            index++;
            break;
        }
    }
    if (index >= argument_count) {
        fprintf(stderr, "usage: denial-report-spike --mode MODE [--read P] [--write P] -- COMMAND\n");
        return 2;
    }
    char **command = &arguments[index];
    if (mode == MODE_PLAIN) {
        execvp(command[0], command);
        fail("exec");
    }
    if (mode == MODE_LANDLOCK) {
        apply_landlock();
        execvp(command[0], command);
        fail("exec");
    }

    remember_rule_inodes();
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) {
        fail("socketpair");
    }
    pid_t child = fork();
    if (child < 0) {
        fail("fork");
    }
    if (child == 0) {
        close(pair[0]);
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            fail("no_new_privs");
        }
        int listener = install_report_filter();
        if (listener < 0) {
            fail("seccomp NEW_LISTENER");
        }
        if (!send_descriptor(pair[1], listener)) {
            fail("handing the listener up");
        }
        close(listener);
        close(pair[1]);
        if (helper_path != nullptr && fork() == 0) {
            usleep(100000);
            run_helper(helper_path);
        }
        apply_landlock();
        install_marker_filter();
        execvp(command[0], command);
        fail("exec");
    }
    close(pair[1]);
    int listener = receive_descriptor(pair[0]);
    if (listener < 0) {
        fail("child gave no listener");
    }
    close(pair[0]);
    if (synchronous_wake_up
        && ioctl(listener, SECCOMP_IOCTL_NOTIF_SET_FLAGS, SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP) != 0) {
        fail("SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP");
    }
    supervise(listener, mode);
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
    fprintf(stderr,
            "denial-report-spike: %lu notifications, %lu denials reported or counted, %lu repeats "
            "suppressed\n",
            notifications_total, denials_total, denials_suppressed);
    for (size_t number = 0; number < CALLS_COUNTED; number++) {
        if (notifications_by_call[number] != 0) {
            fprintf(stderr, "denial-report-spike: syscall %zu trapped %lu times\n", number,
                    notifications_by_call[number]);
        }
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 128 + WTERMSIG(status);
}
