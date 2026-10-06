/*
 * Asks whether a tracer without privileges can observe a Landlock denial.
 *
 * The layer pruner records what the grading layers refuse by running the
 * command under strace, which is ptrace. That only works where ptrace is
 * permitted between a process and its own child (YAMA ptrace_scope at most 1,
 * and a seccomp profile that does not refuse ptrace) and where a refusal made
 * inside a Landlock domain is visible at the traced call's exit. Neither can be
 * read out of the source, so this walks the whole path the pruner relies on.
 *
 * The child asks to be traced, stops, proves that /etc/hostname is readable,
 * applies a Landlock ruleset that handles reading and grants nothing, and opens
 * /etc/hostname again. The parent follows every system call of the child and
 * reads each one's entry and exit with PTRACE_GET_SYSCALL_INFO. The answer is
 * yes only when the parent saw landlock_restrict_self succeed and then saw the
 * open fail with EACCES, and the child agrees that its open was refused.
 *
 * Exactly one line goes to standard output:
 *   OBSERVED openat errno=EACCES      exit 0
 *   TRACEME-REFUSED errno=<NAME>      exit 1
 *   NOT-OBSERVED                      exit 1
 *   NO-LANDLOCK                       exit 3
 *   INDETERMINATE <reason>            exit 3
 * The reasons behind any answer but the first go to standard error.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * The three-valued answer, as runner-capability-probe.sh reads it. An enum
 * rather than constexpr, because that script builds this file with the
 * compiler's default standard, which may predate C23.
 */
enum probe_exit {
    EXIT_AVAILABLE = 0,
    EXIT_UNAVAILABLE = 1,
    EXIT_INDETERMINATE = 3
};

/*
 * How the child tells the parent what it saw. Distinct from every status a
 * signal or a crash produces, so a child that never reached its own verdict
 * cannot be read as one.
 */
enum child_exit {
    CHILD_REFUSED_AS_EXPECTED = 0,
    CHILD_TRACEME_REFUSED = 40,
    CHILD_NOT_REFUSED = 41,
    CHILD_CANNOT_TELL = 42
};

/* The file the child reads, readable in every container image this probe runs in. */
static const char *const TARGET_FILE = "/etc/hostname";

/*
 * The bit the kernel adds to SIGTRAP for a system-call stop once
 * PTRACE_O_TRACESYSGOOD is set, so that a real SIGTRAP is not mistaken for one.
 */
static const int SYSCALL_STOP_BIT = 0x80;

/* What the parent learnt from following the child. */
struct observation {
    bool restricted;
    bool refusal_seen;
    uint64_t entry_number;
};

/* glibc ships no wrapper for this call, so it goes through syscall directly. */
static long create_ruleset(const struct landlock_ruleset_attr *attributes, size_t size, uint32_t flags) {
    return syscall(__NR_landlock_create_ruleset, attributes, size, flags);
}

/* glibc ships no wrapper for this call, so it goes through syscall directly. */
static long restrict_self(int ruleset_fd, uint32_t flags) {
    return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

/* Whether this kernel offers Landlock at all, asked before anything is traced. */
static bool landlock_available(void) {
    return create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) >= 0;
}

/* Whether a file can be opened for reading right now. */
static bool is_readable(const char *file) {
    int fd = open(file, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    close(fd);
    return true;
}

/*
 * Confines the calling process to a ruleset that handles reading and grants
 * nothing, so every later open for reading is refused by Landlock.
 */
static bool deny_every_read(void) {
    struct landlock_ruleset_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    long ruleset_fd = create_ruleset(&attributes, sizeof(attributes), 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "child: cannot create a ruleset: %s\n", strerror(errno));
        return false;
    }
    bool restricted = true;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "child: cannot set no_new_privs: %s\n", strerror(errno));
        restricted = false;
    }
    if (restricted && restrict_self((int) ruleset_fd, 0) != 0) {
        fprintf(stderr, "child: cannot restrict itself: %s\n", strerror(errno));
        restricted = false;
    }
    close((int) ruleset_fd);
    return restricted;
}

/*
 * The traced child. It never returns: its exit status is its own account of
 * what happened, which the parent sets beside what it observed.
 */
static _Noreturn void run_child(void) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
        printf("TRACEME-REFUSED errno=%s\n", strerrorname_np(errno));
        fflush(stdout);
        _exit(CHILD_TRACEME_REFUSED);
    }
    if (raise(SIGSTOP) != 0) {
        _exit(CHILD_CANNOT_TELL);
    }
    if (!is_readable(TARGET_FILE)) {
        fprintf(stderr, "child: %s is unreadable before any restriction\n", TARGET_FILE);
        _exit(CHILD_CANNOT_TELL);
    }
    if (!deny_every_read()) {
        _exit(CHILD_CANNOT_TELL);
    }
    int fd = open(TARGET_FILE, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        close(fd);
        fprintf(stderr, "child: %s was readable under a ruleset that grants nothing\n", TARGET_FILE);
        _exit(CHILD_NOT_REFUSED);
    }
    if (errno != EACCES) {
        fprintf(stderr, "child: %s was refused with %s, which is not Landlock\n", TARGET_FILE,
                strerrorname_np(errno));
        _exit(CHILD_CANNOT_TELL);
    }
    _exit(CHILD_REFUSED_AS_EXPECTED);
}

/* Whether a system-call number opens a path, on whichever architecture this was built for. */
static bool is_open_call(uint64_t number) {
#ifdef SYS_open
    if (number == SYS_open) {
        return true;
    }
#endif
#ifdef SYS_openat2
    if (number == SYS_openat2) {
        return true;
    }
#endif
    return number == SYS_openat;
}

/*
 * Reads one system-call stop and records what it shows: the number at entry,
 * and at exit whether Landlock was applied or an open was refused with EACCES.
 */
static bool read_syscall_stop(pid_t child, struct observation *seen) {
    struct __ptrace_syscall_info info;
    memset(&info, 0, sizeof(info));
    if (ptrace(PTRACE_GET_SYSCALL_INFO, child, (void *) sizeof(info), &info) < 0) {
        fprintf(stderr, "parent: PTRACE_GET_SYSCALL_INFO failed: %s\n", strerror(errno));
        return false;
    }
    if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
        seen->entry_number = info.entry.nr;
        return true;
    }
    if (info.op != PTRACE_SYSCALL_INFO_EXIT) {
        return true;
    }
    if (seen->entry_number == SYS_landlock_restrict_self && info.exit.rval == 0) {
        seen->restricted = true;
    }
    if (seen->restricted && is_open_call(seen->entry_number) && info.exit.is_error
        && info.exit.rval == -EACCES) {
        seen->refusal_seen = true;
    }
    return true;
}

/*
 * Follows the stopped child to its end, system call by system call. Returns the
 * child's exit status, or -1 where the child could not be followed.
 */
static int follow_child(pid_t child, struct observation *seen) {
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, (void *) (PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL)) != 0) {
        fprintf(stderr, "parent: PTRACE_SETOPTIONS failed: %s\n", strerror(errno));
        return -1;
    }
    int pending_signal = 0;
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, child, NULL, (void *) (intptr_t) pending_signal) != 0) {
            fprintf(stderr, "parent: PTRACE_SYSCALL failed: %s\n", strerror(errno));
            return -1;
        }
        pending_signal = 0;
        int status = 0;
        if (waitpid(child, &status, 0) < 0) {
            fprintf(stderr, "parent: waitpid failed: %s\n", strerror(errno));
            return -1;
        }
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "parent: the child was killed by signal %d\n", WTERMSIG(status));
            return -1;
        }
        if (!WIFSTOPPED(status)) {
            continue;
        }
        if (WSTOPSIG(status) == (SIGTRAP | SYSCALL_STOP_BIT)) {
            if (!read_syscall_stop(child, seen)) {
                return -1;
            }
        } else {
            pending_signal = WSTOPSIG(status);
        }
    }
}

/* Prints the one line and turns what the parent and the child saw into the probe's answer. */
static int verdict(int child_status, const struct observation *seen) {
    if (child_status == CHILD_TRACEME_REFUSED) {
        return EXIT_UNAVAILABLE;
    }
    if (child_status != CHILD_REFUSED_AS_EXPECTED) {
        puts("INDETERMINATE the child did not reach a Landlock refusal of its own");
        return EXIT_INDETERMINATE;
    }
    if (seen->refusal_seen) {
        puts("OBSERVED openat errno=EACCES");
        return EXIT_AVAILABLE;
    }
    if (!seen->restricted) {
        fprintf(stderr, "parent: landlock_restrict_self was never seen to succeed\n");
    }
    puts("NOT-OBSERVED");
    return EXIT_UNAVAILABLE;
}

/*
 * Waits for the child's first stop, the SIGSTOP it raises once traced, or for
 * its early exit when it could not ask to be traced. Returns true when the
 * child is stopped and ready to be followed.
 */
static bool wait_for_first_stop(pid_t child, int *early_status) {
    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        fprintf(stderr, "parent: waitpid failed: %s\n", strerror(errno));
        *early_status = -1;
        return false;
    }
    if (WIFEXITED(status)) {
        *early_status = WEXITSTATUS(status);
        return false;
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
        fprintf(stderr, "parent: the child's first stop was not its own SIGSTOP\n");
        *early_status = -1;
        return false;
    }
    return true;
}

int main(void) {
    if (!landlock_available()) {
        fprintf(stderr, "landlock unavailable: %s\n", strerror(errno));
        puts("NO-LANDLOCK");
        return EXIT_INDETERMINATE;
    }
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "parent: fork failed: %s\n", strerror(errno));
        puts("INDETERMINATE fork failed");
        return EXIT_INDETERMINATE;
    }
    if (child == 0) {
        run_child();
    }
    struct observation seen;
    memset(&seen, 0, sizeof(seen));
    int child_status = 0;
    if (wait_for_first_stop(child, &child_status)) {
        child_status = follow_child(child, &seen);
    }
    if (child_status < 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        puts("NOT-OBSERVED");
        return EXIT_UNAVAILABLE;
    }
    return verdict(child_status, &seen);
}
