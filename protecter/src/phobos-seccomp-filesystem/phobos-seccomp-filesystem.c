/*
 * phobos-seccomp-filesystem -- the report-only supervisor: report what Landlock and the timeout
 * layer's group lock refuse, while changing the outcome of no call.
 *
 * The filesystem layer starts it when the network layer is off (with the network layer on, the
 * connect guard is the run's one supervisor, because only one listener may exist per filter tree).
 * It forks: the child installs a seccomp filter with a listener, hands the listener up and becomes
 * the rest of the chain; the parent answers every notification until its child has ended.
 *
 * Usage:
 *   phobos-seccomp-filesystem [--verbose] --landlock-bin PATH [--no-landlock]
 *                             [--group-lock-above] -- COMMAND [ARGUMENTS...]
 *
 * Two kinds of trap, each with exactly one answer. The path calls are observation traps: the
 * reporter (-reporter.c) arms on the Landlock enforcer named by --landlock-bin, judges the calls of
 * the tasks of its domain against the enforcer's own rules, prints a line for a refusal, and
 * answers every one of them with CONTINUE, so Landlock alone decides. They are installed only when
 * Landlock will be applied (no --no-landlock), the kernel has Landlock and the kernel is proved to
 * continue a supervised call. The calls the group lock refuses outright (setsid, setpgid, a foreign
 * ABI) are refusal traps: answered with EACCES only, by -refusals.c, which has no CONTINUE path at
 * all. They are installed only when the layers say the group lock is above (--group-lock-above)
 * and the group lock's signature confirms it, so the supervisor never refuses a call no filter
 * refuses. With neither kind to install it execs the command without forking.
 *
 * Reporting is a diagnostic, never a reason to refuse a run: a filter that cannot be installed (a
 * listener already held above it, EBUSY) is said once and the command runs without reporting.
 * Once its child has ended it prints the run's one summary line, when anything was counted, and a
 * drainer it forks keeps answering whatever the child left behind, with its output silenced, until
 * no task is left; the supervisor ends with the child's status, or with 16 (PHB-ESTATUS) when that
 * status could not be read.
 *
 * This file is the sequence of stages and nothing else. What each stage works with lives beside it:
 *
 *   phobos-seccomp-filesystem-filter.h      the filter and its two kinds of trap
 *   phobos-seccomp-filesystem-handoff.h     the CONTINUE probe, the group lock's signature probe
 *   phobos-seccomp-filesystem-reporter.h    arming, membership, the observation traps' answer
 *   phobos-seccomp-filesystem-refusals.h    the refusal traps' answer
 *   phobos-seccomp-filesystem-judge.h       the mirror of the Landlock decision
 *   phobos-seccomp-filesystem-message.h     the line, its quoting, de-duplication and counts
 *   ../phobos-seccomp-networksystem/phobos-seccomp-networksystem-handoff.h
 *                                            the listener's handoff, signals, reaping, status
 */

#define _GNU_SOURCE
#include "phobos-seccomp-filesystem-filter.h"
#include "phobos-seccomp-filesystem-groups.h"
#include "phobos-seccomp-filesystem-handoff.h"
#include "phobos-seccomp-filesystem-message.h"
#include "phobos-seccomp-filesystem-refusals.h"
#include "phobos-seccomp-filesystem-reporter.h"

#include "../phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-policy.h"
#include "../phobos-seccomp-networksystem/phobos-seccomp-networksystem-handoff.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Linux 6.6: wake the supervisor synchronously, so the trapped thread and the supervisor swap on one
 * CPU instead of each waiting for the scheduler. Older headers lack the names. */
#ifndef SECCOMP_IOCTL_NOTIF_SET_FLAGS
#define SECCOMP_IOCTL_NOTIF_SET_FLAGS SECCOMP_IOW(4, __u64)
#endif
#ifndef SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP
#define SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP (1UL << 0)
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

/* The exit statuses of a call made the wrong way, of a run that cannot be supervised as asked
 * (PHB-ERUNTIME, as phobos-constants.sh names it), and of a command that cannot be executed. */
static constexpr int EXIT_CODE_USAGE = 2;
static constexpr int EXIT_CODE_RUNTIME = 15;
static constexpr int EXIT_CODE_COMMAND_NOT_EXECUTABLE = 127;

/* What the command line asked for. */
struct supervisor_options {
    bool verbose;
    const char *landlock_bin;
    bool no_landlock;
    bool group_lock_above;
    char **command;
};

/* Says how to call this tool and gives up. */
[[noreturn]] static void print_supervisor_usage_and_exit(void) {
    fprintf(stderr, "Usage: phobos-seccomp-filesystem [--verbose] --landlock-bin PATH [--no-landlock]\n"
                    "                                 [--group-lock-above] -- COMMAND [ARGUMENTS...]\n");
    exit(EXIT_CODE_USAGE);
}

/* Reads the command line, or gives up with the usage. */
static void read_supervisor_arguments(int argument_count, char *arguments[], struct supervisor_options *options) {
    memset(options, 0, sizeof(*options));
    int index = 1;
    for (; index < argument_count && strcmp(arguments[index], "--") != 0; index++) {
        if (strcmp(arguments[index], "--verbose") == 0) {
            options->verbose = true;
        } else if (strcmp(arguments[index], "--no-landlock") == 0) {
            options->no_landlock = true;
        } else if (strcmp(arguments[index], "--group-lock-above") == 0) {
            options->group_lock_above = true;
        } else if (strcmp(arguments[index], "--landlock-bin") == 0 && index + 1 < argument_count) {
            options->landlock_bin = arguments[++index];
        } else {
            print_supervisor_usage_and_exit();
        }
    }
    if (index + 1 >= argument_count || options->landlock_bin == NULL) {
        print_supervisor_usage_and_exit();
    }
    options->command = &arguments[index + 1];
}

/* Prints one line under --verbose. */
static void say_verbose(const struct supervisor_options *options, const char *line) {
    if (options->verbose) {
        fprintf(stderr, "[phobos-seccomp-filesystem] %s\n", line);
    }
}

/* Says once what goes unreported in this run, and why: the filesystem denials when the observation
 * traps were wanted, the group lock's refusals when the refusal traps were, or both. A run that
 * would only have reported the group lock's refusals loses nothing of the filesystem's, so the
 * notice does not say it does. */
static void say_reporting_off(bool file_traps, bool refusal_traps, const char *reason) {
    if (file_traps && refusal_traps) {
        fprintf(stderr, "Phobos: filesystem denials and the group lock's refusals are not reported in "
                        "this run, because %s.\n", reason);
    } else if (refusal_traps) {
        fprintf(stderr, "Phobos: the group lock's refusals are not reported in this run, because %s.\n",
                reason);
    } else {
        fprintf(stderr, "Phobos: filesystem denial reporting is off for this run, because %s.\n",
                reason);
    }
}

/* Whether the observation traps may be installed: Landlock will be applied, the kernel has it, and
 * the kernel continues a supervised call. Says why not when the reason is the kernel's. */
static bool file_traps_wanted(const struct supervisor_options *options, int landlock_version) {
    if (options->no_landlock) {
        return false;
    }
    if (landlock_version < 1) {
        say_reporting_off(true, false, "this kernel has no Landlock");
        return false;
    }
    if (!continue_supported()) {
        say_reporting_off(true, false, "this kernel cannot continue a supervised call, or another "
                                       "supervisor already holds the run's listener");
        return false;
    }
    return true;
}

/* Whether the refusal traps may be installed: the layers say the group lock is above, and its
 * signature confirms it. Says so when the layers said it and the signature did not. */
static bool refusal_traps_wanted(const struct supervisor_options *options) {
    if (!options->group_lock_above) {
        return false;
    }
    if (!group_lock_present()) {
        fprintf(stderr, "Phobos: the group lock's refusals are not reported in this run, because "
                        "its signature was not found.\n");
        return false;
    }
    return true;
}

/* The SIGCHLD disposition this supervisor inherited. main gives SIGCHLD its default before anything
 * forks, the probes included, and every way of becoming the command gives this one back. */
static struct sigaction inherited_child_signal;

/* Becomes the command, with the SIGCHLD disposition the supervisor's caller gave it. */
[[noreturn]] static void exec_command(char **command) {
    restore_child_signal(&inherited_child_signal);
    execvp(command[0], command);
    fprintf(stderr, "[phobos-seccomp-filesystem] exec %s: %s\n", command[0], strerror(errno));
    _exit(EXIT_CODE_COMMAND_NOT_EXECUTABLE);
}

/* The child: installs the filter, hands its listener up and becomes the command. A filter that
 * cannot be installed is said once and the command runs without reporting; a listener that cannot
 * be handed up ends the child, because its trapped calls would all fail with no supervisor. */
[[noreturn]] static void run_child(int socket_descriptor, bool file_traps, bool refusal_traps,
                                   char **command) {
    int listener = -1;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0) {
        listener = install_report_filter(file_traps, refusal_traps);
    }
    if (listener < 0) {
        say_reporting_off(file_traps, refusal_traps,
                          errno == EBUSY ? "another supervisor already holds the run's listener"
                                         : "its seccomp filter could not be installed");
        close(socket_descriptor);
        exec_command(command);
    }
    if (!send_descriptor(socket_descriptor, listener)) {
        fprintf(stderr, "[phobos-seccomp-filesystem] handing the listener up: %s\n", strerror(errno));
        _exit(EXIT_CODE_RUNTIME);
    }
    close(listener);
    close(socket_descriptor);
    exec_command(command);
}

/* Receives one notification and answers it: a refusal trap with EACCES, every other with CONTINUE.
 * The refusal class is decided first, from the arch and the number alone, so a refusal can never
 * reach the code that continues. */
static void service_one(int listener, struct seccomp_notif *request, size_t request_size,
                        struct seccomp_notif_resp *response) {
    memset(request, 0, request_size);
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, request) != 0) {
        return;
    }
    if (groups_enabled() && is_group_call(&request->data)) {
        answer_group_call(listener, request, response);
        return;
    }
    if (is_filter_refusal(&request->data)) {
        answer_filter_refusal(listener, request, response, REPORT_LAYER_TIMEOUT);
        return;
    }
    reporter_service(listener, request, response);
}

/* Answers notifications until no task is left under the filter (answering true) or, when child is
 * a process descriptor, until the child has ended (answering false). */
static bool supervise(int listener, int child, struct seccomp_notif *request, size_t request_size,
                      struct seccomp_notif_resp *response) {
    for (;;) {
        struct pollfd watch[2] = {{.fd = listener, .events = POLLIN, .revents = 0},
                                  {.fd = child, .events = POLLIN, .revents = 0}};
        int ready = poll(watch, child >= 0 ? 2 : 1, -1);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready < 0) {
            return true;
        }
        if ((watch[0].revents & POLLIN) != 0) {
            service_one(listener, request, request_size, response);
        }
        if ((watch[0].revents & (POLLHUP | POLLERR)) != 0) {
            return true;
        }
        if (child >= 0 && (watch[1].revents & POLLIN) != 0) {
            return false;
        }
    }
}

/* Keeps answering what the child left behind, in a process of its own with its standard streams
 * on /dev/null, so the run is neither held open nor written to after it has ended. It is forked
 * after the child was reaped and takes the default disposition of the forwarded signals, so it
 * never passes a signal on to a process number the kernel has given away since, and a caller's
 * SIGTERM ends it. A drainer that cannot be forked leaves the leftovers' trapped calls to fail with
 * ENOSYS once the listener closes. */
static void start_drainer(int listener, const sigset_t *forwarded, struct seccomp_notif *request,
                          size_t request_size, struct seccomp_notif_resp *response) {
    if (fork() != 0) {
        return;
    }
    for (int number = 1; number < NSIG; number++) {
        if (sigismember(forwarded, number) == 1) {
            signal(number, SIG_DFL);
        }
    }
    int null_device = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_device >= 0) {
        dup2(null_device, STDIN_FILENO);
        dup2(null_device, STDOUT_FILENO);
        dup2(null_device, STDERR_FILENO);
    }
    supervise(listener, -1, request, request_size, response);
    _exit(0);
}

/* Asks the kernel to wake this supervisor synchronously, and says once when it cannot. */
static void ask_for_synchronous_wake_up(int listener) {
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SET_FLAGS, SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP) != 0) {
        fprintf(stderr, "Phobos: this kernel cannot wake the reporter synchronously, so reporting "
                        "is slower.\n");
    }
}

/* The parent: receives the listener, answers notifications until the child has ended, hands what
 * is left to a drainer, and ends with the child's status. When the supervision ended with nothing
 * left to answer, or because poll failed, the listener is closed before the child is reaped, so a
 * child still waiting in a trapped call is released with ENOSYS rather than waited for for ever.
 * Without a process descriptor (pidfd_open refused) it answers until no task is left, as the
 * connect guard does. */
static int supervise_child(pid_t child, int socket_descriptor, const sigset_t *forwarded,
                           struct seccomp_notif *request, size_t request_size,
                           struct seccomp_notif_resp *response) {
    int status = 0;
    int listener = receive_descriptor(socket_descriptor);
    close(socket_descriptor);
    if (listener >= 0) {
        ask_for_synchronous_wake_up(listener);
        int child_descriptor = (int)syscall(SYS_pidfd_open, child, 0);
        bool nothing_left = supervise(listener, child_descriptor, request, request_size, response);
        if (child_descriptor >= 0) {
            close(child_descriptor);
        }
        if (nothing_left) {
            close(listener);
            listener = -1;
        }
    }
    bool reaped = reap_command(child, forwarded, &status);
    report_summary();
    if (listener >= 0) {
        start_drainer(listener, forwarded, request, request_size, response);
        close(listener);
    }
    if (!reaped) {
        fprintf(stderr, "[phobos-seccomp-filesystem] the command's exit status could not be read, "
                        "so the run cannot say whether it succeeded (PHB-ESTATUS)\n");
        return EXIT_CODE_STATUS_UNREAD;
    }
    return exit_code_from_status(status);
}

int main(int argument_count, char *arguments[]) {
    struct supervisor_options options;
    take_default_child_signal(&inherited_child_signal);
    read_supervisor_arguments(argument_count, arguments, &options);
    int landlock_version = options.no_landlock ? 0 : query_landlock_version();
    bool file_traps = file_traps_wanted(&options, landlock_version);
    bool refusal_traps = refusal_traps_wanted(&options);
    if (!file_traps && !refusal_traps) {
        say_verbose(&options, "nothing to watch, so the command runs unsupervised");
        exec_command(options.command);
    }
    groups_configure(file_traps && refusal_traps, nullptr);
    say_verbose(&options, file_traps ? "watching the path calls" : "not watching the path calls");
    say_verbose(&options, refusal_traps ? "answering the group lock's refusals"
                                        : "not answering the group lock's refusals");
    reporter_configure(options.landlock_bin, landlock_version);

    struct seccomp_notif *request = NULL;
    struct seccomp_notif_resp *response = NULL;
    size_t request_size = 0;
    int pair[2];
    if (!allocate_notification_buffers(&request, &request_size, &response)) {
        say_reporting_off(file_traps, refusal_traps, "there is no memory to answer notifications");
        exec_command(options.command);
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
        say_reporting_off(file_traps, refusal_traps,
                          "no socket pair could be made to hand its listener over");
        exec_command(options.command);
    }
    sigset_t forwarded;
    sigset_t before_fork;
    block_forwarded_signals(&forwarded, &before_fork);
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "[phobos-seccomp-filesystem] fork: %s\n", strerror(errno));
        return EXIT_CODE_RUNTIME;
    }
    if (child == 0) {
        sigprocmask(SIG_SETMASK, &before_fork, NULL);
        close(pair[0]);
        run_child(pair[1], file_traps, refusal_traps, options.command);
    }
    forward_signals_to(child);
    sigprocmask(SIG_SETMASK, &before_fork, NULL);
    close(pair[1]);
    int code = supervise_child(child, pair[0], &forwarded, request, request_size, response);
    free(request);
    free(response);
    return code;
}
