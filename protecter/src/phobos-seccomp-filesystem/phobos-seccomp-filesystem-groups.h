/*
 * The virtual sessions and process groups a supervisor keeps for the command it supervises.
 *
 * The timeout layer bounds a run by signalling the one process group GNU timeout made, so no process under
 * it may really change its group or session. A program that starts another program with setsid, and later
 * stops it with killpg(getpgid(pid)), as the testers of Artemis's C GCC and C++ templates do, and a build
 * tool that starts each child with setpgid(0, 0), as SwiftPM does, want exactly that. This module gives
 * them the answers they expect without the change: setsid and setpgid are never run, never continued, and
 * only recorded in a ledger, so every process stays in the real group the timeout kills. The questions the
 * program asks afterwards (getpgid, getsid, getpgrp) and the signals it sends to a group (kill with a
 * pid of zero or below) are answered from the ledger when the process is in it, and passed on to the kernel
 * otherwise.
 *
 * A process is in the ledger when it, or its nearest ancestor found by walking /proc, asked for a virtual
 * group or session. Membership is by ancestry at the time of the question, not by inheritance at fork: a
 * process whose parent has ended, and so been reparented, is no longer found. waitpid on a group, the
 * terminal calls (TIOCSPGRP and friends) and /proc/<pid>/stat see the real ids.
 *
 * A group signal is delivered by this supervisor, with its own credentials, to the members only, each
 * through a process descriptor opened before the process's start time is read again, so a number the kernel
 * gave away in between is never signalled. Members are descendants of a process that asked for a group, so
 * the signal never leaves the sandboxed lineage; a nested Landlock scope that lineage set up itself does not
 * limit it.
 *
 * It keeps its ledger in static storage without a lock, because it runs in the supervisor's one thread.
 */
#ifndef PHOBOS_SECCOMP_FILESYSTEM_GROUPS_H
#define PHOBOS_SECCOMP_FILESYSTEM_GROUPS_H

#include <linux/seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/* One process as /proc shows it: the numbers the ledger needs and the start time that tells it from
 * another process that was given the same number later. */
struct process_view {
    pid_t process;
    pid_t parent;
    pid_t group;
    pid_t session;
    unsigned long long start;
};

/* Where the ledger gets its facts, so a test can give it a table of its own. */
struct process_table {
    /* Fills the view of a process; false when there is no such process or /proc cannot be read. */
    bool (*read)(pid_t process, struct process_view *view);
    /* The thread-group id of a thread id, or 0 when there is none. */
    pid_t (*thread_group)(pid_t thread);
    /* Lists up to capacity process ids; answers how many, or capacity + 1 when there were more. */
    size_t (*list)(pid_t *processes, size_t capacity);
    /* Sends a signal to the process the view describes, only if it still is that process; 0 or an errno. */
    int (*signal)(const struct process_view *target, int number);
};

/* The most records the ledger holds; a full ledger refuses a new group with ENOMEM and evicts no live one. */
static constexpr size_t GROUP_LEDGER_CAPACITY = 1024;
/* The most processes one scan looks at and the most ancestors one walk follows. Beyond either the
 * question is answered with the error a full table gives, or passed on, and never guessed. */
static constexpr size_t GROUP_SCAN_LIMIT = 8192;
static constexpr int GROUP_ANCESTRY_DEPTH = 64;
/* The highest signal number the kernel takes. */
static constexpr int GROUP_SIGNAL_MAXIMUM = 64;

/* The answer to one trapped call: either let the kernel run it, or this value or error without running it. */
struct group_answer {
    bool pass_on;
    long value;
    int error;
};

/* Reads one line of /proc/<pid>/stat: the numbers after the closing parenthesis of the name, which may hold
 * spaces and parentheses itself. False when the line does not have them. */
bool parse_process_stat(const char *line, pid_t process, struct process_view *view);

/* The thread-group id a /proc/<tid>/status text names, or 0. */
pid_t parse_thread_group(const char *status);

/* Turns the virtual groups on, over the process table given (or /proc when it is null). They are off until
 * a supervisor that has proved it can continue a call turns them on. */
void groups_configure(bool enabled, const struct process_table *table);

/* Whether a supervisor answers the group calls itself. */
bool groups_enabled(void);

/* Whether a notification is one of the calls this module answers: setsid, setpgid, getpgid, getsid,
 * getpgrp where there is one, and a kill whose pid is zero or below. Native ABI only, never x32. */
bool is_group_call(const struct seccomp_data *data);

/* Decides one call. setsid and setpgid are never answered with pass_on: their deciders have no such return. */
struct group_answer decide_group_call(const struct seccomp_notif *request);

/* Decides and sends the answer. */
void answer_group_call(int notify_descriptor, const struct seccomp_notif *request,
                       struct seccomp_notif_resp *response);

/* The table that reads /proc, for a test. */
const struct process_table *groups_table_for_tests(void);

/* The ledger made empty, for a test. */
void groups_reset_for_tests(void);

#endif
