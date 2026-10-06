/*
 * The report-only supervisor's seccomp filter.
 *
 * It traps two kinds of call, each with exactly one answer (A.5.2 and A.5.8 of the plan): the
 * observation traps, the path calls of REPORT_TRAPPED_CALLS, which the reporter always continues;
 * and, only when the timeout layer's group lock is above the supervisor, the refusal traps, the
 * calls the group lock refuses outright (setsid, setpgid and every call through a foreign ABI),
 * which the supervisor always answers with EACCES. Everything else is allowed, so the filter
 * refuses nothing that no other filter refuses.
 */
#ifndef PHOBOS_SECCOMP_FILESYSTEM_FILTER_H
#define PHOBOS_SECCOMP_FILESYSTEM_FILTER_H

#include <linux/filter.h>
#include <stddef.h>

/* Room for the longest filter built here. */
static constexpr size_t REPORT_FILTER_MAXIMUM = 128;

/* Appends the observation traps to a filter under construction, with the call number already in
 * the accumulator: one comparison and one USER_NOTIF answer per call of REPORT_TRAPPED_CALLS.
 * Answers the number of instructions written, or 0 when they do not fit in room. */
size_t append_report_traps(struct sock_filter *instructions, size_t room);

/* Writes the whole filter into instructions: the native-ABI check, the refusal traps when
 * refusal_traps, the observation traps when file_traps, and ALLOW for everything else. A foreign
 * ABI is trapped as a refusal when refusal_traps and allowed otherwise. Answers the number of
 * instructions. */
size_t build_report_filter(struct sock_filter *instructions, bool file_traps, bool refusal_traps);

/* Installs the filter with a listener and answers the listener, or -1 with errno set. The caller
 * has set no_new_privs. */
int install_report_filter(bool file_traps, bool refusal_traps);

#endif
