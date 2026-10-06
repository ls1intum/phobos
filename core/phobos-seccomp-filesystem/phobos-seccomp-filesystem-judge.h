/*
 * Whether Landlock refuses a trapped path call, judged against the model of the enforcer's rules,
 * and the one line that names it.
 *
 * The judgement only decides whether to print. It never answers the notification and never
 * changes what the kernel does: the call is continued whatever the judgement says, and Landlock
 * alone decides it. So every doubt is resolved towards silence. A call is judged only when every
 * flag it carries is in the plan's whitelist, and only when nothing the kernel checks before
 * Landlock would end it first (a missing name, an existing one, the file mode, a read-only,
 * noexec or nodev mount, an append-only file, the protection of sticky directories, a type
 * mismatch, a final symbolic link under a no-follow flag, two mounts). Every name is resolved as
 * the kernel resolves it for the task, /proc/self and /proc/thread-self included, so the object
 * judged is the task's and not the supervisor's. A task whose credentials or root differ from the
 * supervisor's is not judged at all, because the supervisor could not tell the file mode's refusal
 * from Landlock's.
 */
#ifndef PHOBOS_SECCOMP_FILESYSTEM_JUDGE_H
#define PHOBOS_SECCOMP_FILESYSTEM_JUDGE_H

#include "phobos-seccomp-filesystem-access.h"
#include "phobos-seccomp-filesystem-path.h"

#include "../phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-model.h"

/* The transport of one of the command's sockets, SOCK_STREAM or SOCK_DGRAM, or -1 when unknown. */
typedef int (*socket_type_lookup)(pid_t pid, int descriptor);

/* Judges one decoded request of a task inside the filesystem domain against the filesystem model,
 * and reports it when Landlock refuses it. Reads only; never answers the notification. Returns
 * after at most one report_blocked. */
void judge_and_report(const struct task_view *task, const struct access_request *request,
                      const struct policy_model *filesystem);

/* Judges a bind to an IPv4 or IPv6 port against the network model, and reports it when the
 * network ruleset refuses it. The transport comes from socket_type_of; a socket it does not know
 * is not judged. Reads only; never answers the notification. */
void judge_bind_port(const struct task_view *task, const struct access_request *request,
                     const struct policy_model *network, socket_type_lookup socket_type_of);

#ifdef PHOBOS_REPORTER_UNIT_TEST
/* Forgets the supervisor's own status read earlier, so a case can hand it a different one. */
void reset_judge_for_tests(void);
#endif

#endif
