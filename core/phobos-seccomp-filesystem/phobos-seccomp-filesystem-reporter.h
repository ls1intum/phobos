/*
 * The observation traps of a supervisor: arming on the Landlock enforcer, telling the tasks of the
 * filesystem domain from the layers' helpers beside them, and answering every observation trap with
 * CONTINUE.
 *
 * The supervisor's filter is in force long before the filesystem domain exists, over the layers'
 * own shells and helpers, which read paths the policy does not grant. So nothing is judged until the
 * enforcer itself arms the reporter: it calls landlock_restrict_self, which the filter traps, and
 * the reporter reads the exact rules from the enforcer's own command line (A.5.3 of the plan). Right
 * after the restriction the enforcer installs one more seccomp filter that allows everything, so the
 * tasks of the domain, and only they, carry one filter more than the count recorded at arming.
 *
 * Every notification this module services is answered with SECCOMP_USER_NOTIF_FLAG_CONTINUE, error
 * 0 and value 0, whatever was judged: the kernel, and Landlock in it, decides the call.
 */
#ifndef PHOBOS_SECCOMP_FILESYSTEM_REPORTER_H
#define PHOBOS_SECCOMP_FILESYSTEM_REPORTER_H

#include "phobos-seccomp-filesystem-judge.h"

#include <linux/seccomp.h>

/* The arming state machine's state. */
enum reporter_state {
    REPORTER_UNARMED,
    REPORTER_NETWORK_ARMED,
    REPORTER_FILESYSTEM_ARMED,
};

/* Tells the reporter the enforcer's path, which arming compares with /proc/<pid>/exe, and the
 * Landlock version the models are built for. Both supervisors take the path as --landlock-bin,
 * from the same value the layers give the enforcer. */
void reporter_configure(const char *landlock_bin, int landlock_version);

/* The arming state machine's state, for the tests and the --verbose lines. */
enum reporter_state reporter_current_state(void);

/* Whether this notification is one of the observation traps, the calls of REPORT_TRAPPED_CALLS
 * through the native ABI. */
bool reporter_handles(const struct seccomp_notif *request);

/* Services one observation-trap notification: arms on landlock_restrict_self, judges a call of a
 * task in the filesystem domain, and always answers CONTINUE. Never answers anything else. */
void reporter_service(int notify_descriptor, const struct seccomp_notif *request,
                      struct seccomp_notif_resp *response);

/* Gives the reporter the guard's socket table, so a bind can be judged by its transport; the
 * report-only supervisor gives none and judges UNIX paths only. */
void reporter_use_socket_types(socket_type_lookup lookup);

#ifdef PHOBOS_REPORTER_UNIT_TEST
/* Forgets the arming, the models and the configuration, so each case starts unarmed. */
void reset_reporter_for_tests(void);

/* How many rules the filesystem model holds, so a case can tell which command line armed it. */
size_t reporter_filesystem_rule_count(void);
#endif

#endif
