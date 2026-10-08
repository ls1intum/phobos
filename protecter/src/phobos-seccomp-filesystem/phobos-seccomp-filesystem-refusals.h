/*
 * The calls a Phobos seccomp filter refuses outright, and the one answer a supervisor gives them.
 *
 * The group lock (and, from the guard's side, the connect guard's filter) refuses these calls with
 * a user notification rather than an errno, so that a supervisor can report them: a listener-less
 * filter refuses such a call on its own with ENOSYS, and a newer filter trapping the same call with
 * a listener wins the tie, so its supervisor is asked (A.5.8 of the plan).
 *
 * The supervisor must never let such a call through. So this file is a separate code path with no
 * CONTINUE branch at all, structurally rather than by a condition: it never names the continue
 * flag, never calls a shared answering helper, and builds its one response from compile-time
 * constants (error -EACCES, value 0, flags 0), so no input can change what it sends. The unit
 * runner checks the source for those names before it builds anything.
 */
#ifndef PHOBOS_SECCOMP_FILESYSTEM_REFUSALS_H
#define PHOBOS_SECCOMP_FILESYSTEM_REFUSALS_H

#include "phobos-seccomp-filesystem-message.h"

#include <linux/seccomp.h>

/* Whether this notification belongs to the class a Phobos filter refuses outright: a foreign
 * arch or x32 number, io_uring_setup, io_uring_enter, io_uring_register, setsid or setpgid.
 * Decided from the arch first, so a foreign number equal to a native one is never read as it,
 * then from the number. Shared by both supervisors. */
bool is_filter_refusal(const struct seccomp_data *data);

/* Answers such a notification with error -EACCES, value 0 and flags 0, and reports it with the
 * wording of A.6.2, counted for the layer given. */
void answer_filter_refusal(int notify_descriptor, const struct seccomp_notif *request,
                           struct seccomp_notif_resp *response, enum report_layer layer);

#endif
