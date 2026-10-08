/*
 * What a supervisor asks the kernel before it installs a filter it will answer: whether a
 * supervised call can be continued at all, and how big the kernel's notification structures are.
 *
 * A kernel can accept a listener filter (Linux 5.0) without knowing SECCOMP_USER_NOTIF_FLAG_CONTINUE
 * (Linux 5.5), and a vendor kernel can carry a Landlock backport on an older seccomp. A refused
 * CONTINUE would leave a trapped call failed, which is exactly the change of outcome a reporter must
 * never make, so CONTINUE is proved by a throwaway probe rather than inferred from a version.
 */
#ifndef PHOBOS_SECCOMP_FILESYSTEM_HANDOFF_H
#define PHOBOS_SECCOMP_FILESYSTEM_HANDOFF_H

#include <linux/seccomp.h>
#include <stddef.h>

/* How long the probe waits for its one notification, in milliseconds. */
static constexpr int CONTINUE_PROBE_WAIT_MS = 1000;

/* Proves SECCOMP_USER_NOTIF_FLAG_CONTINUE on this kernel with a throwaway probe child: true only
 * when the probe's trapped getppid was continued and returned this process's number. Every failure
 * of the check (a socket pair or fork that fails, a probe that cannot install or hand over its
 * listener, a notification that does not come within CONTINUE_PROBE_WAIT_MS, a refused send) is
 * false, never an exit, and the probe is reaped and every descriptor closed before it returns. The
 * listener is closed before the probe's answer is read, which releases a probe still waiting in its
 * trapped call (it then gets ENOSYS), so the check can never hang. */
bool continue_supported(void);

/* Whether the timeout layer's group lock is above this process: a throwaway child makes the group
 * lock's signature call, setpgid(0, PHB_GROUP_LOCK_SIGNATURE_PGID), and the answer is true only
 * for ENOTRECOVERABLE, the errno only the group lock gives it. EINVAL, any other answer and any
 * failure of the probe answer false, the safe direction: no refusal trap is installed, so nothing is
 * refused that no filter refuses. The child carries every filter this process carries, and the
 * supervisor's own filter does not exist yet when this is asked. */
bool group_lock_present(void);

/* Allocates a notification and a response of the sizes the running kernel uses, which may be
 * larger than this build's structures. Answers false, with neither allocated, when memory runs out. */
bool allocate_notification_buffers(struct seccomp_notif **request, size_t *request_size,
                                   struct seccomp_notif_resp **response);

#endif
