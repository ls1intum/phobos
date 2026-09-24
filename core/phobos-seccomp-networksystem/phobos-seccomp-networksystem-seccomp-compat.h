/*
 * The seccomp user-notification names older kernel headers lack.
 *
 * Defined here rather than assumed, so the guard builds where the headers are older than
 * the kernel it runs on, the way the Landlock sources define the names they use.
 */
#ifndef PHOBOS_CONNECT_GUARD_SECCOMP_COMPAT_H
#define PHOBOS_CONNECT_GUARD_SECCOMP_COMPAT_H

#include <linux/seccomp.h>
#include <linux/types.h>
#include <sys/ioctl.h>

/* Older kernel headers describe user-notification without the addfd ioctl that
 * lets the supervisor inject a socket. The run-phase image is new enough, but the
 * fallbacks keep the file buildable where the headers are not, matching how the
 * Landlock sources define what they use rather than assuming the headers carry it. */
#ifndef SECCOMP_ADDFD_FLAG_SETFD
#define SECCOMP_ADDFD_FLAG_SETFD (1UL << 0)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_ADDFD
struct seccomp_notif_addfd {
    __u64 id;
    __u32 flags;
    __u32 srcfd;
    __u32 newfd;
    __u32 newfd_flags;
};
#define SECCOMP_IOCTL_NOTIF_ADDFD _IOW('!', 3, struct seccomp_notif_addfd)
#endif

/* Letting the kernel run the child's own syscall after the supervisor has looked at it.
 * Older headers lack the flag; the value is stable. */
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

#endif
