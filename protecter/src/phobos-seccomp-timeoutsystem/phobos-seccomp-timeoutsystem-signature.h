/*
 * The one call that tells a supervisor the timeout layer's group lock is above it.
 *
 * The group lock answers setpgid with this negative process group by ENOTRECOVERABLE, an errno no
 * kernel path gives setpgid; the kernel itself refuses a negative group with EINVAL, so a program
 * that makes the call fails either way and only the errno differs. A supervisor that makes the
 * call and gets ENOTRECOVERABLE knows the group lock is installed above it, which, together with
 * the layers' own --group-lock-above, is when it may answer the group lock's refusals (A.5.8 of
 * the denial-reporting plan). Shared by the group lock and the report-only supervisor, so the two
 * can never disagree on the number.
 */
#ifndef PHOBOS_SECCOMP_TIMEOUTSYSTEM_SIGNATURE_H
#define PHOBOS_SECCOMP_TIMEOUTSYSTEM_SIGNATURE_H

static constexpr int PHB_GROUP_LOCK_SIGNATURE_PGID = -20555;

#endif
