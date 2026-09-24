/*
 * The sandboxed half of the guard: it installs the seccomp filter, hands its notification
 * descriptor to the supervisor, and becomes the rest of the layer chain.
 */
#ifndef PHOBOS_CONNECT_GUARD_CHILD_H
#define PHOBOS_CONNECT_GUARD_CHILD_H

#include <linux/audit.h>

/* The one native ABI this build's syscall numbers belong to. The filter denies every other
 * ABI, so a call made through an alternate one (i386 int 0x80, or x32) cannot slip past the
 * native-number comparisons unwatched. It lives here rather than beside the filter so that
 * the suite which runs the filter names the same architecture the filter was built for,
 * rather than carrying a second copy of this choice. */
#if defined(__x86_64__)
#define GUARD_NATIVE_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define GUARD_NATIVE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "phobos-seccomp-networksystem supports x86-64 and aarch64 only"
#endif

/* The child. Installs the filter, sends its notification descriptor up, then
 * becomes the rest of the chain. Never returns: it execs, or it exits. */
[[noreturn]] void run_child(int send_descriptor_to_parent, char *const command[]);

#endif
