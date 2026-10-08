/*
 * The sandboxed half of the guard: it installs the seccomp filter, hands its notification
 * descriptor to the supervisor, and becomes the rest of the layer chain.
 */
#ifndef PHOBOS_CONNECT_GUARD_CHILD_H
#define PHOBOS_CONNECT_GUARD_CHILD_H

#include <linux/audit.h>
#include <linux/filter.h>
#include <stddef.h>

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

/* Which observation traps the guard's filter carries beside the calls it enforces (A.5.2 of the
 * denial-reporting plan). None is exactly the filter the guard had before it reported anything. */
enum guard_report_mode {
    GUARD_REPORT_NONE,
    GUARD_REPORT_NETWORK,
    GUARD_REPORT_FILESYSTEM,
};

/* Room for the longest filter built here: the enforced calls, every observation trap and the two
 * blocks that handle the sends. */
static constexpr size_t GUARD_FILTER_MAXIMUM = 192;

/* Writes the guard's whole filter into instructions, which holds GUARD_FILTER_MAXIMUM, with the
 * observation traps the mode asks for, and answers the number of instructions. Exposed so the unit
 * suite can run it against every call number and compare the modes. */
size_t build_connect_filter(struct sock_filter *instructions, int bootstrap_descriptor,
                            enum guard_report_mode mode);

/* The child. Installs the filter, with the observation traps the mode asks for, sends its
 * notification descriptor up, then becomes the rest of the chain. Never returns: it execs, or it
 * exits. */
[[noreturn]] void run_child(int send_descriptor_to_parent, char *const command[],
                            enum guard_report_mode mode);

#endif
