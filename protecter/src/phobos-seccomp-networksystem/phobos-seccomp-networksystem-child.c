#define _GNU_SOURCE
#include "phobos-seccomp-networksystem-child.h"

#include "phobos-seccomp-networksystem-diagnostics.h"
#include "phobos-seccomp-networksystem-handoff.h"

#include "../phobos-seccomp-filesystem/phobos-seccomp-filesystem-filter.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

/* The two ways this guard refuses a call outright. A call a filter refuses is handed to the
 * supervisor as a user notification, which answers it with EACCES, as an ordinary denied call
 * would, and reports it; once the supervisor is gone the kernel refuses the call itself, with
 * ENOSYS, because a filter that answers USER_NOTIF with no listener refuses it (A.5.8 of the
 * denial-reporting plan). The call never runs in either state. */
#define GUARD_REFUSE BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)

/* The refusal that stays an errno: the lockout of the bootstrap descriptor's sendmsg. It is the
 * newest filter, so as a notification it would be the match and, with no listener of its own,
 * answer ENOSYS without ever notifying the guard (A.10). It covers one descriptor number the
 * command does not reach, so nothing is lost by not reporting it. */
#define GUARD_REFUSE_AT_ONCE BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA))

/* Where the bootstrap descriptor is moved to: high enough that a command allocating descriptors
 * from the lowest free number up does not reach it before it runs out, so the lockout below never
 * falls on a descriptor the command actually reopened, yet low enough that the descriptor table
 * stays small. It is the target unless the descriptor limit is smaller, in which case the move
 * targets one below the limit instead. */
static constexpr int BOOTSTRAP_DESCRIPTOR_FLOOR = 1023;

/* One syscall refused outright, and one handed to the supervisor to decide. Each is a
 * comparison that skips the next instruction when the number does not match, so the
 * refusal or the trap must be exactly one instruction long and the jump distances must
 * stay 0 and 1. Writing the pair once is what keeps that true: the distances were
 * correct nine times over only because every branch happened to be one instruction, and
 * a two-instruction branch written by hand would have jumped into the middle of itself. */
#define GUARD_DENY_SYSCALL(number) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1), GUARD_REFUSE
#define GUARD_TRAP_SYSCALL(number) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)

/* The filter, over every egress path a submission has, not connect alone. On any but the
 * native ABI it refuses outright, so an i386 (int 0x80) socketcall or an x32 call cannot
 * arrive under a different arch or number and fall through to ALLOW unwatched. On the native
 * ABI it refuses io_uring (a second syscall interface that would reach connect unseen) and
 * setsid/setpgid (a new session or group would escape the timeout's group-kill), and it traps
 * socket, connect, listen, sendmmsg, sendmsg and every sendto that names a destination to the
 * supervisor, which decides them from the kernel's own copy of the scalar arguments and, for a
 * destination behind a pointer, from the child's memory. listen is trapped because the kernel gives a socket that was never bound a port
 * of its own choosing when it listens, a listener no bind rule judged; the supervisor therefore
 * runs every listen itself, on a socket it created. A sendto whose address pointer is null names no
 * destination, is the send() of a connected socket, and is allowed: its connect was the
 * supervisor's, so the peer is one the guard vetted, and its registers are a copy the command
 * cannot change, so there is nothing to race. Everything else is allowed.
 *
 * Three kinds of trap, each with exactly one answer. The enforcement traps (socket, connect,
 * listen and the sends) are decided by the guard. The refusal traps (a foreign ABI, io_uring,
 * setsid and setpgid) are answered with EACCES and never with anything else. The observation traps
 * (the path calls, bind and the arming call, from the denial reporter, and only in a report mode)
 * are answered with CONTINUE and never with anything else, so they decide nothing. The three sets
 * are disjoint, and the unit suite holds them so.
 *
 * sendmsg is the one call the child itself must make while this filter is in force: it hands
 * the notification descriptor up to the supervisor with sendmsg, because SCM_RIGHTS is the
 * only way to pass a descriptor and pidfd_getfd is refused in the container. Trapping every
 * sendmsg would park that handoff before the supervisor holds the descriptor to service it, so
 * the filter allows sendmsg on exactly one descriptor, the bootstrap socket the child hands the
 * descriptor over, and traps it on every other. The descriptor's number is read as two 32-bit
 * words, because a classic BPF register is 32 bits wide; a non-zero high word is not that small
 * descriptor and is trapped. The exception lasts only until the handoff is done:
 * install_sendmsg_lockout then denies sendmsg on that one descriptor for good, so a reused
 * descriptor number cannot inherit the allowance once the untrusted command runs.
 *
 * The trapped calls are decided in the supervisor rather than here, because a classic BPF
 * program cannot follow a pointer to read an address, and deciding the scalar cases there too
 * keeps the one decision in one testable place.
 *
 * The filter is written in two parts with the observation traps between them, so each part's
 * jumps stay local to it. The first part ends with the enforcement traps, which compare and fall
 * through, and the observation traps only compare, so nr still holds in the accumulator when the
 * sendto and sendmsg blocks are entered. Those blocks sit last, right before the final ALLOW:
 * the first instruction of each skips the whole block when the call is not its own, and the loads
 * of an argument's two words only clobber the accumulator on that block's own path, where no
 * later instruction reads it. The sendto block reads the address pointer as two 32-bit words for
 * the same reason the sendmsg block reads the descriptor so. */

/* Writes the first part, up to and including the enforcement traps, and answers its length. */
static size_t append_enforced_calls(struct sock_filter *out) {
    const struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, GUARD_NATIVE_AUDIT_ARCH, 1, 0),
        GUARD_REFUSE,
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#ifdef __X32_SYSCALL_BIT
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, __X32_SYSCALL_BIT, 0, 1),
        GUARD_REFUSE,
#endif
        GUARD_DENY_SYSCALL(__NR_io_uring_setup),
        GUARD_DENY_SYSCALL(__NR_io_uring_enter),
        GUARD_DENY_SYSCALL(__NR_io_uring_register),
        GUARD_DENY_SYSCALL(__NR_setsid),
        GUARD_DENY_SYSCALL(__NR_setpgid),
        GUARD_TRAP_SYSCALL(__NR_connect),
        GUARD_TRAP_SYSCALL(__NR_socket),
        GUARD_TRAP_SYSCALL(__NR_listen),
        GUARD_TRAP_SYSCALL(__NR_sendmmsg),
    };
    memcpy(out, instructions, sizeof(instructions));
    return sizeof(instructions) / sizeof(instructions[0]);
}

/* Writes the second part, the sendto and sendmsg blocks and the final ALLOW, and answers its
 * length. */
static size_t append_send_blocks(struct sock_filter *out, int bootstrap_descriptor) {
    const struct sock_filter instructions[] = {
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto, 0, 6),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[4]) + sizeof(__u32)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[4])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]) + sizeof(__u32)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (__u32)bootstrap_descriptor, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    memcpy(out, instructions, sizeof(instructions));
    return sizeof(instructions) / sizeof(instructions[0]);
}

/* Writes the observation traps the mode asks for, with the call number in the accumulator, and
 * answers their length. A mode of none writes nothing, which is exactly the filter the guard had
 * before it reported anything. */
static size_t append_observation_traps(struct sock_filter *out, size_t room,
                                       enum guard_report_mode mode) {
    if (mode == GUARD_REPORT_FILESYSTEM) {
        return append_report_traps(out, room);
    }
    if (mode == GUARD_REPORT_NETWORK) {
        return append_network_report_traps(out, room);
    }
    return 0;
}

size_t build_connect_filter(struct sock_filter *instructions, int bootstrap_descriptor,
                            enum guard_report_mode mode) {
    size_t used = append_enforced_calls(instructions);
    if (mode != GUARD_REPORT_NONE) {
        used += append_group_traps(&instructions[used]);
    }
    used += append_observation_traps(&instructions[used], GUARD_FILTER_MAXIMUM - used, mode);
    used += append_send_blocks(&instructions[used], bootstrap_descriptor);
    return used;
}

static int install_connect_filter(int bootstrap_descriptor, enum guard_report_mode mode) {
    struct sock_filter instructions[GUARD_FILTER_MAXIMUM];
    struct sock_fprog program = {
        .len = (unsigned short)build_connect_filter(instructions, bootstrap_descriptor, mode),
        .filter = instructions,
    };
    long listener = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                            SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
    if (listener < 0) {
        return -1;
    }
    return (int)listener;
}

/* Denies sendmsg on the bootstrap descriptor for the rest of the child's life, installed once
 * the handoff is done and before the untrusted command runs. The first filter allows sendmsg on
 * that one descriptor so the handoff can pass the listener; without this a descriptor number the
 * command later reopens at the same value would inherit that allowance. Stacked after the first
 * filter, so where both speak the kernel takes the stricter action: this filter's EACCES beats
 * the first's ALLOW on the bootstrap descriptor, while its ALLOW on every other call leaves the
 * first filter's trap in force. It reads the descriptor as two 32-bit words for the same reason
 * the first filter does, and does not re-check the ABI because the first filter already refuses
 * every non-native call, which the kernel takes over this filter's ALLOW. The refusal
 * is blanket on the bootstrap number, so relocate_bootstrap_descriptor moves that number high
 * first, out of the range a command reopens, so it never falls on the command's own traffic.
 * Returns whether the filter was installed. */
static bool install_sendmsg_lockout(int bootstrap_descriptor) {
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]) + sizeof(__u32)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (__u32)bootstrap_descriptor, 0, 1),
        GUARD_REFUSE_AT_ONCE,
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
        .filter = instructions,
    };
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) == 0;
}

/* The descriptor the bootstrap is moved to: the floor, reduced to one below the soft descriptor
 * limit only when that limit is smaller. Reaching for the top of the range instead would grow the
 * child's descriptor table to the whole limit under a large one, and overshoot it under a very
 * large or very small one, falling back to the original low descriptor for no gain. The floor is
 * already far above any realistic low-descriptor reuse. */
static int high_bootstrap_descriptor(void) {
    struct rlimit limit;
    int high = BOOTSTRAP_DESCRIPTOR_FLOOR;
    if (getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY
        && limit.rlim_cur - 1 < (rlim_t)high) {
        high = (int)limit.rlim_cur - 1;
    }
    return high;
}

/* Moves the bootstrap descriptor to a high number and closes the original, returning the number
 * to hand the listener over on and to lock out. The lockout refuses sendmsg on that number for the
 * child's whole life, so a low number the command reopens would meet the refusal on legitimate
 * traffic; a high number is one the command does not reach. On any failure the original is kept,
 * which the lockout still covers, at the cost of that residual. */
static int relocate_bootstrap_descriptor(int descriptor) {
    int high = high_bootstrap_descriptor();
    if (high <= descriptor || dup2(descriptor, high) < 0) {
        return descriptor;
    }
    close(descriptor);
    return high;
}

[[noreturn]] void run_child(int send_descriptor_to_parent, char *const command[],
                            enum guard_report_mode mode) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        report_failure("prctl(NO_NEW_PRIVS): %s", strerror(errno));
        _exit(EXIT_CODE_SETUP_ERROR);
    }
    int bootstrap_descriptor = relocate_bootstrap_descriptor(send_descriptor_to_parent);
    int notify_descriptor = install_connect_filter(bootstrap_descriptor, mode);
    if (notify_descriptor < 0) {
        report_failure("seccomp NEW_LISTENER: %s", strerror(errno));
        _exit(EXIT_CODE_SETUP_ERROR);
    }
    if (!send_descriptor(bootstrap_descriptor, notify_descriptor)) {
        report_failure("handing the notification descriptor up: %s", strerror(errno));
        _exit(EXIT_CODE_SETUP_ERROR);
    }
    if (!install_sendmsg_lockout(bootstrap_descriptor)) {
        report_failure("locking out the bootstrap sendmsg: %s", strerror(errno));
        _exit(EXIT_CODE_SETUP_ERROR);
    }
    close(notify_descriptor);
    close(bootstrap_descriptor);

    execvp(command[0], command);
    report_failure("exec %s: %s", command[0], strerror(errno));
    _exit(EXIT_CODE_COMMAND_NOT_EXECUTABLE);
}
