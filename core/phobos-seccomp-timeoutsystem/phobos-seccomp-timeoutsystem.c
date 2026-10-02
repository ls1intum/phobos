/*
 * phobos-seccomp-timeoutsystem -- deny setsid and setpgid, then exec a command.
 *
 * The timeout layer bounds a run by putting the command in its own process group and, on
 * expiry, signalling the whole group (GNU timeout without --foreground, escalating to SIGKILL).
 * A process that starts a new session or process group leaves that group, so the group-kill no
 * longer reaches it and the run outlives its timeout. This helper installs a seccomp filter that
 * refuses setsid and setpgid, so nothing the timeout layer wraps can step out of the group the
 * kill targets, and then becomes the rest of the chain.
 *
 * The connect guard already refuses these two calls for the command it supervises, but that
 * cover is the network layer's. This helper is the timeout layer's own, so a run with the network
 * restriction disabled, or the timeout layer used on its own, keeps the group-kill unescapable.
 * The two filters stack; where both speak the kernel takes the stricter action, and denying the
 * same call twice denies it once.
 *
 * It needs no privileges: with no_new_privs set, an ordinary process may install a seccomp
 * filter. It fails closed: if no_new_privs or the filter cannot be set, the command is refused
 * rather than run outside the group lock.
 *
 * Usage:
 *   phobos-seccomp-timeoutsystem [--] COMMAND [ARGUMENTS...]
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <sys/syscall.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

/* The one native ABI this build's syscall numbers belong to. The filter refuses every other
 * ABI, so a setsid or setpgid made through an alternate one (i386 int 0x80, or x32) cannot slip
 * past the native-number comparisons unwatched. */
#if defined(__x86_64__)
#define NATIVE_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define NATIVE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "phobos-seccomp-timeoutsystem supports x86-64 and aarch64 only"
#endif

/* The setup exit status, and the status for a command that cannot be executed. They match the
 * connect guard and phobos-landlock-filesystem-and-networksystem, so a caller reads one meaning across the enforcers. */
static constexpr int EXIT_CODE_SETUP_ERROR = 125;
static constexpr int EXIT_CODE_COMMAND_NOT_EXECUTABLE = 127;

/* The one refusal this filter returns: EACCES, as an ordinary denied call would. */
#define PGROUP_REFUSE BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA))

/* One syscall refused outright: a comparison that skips the refusal when the number does not
 * match, so the refusal must be exactly one instruction and the jump distances stay 0 and 1. */
#define PGROUP_DENY_SYSCALL(number) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1), PGROUP_REFUSE

/* Installs the filter: refuse every non-native ABI, refuse setsid and setpgid, allow the rest. */
static int install_pgroup_lock_filter(void) {
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_AUDIT_ARCH, 1, 0),
        PGROUP_REFUSE,
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#ifdef __X32_SYSCALL_BIT
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, __X32_SYSCALL_BIT, 0, 1),
        PGROUP_REFUSE,
#endif
        PGROUP_DENY_SYSCALL(__NR_setsid),
        PGROUP_DENY_SYSCALL(__NR_setpgid),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
        .filter = instructions,
    };
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program);
}

int main(int argument_count, char *arguments[]) {
    char **command = &arguments[1];
    if (argument_count >= 2 && strcmp(arguments[1], "--") == 0) {
        command = &arguments[2];
    }
    if (command[0] == nullptr) {
        fprintf(stderr, "Usage: phobos-seccomp-timeoutsystem [--] COMMAND [ARGUMENTS...]\n");
        return EXIT_CODE_SETUP_ERROR;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "[phobos-seccomp-timeoutsystem] prctl(NO_NEW_PRIVS): %s\n", strerror(errno));
        return EXIT_CODE_SETUP_ERROR;
    }
    if (install_pgroup_lock_filter() != 0) {
        fprintf(stderr, "[phobos-seccomp-timeoutsystem] seccomp: %s\n", strerror(errno));
        return EXIT_CODE_SETUP_ERROR;
    }
    execvp(command[0], command);
    fprintf(stderr, "[phobos-seccomp-timeoutsystem] exec %s: %s\n", command[0], strerror(errno));
    return EXIT_CODE_COMMAND_NOT_EXECUTABLE;
}
