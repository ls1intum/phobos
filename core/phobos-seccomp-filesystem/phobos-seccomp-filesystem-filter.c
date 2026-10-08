#define _GNU_SOURCE
#include "phobos-seccomp-filesystem-filter.h"

#include "phobos-seccomp-filesystem-access.h"

#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/seccomp.h>

/* Instructions per trapped call: the comparison and its answer. The comparison skips the answer
 * when the number does not match, so the answer must be exactly one instruction long. */
static constexpr size_t TRAP_LENGTH = 2;

/* Writes one trap: compare the call number with number and, when it matches, hand the call to the
 * listener. */
static void write_trap(struct sock_filter *at, unsigned int number) {
    at[0] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, number, 0, 1);
    at[1] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
}

/* Writes one trap for each of count calls, or none when they do not fit in room. Answers the number
 * of instructions written. */
static size_t append_traps(struct sock_filter *instructions, size_t room, const int *calls,
                           size_t count) {
    if (room < count * TRAP_LENGTH) {
        return 0;
    }
    for (size_t index = 0; index < count; index++) {
        write_trap(&instructions[index * TRAP_LENGTH], (unsigned int)calls[index]);
    }
    return count * TRAP_LENGTH;
}

size_t append_report_traps(struct sock_filter *instructions, size_t room) {
    return append_traps(instructions, room, REPORT_TRAPPED_CALLS, REPORT_TRAPPED_CALL_COUNT);
}

size_t append_network_report_traps(struct sock_filter *instructions, size_t room) {
    return append_traps(instructions, room, REPORT_NETWORK_TRAPPED_CALLS,
                        REPORT_NETWORK_TRAPPED_CALL_COUNT);
}

/* Appends the refusal traps: an x32 number, where the ABI has one, setsid and setpgid. */
static size_t append_refusal_traps(struct sock_filter *instructions) {
    size_t used = 0;
#ifdef __X32_SYSCALL_BIT
    instructions[used++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
                                                        __X32_SYSCALL_BIT, 0, 1);
    instructions[used++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
#endif
    write_trap(&instructions[used], __NR_setsid);
    used += TRAP_LENGTH;
    write_trap(&instructions[used], __NR_setpgid);
    used += TRAP_LENGTH;
    return used;
}

size_t build_report_filter(struct sock_filter *instructions, bool file_traps, bool refusal_traps) {
    size_t used = 0;
    unsigned int foreign = refusal_traps ? SECCOMP_RET_USER_NOTIF : SECCOMP_RET_ALLOW;
    instructions[used++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                                        offsetof(struct seccomp_data, arch));
    instructions[used++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                        REPORT_NATIVE_AUDIT_ARCH, 1, 0);
    instructions[used++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, foreign);
    instructions[used++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                                        offsetof(struct seccomp_data, nr));
    if (refusal_traps) {
        used += append_refusal_traps(&instructions[used]);
    }
    if (file_traps) {
        used += append_report_traps(&instructions[used], REPORT_FILTER_MAXIMUM - used - 1);
    }
    instructions[used++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    return used;
}

int install_report_filter(bool file_traps, bool refusal_traps) {
    struct sock_filter instructions[REPORT_FILTER_MAXIMUM];
    struct sock_fprog program = {
        .len = (unsigned short)build_report_filter(instructions, file_traps, refusal_traps),
        .filter = instructions,
    };
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER,
                        &program);
}
