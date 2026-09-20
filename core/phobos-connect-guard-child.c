#define _GNU_SOURCE
#include "phobos-connect-guard-child.h"

#include "phobos-connect-guard-diagnostics.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

/* The one refusal this filter ever returns: EACCES, as an ordinary denied call would. */
#define GUARD_REFUSE BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA))

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
 * socket, connect, sendto and sendmmsg to the supervisor, which decides them from the kernel's
 * own copy of the scalar arguments and, for a destination behind a pointer, from the child's
 * memory. Everything else is allowed. sendmsg is deliberately NOT trapped: the child hands the
 * notification descriptor up to the supervisor with sendmsg (SCM_RIGHTS is the only way to pass
 * a descriptor, and pidfd_getfd is refused in the container), so trapping it would park that
 * handoff before the supervisor holds the descriptor to service it. A sendmsg datagram is left
 * to libnetblocker, which hooks sendmsg for a dynamically linked command, and to the
 * no-network container that is the boundary either way. libnetblocker hooks sendmmsg as well,
 * but a hook is stepped around by a raw system call or a re-exec without LD_PRELOAD, so
 * sendmmsg is trapped here too and sendmsg is the one call that cannot be, whatever the hook
 * covers. The trapped calls are decided in the supervisor rather than here, because a classic
 * BPF program cannot follow a pointer to read an address, and deciding the scalar cases there
 * too keeps the one decision in one testable place. */
static int install_connect_filter(void) {
    struct sock_filter instructions[] = {
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
        GUARD_TRAP_SYSCALL(__NR_sendto),
        GUARD_TRAP_SYSCALL(__NR_sendmmsg),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
        .filter = instructions,
    };
    long listener = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                            SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
    if (listener < 0) {
        return -1;
    }
    return (int)listener;
}

/* Hand one file descriptor to the supervisor over the socket pair. */
static bool send_descriptor(int socket_descriptor, int descriptor_to_send) {
    char payload = 'N';
    struct iovec vector = { .iov_base = &payload, .iov_len = 1 };
    union {
        char buffer[CMSG_SPACE(sizeof(int))];
        struct cmsghdr alignment;
    } control;
    memset(&control, 0, sizeof(control));

    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.buffer;
    message.msg_controllen = sizeof(control.buffer);

    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &descriptor_to_send, sizeof(int));

    ssize_t sent;
    do {
        sent = sendmsg(socket_descriptor, &message, 0);
    } while (sent < 0 && errno == EINTR);
    return sent == 1;
}

[[noreturn]] void run_child(int send_descriptor_to_parent, char *const command[]) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        report_failure("prctl(NO_NEW_PRIVS): %s", strerror(errno));
        _exit(EXIT_CODE_SETUP_ERROR);
    }
    int notify_descriptor = install_connect_filter();
    if (notify_descriptor < 0) {
        report_failure("seccomp NEW_LISTENER: %s", strerror(errno));
        _exit(EXIT_CODE_SETUP_ERROR);
    }
    if (!send_descriptor(send_descriptor_to_parent, notify_descriptor)) {
        report_failure("handing the notification descriptor up: %s", strerror(errno));
        _exit(EXIT_CODE_SETUP_ERROR);
    }
    close(notify_descriptor);
    close(send_descriptor_to_parent);

    execvp(command[0], command);
    report_failure("exec %s: %s", command[0], strerror(errno));
    _exit(EXIT_CODE_COMMAND_NOT_EXECUTABLE);
}
