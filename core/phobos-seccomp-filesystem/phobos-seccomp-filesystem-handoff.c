#define _GNU_SOURCE
#include "phobos-seccomp-filesystem-handoff.h"

#include "../phobos-seccomp-networksystem/phobos-seccomp-networksystem-handoff.h"
#include "../phobos-seccomp-timeoutsystem/phobos-seccomp-timeoutsystem-signature.h"

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/filter.h>

/* Older kernel headers lack the flag; its value is stable. */
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

/* How the probe child ends when it could not install or hand over its listener, or report. */
static constexpr int PROBE_FAILED = 3;

/* The probe: a filter that traps getppid and nothing else, installed with a listener it hands up,
 * then the one trapped call, whose answer it reports back. Never returns. */
[[noreturn]] static void run_continue_probe(int socket_descriptor) {
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getppid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
        .filter = instructions,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        _exit(PROBE_FAILED);
    }
    int listener = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                                SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
    if (listener < 0 || !send_descriptor(socket_descriptor, listener)) {
        _exit(PROBE_FAILED);
    }
    close(listener);
    pid_t parent = getppid();
    if (write(socket_descriptor, &parent, sizeof(parent)) != (ssize_t)sizeof(parent)) {
        _exit(PROBE_FAILED);
    }
    _exit(0);
}

bool allocate_notification_buffers(struct seccomp_notif **request, size_t *request_size,
                                   struct seccomp_notif_resp **response) {
    struct seccomp_notif_sizes sizes;
    memset(&sizes, 0, sizeof(sizes));
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0) {
        sizes.seccomp_notif = sizeof(struct seccomp_notif);
        sizes.seccomp_notif_resp = sizeof(struct seccomp_notif_resp);
    }
    *request_size = sizes.seccomp_notif < sizeof(struct seccomp_notif)
                        ? sizeof(struct seccomp_notif)
                        : sizes.seccomp_notif;
    size_t response_size = sizes.seccomp_notif_resp < sizeof(struct seccomp_notif_resp)
                               ? sizeof(struct seccomp_notif_resp)
                               : sizes.seccomp_notif_resp;
    *request = calloc(1, *request_size);
    *response = calloc(1, response_size);
    if (*request == NULL || *response == NULL) {
        free(*request);
        free(*response);
        *request = NULL;
        *response = NULL;
        return false;
    }
    return true;
}

/* Waits at most CONTINUE_PROBE_WAIT_MS for the probe's notification and answers it with CONTINUE.
 * Answers whether the kernel accepted that answer. */
static bool continue_one_notification(int listener) {
    struct seccomp_notif *request = NULL;
    struct seccomp_notif_resp *response = NULL;
    size_t request_size = 0;
    struct pollfd watch = {.fd = listener, .events = POLLIN, .revents = 0};
    if (poll(&watch, 1, CONTINUE_PROBE_WAIT_MS) != 1 || (watch.revents & POLLIN) == 0
        || !allocate_notification_buffers(&request, &request_size, &response)) {
        return false;
    }
    bool continued = false;
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, request) == 0) {
        response->id = request->id;
        response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        continued = ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, response) == 0;
    }
    free(request);
    free(response);
    return continued;
}

/* How the signature probe ends: a status nothing else ends it with when the group lock answered,
 * and 1 otherwise. Not 0, so that a status that was never read can never pass for a sighting. */
static constexpr int SIGNATURE_SEEN = 42;
static constexpr int SIGNATURE_NOT_SEEN = 1;

bool group_lock_present(void) {
    pid_t probe = fork();
    if (probe < 0) {
        return false;
    }
    if (probe == 0) {
        long result = syscall(SYS_setpgid, 0, PHB_GROUP_LOCK_SIGNATURE_PGID);
        _exit(result < 0 && errno == ENOTRECOVERABLE ? SIGNATURE_SEEN : SIGNATURE_NOT_SEEN);
    }
    int status = 0;
    pid_t reaped = -1;
    do {
        reaped = waitpid(probe, &status, 0);
    } while (reaped < 0 && errno == EINTR);
    return reaped == probe && WIFEXITED(status) && WEXITSTATUS(status) == SIGNATURE_SEEN;
}

bool continue_supported(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) {
        return false;
    }
    pid_t probe = fork();
    if (probe < 0) {
        close(pair[0]);
        close(pair[1]);
        return false;
    }
    if (probe == 0) {
        close(pair[0]);
        run_continue_probe(pair[1]);
    }
    close(pair[1]);
    int listener = receive_descriptor(pair[0]);
    bool continued = false;
    if (listener >= 0) {
        continued = continue_one_notification(listener);
        close(listener);
    }
    pid_t seen = 0;
    bool reported = listener >= 0 && read(pair[0], &seen, sizeof(seen)) == (ssize_t)sizeof(seen);
    close(pair[0]);
    int status = 0;
    while (waitpid(probe, &status, 0) < 0 && errno == EINTR) {
    }
    return continued && reported && seen == getpid();
}
