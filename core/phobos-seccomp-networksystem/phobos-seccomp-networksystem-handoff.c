#define _GNU_SOURCE
#include "phobos-seccomp-networksystem-handoff.h"

#include "phobos-seccomp-networksystem-diagnostics.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>

/* A shell reports a command killed by a signal as this plus the signal's number. */
static constexpr int SIGNALLED_EXIT_BASE = 128;

/* The command the supervisor passes a caller's signals on to, and the signals it passes on. */
static pid_t command_to_signal = 0;
static constexpr int FORWARDED_SIGNALS[] = { SIGTERM, SIGHUP, SIGINT, SIGQUIT };

bool send_descriptor(int socket_descriptor, int descriptor_to_send) {
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

int receive_descriptor(int socket_descriptor) {
    char payload = 0;
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

    ssize_t received;
    do {
        received = recvmsg(socket_descriptor, &message, MSG_CMSG_CLOEXEC);
    } while (received < 0 && errno == EINTR);
    if (received != 1) {
        return -1;
    }
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (header == nullptr || header->cmsg_level != SOL_SOCKET ||
        header->cmsg_type != SCM_RIGHTS || header->cmsg_len != CMSG_LEN(sizeof(int))) {
        return -1;
    }
    int descriptor = -1;
    memcpy(&descriptor, CMSG_DATA(header), sizeof(int));
    return descriptor;
}

void block_forwarded_signals(sigset_t *forwarded, sigset_t *before) {
    sigemptyset(forwarded);
    for (size_t index = 0; index < sizeof(FORWARDED_SIGNALS) / sizeof(FORWARDED_SIGNALS[0]); index++) {
        sigaddset(forwarded, FORWARDED_SIGNALS[index]);
    }
    sigprocmask(SIG_BLOCK, forwarded, before);
}

/* Passes a signal the supervisor received on to the command. */
static void forward_signal_to_command(int number) {
    pid_t target = command_to_signal;
    if (target > 0) {
        kill(target, number);
    }
}

void forward_signals_to(pid_t command) {
    command_to_signal = command;
    for (size_t index = 0; index < sizeof(FORWARDED_SIGNALS) / sizeof(FORWARDED_SIGNALS[0]); index++) {
        signal(FORWARDED_SIGNALS[index], forward_signal_to_command);
    }
}

void take_default_child_signal(struct sigaction *inherited) {
    struct sigaction standard;
    memset(&standard, 0, sizeof(standard));
    standard.sa_handler = SIG_DFL;
    sigemptyset(&standard.sa_mask);
    sigaction(SIGCHLD, &standard, inherited);
}

void restore_child_signal(const struct sigaction *inherited) {
    sigaction(SIGCHLD, inherited, nullptr);
}

bool reap_command(pid_t child, const sigset_t *forwarded, int *status) {
    siginfo_t ended;
    sigset_t outside;
    pid_t reaped = -1;
    while (waitid(P_PID, (id_t)child, &ended, WEXITED | WNOWAIT) < 0 && errno == EINTR) {
    }
    sigprocmask(SIG_BLOCK, forwarded, &outside);
    while ((reaped = waitpid(child, status, 0)) < 0 && errno == EINTR) {
    }
    command_to_signal = 0;
    sigprocmask(SIG_SETMASK, &outside, nullptr);
    return reaped == child;
}

bool send_notification_response(int notify_descriptor, struct seccomp_notif_resp *response) {
    int sent = -1;
    while ((sent = ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_SEND, response)) != 0
           && errno == EINTR) {
    }
    return sent == 0;
}

int exit_code_from_status(int status) {
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return SIGNALLED_EXIT_BASE + WTERMSIG(status);
    }
    return EXIT_CODE_SETUP_ERROR;
}
