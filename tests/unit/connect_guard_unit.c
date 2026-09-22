/*
 * Unit tests for phobos-connect-guard.
 *
 * The integration suite tests/connect_guard.sh and the acceptance suite
 * tests/landlock-acceptance/connect-guard-test.sh exercise the guard against a real
 * kernel, which is what proves it works. They cannot reach the failure paths,
 * though: a filter that will not install, a memory read that fails, a connection
 * that times out, a descriptor handoff that breaks. Those decide whether the guard
 * fails closed, so they are the ones that must not go untested.
 *
 * The file holding main is included with main renamed, so this file can provide its own,
 * and the modules beside it are linked, built with PHOBOS_CONNECT_GUARD_UNIT_TEST so the
 * functions that reset their tables for each case exist. Every syscall the guard
 * makes is interposed through the linker's --wrap, so success and failure can be
 * injected without a special kernel, and fork is wrapped so the parent and the child
 * halves of the guard can each be driven in turn. Cases that end in exit() run in a
 * forked child of the test and are judged by the exit status.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <signal.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>

#ifndef PHOBOS_CONNECT_GUARD_UNIT_TEST
#define PHOBOS_CONNECT_GUARD_UNIT_TEST
#endif
#define main sut_main
#include "../../core/phobos-connect-guard.c"
#undef main
#include "../../core/phobos-connect-guard-child.h"
#include "../../core/phobos-connect-guard-destination.h"
#include "../../core/phobos-connect-guard-socket-types.h"

#include <linux/filter.h>
#include <linux/seccomp.h>

/* ------------------------------------------------------------ the behaviour */

/* The descriptors, identifiers and addresses the wrapped calls hand out and the cases hand in.
 * None of them is real; each only has to be the same wherever it is handed on or read back. */
static constexpr long FAKE_LISTENER_DESCRIPTOR = 4;             /* the listener the child's filter install returns */
static constexpr int FAKE_OUTWARD_SOCKET_DESCRIPTOR = 7;        /* the socket the guard creates to connect */
static constexpr int FAKE_NOTIFY_DESCRIPTOR = 9;                /* the listener a case hands the supervisor itself */
static constexpr int FAKE_HANDOFF_SOCKET_DESCRIPTOR = 5;        /* the socket the listener is received on */
static constexpr int FAKE_TARGET_DESCRIPTOR = 5;                /* the command's descriptor a connect is made for */
static constexpr int FAKE_SOCKETPAIR_FIRST_END = 20;            /* the first end socketpair returns */
static constexpr int FAKE_SOCKETPAIR_SECOND_END = 21;           /* the second end socketpair returns */
static constexpr int FAKE_RECEIVED_DESCRIPTOR = 30;             /* the descriptor recvmsg carries */
static constexpr int FAKE_ADDFD_DESCRIPTOR = 40;                /* the descriptor ADDFD reports installed */
static constexpr uint64_t FAKE_NOTIFICATION_ID = 555;           /* the id of every notification NOTIF_RECV returns */
static constexpr uint32_t FAKE_COMMAND_PID = 12345;             /* the pid of every notification NOTIF_RECV returns */
static constexpr pid_t FAKE_CHILD_PID = 99;                     /* what the wrapped fork returns on the parent path */
static constexpr uint64_t FAKE_ADDRESS_POINTER = 0x4000;        /* a command pointer to an address or a message vector */
static constexpr uintptr_t FAKE_MESSAGE_NAME_POINTER = 0x5000;  /* msg_name inside a faked sendmmsg entry */

/* The exit status the wrapped execvp ends the child with, in place of a successful exec. */
static constexpr int EXEC_STAND_IN_EXIT_STATUS = 200;

/* main's exit status when the shared record cannot be mapped, so no case can run. */
static constexpr int HARNESS_SETUP_FAILURE = 2;

/* A notif_addfd_result or notif_send_result that fails the call with ENOENT, as when the
 * command has gone; -1 fails it with an error of the guard's own. */
static constexpr int FAKE_FAILS_TARGET_GONE = -2;

/* In a heterogeneous sendmmsg batch, every address read from this one on reports the
 * other port, so a later entry names a destination the first does not. */
static constexpr int HETEROGENEOUS_FIRST_DIFFERING_READ = 2;
static constexpr uint16_t HETEROGENEOUS_LATER_PORT = 9999;

/* What the wrapped recvmsg gets wrong in the control message, if anything. */
enum recvmsg_fault {
    RECVMSG_WELL_FORMED,  /* SOL_SOCKET, SCM_RIGHTS and room for one descriptor */
    RECVMSG_WRONG_LEVEL,  /* IPPROTO_IP in place of SOL_SOCKET */
    RECVMSG_WRONG_TYPE,   /* SCM_CREDENTIALS in place of SCM_RIGHTS */
    RECVMSG_WRONG_LENGTH  /* a length with no room for a descriptor */
};

/* What the wrapped readlink answers for a descriptor's /proc link. */
enum readlink_answer {
    READLINK_SOCKET,  /* socket:[inode], with the arranged readlink_inode */
    READLINK_PIPE,    /* a pipe, so no socket at all */
    READLINK_FAILS    /* EACCES, as when /proc cannot be read */
};

/* Room for the link text the wrapped readlink writes. */
static constexpr size_t READLINK_TEXT_LENGTH = 64;

/* Room for the filter the child installs, so a case can run it against a seccomp_data of its
 * own. Generous: a filter longer than this is a filter nobody meant to write. */
static constexpr size_t CAPTURED_FILTER_LENGTH = 64;

/* An audit architecture the build's own syscall numbers do not belong to, used to ask the
 * filter what it does with a call arriving under a foreign ABI. */
static constexpr uint32_t FOREIGN_AUDIT_ARCH = 0xdead0000;

/* What the wrapped calls should do, and what they were handed. The record lives in
 * shared memory because a case that ends in exit() runs in a forked child of the
 * test while the assertions are made by the parent. */
struct behaviour {
    /* seccomp NEW_LISTENER (via syscall) */
    long seccomp_listener_result;
    /* The filter the child handed SECCOMP_SET_MODE_FILTER, kept so a case can run it. */
    struct sock_filter installed_filter[CAPTURED_FILTER_LENGTH];
    unsigned short installed_filter_length;
    /* SECCOMP_GET_NOTIF_SIZES (via syscall) */
    int notif_sizes_result;
    int notif_sizes_small;
    /* socketpair, fork, prctl, signal, execvp */
    int socketpair_result;
    long fork_result;
    int prctl_result;
    int execvp_returns;
    /* sendmsg / recvmsg for the descriptor handoff */
    ssize_t sendmsg_result;
    int sendmsg_eintr_once;
    ssize_t recvmsg_result;
    int recvmsg_bad_cmsg;
    int recvmsg_wrong;
    int recvmsg_eintr_once;
    /* the notification descriptor traffic */
    int notif_recv_result;
    int notif_recv_nr;
    int notif_socket_domain;
    int notif_socket_type;
    int notif_socket_protocol;
    unsigned int notif_send_flags;
    int mmsg_mode;
    int mmsg_name_missing;
    int mmsg_addr_short;
    int mmsg_hetero;
    int addr_read_seen;
    unsigned int mmsg_count;
    int id_valid_seen;
    int id_valid_fail_at;
    int notif_recv_family;
    uint16_t notif_recv_port;
    uint32_t notif_recv_target_fd;
    int notif_id_valid_result;
    int notif_addfd_result;
    int notif_send_result;
    int readlink_kind;
    unsigned long long readlink_inode;
    int fcntl_fails;
    /* the peer-address read */
    ssize_t process_vm_readv_result;
    /* the outward connection */
    int socket_result;
    int connect_result;      /* 0 ok, -1 sets connect_errno */
    int connect_errno;
    int poll_result;
    int poll_eintr_once;
    short poll_revents;
    int getsockopt_result;
    int getsockopt_so_error;
    /* the supervise loop */
    int supervise_services;
    int supervise_poll_error;
    int supervise_poll_eintr_once;
    /* what was observed */
    int last_answer_error;
    int64_t last_answer_val;
    uint32_t last_answer_flags;
    int answers;
    int addfd_calls;
    int connect_calls;
    int recorded_child_status;
    int waitpid_eintr_once;
    int calloc_fails;
};

static struct behaviour *bx;

static void reset_behaviour(void) {
    memset(bx, 0, sizeof(*bx));
    bx->notif_recv_nr = __NR_connect;
    bx->seccomp_listener_result = FAKE_LISTENER_DESCRIPTOR;
    bx->notif_sizes_result = 0;
    bx->socketpair_result = 0;
    bx->prctl_result = 0;
    bx->sendmsg_result = 1;
    bx->recvmsg_result = 1;
    bx->socket_result = FAKE_OUTWARD_SOCKET_DESCRIPTOR;
    bx->connect_result = 0;
    bx->getsockopt_result = 0;
    connect_rules_reset_for_tests();
    set_verbose(false);
    socket_types_reset_for_tests();
}

/* ------------------------------------------------------------------- wraps */

/* The guard ends the child with _exit, which does not flush the coverage counters. So that
 * the paths run in a forked child of the test are still measured, this dumps them first. The
 * dump function is weak, so a plain (non-instrumented) build links without it. */
extern void __gcov_dump(void) __attribute__((weak));
void __real__exit(int status) __attribute__((noreturn));
void __wrap__exit(int status) __attribute__((noreturn));
void __wrap__exit(int status) {
    if (__gcov_dump != NULL) {
        __gcov_dump();
    }
    __real__exit(status);
}

void *__real_calloc(size_t count, size_t size);
void *__wrap_calloc(size_t count, size_t size) {
    if (bx != NULL && bx->calloc_fails) {
        errno = ENOMEM;
        return NULL;
    }
    return __real_calloc(count, size);
}

long __real_syscall(long number, ...);
long __wrap_syscall(long number, ...) {
    va_list arguments;
    va_start(arguments, number);
    unsigned long a1 = va_arg(arguments, unsigned long);
    unsigned long a2 = va_arg(arguments, unsigned long);
    unsigned long a3 = va_arg(arguments, unsigned long);
    va_end(arguments);
    if (number == SYS_seccomp && a1 == SECCOMP_SET_MODE_FILTER) {
        (void)a2;
        const struct sock_fprog *program = (const struct sock_fprog *)(uintptr_t)a3;
        if (program != NULL && program->len <= CAPTURED_FILTER_LENGTH) {
            memcpy(bx->installed_filter, program->filter,
                   (size_t)program->len * sizeof(struct sock_filter));
            bx->installed_filter_length = program->len;
        }
        if (bx->seccomp_listener_result < 0) {
            errno = EACCES;
        }
        return bx->seccomp_listener_result;
    }
    if (number == SYS_seccomp && a1 == SECCOMP_GET_NOTIF_SIZES) {
        struct seccomp_notif_sizes *sizes = (struct seccomp_notif_sizes *)(uintptr_t)a3;
        if (bx->notif_sizes_result != 0) {
            errno = EINVAL;
            return -1;
        }
        if (bx->notif_sizes_small) {
            sizes->seccomp_notif = 1;
            sizes->seccomp_notif_resp = 1;
        } else {
            sizes->seccomp_notif = sizeof(struct seccomp_notif);
            sizes->seccomp_notif_resp = sizeof(struct seccomp_notif_resp);
        }
        sizes->seccomp_data = sizeof(struct seccomp_data);
        return 0;
    }
    return __real_syscall(number, a1, a2, a3);
}

int __wrap_socketpair(int domain, int type, int protocol, int pair[2]) {
    (void)domain;
    (void)type;
    (void)protocol;
    if (bx->socketpair_result != 0) {
        errno = EMFILE;
        return -1;
    }
    pair[0] = FAKE_SOCKETPAIR_FIRST_END;
    pair[1] = FAKE_SOCKETPAIR_SECOND_END;
    return 0;
}

pid_t __real_fork(void);
pid_t __wrap_fork(void) {
    return (pid_t)bx->fork_result;
}

int __wrap_prctl(int option, ...) {
    (void)option;
    if (bx->prctl_result != 0) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

void (*__wrap_signal(int signum, void (*handler)(int)))(int) {
    (void)signum;
    (void)handler;
    return NULL;
}

int __wrap_execvp(const char *file, char *const argv[]) {
    (void)file;
    (void)argv;
    if (bx->execvp_returns) {
        errno = ENOENT;
        return -1;
    }
    _exit(EXEC_STAND_IN_EXIT_STATUS);
}

pid_t __wrap_waitpid(pid_t pid, int *status, int options) {
    (void)options;
    if (bx->waitpid_eintr_once) {
        bx->waitpid_eintr_once = 0;
        errno = EINTR;
        return -1;
    }
    if (status != NULL) {
        *status = bx->recorded_child_status;
    }
    return pid;
}

ssize_t __wrap_sendmsg(int fd, const struct msghdr *message, int flags) {
    (void)fd;
    (void)message;
    (void)flags;
    if (bx->sendmsg_eintr_once) {
        bx->sendmsg_eintr_once = 0;
        errno = EINTR;
        return -1;
    }
    if (bx->sendmsg_result < 0) {
        errno = EPIPE;
    }
    return bx->sendmsg_result;
}

ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags) {
    (void)fd;
    (void)flags;
    if (bx->recvmsg_eintr_once) {
        bx->recvmsg_eintr_once = 0;
        errno = EINTR;
        return -1;
    }
    if (bx->recvmsg_result != 1) {
        errno = ECONNRESET;
        return bx->recvmsg_result;
    }
    if (bx->recvmsg_bad_cmsg) {
        message->msg_controllen = 0;
        return 1;
    }
    struct cmsghdr *header = CMSG_FIRSTHDR(message);
    header->cmsg_level = bx->recvmsg_wrong == RECVMSG_WRONG_LEVEL ? IPPROTO_IP : SOL_SOCKET;
    header->cmsg_type = bx->recvmsg_wrong == RECVMSG_WRONG_TYPE ? SCM_CREDENTIALS : SCM_RIGHTS;
    header->cmsg_len = bx->recvmsg_wrong == RECVMSG_WRONG_LENGTH ? CMSG_LEN(0) : CMSG_LEN(sizeof(int));
    int descriptor = FAKE_RECEIVED_DESCRIPTOR;
    memcpy(CMSG_DATA(header), &descriptor, sizeof(int));
    return 1;
}

/* Stands in for reading the command's memory. A result of 0 arranged by a case is a
 * short read: fewer bytes than asked. Otherwise it fills the destination the guard is
 * reading into with a socket address of the requested family, so the read looks like
 * the command's real connect target. The real call reads the whole requested length
 * from the command's memory; this reports that, so read_peer_address sees the full
 * read it asked for. */
ssize_t __wrap_process_vm_readv(pid_t pid, const struct iovec *local, unsigned long liovcnt,
                                const struct iovec *remote, unsigned long riovcnt,
                                unsigned long flags) {
    (void)pid;
    (void)riovcnt;
    (void)flags;
    if (bx->process_vm_readv_result < 0) {
        errno = EFAULT;
        return -1;
    }
    if (bx->process_vm_readv_result == 0) {
        return 0;
    }
    if (bx->mmsg_mode && local->iov_len == sizeof(struct mmsghdr)) {
        struct mmsghdr batch_entry;
        memset(&batch_entry, 0, sizeof(batch_entry));
        if (!bx->mmsg_name_missing) {
            batch_entry.msg_hdr.msg_name = (void *)FAKE_MESSAGE_NAME_POINTER;
            batch_entry.msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
        }
        memcpy(local->iov_base, &batch_entry, local->iov_len);
        return (ssize_t)local->iov_len;
    }
    if (bx->mmsg_mode && bx->mmsg_addr_short) {
        return 0;
    }
    struct sockaddr_storage storage;
    memset(&storage, 0, sizeof(storage));
    socklen_t length;
    bx->addr_read_seen++;
    uint16_t effective_port = bx->notif_recv_port;
    if (bx->mmsg_hetero && bx->addr_read_seen >= HETEROGENEOUS_FIRST_DIFFERING_READ) {
        effective_port = HETEROGENEOUS_LATER_PORT;
    }
    if (bx->notif_recv_family == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&storage;
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(effective_port);
        inet_pton(AF_INET6, "2001:db8::1", &v6->sin6_addr);
        length = sizeof(*v6);
    } else if (bx->notif_recv_family == AF_UNIX) {
        struct sockaddr_un *un = (struct sockaddr_un *)&storage;
        un->sun_family = AF_UNIX;
        length = sizeof(*un);
    } else {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&storage;
        v4->sin_family = AF_INET;
        v4->sin_port = htons(effective_port);
        v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        length = sizeof(*v4);
    }
    size_t copy = local->iov_len < length ? local->iov_len : length;
    memcpy(local->iov_base, &storage, copy);
    (void)liovcnt;
    (void)remote;
    return (ssize_t)local->iov_len;
}

int __wrap_socket(int domain, int type, int protocol) {
    (void)domain;
    (void)type;
    (void)protocol;
    if (bx->socket_result < 0) {
        errno = EMFILE;
        return -1;
    }
    return bx->socket_result;
}

int __wrap_fcntl(int fd, int command, ...) {
    (void)fd;
    (void)command;
    if (bx->fcntl_fails) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

ssize_t __wrap_readlink(const char *path, char *buffer, size_t size) {
    (void)path;
    if (bx->readlink_kind == READLINK_FAILS) {
        errno = EACCES;
        return -1;
    }
    char text[READLINK_TEXT_LENGTH];
    if (bx->readlink_kind == READLINK_PIPE) {
        snprintf(text, sizeof(text), "pipe:[1]");
    } else {
        snprintf(text, sizeof(text), "socket:[%llu]", bx->readlink_inode);
    }
    size_t length = strlen(text);
    if (length > size) {
        length = size;
    }
    memcpy(buffer, text, length);
    return (ssize_t)length;
}

int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length) {
    (void)fd;
    (void)address;
    (void)length;
    bx->connect_calls++;
    if (bx->connect_result == 0) {
        return 0;
    }
    errno = bx->connect_errno;
    return -1;
}

/* The supervise loop waits for POLLIN: hand out a readable turn for each arranged
 * service, an EINTR to exercise the retry, or a poll error, then a hangup that ends
 * the loop. */
static int supervise_loop_poll(struct pollfd *fds) {
    if (bx->supervise_poll_eintr_once) {
        bx->supervise_poll_eintr_once = 0;
        errno = EINTR;
        return -1;
    }
    if (bx->supervise_services > 0) {
        bx->supervise_services--;
        fds[0].revents = POLLIN;
        return 1;
    }
    if (bx->supervise_poll_error) {
        bx->supervise_poll_error = 0;
        errno = EBADF;
        return -1;
    }
    fds[0].revents = POLLHUP;
    return 1;
}

/* connect_within_deadline waits for POLLOUT. */
static int connect_deadline_poll(struct pollfd *fds) {
    if (bx->poll_eintr_once) {
        bx->poll_eintr_once = 0;
        errno = EINTR;
        return -1;
    }
    if (bx->poll_result <= 0) {
        if (bx->poll_result < 0) {
            errno = ECONNREFUSED;
        }
        return bx->poll_result;
    }
    fds[0].revents = bx->poll_revents;
    return bx->poll_result;
}

int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout) {
    (void)timeout;
    (void)count;
    if (fds[0].events & POLLIN) {
        return supervise_loop_poll(fds);
    }
    return connect_deadline_poll(fds);
}

int __wrap_getsockopt(int fd, int level, int name, void *value, socklen_t *length) {
    (void)fd;
    (void)level;
    (void)name;
    if (bx->getsockopt_result != 0) {
        errno = EINVAL;
        return -1;
    }
    int *out = value;
    *out = bx->getsockopt_so_error;
    *length = sizeof(int);
    return 0;
}

/* Stands in for the seccomp notification ioctls. For a connect notification the address
 * argument is FAKE_ADDRESS_POINTER, which is never dereferenced here. */
int __wrap_ioctl(int fd, unsigned long request, ...) {
    (void)fd;
    va_list arguments;
    va_start(arguments, request);
    void *argument = va_arg(arguments, void *);
    va_end(arguments);
    if (request == SECCOMP_IOCTL_NOTIF_RECV) {
        if (bx->notif_recv_result != 0) {
            errno = ENOENT;
            return -1;
        }
        struct seccomp_notif *req = argument;
        req->id = FAKE_NOTIFICATION_ID;
        req->pid = FAKE_COMMAND_PID;
        req->data.nr = bx->notif_recv_nr;
        uint64_t address_length = bx->notif_recv_family == AF_INET6 ? sizeof(struct sockaddr_in6)
                                                                    : sizeof(struct sockaddr_in);
        if (bx->notif_recv_nr == __NR_socket) {
            req->data.args[0] = (uint64_t)bx->notif_socket_domain;
            req->data.args[1] = (uint64_t)bx->notif_socket_type;
            req->data.args[2] = (uint64_t)bx->notif_socket_protocol;
        } else if (bx->notif_recv_nr == __NR_sendto) {
            req->data.args[3] = bx->notif_send_flags;
            req->data.args[4] = bx->notif_recv_family == 0 ? 0 : FAKE_ADDRESS_POINTER;
            req->data.args[5] = bx->notif_recv_family == 0 ? 0 : address_length;
        } else if (bx->notif_recv_nr == __NR_sendmmsg) {
            req->data.args[1] = FAKE_ADDRESS_POINTER;
            req->data.args[2] = bx->mmsg_count ? bx->mmsg_count : 1;
            req->data.args[3] = bx->notif_send_flags;
        } else {
            req->data.args[0] = bx->notif_recv_target_fd;
            req->data.args[1] = FAKE_ADDRESS_POINTER;
            req->data.args[2] = address_length;
        }
        return 0;
    }
    if (request == SECCOMP_IOCTL_NOTIF_ID_VALID) {
        bx->id_valid_seen++;
        if (bx->id_valid_fail_at != 0 && bx->id_valid_seen == bx->id_valid_fail_at) {
            return -1;
        }
        return bx->notif_id_valid_result;
    }
    if (request == SECCOMP_IOCTL_NOTIF_ADDFD) {
        bx->addfd_calls++;
        if (bx->notif_addfd_result != 0) {
            errno = bx->notif_addfd_result == FAKE_FAILS_TARGET_GONE ? ENOENT : EINVAL;
            return -1;
        }
        return FAKE_ADDFD_DESCRIPTOR;
    }
    if (request == SECCOMP_IOCTL_NOTIF_SEND) {
        struct seccomp_notif_resp *resp = argument;
        bx->last_answer_error = resp->error;
        bx->last_answer_val = resp->val;
        bx->last_answer_flags = resp->flags;
        bx->answers++;
        if (bx->notif_send_result != 0) {
            errno = bx->notif_send_result == FAKE_FAILS_TARGET_GONE ? ENOENT : EPIPE;
            return -1;
        }
        return 0;
    }
    errno = ENOTTY;
    return -1;
}

/* -------------------------------------------------------------- the harness */

static int passed = 0;
static int failed = 0;

static void check(const char *what, bool condition) {
    if (condition) {
        printf("ok    %s\n", what);
        passed++;
    } else {
        printf("FAIL  %s\n", what);
        failed++;
    }
}

pid_t __real_waitpid(pid_t pid, int *status, int options);

/* Runs the guard's main in a forked child of the test, with argv, and returns the
 * child's exit code. The guard's own fork is wrapped, so the child does not fork
 * again; this fork only isolates the exit() the guard makes on a setup failure. */
static int run_main(char *const argv[]) {
    int count = 0;
    while (argv[count] != NULL) {
        count++;
    }
    pid_t child = __real_fork();
    if (child == 0) {
        _exit(sut_main(count, (char **)argv));
    }
    int status = 0;
    __real_waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* --------------------------------------------------------- the logic tests */

/* How far the over-long host runs past MAXIMUM_HOST. */
static constexpr size_t OVERLONG_HOST_EXCESS = 8;

/* How many rules more than MAXIMUM_RULES are offered to the full table. */
static constexpr size_t RULE_TABLE_OVERFLOW = 4;

/* A normal exit's code sits in the second byte of a wait status. */
static constexpr int WAIT_STATUS_EXIT_CODE_SHIFT = 8;

/* The low byte of a stopped child's wait status: neither an exit nor a signal. */
static constexpr int WAIT_STATUS_STOPPED = 0x7f;

/* A command killed by a signal is reported as this plus the signal's number. */
static constexpr int SIGNAL_EXIT_CODE_BASE = 128;

static void test_rule_parsing(void) {
    reset_behaviour();
    char path[] = "/tmp/phobos-guard-rules.XXXXXX";
    int fd = mkstemp(path);
    dprintf(fd, "127.0.0.1 443\nexample.com *\nloner\n%s bad\n* 8080\n", "junk");
    close(fd);
    check("a rules file loads", load_rules(path));
    unlink(path);
    check("the three well-formed rules were kept", connect_rules_count_for_tests() == 3);

    reset_behaviour();
    check("a null path is no rules and no error", load_rules(NULL));
    check("an absent file is no rules and no error", load_rules("/tmp/phobos-guard-absent.XXXX"));
    check("an unreadable file refuses (not ENOENT)", !load_rules("/dev/null/impossible"));

    reset_behaviour();
    remember_rule("h", "0");
    remember_rule("h", "70000");
    remember_rule("h", "notanumber");
    check("port zero, out of range and non-numeric are dropped", connect_rules_count_for_tests() == 0);
    char big[MAXIMUM_HOST + OVERLONG_HOST_EXCESS];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    remember_rule(big, "443");
    check("an over-long host is dropped", connect_rules_count_for_tests() == 0);
    for (size_t i = 0; i < MAXIMUM_RULES + RULE_TABLE_OVERFLOW; i++) {
        remember_rule("127.0.0.1", "443");
    }
    check("the rule table does not overflow", connect_rules_count_for_tests() == MAXIMUM_RULES);
}

static bool permits_v4(const char *ip, uint16_t port) {
    struct in_addr address;
    inet_pton(AF_INET, ip, &address);
    return connection_permitted(AF_INET, &address, port);
}

static void test_policy_matching(void) {
    reset_behaviour();
    check("an empty allow-list denies every connect", !permits_v4("9.9.9.9", 443));

    reset_behaviour();
    remember_rule("127.0.0.1", "443");
    check("an allow-listed IP and port is permitted", permits_v4("127.0.0.1", 443));
    check("the same IP on another port is refused", !permits_v4("127.0.0.1", 444));
    check("another IP on the allowed port is refused", !permits_v4("127.0.0.2", 443));

    reset_behaviour();
    remember_rule("example.com", "8080");
    check("a hostname rule permits any host on its port", permits_v4("9.9.9.9", 8080));
    check("a hostname rule refuses another port", !permits_v4("9.9.9.9", 80));

    reset_behaviour();
    remember_rule("localhost", "*");
    check("localhost matches a loopback address", permits_v4("127.0.0.5", 12345));
    check("localhost refuses a non-loopback address", !permits_v4("8.8.8.8", 12345));

    reset_behaviour();
    remember_rule("*", "443");
    check("a wildcard host rests on the port", permits_v4("8.8.8.8", 443));

    reset_behaviour();
    remember_rule("::1", "443");
    struct in6_addr loop;
    inet_pton(AF_INET6, "::1", &loop);
    check("an IPv6 literal matches its address", connection_permitted(AF_INET6, &loop, 443));
    struct in6_addr other;
    inet_pton(AF_INET6, "2001:db8::2", &other);
    check("an IPv6 literal refuses another address", !connection_permitted(AF_INET6, &other, 443));

    reset_behaviour();
    remember_rule("2001:db8::1", "443");
    check("an IPv6 literal refuses yet another address",
          !connection_permitted(AF_INET6, &loop, 443));
    struct in_addr v4;
    inet_pton(AF_INET, "127.0.0.1", &v4);
    check("an IPv6 literal rule does not match an IPv4 destination",
          !connection_permitted(AF_INET, &v4, 443));

    reset_behaviour();
    remember_rule("1.2.3.4", "443");
    struct in6_addr any6;
    inet_pton(AF_INET6, "2001:db8::1", &any6);
    check("an IPv4 literal rule does not match an IPv6 destination",
          !connection_permitted(AF_INET6, &any6, 443));
}

static bool permits_v6(const char *ip, uint16_t port) {
    struct in6_addr address;
    inet_pton(AF_INET6, ip, &address);
    return connection_permitted(AF_INET6, &address, port);
}

static void test_connect_ranges(void) {
    reset_behaviour();
    remember_rule("104.16.0.0/12", "443");
    check("the range table kept the rule", connect_rules_count_for_tests() == 1);
    check("an IPv4 address inside the range on its port is permitted",
          permits_v4("104.16.5.5", 443));
    check("an IPv4 address inside the range on another port is refused",
          !permits_v4("104.16.5.5", 80));
    check("an IPv4 address outside the range is refused", !permits_v4("8.8.8.8", 443));

    reset_behaviour();
    remember_rule("127.0.0.1/32", "443");
    check("a /32 range matches exactly its address", permits_v4("127.0.0.1", 443));
    check("a /32 range refuses the neighbouring address", !permits_v4("127.0.0.2", 443));

    reset_behaviour();
    remember_rule("2001:db8::/32", "443");
    check("an IPv6 address inside the range is permitted", permits_v6("2001:db8::5", 443));
    check("an IPv6 address outside the range is refused", !permits_v6("2001:dead::5", 443));

    reset_behaviour();
    remember_rule("10.0.0.0/33", "443");
    remember_rule("10.0.0.0/0", "443");
    remember_rule("10.0.0.0/x", "443");
    remember_rule("nothost/8", "443");
    check("a malformed range is dropped", connect_rules_count_for_tests() == 0);

    reset_behaviour();
    remember_rule("::ffff:104.16.0.0/12", "443");
    check("an IPv4-mapped range with too short a prefix is dropped, as libnetblocker drops it",
          connect_rules_count_for_tests() == 0);

    reset_behaviour();
    remember_rule("::ffff:104.16.0.0/108", "443");
    check("an IPv4-mapped range with a long-enough prefix is kept", connect_rules_count_for_tests() == 1);
    check("the mapped range matches an in-range IPv4 address", permits_v4("104.16.5.5", 443));
    check("the mapped range refuses an out-of-range IPv4 address", !permits_v4("8.8.8.8", 443));

    reset_behaviour();
    remember_rule("104.16.0.0/12", "*");
    check("an any-port range permits an in-range address on any port",
          permits_v4("104.16.5.5", 12345));
    check("an any-port range refuses an out-of-range address", !permits_v4("8.8.8.8", 12345));

    struct in6_addr network;
    struct in6_addr probe;
    memset(&network, 0, sizeof(network));
    memset(&probe, 0, sizeof(probe));
    check("a non-positive prefix matches nothing", !address_within(&probe, &network, 0));
    check("a prefix past the address width matches nothing", !address_within(&probe, &network, 200));

    struct connect_rule range_rule;
    memset(&range_rule, 0, sizeof(range_rule));
    range_rule.is_range = true;
    range_rule.prefix_length = 96;
    check("a range rule refuses a family it cannot canonicalise",
          !rule_host_matches(&range_rule, AF_UNIX, NULL));
}

static void test_address_and_destination(void) {
    reset_behaviour();
    struct in6_addr v6loop;
    inet_pton(AF_INET6, "::1", &v6loop);
    check("IPv6 loopback is loopback", address_is_loopback(AF_INET6, &v6loop));
    struct in6_addr v6other;
    inet_pton(AF_INET6, "2001:db8::9", &v6other);
    check("an IPv6 non-loopback is not loopback", !address_is_loopback(AF_INET6, &v6other));
    struct in_addr v4;
    inet_pton(AF_INET, "10.0.0.1", &v4);
    check("an IPv4 non-loopback is not loopback", !address_is_loopback(AF_INET, &v4));
    check("an unknown family is not loopback", !address_is_loopback(AF_UNIX, &v4));

    struct sockaddr_storage storage;
    memset(&storage, 0, sizeof(storage));
    struct sockaddr_in *v4in = (struct sockaddr_in *)&storage;
    v4in->sin_family = AF_INET;
    v4in->sin_port = htons(443);
    v4in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    struct destination where = read_destination(&storage);
    check("an IPv4 destination reads its port back in host order",
          where.family == AF_INET && where.port == 443);
    check("an IPv4 destination points at its own address field",
          where.address == &v4in->sin_addr);
    memset(&storage, 0, sizeof(storage));
    struct sockaddr_in6 *v6in = (struct sockaddr_in6 *)&storage;
    v6in->sin6_family = AF_INET6;
    v6in->sin6_port = htons(8443);
    where = read_destination(&storage);
    check("an IPv6 destination reads its port back in host order",
          where.family == AF_INET6 && where.port == 8443);
    check("an IPv6 destination points at its own address field",
          where.address == &v6in->sin6_addr);
    storage.ss_family = AF_UNIX;
    where = read_destination(&storage);
    check("a non-INET destination carries no address", where.address == NULL);
}

static void test_exit_code_mapping(void) {
    int status = 0;
    check("a clean exit maps to its code", exit_code_from_status((7 << WAIT_STATUS_EXIT_CODE_SHIFT)) == 7);
    status = SIGKILL;
    check("a signal maps to 128 plus the signal", exit_code_from_status(status) == SIGNAL_EXIT_CODE_BASE + SIGKILL);
    check("an unusual status maps to the setup error", exit_code_from_status(WAIT_STATUS_STOPPED) == EXIT_CODE_SETUP_ERROR);
}

/* Logs once quiet, which returns without writing, and once verbose, which writes and so
 * exercises the va_list block. */
static void test_verbose_logging(void) {
    reset_behaviour();
    set_verbose(false);
    log_verbose("quiet %d", 1);
    set_verbose(true);
    log_verbose("loud %d", 2);
    set_verbose(false);
    check("verbose logging runs both ways", true);
}

/* ------------------------------------------------- the notification service */

/* The socket inodes the wrapped readlink reports, each also recorded or looked up by its case. */
static constexpr uint64_t PERMITTED_STREAM_INODE = 5001;         /* an IPv4 stream socket a connect is made for */
static constexpr uint64_t PERMITTED_IPV6_STREAM_INODE = 5002;    /* an IPv6 stream socket a connect is made for */
static constexpr uint64_t CREATED_TCP_INODE = 8100;              /* the TCP socket the guard creates */
static constexpr uint64_t CREATED_UDP_INODE = 8200;              /* the UDP socket the guard creates */
static constexpr uint64_t CREATED_NONBLOCKING_UDP_INODE = 8201;  /* the non-blocking UDP socket the guard creates */
static constexpr uint64_t TRACKED_DATAGRAM_INODE = 8300;         /* a datagram socket already recorded */
static constexpr uint64_t UNNAMEABLE_STREAM_INODE = 8300;        /* a recorded stream socket /proc cannot name */
static constexpr uint64_t TRACKED_STREAM_INODE = 8400;           /* a stream socket already recorded */

static void service_once(void) {
    struct seccomp_notif request;
    struct seccomp_notif_resp response;
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    service_one(FAKE_NOTIFY_DESCRIPTOR, &request, &response, sizeof(request));
}

static void test_service_paths(void) {
    reset_behaviour();
    bx->notif_recv_result = -1;
    service_once();
    check("a recv that fails is abandoned without answering", bx->answers == 0);

    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 443;
    bx->notif_id_valid_result = -1;
    service_once();
    check("an invalid notification is not acted on", bx->answers == 0);

    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    bx->process_vm_readv_result = -1;
    service_once();
    check("an unreadable address is refused with EACCES",
          bx->answers == 1 && bx->last_answer_error == -EACCES);

    reset_behaviour();
    bx->notif_recv_family = AF_UNIX;
    bx->process_vm_readv_result = 1;
    service_once();
    check("a UNIX-domain connect is refused", bx->answers == 1 && bx->last_answer_error == -EACCES);

    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 443;
    bx->process_vm_readv_result = 1;
    remember_rule("127.0.0.2", "443");
    service_once();
    check("a destination the list forbids is refused",
          bx->answers == 1 && bx->last_answer_error == -EACCES && bx->connect_calls == 0);

    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 443;
    bx->notif_recv_target_fd = 5;
    bx->process_vm_readv_result = 1;
    bx->readlink_inode = PERMITTED_STREAM_INODE;
    record_socket_type(PERMITTED_STREAM_INODE, FD_TYPE_STREAM);
    remember_rule("127.0.0.1", "443");
    service_once();
    check("a destination the list names by host and port is connected on the command's behalf",
          bx->connect_calls == 1 && bx->addfd_calls == 1 && bx->last_answer_error == 0);

    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 443;
    bx->notif_recv_target_fd = 5;
    bx->process_vm_readv_result = 1;
    bx->readlink_inode = PERMITTED_STREAM_INODE;
    record_socket_type(PERMITTED_STREAM_INODE, FD_TYPE_STREAM);
    remember_rule("127.0.0.1", "443");
    service_once();
    check("a permitted connect is made and answered with success",
          bx->connect_calls == 1 && bx->addfd_calls == 1 && bx->answers == 1 &&
              bx->last_answer_error == 0);

    reset_behaviour();
    bx->notif_recv_family = AF_INET6;
    bx->notif_recv_port = 443;
    bx->process_vm_readv_result = 1;
    bx->readlink_inode = PERMITTED_IPV6_STREAM_INODE;
    record_socket_type(PERMITTED_IPV6_STREAM_INODE, FD_TYPE_STREAM);
    remember_rule("2001:db8::1", "443");
    service_once();
    check("a permitted IPv6 connect is made on the command's behalf",
          bx->connect_calls == 1 && bx->addfd_calls == 1 && bx->last_answer_error == 0);
}

/* The supervisor decides socket() and the send syscalls, not only connect. These drive each
 * new branch through the notification dispatcher: a socket kind refused, a socket kind allowed,
 * TCP Fast Open refused, and a datagram judged by its destination. */
static void test_egress_syscalls(void) {
    reset_behaviour();
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_INET;
    bx->notif_socket_type = SOCK_RAW;
    service_once();
    check("a raw socket is refused", bx->answers == 1 && bx->last_answer_error == -EACCES);

    reset_behaviour();
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_INET;
    bx->notif_socket_type = SOCK_DGRAM;
    bx->notif_socket_protocol = IPPROTO_ICMP;
    service_once();
    check("an ICMP datagram socket is refused", bx->answers == 1 && bx->last_answer_error == -EACCES);

    reset_behaviour();
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_PACKET;
    bx->notif_socket_type = SOCK_RAW;
    service_once();
    check("a packet socket is refused", bx->answers == 1 && bx->last_answer_error == -EACCES);

    reset_behaviour();
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_INET;
    bx->notif_socket_type = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
    bx->readlink_inode = CREATED_TCP_INODE;
    service_once();
    check("an ordinary TCP socket is created and handed to the child, its type recorded",
          bx->answers == 1 && bx->last_answer_error == 0 && bx->last_answer_val == FAKE_ADDFD_DESCRIPTOR &&
              lookup_socket_type(CREATED_TCP_INODE) == FD_TYPE_STREAM);

    reset_behaviour();
    bx->notif_recv_nr = __NR_sendto;
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 443;
    bx->notif_send_flags = MSG_FASTOPEN;
    bx->process_vm_readv_result = 1;
    remember_rule("127.0.0.1", "443");
    service_once();
    check("a TCP Fast Open send is refused even to a listed destination",
          bx->answers == 1 && bx->last_answer_error == -EACCES);

    reset_behaviour();
    bx->notif_recv_nr = __NR_sendto;
    bx->process_vm_readv_result = 1;
    service_once();
    check("a datagram with no destination is a connected send and continues",
          bx->answers == 1 && bx->last_answer_error == 0 &&
              bx->last_answer_flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);

    reset_behaviour();
    bx->notif_recv_nr = __NR_sendto;
    bx->notif_recv_family = AF_UNIX;
    bx->process_vm_readv_result = 1;
    service_once();
    check("a datagram to a non-INET address continues untouched",
          bx->answers == 1 && bx->last_answer_error == 0 &&
              bx->last_answer_flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);

    reset_behaviour();
    bx->notif_recv_nr = __NR_sendto;
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    bx->process_vm_readv_result = 1;
    remember_rule("127.0.0.1", "53");
    service_once();
    check("a datagram to a listed destination continues",
          bx->answers == 1 && bx->last_answer_error == 0 &&
              bx->last_answer_flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);

    reset_behaviour();
    bx->notif_recv_nr = __NR_sendto;
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 9999;
    bx->process_vm_readv_result = 1;
    remember_rule("127.0.0.1", "53");
    service_once();
    check("a datagram to a destination the list does not name is refused",
          bx->answers == 1 && bx->last_answer_error == -EACCES);

    reset_behaviour();
    bx->notif_recv_nr = __NR_sendto;
    bx->notif_recv_family = AF_INET;
    bx->process_vm_readv_result = 0;
    service_once();
    check("a datagram whose address cannot be read is refused",
          bx->answers == 1 && bx->last_answer_error == -EACCES);

    reset_behaviour();
    bx->notif_recv_nr = __NR_sendmmsg;
    bx->mmsg_mode = 1;
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    bx->process_vm_readv_result = 1;
    remember_rule("127.0.0.1", "53");
    service_once();
    check("a sendmmsg batch to a listed destination continues",
          bx->answers == 1 && bx->last_answer_error == 0 &&
              bx->last_answer_flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);

    reset_behaviour();
    bx->notif_recv_nr = __NR_sendmmsg;
    bx->mmsg_mode = 1;
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 9999;
    bx->process_vm_readv_result = 1;
    remember_rule("127.0.0.1", "53");
    service_once();
    check("a sendmmsg batch naming a disallowed destination is refused whole",
          bx->answers == 1 && bx->last_answer_error == -EACCES);

    reset_behaviour();
    bx->notif_recv_nr = __NR_sendmmsg;
    bx->mmsg_mode = 1;
    bx->process_vm_readv_result = -1;
    service_once();
    check("a sendmmsg whose header cannot be read is refused",
          bx->answers == 1 && bx->last_answer_error == -EACCES);

    reset_behaviour();
    bx->notif_recv_nr = __NR_sendmmsg;
    bx->mmsg_mode = 1;
    bx->mmsg_name_missing = 1;
    bx->process_vm_readv_result = 1;
    service_once();
    check("a sendmmsg batch of connected sends continues",
          bx->answers == 1 && bx->last_answer_error == 0 &&
              bx->last_answer_flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);

    reset_behaviour();
    bx->notif_recv_nr = __NR_sendmmsg;
    bx->mmsg_mode = 1;
    bx->mmsg_addr_short = 1;
    bx->process_vm_readv_result = 1;
    service_once();
    check("a sendmmsg entry whose address cannot be read is refused",
          bx->answers == 1 && bx->last_answer_error == -EACCES);

    reset_behaviour();
    bx->notif_recv_nr = __NR_getpid;
    service_once();
    check("a notification for a syscall the filter does not trap is refused closed",
          bx->answers == 1 && bx->last_answer_error == -EACCES);

    reset_behaviour();
    set_verbose(true);
    bx->notif_recv_nr = __NR_sendto;
    bx->notif_send_result = -1;
    service_once();
    set_verbose(false);
    check("a continue whose notify send fails is tolerated", bx->answers == 1);

    reset_behaviour();
    bx->notif_recv_nr = __NR_sendto;
    bx->notif_recv_family = AF_INET;
    bx->process_vm_readv_result = 1;
    bx->notif_id_valid_result = -1;
    service_once();
    check("a sendto whose notification turns invalid is dropped", bx->answers == 0);

    reset_behaviour();
    bx->notif_recv_nr = __NR_sendmmsg;
    bx->mmsg_mode = 1;
    bx->mmsg_name_missing = 1;
    bx->mmsg_count = 2000;
    bx->process_vm_readv_result = 1;
    service_once();
    check("a sendmmsg batch is capped and still continues",
          bx->answers == 1 && bx->last_answer_flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);

    reset_behaviour();
    bx->notif_recv_nr = __NR_sendmmsg;
    bx->mmsg_mode = 1;
    bx->process_vm_readv_result = 1;
    bx->id_valid_fail_at = 1;
    service_once();
    check("a sendmmsg whose notification turns invalid before the header check is dropped",
          bx->answers == 0);

    reset_behaviour();
    bx->notif_recv_nr = __NR_sendmmsg;
    bx->mmsg_mode = 1;
    bx->process_vm_readv_result = 1;
    bx->id_valid_fail_at = 2;
    service_once();
    check("a sendmmsg whose notification turns invalid after the address read is dropped",
          bx->answers == 0);

    reset_behaviour();
    bx->notif_recv_nr = __NR_sendmmsg;
    bx->mmsg_mode = 1;
    bx->mmsg_hetero = 1;
    bx->mmsg_count = 2;
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    bx->process_vm_readv_result = 1;
    remember_rule("127.0.0.1", "53");
    service_once();
    check("a sendmmsg batch is refused when a later entry names a disallowed destination",
          bx->answers == 1 && bx->last_answer_error == -EACCES);
}

/* The guard creates each INET socket itself and records its type, so a later connect can tell a
 * datagram socket (checked then let through) from a stream socket (injected, race-free). */
static void test_socket_tracking(void) {
    reset_behaviour();
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_INET;
    bx->notif_socket_type = SOCK_DGRAM;
    bx->readlink_inode = CREATED_UDP_INODE;
    service_once();
    check("a UDP socket is created and its type recorded",
          bx->answers == 1 && bx->last_answer_error == 0 && bx->last_answer_val == FAKE_ADDFD_DESCRIPTOR &&
              lookup_socket_type(CREATED_UDP_INODE) == FD_TYPE_DGRAM);

    reset_behaviour();
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_INET;
    bx->notif_socket_type = SOCK_STREAM;
    bx->socket_result = -1;
    service_once();
    check("a socket the guard cannot create is answered with the errno",
          bx->answers == 1 && bx->last_answer_error < 0);

    reset_behaviour();
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_INET;
    bx->notif_socket_type = SOCK_STREAM;
    bx->notif_addfd_result = FAKE_FAILS_TARGET_GONE;
    service_once();
    check("a socket whose ADDFD finds the child gone is dropped", bx->answers == 0);

    reset_behaviour();
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_INET;
    bx->notif_socket_type = SOCK_STREAM;
    bx->notif_addfd_result = -1;
    service_once();
    check("a socket whose ADDFD fails is answered with the errno",
          bx->answers == 1 && bx->last_answer_error < 0);

    reset_behaviour();
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_INET6;
    bx->notif_socket_type = SOCK_DGRAM | SOCK_NONBLOCK;
    bx->fcntl_fails = 1;
    bx->readlink_inode = CREATED_NONBLOCKING_UDP_INODE;
    service_once();
    check("a non-blocking socket is still created when its flag cannot be read",
          bx->answers == 1 && bx->last_answer_val == FAKE_ADDFD_DESCRIPTOR &&
              lookup_socket_type(CREATED_NONBLOCKING_UDP_INODE) == FD_TYPE_DGRAM);

    reset_behaviour();
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_UNIX;
    bx->notif_socket_type = SOCK_STREAM;
    service_once();
    check("a non-INET socket is left to the kernel untracked",
          bx->answers == 1 && bx->last_answer_flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);

    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    bx->notif_recv_target_fd = 6;
    bx->process_vm_readv_result = 1;
    bx->readlink_inode = TRACKED_DATAGRAM_INODE;
    record_socket_type(TRACKED_DATAGRAM_INODE, FD_TYPE_DGRAM);
    remember_rule("127.0.0.1", "53");
    service_once();
    check("a connect on a datagram socket is checked then let through, not injected",
          bx->answers == 1 && bx->last_answer_error == 0 && bx->connect_calls == 0 &&
              bx->last_answer_flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);

    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    bx->notif_recv_target_fd = 9;
    bx->process_vm_readv_result = 1;
    bx->readlink_inode = 8301;
    remember_rule("127.0.0.1", "53");
    service_once();
    check("a connect on an untracked socket is refused, making no upstream connection",
          bx->answers == 1 && bx->connect_calls == 0 && bx->last_answer_error == -EACCES &&
              bx->last_answer_flags != SECCOMP_USER_NOTIF_FLAG_CONTINUE);

    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    bx->notif_recv_target_fd = 6;
    bx->process_vm_readv_result = 1;
    bx->readlink_kind = READLINK_PIPE;
    remember_rule("127.0.0.1", "53");
    service_once();
    check("a connect on a descriptor that is not a socket is refused, not injected over",
          bx->answers == 1 && bx->connect_calls == 0 && bx->last_answer_error == -EACCES &&
              bx->last_answer_flags != SECCOMP_USER_NOTIF_FLAG_CONTINUE);

    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    bx->notif_recv_target_fd = 6;
    bx->process_vm_readv_result = 1;
    bx->readlink_kind = READLINK_FAILS;
    bx->readlink_inode = UNNAMEABLE_STREAM_INODE;
    record_socket_type(UNNAMEABLE_STREAM_INODE, FD_TYPE_STREAM);
    remember_rule("127.0.0.1", "53");
    service_once();
    check("a stream connect is refused when /proc cannot name the inode",
          bx->answers == 1 && bx->connect_calls == 0 && bx->last_answer_error == -EACCES &&
              bx->last_answer_flags != SECCOMP_USER_NOTIF_FLAG_CONTINUE);

    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    bx->notif_recv_target_fd = 6;
    bx->process_vm_readv_result = 1;
    bx->readlink_inode = TRACKED_STREAM_INODE;
    record_socket_type(TRACKED_STREAM_INODE, FD_TYPE_STREAM);
    remember_rule("127.0.0.1", "53");
    service_once();
    check("a connect on a tracked stream socket is injected, race-free",
          bx->answers == 1 && bx->connect_calls == 1 && bx->addfd_calls == 1);

    reset_behaviour();
    record_socket_type(0, FD_TYPE_STREAM);
    bool map_ok = lookup_socket_type(0) == FD_TYPE_UNKNOWN
                  && lookup_socket_type(9999) == FD_TYPE_UNKNOWN;
    record_socket_type(4242, FD_TYPE_STREAM);
    map_ok = map_ok && lookup_socket_type(4242) == FD_TYPE_STREAM;
    record_socket_type(4242, FD_TYPE_DGRAM);
    map_ok = map_ok && lookup_socket_type(4242) == FD_TYPE_DGRAM;
    check("inode zero is ignored, an absent inode is unknown, and reuse overwrites", map_ok);

    reset_behaviour();
    for (unsigned long long inode = 1; inode <= SOCKET_TYPE_TABLE_SIZE; inode++) {
        record_socket_type(inode, FD_TYPE_STREAM);
    }
    record_socket_type(SOCKET_TYPE_TABLE_SIZE + 1, FD_TYPE_DGRAM);
    check("a full table still records by evicting a slot, and an absent inode reads unknown",
          lookup_socket_type(SOCKET_TYPE_TABLE_SIZE + 1) == FD_TYPE_DGRAM
              && lookup_socket_type(SOCKET_TYPE_TABLE_SIZE + 2) == FD_TYPE_UNKNOWN);
}

/* Every way a connect made on the command's behalf can end. A poll result of 0 is a
 * timeout, and one of -1 is a poll error that is not EINTR. FAKE_FAILS_TARGET_GONE
 * stands for ENOENT: on addfd the command is gone, not our failure, and on send it is
 * ignored. Any other send error is logged under verbose. */
static void test_connect_on_behalf_paths(void) {
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    struct seccomp_notif_resp response;

    reset_behaviour();
    bx->socket_result = -1;
    connect_on_behalf(FAKE_NOTIFY_DESCRIPTOR, &response, 1, FAKE_TARGET_DESCRIPTOR, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("a socket that cannot be made is reported", bx->last_answer_error == -EMFILE);

    reset_behaviour();
    bx->connect_result = -1;
    bx->connect_errno = ECONNREFUSED;
    connect_on_behalf(FAKE_NOTIFY_DESCRIPTOR, &response, 1, FAKE_TARGET_DESCRIPTOR, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("a refused connection is reported as its errno", bx->last_answer_error == -ECONNREFUSED);

    reset_behaviour();
    bx->connect_result = -1;
    bx->connect_errno = EINPROGRESS;
    bx->poll_result = 1;
    bx->poll_revents = POLLOUT;
    bx->getsockopt_so_error = 0;
    connect_on_behalf(FAKE_NOTIFY_DESCRIPTOR, &response, 1, FAKE_TARGET_DESCRIPTOR, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("a connection that completes after polling is injected",
          bx->addfd_calls == 1 && bx->last_answer_error == 0);

    reset_behaviour();
    bx->connect_result = -1;
    bx->connect_errno = EINPROGRESS;
    bx->poll_result = 0;
    connect_on_behalf(FAKE_NOTIFY_DESCRIPTOR, &response, 1, FAKE_TARGET_DESCRIPTOR, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("a connection that times out is reported", bx->last_answer_error == -ETIMEDOUT);

    reset_behaviour();
    bx->connect_result = -1;
    bx->connect_errno = EINPROGRESS;
    bx->poll_result = -1;
    connect_on_behalf(FAKE_NOTIFY_DESCRIPTOR, &response, 1, FAKE_TARGET_DESCRIPTOR, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("a poll error while connecting is reported", bx->last_answer_error == -ECONNREFUSED);

    reset_behaviour();
    bx->connect_result = -1;
    bx->connect_errno = EINPROGRESS;
    bx->poll_result = 1;
    bx->poll_revents = POLLOUT;
    bx->getsockopt_so_error = ECONNREFUSED;
    connect_on_behalf(FAKE_NOTIFY_DESCRIPTOR, &response, 1, FAKE_TARGET_DESCRIPTOR, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("a socket error found after polling is reported", bx->last_answer_error == -ECONNREFUSED);

    reset_behaviour();
    bx->connect_result = -1;
    bx->connect_errno = EINPROGRESS;
    bx->poll_eintr_once = 1;
    bx->poll_result = 1;
    bx->poll_revents = POLLOUT;
    connect_on_behalf(FAKE_NOTIFY_DESCRIPTOR, &response, 1, FAKE_TARGET_DESCRIPTOR, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("poll retries on EINTR", bx->addfd_calls == 1);

    reset_behaviour();
    bx->connect_result = -1;
    bx->connect_errno = EINPROGRESS;
    bx->poll_result = 1;
    bx->poll_revents = POLLOUT;
    bx->getsockopt_result = -1;
    connect_on_behalf(FAKE_NOTIFY_DESCRIPTOR, &response, 1, FAKE_TARGET_DESCRIPTOR, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("a getsockopt failure is reported", bx->last_answer_error == -EINVAL);

    reset_behaviour();
    bx->notif_addfd_result = -1;
    connect_on_behalf(FAKE_NOTIFY_DESCRIPTOR, &response, 1, FAKE_TARGET_DESCRIPTOR, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("an addfd failure is reported", bx->last_answer_error == -EINVAL);

    reset_behaviour();
    bx->notif_addfd_result = FAKE_FAILS_TARGET_GONE;
    connect_on_behalf(FAKE_NOTIFY_DESCRIPTOR, &response, 1, FAKE_TARGET_DESCRIPTOR, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("an addfd on a vanished command is not answered", bx->answers == 0);

    reset_behaviour();
    bx->notif_send_result = FAKE_FAILS_TARGET_GONE;
    answer(FAKE_NOTIFY_DESCRIPTOR, &response, 1, 0, -EACCES);
    check("a send to a vanished command is not an error", bx->answers == 1);

    reset_behaviour();
    set_verbose(true);
    bx->notif_send_result = -1;
    answer(FAKE_NOTIFY_DESCRIPTOR, &response, 1, 0, -EACCES);
    set_verbose(false);
    check("a send error is logged", bx->answers == 1);
}

static void test_read_peer_address_edges(void) {
    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    struct sockaddr_storage out;
    check("a length too short to carry a family is refused",
          read_peer_address(1, FAKE_ADDRESS_POINTER, 1, &out) == 0);
    bx->process_vm_readv_result = 1;
    check("a claimed length beyond the storage is clamped and read",
          read_peer_address(1, FAKE_ADDRESS_POINTER, 4096, &out) > 0);
}

static void test_receive_descriptor(void) {
    reset_behaviour();
    check("a valid descriptor message yields the descriptor", receive_descriptor(FAKE_HANDOFF_SOCKET_DESCRIPTOR) == FAKE_RECEIVED_DESCRIPTOR);
    reset_behaviour();
    bx->recvmsg_result = 0;
    check("an end of file on the socket is refused", receive_descriptor(FAKE_HANDOFF_SOCKET_DESCRIPTOR) == -1);
    reset_behaviour();
    bx->recvmsg_bad_cmsg = 1;
    check("a message with no control data is refused", receive_descriptor(FAKE_HANDOFF_SOCKET_DESCRIPTOR) == -1);
    reset_behaviour();
    bx->recvmsg_wrong = RECVMSG_WRONG_LEVEL;
    check("a message with the wrong control level is refused", receive_descriptor(FAKE_HANDOFF_SOCKET_DESCRIPTOR) == -1);
    reset_behaviour();
    bx->recvmsg_wrong = RECVMSG_WRONG_TYPE;
    check("a message with the wrong control type is refused", receive_descriptor(FAKE_HANDOFF_SOCKET_DESCRIPTOR) == -1);
    reset_behaviour();
    bx->recvmsg_wrong = RECVMSG_WRONG_LENGTH;
    check("a message of the wrong control length is refused", receive_descriptor(FAKE_HANDOFF_SOCKET_DESCRIPTOR) == -1);
}

/* The supervise loop. A failing size query falls back to the compiled sizes, and the
 * case with small sizes has the kernel report sizes smaller than this build's structs. */
static void test_supervise_loop(void) {
    reset_behaviour();
    bx->notif_sizes_result = -1;
    bx->supervise_services = 1;
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 443;
    bx->process_vm_readv_result = 1;
    supervise(FAKE_NOTIFY_DESCRIPTOR);
    check("the supervise loop services a notification then ends on hangup", bx->answers == 1);

    reset_behaviour();
    bx->supervise_poll_error = 1;
    supervise(FAKE_NOTIFY_DESCRIPTOR);
    check("the supervise loop ends on a poll error without servicing anything", bx->answers == 0);

    reset_behaviour();
    bx->supervise_poll_eintr_once = 1;
    supervise(FAKE_NOTIFY_DESCRIPTOR);
    check("the supervise loop retries on EINTR then ends on hangup", bx->answers == 0);

    reset_behaviour();
    bx->notif_sizes_small = 1;
    bx->supervise_services = 1;
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 443;
    bx->process_vm_readv_result = 1;
    supervise(FAKE_NOTIFY_DESCRIPTOR);
    check("undersized reported notif sizes are clamped up so a notification is still serviced",
          bx->answers == 1);

    reset_behaviour();
    bx->calloc_fails = 1;
    supervise(FAKE_NOTIFY_DESCRIPTOR);
    bx->calloc_fails = 0;
    check("a supervisor that cannot allocate its buffers gives up cleanly", bx->answers == 0);
}

/* ---------------------------------------------------------- the exit paths */

static void test_argument_errors(void) {
    char *none[] = { "guard", NULL };
    check("no command is a usage error", run_main(none) == EXIT_CODE_USAGE);
    char *only_dashes[] = { "guard", "--", NULL };
    check("nothing after -- is a usage error", run_main(only_dashes) == EXIT_CODE_USAGE);
    char *bad_option[] = { "guard", "--nonsense", "--", "cmd", NULL };
    check("an unknown option is a usage error", run_main(bad_option) == EXIT_CODE_USAGE);
    char *dangling_rules[] = { "guard", "--rules", NULL };
    check("a --rules with no value is a usage error", run_main(dangling_rules) == EXIT_CODE_USAGE);
    char *unreadable[] = { "guard", "--rules", "/dev/null/impossible", "--", "cmd", NULL };
    check("an unreadable rules file refuses the run", run_main(unreadable) == EXIT_CODE_SETUP_ERROR);
}

/* Setup failures before the command runs. A fork result of 0 takes the child path. */
/* Runs the filter the child installed against one seccomp_data and answers what it returns.
 * A classic BPF program of this shape is four instruction forms: load a word of the data,
 * compare the accumulator with a constant, test bits of it, and return. Anything else is a
 * form this filter does not use, and answering zero for it makes the case fail rather than
 * quietly pass. Assumes a case has already run the child, so a filter was captured. */
static uint32_t filter_answer(uint32_t audit_arch, int syscall_number) {
    struct seccomp_data data;
    memset(&data, 0, sizeof(data));
    data.arch = audit_arch;
    data.nr = syscall_number;
    uint32_t accumulator = 0;
    for (unsigned short at = 0; at < bx->installed_filter_length; at++) {
        const struct sock_filter *instruction = &bx->installed_filter[at];
        if (instruction->code == (BPF_LD | BPF_W | BPF_ABS)) {
            memcpy(&accumulator, (const char *)&data + instruction->k, sizeof(accumulator));
            continue;
        }
        if (instruction->code == (BPF_JMP | BPF_JEQ | BPF_K)) {
            at += (accumulator == instruction->k) ? instruction->jt : instruction->jf;
            continue;
        }
        if (instruction->code == (BPF_JMP | BPF_JSET | BPF_K)) {
            at += (accumulator & instruction->k) ? instruction->jt : instruction->jf;
            continue;
        }
        if (instruction->code == (BPF_RET | BPF_K)) {
            return instruction->k;
        }
        return 0;
    }
    return 0;
}

/* Installs the filter by running the child far enough to hand it over, so that the checks
 * below have one to run. The exec stand-in ends the child, which is what a case expects. */
static void install_filter_for_inspection(void) {
    char *argv[] = { "guard", "--", "cmd", NULL };
    reset_behaviour();
    bx->fork_result = 0;
    bx->execvp_returns = 1;
    (void)run_main(argv);
}

/* What the filter does with each class of call. The filter is the whole of the guard's
 * reach: a syscall it allows is one the supervisor never sees, so the decision belongs to
 * this program and not only to the code that services a notification. */
static void test_egress_filter(void) {
    constexpr uint32_t deny = SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA);
    install_filter_for_inspection();
    check("the child hands the kernel a filter at all", bx->installed_filter_length > 0);

    check("a call under a foreign ABI is refused",
          filter_answer(FOREIGN_AUDIT_ARCH, __NR_read) == deny);
    check("an ordinary call under the native ABI is allowed",
          filter_answer(GUARD_NATIVE_AUDIT_ARCH, __NR_read) == SECCOMP_RET_ALLOW);

    check("io_uring_setup is refused",
          filter_answer(GUARD_NATIVE_AUDIT_ARCH, __NR_io_uring_setup) == deny);
    check("io_uring_enter is refused",
          filter_answer(GUARD_NATIVE_AUDIT_ARCH, __NR_io_uring_enter) == deny);
    check("io_uring_register is refused",
          filter_answer(GUARD_NATIVE_AUDIT_ARCH, __NR_io_uring_register) == deny);
    check("setsid is refused, so the command cannot leave the timeout's group",
          filter_answer(GUARD_NATIVE_AUDIT_ARCH, __NR_setsid) == deny);
    check("setpgid is refused, for the same reason",
          filter_answer(GUARD_NATIVE_AUDIT_ARCH, __NR_setpgid) == deny);

    check("connect is trapped to the supervisor",
          filter_answer(GUARD_NATIVE_AUDIT_ARCH, __NR_connect) == SECCOMP_RET_USER_NOTIF);
    check("socket is trapped to the supervisor",
          filter_answer(GUARD_NATIVE_AUDIT_ARCH, __NR_socket) == SECCOMP_RET_USER_NOTIF);
    check("sendto is trapped to the supervisor",
          filter_answer(GUARD_NATIVE_AUDIT_ARCH, __NR_sendto) == SECCOMP_RET_USER_NOTIF);
    check("sendmmsg is trapped to the supervisor",
          filter_answer(GUARD_NATIVE_AUDIT_ARCH, __NR_sendmmsg) == SECCOMP_RET_USER_NOTIF);
    check("sendmsg is deliberately not trapped, or the descriptor handoff would park",
          filter_answer(GUARD_NATIVE_AUDIT_ARCH, __NR_sendmsg) == SECCOMP_RET_ALLOW);
}

static void test_child_setup_failures(void) {
    char *argv[] = { "guard", "--", "cmd", NULL };

    reset_behaviour();
    bx->socketpair_result = -1;
    check("a socketpair failure refuses the run", run_main(argv) == EXIT_CODE_SETUP_ERROR);

    char *verbose_argv[] = { "guard", "--verbose", "--", "cmd", NULL };
    reset_behaviour();
    bx->socketpair_result = -1;
    check("--verbose is accepted before the command", run_main(verbose_argv) == EXIT_CODE_SETUP_ERROR);

    reset_behaviour();
    bx->fork_result = -1;
    check("a fork failure refuses the run", run_main(argv) == EXIT_CODE_SETUP_ERROR);

    reset_behaviour();
    bx->fork_result = 0;
    bx->prctl_result = -1;
    check("a no_new_privs failure fails the child closed", run_main(argv) == EXIT_CODE_SETUP_ERROR);

    reset_behaviour();
    bx->fork_result = 0;
    bx->seccomp_listener_result = -1;
    check("a filter that will not install fails the child closed",
          run_main(argv) == EXIT_CODE_SETUP_ERROR);

    reset_behaviour();
    bx->fork_result = 0;
    bx->sendmsg_result = -1;
    check("a descriptor handoff that fails fails the child closed",
          run_main(argv) == EXIT_CODE_SETUP_ERROR);

    reset_behaviour();
    bx->fork_result = 0;
    bx->sendmsg_eintr_once = 1;
    bx->execvp_returns = 1;
    check("the child that hands over and cannot exec exits 127", run_main(argv) == EXIT_CODE_COMMAND_NOT_EXECUTABLE);
}

/* The parent path, taken with a fork result of FAKE_CHILD_PID. When the parent is never
 * handed the descriptor, the reap on the refusal path retries once; in the next case
 * the child died with a code of its own. On the normal path the recv retries, then the
 * first poll hangs up, and the reap retries once. */
static void test_parent_paths(void) {
    char *argv[] = { "guard", "--", "cmd", NULL };

    reset_behaviour();
    bx->fork_result = FAKE_CHILD_PID;
    bx->recvmsg_result = -1;
    bx->waitpid_eintr_once = 1;
    check("a parent that is never handed the descriptor refuses the run",
          run_main(argv) == EXIT_CODE_SETUP_ERROR);

    reset_behaviour();
    bx->fork_result = FAKE_CHILD_PID;
    bx->recvmsg_result = -1;
    bx->recorded_child_status = (3 << WAIT_STATUS_EXIT_CODE_SHIFT);
    check("a refusal keeps the child's own non-zero exit code", run_main(argv) == 3);

    reset_behaviour();
    bx->fork_result = FAKE_CHILD_PID;
    bx->recvmsg_bad_cmsg = 1;
    check("a parent handed a malformed message refuses the run",
          run_main(argv) == EXIT_CODE_SETUP_ERROR);

    reset_behaviour();
    bx->fork_result = FAKE_CHILD_PID;
    bx->recvmsg_eintr_once = 1;
    bx->waitpid_eintr_once = 1;
    check("a parent supervises and then reaps the child, mapping its status",
          run_main(argv) == 0);
}

/* Runs every case. stdout is line-buffered so a forked test-child never inherits a
 * partial buffer and re-emits it on exit, which would otherwise print every line several
 * times when stdout is a pipe rather than a terminal, as it is under CI. */
int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    bx = mmap(NULL, sizeof(*bx), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (bx == MAP_FAILED) {
        perror("mmap");
        return HARNESS_SETUP_FAILURE;
    }
    reset_behaviour();

    test_rule_parsing();
    test_policy_matching();
    test_connect_ranges();
    test_address_and_destination();
    test_exit_code_mapping();
    test_verbose_logging();
    test_read_peer_address_edges();
    test_receive_descriptor();
    test_service_paths();
    test_egress_syscalls();
    test_socket_tracking();
    test_connect_on_behalf_paths();
    test_supervise_loop();
    test_argument_errors();
    test_egress_filter();
    test_child_setup_failures();
    test_parent_paths();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
