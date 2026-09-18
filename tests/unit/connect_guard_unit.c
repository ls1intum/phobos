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
 * The source is included rather than linked, so the static functions are reachable,
 * and main is renamed so this file can provide its own. Every syscall the guard
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

#define main sut_main
#include "../../core/phobos-connect-guard.c"
#undef main

/* ------------------------------------------------------------ the behaviour */

/* What the wrapped calls should do, and what they were handed. The record lives in
 * shared memory because a case that ends in exit() runs in a forked child of the
 * test while the assertions are made by the parent. */
struct behaviour {
    /* seccomp NEW_LISTENER (via syscall) */
    long seccomp_listener_result;
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

static void reset_behaviour(void)
{
    memset(bx, 0, sizeof(*bx));
    bx->notif_recv_nr = __NR_connect;
    bx->seccomp_listener_result = 4;
    bx->notif_sizes_result = 0;
    bx->socketpair_result = 0;
    bx->prctl_result = 0;
    bx->sendmsg_result = 1;
    bx->recvmsg_result = 1;
    bx->socket_result = 7;
    bx->connect_result = 0;
    bx->getsockopt_result = 0;
    connect_rule_count = 0;
    verbose = false;
}

/* ------------------------------------------------------------------- wraps */

/* The guard ends the child with _exit, which does not flush the coverage counters. So that
 * the paths run in a forked child of the test are still measured, this dumps them first. The
 * dump function is weak, so a plain (non-instrumented) build links without it. */
extern void __gcov_dump(void) __attribute__((weak));
void __real__exit(int status) __attribute__((noreturn));
void __wrap__exit(int status) __attribute__((noreturn));
void __wrap__exit(int status)
{
    if (__gcov_dump != NULL) {
        __gcov_dump();
    }
    __real__exit(status);
}

void *__real_calloc(size_t count, size_t size);
void *__wrap_calloc(size_t count, size_t size)
{
    if (bx != NULL && bx->calloc_fails) {
        errno = ENOMEM;
        return NULL;
    }
    return __real_calloc(count, size);
}

long __real_syscall(long number, ...);
long __wrap_syscall(long number, ...)
{
    va_list arguments;
    va_start(arguments, number);
    unsigned long a1 = va_arg(arguments, unsigned long);
    unsigned long a2 = va_arg(arguments, unsigned long);
    unsigned long a3 = va_arg(arguments, unsigned long);
    va_end(arguments);
    if (number == SYS_seccomp && a1 == SECCOMP_SET_MODE_FILTER) {
        (void)a2;
        (void)a3;
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

int __wrap_socketpair(int domain, int type, int protocol, int pair[2])
{
    (void)domain;
    (void)type;
    (void)protocol;
    if (bx->socketpair_result != 0) {
        errno = EMFILE;
        return -1;
    }
    pair[0] = 20;
    pair[1] = 21;
    return 0;
}

pid_t __real_fork(void);
pid_t __wrap_fork(void)
{
    return (pid_t)bx->fork_result;
}

int __wrap_prctl(int option, ...)
{
    (void)option;
    if (bx->prctl_result != 0) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

void (*__wrap_signal(int signum, void (*handler)(int)))(int)
{
    (void)signum;
    (void)handler;
    return NULL;
}

int __wrap_execvp(const char *file, char *const argv[])
{
    (void)file;
    (void)argv;
    if (bx->execvp_returns) {
        errno = ENOENT;
        return -1;
    }
    _exit(200); /* stands in for a successful exec */
}

pid_t __wrap_waitpid(pid_t pid, int *status, int options)
{
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

ssize_t __wrap_sendmsg(int fd, const struct msghdr *message, int flags)
{
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

ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags)
{
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
    header->cmsg_level = bx->recvmsg_wrong == 1 ? IPPROTO_IP : SOL_SOCKET;
    header->cmsg_type = bx->recvmsg_wrong == 2 ? SCM_CREDENTIALS : SCM_RIGHTS;
    header->cmsg_len = bx->recvmsg_wrong == 3 ? CMSG_LEN(0) : CMSG_LEN(sizeof(int));
    int descriptor = 30;
    memcpy(CMSG_DATA(header), &descriptor, sizeof(int));
    return 1;
}

ssize_t __wrap_process_vm_readv(pid_t pid, const struct iovec *local, unsigned long liovcnt,
                                const struct iovec *remote, unsigned long riovcnt,
                                unsigned long flags)
{
    (void)pid;
    (void)riovcnt;
    (void)flags;
    if (bx->process_vm_readv_result < 0) {
        errno = EFAULT;
        return -1;
    }
    if (bx->process_vm_readv_result == 0) {
        return 0; /* a short read: fewer bytes than asked */
    }
    if (bx->mmsg_mode && local->iov_len == sizeof(struct mmsghdr)) {
        struct mmsghdr batch_entry;
        memset(&batch_entry, 0, sizeof(batch_entry));
        if (!bx->mmsg_name_missing) {
            batch_entry.msg_hdr.msg_name = (void *)0x5000;
            batch_entry.msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
        }
        memcpy(local->iov_base, &batch_entry, local->iov_len);
        return (ssize_t)local->iov_len;
    }
    if (bx->mmsg_mode && bx->mmsg_addr_short) {
        return 0;
    }
    /* Fill the destination the guard is reading into with a socket address of the
     * requested family, so the read looks like the command's real connect target. */
    struct sockaddr_storage storage;
    memset(&storage, 0, sizeof(storage));
    socklen_t length;
    bx->addr_read_seen++;
    uint16_t effective_port = bx->notif_recv_port;
    if (bx->mmsg_hetero && bx->addr_read_seen >= 2) {
        effective_port = 9999;
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
    /* The real call reads the whole requested length from the command's memory; report
     * that, so read_peer_address sees the full read it asked for. */
    return (ssize_t)local->iov_len;
}

int __wrap_socket(int domain, int type, int protocol)
{
    (void)domain;
    (void)type;
    (void)protocol;
    if (bx->socket_result < 0) {
        errno = EMFILE;
        return -1;
    }
    return bx->socket_result;
}

int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length)
{
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

int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    (void)timeout;
    (void)count;
    if (fds[0].events & POLLIN) {
        /* The supervise loop waits for POLLIN: hand out a readable turn for each
         * arranged service, an EINTR to exercise the retry, or a poll error, then a
         * hangup that ends the loop. */
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

int __wrap_getsockopt(int fd, int level, int name, void *value, socklen_t *length)
{
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

int __wrap_ioctl(int fd, unsigned long request, ...)
{
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
        req->id = 555;
        req->pid = 12345;
        req->data.nr = bx->notif_recv_nr;
        uint64_t address_length = bx->notif_recv_family == AF_INET6 ? sizeof(struct sockaddr_in6)
                                                                    : sizeof(struct sockaddr_in);
        if (bx->notif_recv_nr == __NR_socket) {
            req->data.args[0] = (uint64_t)bx->notif_socket_domain;
            req->data.args[1] = (uint64_t)bx->notif_socket_type;
            req->data.args[2] = (uint64_t)bx->notif_socket_protocol;
        } else if (bx->notif_recv_nr == __NR_sendto) {
            req->data.args[3] = bx->notif_send_flags;
            req->data.args[4] = bx->notif_recv_family == 0 ? 0 : 0x4000;
            req->data.args[5] = bx->notif_recv_family == 0 ? 0 : address_length;
        } else if (bx->notif_recv_nr == __NR_sendmmsg) {
            req->data.args[1] = 0x4000;
            req->data.args[2] = bx->mmsg_count ? bx->mmsg_count : 1;
            req->data.args[3] = bx->notif_send_flags;
        } else {
            req->data.args[0] = bx->notif_recv_target_fd;
            req->data.args[1] = 0x4000; /* a plausible userspace pointer, never dereferenced here */
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
            errno = bx->notif_addfd_result == -2 ? ENOENT : EINVAL;
            return -1;
        }
        return 40;
    }
    if (request == SECCOMP_IOCTL_NOTIF_SEND) {
        struct seccomp_notif_resp *resp = argument;
        bx->last_answer_error = resp->error;
        bx->last_answer_val = resp->val;
        bx->last_answer_flags = resp->flags;
        bx->answers++;
        if (bx->notif_send_result != 0) {
            errno = bx->notif_send_result == -2 ? ENOENT : EPIPE;
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

static void check(const char *what, bool condition)
{
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
static int run_main(char *const argv[])
{
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

static void test_rule_parsing(void)
{
    reset_behaviour();
    char path[] = "/tmp/phobos-guard-rules.XXXXXX";
    int fd = mkstemp(path);
    dprintf(fd, "127.0.0.1 443\nexample.com *\nloner\n%s bad\n* 8080\n", "junk");
    close(fd);
    check("a rules file loads", load_rules(path));
    unlink(path);
    check("the three well-formed rules were kept", connect_rule_count == 3);

    reset_behaviour();
    check("a null path is no rules and no error", load_rules(NULL));
    check("an absent file is no rules and no error", load_rules("/tmp/phobos-guard-absent.XXXX"));
    check("an unreadable file refuses (not ENOENT)", !load_rules("/dev/null/impossible"));

    reset_behaviour();
    remember_rule("h", "0");
    remember_rule("h", "70000");
    remember_rule("h", "notanumber");
    check("port zero, out of range and non-numeric are dropped", connect_rule_count == 0);
    char big[MAXIMUM_HOST + 8];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    remember_rule(big, "443");
    check("an over-long host is dropped", connect_rule_count == 0);
    for (size_t i = 0; i < MAXIMUM_RULES + 4; i++) {
        remember_rule("127.0.0.1", "443");
    }
    check("the rule table does not overflow", connect_rule_count == MAXIMUM_RULES);
}

static bool permits_v4(const char *ip, uint16_t port)
{
    struct in_addr address;
    inet_pton(AF_INET, ip, &address);
    return connection_permitted(AF_INET, &address, port);
}

static void test_policy_matching(void)
{
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

static void test_address_and_destination(void)
{
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

static void test_exit_code_mapping(void)
{
    int status = 0;
    check("a clean exit maps to its code", exit_code_from_status((7 << 8)) == 7);
    status = SIGKILL;
    check("a signal maps to 128 plus the signal", exit_code_from_status(status) == 128 + SIGKILL);
    check("an unusual status maps to the setup error", exit_code_from_status(0x7f) == EXIT_SETUP_ERROR);
}

static void test_verbose_logging(void)
{
    reset_behaviour();
    verbose = false;
    log_verbose("quiet %d", 1); /* returns without writing */
    verbose = true;
    log_verbose("loud %d", 2); /* writes, exercising the va_list block */
    verbose = false;
    check("verbose logging runs both ways", true);
}

/* ------------------------------------------------- the notification service */

static void service_once(void)
{
    struct seccomp_notif request;
    struct seccomp_notif_resp response;
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    service_one(9, &request, &response, sizeof(request));
}

static void test_service_paths(void)
{
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
    remember_rule("127.0.0.1", "443");
    service_once();
    check("a destination the list names by host and port is connected on the command's behalf",
          bx->connect_calls == 1 && bx->addfd_calls == 1 && bx->last_answer_error == 0);

    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 443;
    bx->notif_recv_target_fd = 5;
    bx->process_vm_readv_result = 1;
    remember_rule("127.0.0.1", "443");
    service_once();
    check("a permitted connect is made and answered with success",
          bx->connect_calls == 1 && bx->addfd_calls == 1 && bx->answers == 1 &&
              bx->last_answer_error == 0);

    reset_behaviour();
    bx->notif_recv_family = AF_INET6;
    bx->notif_recv_port = 443;
    bx->process_vm_readv_result = 1;
    remember_rule("2001:db8::1", "443");
    service_once();
    check("a permitted IPv6 connect is made on the command's behalf",
          bx->connect_calls == 1 && bx->addfd_calls == 1 && bx->last_answer_error == 0);
}

/* The supervisor decides socket() and the send syscalls, not only connect. These drive each
 * new branch through the notification dispatcher: a socket kind refused, a socket kind allowed,
 * TCP Fast Open refused, and a datagram judged by its destination. */
static void test_egress_syscalls(void)
{
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
    service_once();
    check("an ordinary TCP socket is allowed to continue",
          bx->answers == 1 && bx->last_answer_error == 0 &&
              bx->last_answer_flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);

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
    verbose = true;
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_INET;
    bx->notif_socket_type = SOCK_STREAM;
    bx->notif_send_result = -1;
    service_once();
    verbose = false;
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

static void test_connect_on_behalf_paths(void)
{
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    struct seccomp_notif_resp response;

    reset_behaviour();
    bx->socket_result = -1;
    connect_on_behalf(9, &response, 1, 5, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("a socket that cannot be made is reported", bx->last_answer_error == -EMFILE);

    reset_behaviour();
    bx->connect_result = -1;
    bx->connect_errno = ECONNREFUSED;
    connect_on_behalf(9, &response, 1, 5, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("a refused connection is reported as its errno", bx->last_answer_error == -ECONNREFUSED);

    reset_behaviour();
    bx->connect_result = -1;
    bx->connect_errno = EINPROGRESS;
    bx->poll_result = 1;
    bx->poll_revents = POLLOUT;
    bx->getsockopt_so_error = 0;
    connect_on_behalf(9, &response, 1, 5, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("a connection that completes after polling is injected",
          bx->addfd_calls == 1 && bx->last_answer_error == 0);

    reset_behaviour();
    bx->connect_result = -1;
    bx->connect_errno = EINPROGRESS;
    bx->poll_result = 0; /* timeout */
    connect_on_behalf(9, &response, 1, 5, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("a connection that times out is reported", bx->last_answer_error == -ETIMEDOUT);

    reset_behaviour();
    bx->connect_result = -1;
    bx->connect_errno = EINPROGRESS;
    bx->poll_result = -1; /* a poll error that is not EINTR */
    connect_on_behalf(9, &response, 1, 5, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("a poll error while connecting is reported", bx->last_answer_error == -ECONNREFUSED);

    reset_behaviour();
    bx->connect_result = -1;
    bx->connect_errno = EINPROGRESS;
    bx->poll_result = 1;
    bx->poll_revents = POLLOUT;
    bx->getsockopt_so_error = ECONNREFUSED;
    connect_on_behalf(9, &response, 1, 5, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("a socket error found after polling is reported", bx->last_answer_error == -ECONNREFUSED);

    reset_behaviour();
    bx->connect_result = -1;
    bx->connect_errno = EINPROGRESS;
    bx->poll_eintr_once = 1;
    bx->poll_result = 1;
    bx->poll_revents = POLLOUT;
    connect_on_behalf(9, &response, 1, 5, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("poll retries on EINTR", bx->addfd_calls == 1);

    reset_behaviour();
    bx->connect_result = -1;
    bx->connect_errno = EINPROGRESS;
    bx->poll_result = 1;
    bx->poll_revents = POLLOUT;
    bx->getsockopt_result = -1;
    connect_on_behalf(9, &response, 1, 5, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("a getsockopt failure is reported", bx->last_answer_error == -EINVAL);

    reset_behaviour();
    bx->notif_addfd_result = -1;
    connect_on_behalf(9, &response, 1, 5, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("an addfd failure is reported", bx->last_answer_error == -EINVAL);

    reset_behaviour();
    bx->notif_addfd_result = -2; /* ENOENT: the command is gone, not our failure */
    connect_on_behalf(9, &response, 1, 5, AF_INET, (struct sockaddr *)&address, sizeof(address));
    check("an addfd on a vanished command is not answered", bx->answers == 0);

    reset_behaviour();
    bx->notif_send_result = -2; /* ENOENT on send: ignored */
    answer(9, &response, 1, 0, -EACCES);
    check("a send to a vanished command is not an error", bx->answers == 1);

    reset_behaviour();
    verbose = true;
    bx->notif_send_result = -1; /* other error: logged under verbose */
    answer(9, &response, 1, 0, -EACCES);
    verbose = false;
    check("a send error is logged", bx->answers == 1);
}

static void test_read_peer_address_edges(void)
{
    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    struct sockaddr_storage out;
    check("a length too short to carry a family is refused",
          read_peer_address(1, 0x4000, 1, &out) == 0);
    bx->process_vm_readv_result = 1;
    check("a claimed length beyond the storage is clamped and read",
          read_peer_address(1, 0x4000, 4096, &out) > 0);
}

static void test_receive_descriptor(void)
{
    reset_behaviour();
    check("a valid descriptor message yields the descriptor", receive_descriptor(5) == 30);
    reset_behaviour();
    bx->recvmsg_result = 0;
    check("an end of file on the socket is refused", receive_descriptor(5) == -1);
    reset_behaviour();
    bx->recvmsg_bad_cmsg = 1;
    check("a message with no control data is refused", receive_descriptor(5) == -1);
    reset_behaviour();
    bx->recvmsg_wrong = 1;
    check("a message with the wrong control level is refused", receive_descriptor(5) == -1);
    reset_behaviour();
    bx->recvmsg_wrong = 2;
    check("a message with the wrong control type is refused", receive_descriptor(5) == -1);
    reset_behaviour();
    bx->recvmsg_wrong = 3;
    check("a message of the wrong control length is refused", receive_descriptor(5) == -1);
}

static void test_supervise_loop(void)
{
    reset_behaviour();
    bx->notif_sizes_result = -1; /* falls back to the compiled sizes */
    bx->supervise_services = 1;
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 443;
    bx->process_vm_readv_result = 1;
    supervise(9);
    check("the supervise loop services a notification then ends on hangup", bx->answers == 1);

    reset_behaviour();
    bx->supervise_poll_error = 1;
    supervise(9);
    check("the supervise loop ends on a poll error without servicing anything", bx->answers == 0);

    reset_behaviour();
    bx->supervise_poll_eintr_once = 1;
    supervise(9);
    check("the supervise loop retries on EINTR then ends on hangup", bx->answers == 0);

    reset_behaviour();
    bx->notif_sizes_small = 1; /* the kernel reports sizes smaller than this build's structs */
    bx->supervise_services = 1;
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 443;
    bx->process_vm_readv_result = 1;
    supervise(9);
    check("undersized reported notif sizes are clamped up so a notification is still serviced",
          bx->answers == 1);

    reset_behaviour();
    bx->calloc_fails = 1;
    supervise(9);
    bx->calloc_fails = 0;
    check("a supervisor that cannot allocate its buffers gives up cleanly", bx->answers == 0);
}

/* ---------------------------------------------------------- the exit paths */

static void test_argument_errors(void)
{
    char *none[] = { "guard", NULL };
    check("no command is a usage error", run_main(none) == 2);
    char *only_dashes[] = { "guard", "--", NULL };
    check("nothing after -- is a usage error", run_main(only_dashes) == 2);
    char *bad_option[] = { "guard", "--nonsense", "--", "cmd", NULL };
    check("an unknown option is a usage error", run_main(bad_option) == 2);
    char *dangling_rules[] = { "guard", "--rules", NULL };
    check("a --rules with no value is a usage error", run_main(dangling_rules) == 2);
    char *unreadable[] = { "guard", "--rules", "/dev/null/impossible", "--", "cmd", NULL };
    check("an unreadable rules file refuses the run", run_main(unreadable) == EXIT_SETUP_ERROR);
}

static void test_child_setup_failures(void)
{
    char *argv[] = { "guard", "--", "cmd", NULL };

    reset_behaviour();
    bx->socketpair_result = -1;
    check("a socketpair failure refuses the run", run_main(argv) == EXIT_SETUP_ERROR);

    char *verbose_argv[] = { "guard", "--verbose", "--", "cmd", NULL };
    reset_behaviour();
    bx->socketpair_result = -1;
    check("--verbose is accepted before the command", run_main(verbose_argv) == EXIT_SETUP_ERROR);

    reset_behaviour();
    bx->fork_result = -1;
    check("a fork failure refuses the run", run_main(argv) == EXIT_SETUP_ERROR);

    reset_behaviour();
    bx->fork_result = 0; /* the child path */
    bx->prctl_result = -1;
    check("a no_new_privs failure fails the child closed", run_main(argv) == EXIT_SETUP_ERROR);

    reset_behaviour();
    bx->fork_result = 0;
    bx->seccomp_listener_result = -1;
    check("a filter that will not install fails the child closed",
          run_main(argv) == EXIT_SETUP_ERROR);

    reset_behaviour();
    bx->fork_result = 0;
    bx->sendmsg_result = -1;
    check("a descriptor handoff that fails fails the child closed",
          run_main(argv) == EXIT_SETUP_ERROR);

    reset_behaviour();
    bx->fork_result = 0;
    bx->sendmsg_eintr_once = 1;
    bx->execvp_returns = 1;
    check("the child that hands over and cannot exec exits 127", run_main(argv) == 127);
}

static void test_parent_paths(void)
{
    char *argv[] = { "guard", "--", "cmd", NULL };

    reset_behaviour();
    bx->fork_result = 99; /* the parent path */
    bx->recvmsg_result = -1;
    bx->waitpid_eintr_once = 1; /* the reap on the refusal path retries once */
    check("a parent that is never handed the descriptor refuses the run",
          run_main(argv) == EXIT_SETUP_ERROR);

    reset_behaviour();
    bx->fork_result = 99;
    bx->recvmsg_result = -1;
    bx->recorded_child_status = (3 << 8); /* the child died with a code of its own */
    check("a refusal keeps the child's own non-zero exit code", run_main(argv) == 3);

    reset_behaviour();
    bx->fork_result = 99;
    bx->recvmsg_bad_cmsg = 1;
    check("a parent handed a malformed message refuses the run",
          run_main(argv) == EXIT_SETUP_ERROR);

    reset_behaviour();
    bx->fork_result = 99;
    bx->recvmsg_eintr_once = 1; /* the recv retries, then the first poll hangs up */
    bx->waitpid_eintr_once = 1; /* the reap on the normal path retries once */
    check("a parent supervises and then reaps the child, mapping its status",
          run_main(argv) == 0);
}

int main(void)
{
    /* Line-buffer stdout so a forked test-child never inherits a partial buffer and
     * re-emits it on exit, which would otherwise print every line several times when
     * stdout is a pipe rather than a terminal, as it is under CI. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    bx = mmap(NULL, sizeof(*bx), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (bx == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    reset_behaviour();

    test_rule_parsing();
    test_policy_matching();
    test_address_and_destination();
    test_exit_code_mapping();
    test_verbose_logging();
    test_read_peer_address_edges();
    test_receive_descriptor();
    test_service_paths();
    test_egress_syscalls();
    test_connect_on_behalf_paths();
    test_supervise_loop();
    test_argument_errors();
    test_child_setup_failures();
    test_parent_paths();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
