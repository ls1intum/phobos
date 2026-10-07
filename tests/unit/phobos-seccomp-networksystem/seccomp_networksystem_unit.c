/*
 * Unit tests for phobos-seccomp-networksystem.
 *
 * The integration suite tests/integration/seccomp_networksystem.sh and the acceptance suite
 * tests/integration/landlock-filesystem-and-networksystem-acceptance/seccomp-networksystem-test.sh exercise the guard against a real
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
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>

#ifndef PHOBOS_CONNECT_GUARD_UNIT_TEST
#define PHOBOS_CONNECT_GUARD_UNIT_TEST
#endif
#define main sut_main
#include "../../../core/phobos-seccomp-networksystem/phobos-seccomp-networksystem.c"
#undef main
#include "../../../core/phobos-seccomp-networksystem/phobos-seccomp-networksystem-child.h"
#include "../../../core/phobos-seccomp-networksystem/phobos-seccomp-networksystem-destination.h"
#include "../../../core/phobos-seccomp-networksystem/phobos-seccomp-networksystem-held-sockets.h"
#include "../../../core/phobos-seccomp-networksystem/phobos-seccomp-networksystem-socket-types.h"

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
static constexpr unsigned long FAKE_NOFILE_LIMIT = 4096;        /* a soft descriptor limit larger than the floor */
static constexpr int FAKE_BOOTSTRAP_DESCRIPTOR = 1023;          /* where the bootstrap end is moved under that limit; matches BOOTSTRAP_DESCRIPTOR_FLOOR */
static constexpr unsigned long FAKE_SMALL_NOFILE = 512;         /* a soft descriptor limit below the floor */
static constexpr int FAKE_SMALL_BOOTSTRAP = 511;                /* where the bootstrap end is moved under that small limit: FAKE_SMALL_NOFILE - 1 */
static constexpr int FAKE_RECEIVED_DESCRIPTOR = 30;             /* the descriptor recvmsg carries */
static constexpr int FAKE_ADDFD_DESCRIPTOR = 40;                /* the descriptor ADDFD reports installed */
static constexpr uint64_t FAKE_NOTIFICATION_ID = 555;           /* the id of every notification NOTIF_RECV returns */
static constexpr uint32_t FAKE_COMMAND_PID = 12345;             /* the pid of every notification NOTIF_RECV returns */
static constexpr pid_t FAKE_CHILD_PID = 99;                     /* what the wrapped fork returns on the parent path */
static constexpr uint64_t FAKE_ADDRESS_POINTER = 0x4000;        /* a command pointer to an address or a message vector */
static constexpr uintptr_t FAKE_MESSAGE_NAME_POINTER = 0x5000;  /* msg_name inside a faked sendmmsg entry */
static constexpr uintptr_t FAKE_IOVEC_POINTER = 0x1000000;      /* msg_iov inside a faked message header, beyond any faked sendmmsg vector */
static constexpr uintptr_t FAKE_DATA_POINTER = 0x2000000;       /* the data a faked send names, up to FAKE_DATA_SPAN bytes */
static constexpr uintptr_t FAKE_DATA_SPAN = 0x1000000;          /* how far past FAKE_DATA_POINTER a read still counts as data */
static constexpr size_t FAKE_DATAGRAM_LENGTH = 16;              /* the length of every segment a faked send names */
static constexpr uint16_t FAKE_DNS_ID = 0xBEEF;                 /* what the wrapped getrandom hands out, so a case knows the id */
static constexpr size_t DNS_TEST_HEADER = 12;                   /* the length of a DNS message's header */
static constexpr size_t DNS_TEST_OPT_RECORD = 11;               /* the EDNS0 record the query ends with */

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

/* What the wrapped resolver answers a query of one record type with. */
enum dns_behaviour {
    DNS_NORMAL,             /* two IPv4 addresses for A, one IPv6 address for AAAA */
    DNS_NO_RECORDS,         /* no error, and no record */
    DNS_NXDOMAIN,           /* the name does not exist */
    DNS_SERVFAIL,           /* the resolver failed */
    DNS_TRUNCATED,          /* the truncation bit set */
    DNS_SILENT,             /* no answer at all */
    DNS_WRONG_ID,           /* an answer to another query */
    DNS_WRONG_QUESTION,     /* an answer whose question is another name */
    DNS_NOT_A_RESPONSE,     /* the query echoed back, not marked as a response */
    DNS_NONSTANDARD_OPCODE, /* a response with an opcode that is not a query */
    DNS_TWO_QUESTIONS,      /* a response that claims two questions */
    DNS_MANY,               /* twenty addresses of the asked type */
    DNS_ALIAS,              /* an alias record, then the addresses */
    DNS_FOREIGN_CLASS,      /* records of a class other than the Internet one */
    DNS_OTHER_TYPE,         /* an AAAA record in the answer to an A query, and the other way round */
    DNS_LABEL_OWNER,        /* the normal answer, its records named by labels, not a pointer */
    DNS_FOREIGN_OWNER,      /* well formed address records that belong to another name */
    DNS_ALIAS_CHAIN,        /* the address first, then two aliases that lead to it, in the wrong order */
    DNS_ALIAS_LOOP,         /* two aliases that lead to each other, and an address for neither */
    DNS_ALIAS_DEEP,         /* a chain of ten aliases, the address at the end of it */
    DNS_ALIAS_TARGET_CUT,   /* an alias whose target runs past the end of its data */
    DNS_TOO_MANY_RECORDS,   /* more records than one answer may hold */
    DNS_OWNER_WITH_DOT,     /* an address record owned by one label that holds a dot, spelling the name asked */
    DNS_OWNER_WITH_ZERO     /* an address record owned by labels one of which holds a zero byte */
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
/* Room for the handler of every signal number the supervisor installs one for. */
static constexpr int SIGNAL_SLOTS = 64;

struct behaviour {
    /* seccomp NEW_LISTENER (via syscall) */
    long seccomp_listener_result;
    /* The filter the child handed SECCOMP_SET_MODE_FILTER, kept so a case can run it. */
    struct sock_filter installed_filter[CAPTURED_FILTER_LENGTH];
    unsigned short installed_filter_length;
    /* The second, listener-less filter that locks out the bootstrap sendmsg, kept apart. */
    struct sock_filter installed_filter2[CAPTURED_FILTER_LENGTH];
    unsigned short installed_filter2_length;
    long sendmsg_lockout_result;
    /* SECCOMP_GET_NOTIF_SIZES (via syscall) */
    int notif_sizes_result;
    int notif_sizes_small;
    /* socketpair, fork, prctl, signal, execvp */
    int socketpair_result;
    long fork_result;
    int prctl_result;
    int execvp_returns;
    /* getrlimit and dup2, for moving the bootstrap descriptor high before the filters go on */
    int getrlimit_result;
    unsigned long rlimit_nofile_cur;
    int dup2_fails;
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
    int msg_mode;
    int msg_name_missing;
    int addr_read_seen;
    unsigned int mmsg_count;
    int mmsg_vlen_zero;
    int id_valid_seen;
    int id_valid_fail_at;
    int notif_recv_family;
    uint16_t notif_recv_port;
    uint32_t notif_recv_v4_addr;
    uint32_t notif_recv_target_fd;
    int notif_id_valid_result;
    int notif_addfd_result;
    int notif_send_result;
    int readlink_kind;
    unsigned long long readlink_inode;
    int fcntl_fails;
    /* the listen the supervisor runs itself, and the socket address it reads first */
    int notif_listen_backlog;
    int listen_result;
    int listen_errno;
    int listen_calls;
    int last_listen_backlog;
    int last_listen_descriptor;
    int getsockname_result;
    int getsockname_family;
    uint16_t getsockname_port;
    /* the datagrams the supervisor sends itself */
    int sendto_result;          /* 0: the whole length goes; above 0: that many bytes; below 0: fail */
    int sendto_errno;
    int sendto_calls;
    int sendto_eagain_first;    /* how many calls fail with EAGAIN before one is let go */
    int sendto_eintr_once;
    size_t last_sendto_length;
    int last_sendto_flags;
    socklen_t last_sendto_name_length;
    uint16_t last_sendto_port;
    int fcntl_getfl_value;
    int last_connect_descriptor;
    int writev_fail_at;         /* the 1-based write-back that fails, and every one after it; 0 never */
    int writev_short;           /* when not zero, a write-back that reports fewer bytes than asked */
    int writev_calls;
    unsigned int written_lengths[8];
    int iov_count;              /* the segments a faked message header names */
    size_t segment_length;      /* the length of each of them */
    size_t message_iovlen;      /* when not zero, msg_iovlen claims this instead */
    int message_control;        /* when not zero, the header carries ancillary data */
    int iov_unreadable;
    int data_unreadable;
    size_t sendto_length;       /* the length argument of a faked sendto */
    socklen_t sendto_address_length;  /* when not zero, the address length argument of a faked sendto */
    /* the resolve mode's lookups: what each record type is answered with, and what it was asked */
    int dns_active;             /* set while a resolve case runs, so poll and send know whose they are */
    int dns_behaviour[2];       /* for A (0) and AAAA (1), a dns_behaviour value */
    int dns_strays;             /* how many packets that are not the answer arrive before it, per try */
    int dns_stray_remaining;
    int dns_cut_to;             /* when not zero, the reply is cut to this many bytes */
    int dns_count_override;     /* when not negative, the reply's answer count is this */
    int dns_poke_offset;        /* when not negative, a byte of the first answer is changed */
    int dns_poke_value;
    int dns_poke_second;        /* the byte after it, which a pointer needs as its second half */
    int dns_record_class;       /* when not zero, the class of the records in the reply */
    int recv_fails;
    int getrandom_fails;
    int dns_queries;
    unsigned char dns_query[512];
    size_t dns_query_length;
    /* the peer-address read */
    ssize_t process_vm_readv_result;
    /* the outward connection */
    int socket_result;
    int connect_result;      /* 0 ok, -1 sets connect_errno */
    int connect_errno;
    int last_connect_family;
    uint16_t last_connect_port;
    int poll_result;
    int poll_eintr_once;
    int poll_calls;
    short poll_revents;
    int getsockopt_result;
    int getsockopt_so_error;
    /* the PROXY header the guard sends a broker before the command's bytes */
    int send_calls;
    int send_fails;
    int send_eintr_once;
    int send_short_once;
    unsigned char captured_header[64];
    size_t captured_header_length;
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
    int waitpid_echild;
    int notif_send_eintr;
    /* sigaction on SIGCHLD: how often the default was taken (with the old one kept) and how
     * often a kept disposition was given back */
    int child_signal_taken;
    int child_signal_restored;
    int calloc_fails;
    /* signal and kill: the handlers the supervisor installed, and what they then sent */
    void (*signal_handler[SIGNAL_SLOTS])(int);
    int kill_calls;
    int last_kill_pid;
    int last_kill_signal;
    unsigned int kill_signal_mask;
    int signals_at_reap;
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
    bx->getrlimit_result = 0;
    bx->rlimit_nofile_cur = FAKE_NOFILE_LIMIT;
    bx->dup2_fails = 0;
    connect_rules_reset_for_tests();
    broker_reset_for_tests();
    set_verbose(false);
    socket_types_reset_for_tests();
    held_sockets_reset_for_tests();
    ephemeral_listen_reset_for_tests();
    ephemeral_udp_bind_reset_for_tests();
    bx->getsockname_family = AF_INET;
    bx->iov_count = 1;
    bx->segment_length = FAKE_DATAGRAM_LENGTH;
    bx->sendto_length = FAKE_DATAGRAM_LENGTH;
    bx->dns_count_override = -1;
    bx->dns_poke_offset = -1;
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
        const struct sock_fprog *program = (const struct sock_fprog *)(uintptr_t)a3;
        if (a2 & SECCOMP_FILTER_FLAG_NEW_LISTENER) {
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
        if (program != NULL && program->len <= CAPTURED_FILTER_LENGTH) {
            memcpy(bx->installed_filter2, program->filter,
                   (size_t)program->len * sizeof(struct sock_filter));
            bx->installed_filter2_length = program->len;
        }
        if (bx->sendmsg_lockout_result != 0) {
            errno = EACCES;
        }
        return bx->sendmsg_lockout_result;
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

int __wrap_getrlimit(int resource, struct rlimit *limit) {
    (void)resource;
    if (bx->getrlimit_result != 0) {
        errno = EINVAL;
        return -1;
    }
    limit->rlim_cur = (rlim_t)bx->rlimit_nofile_cur;
    limit->rlim_max = (rlim_t)bx->rlimit_nofile_cur;
    return 0;
}

int __wrap_dup2(int old_descriptor, int new_descriptor) {
    (void)old_descriptor;
    if (bx->dup2_fails) {
        errno = EBADF;
        return -1;
    }
    return new_descriptor;
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
    if (signum > 0 && signum < SIGNAL_SLOTS) {
        bx->signal_handler[signum] = handler;
    }
    return NULL;
}

/* Records each change of SIGCHLD's disposition, then makes it: giving it the default while keeping
 * the old one is the supervisor taking it over, and setting one without keeping is giving it back. */
int __real_sigaction(int signum, const struct sigaction *action, struct sigaction *old);
int __wrap_sigaction(int signum, const struct sigaction *action, struct sigaction *old) {
    if (signum == SIGCHLD && action != NULL && old != NULL && action->sa_handler == SIG_DFL) {
        bx->child_signal_taken++;
    } else if (signum == SIGCHLD && action != NULL && old == NULL) {
        bx->child_signal_restored++;
    }
    return __real_sigaction(signum, action, old);
}

int __wrap_kill(pid_t pid, int signum) {
    bx->kill_calls++;
    bx->last_kill_pid = (int)pid;
    bx->last_kill_signal = signum;
    bx->kill_signal_mask |= 1u << signum;
    return 0;
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
    if (bx->signals_at_reap) {
        bx->signals_at_reap = 0;
        for (int number = 1; number < SIGNAL_SLOTS; number++) {
            if (bx->signal_handler[number] != nullptr) {
                bx->signal_handler[number](number);
            }
        }
    }
    if (bx->waitpid_eintr_once) {
        bx->waitpid_eintr_once = 0;
        errno = EINTR;
        return -1;
    }
    if (bx->waitpid_echild) {
        errno = ECHILD;
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
    uintptr_t remote_base = (uintptr_t)remote->iov_base;
    if (remote_base == FAKE_IOVEC_POINTER) {
        if (bx->iov_unreadable) {
            return 0;
        }
        struct iovec *segments = local->iov_base;
        for (size_t index = 0; index < local->iov_len / sizeof(struct iovec); index++) {
            segments[index].iov_base = (void *)(FAKE_DATA_POINTER + index * FAKE_DATAGRAM_LENGTH);
            segments[index].iov_len = bx->segment_length;
        }
        return (ssize_t)local->iov_len;
    }
    if (remote_base >= FAKE_DATA_POINTER && remote_base < FAKE_DATA_POINTER + FAKE_DATA_SPAN) {
        if (bx->data_unreadable) {
            return 0;
        }
        memset(local->iov_base, 0xAB, local->iov_len);
        return (ssize_t)local->iov_len;
    }
    if (bx->mmsg_mode && local->iov_len == sizeof(struct mmsghdr)) {
        struct mmsghdr batch_entry;
        memset(&batch_entry, 0, sizeof(batch_entry));
        if (!bx->mmsg_name_missing) {
            batch_entry.msg_hdr.msg_name = (void *)FAKE_MESSAGE_NAME_POINTER;
            batch_entry.msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
        }
        batch_entry.msg_hdr.msg_iov = (struct iovec *)FAKE_IOVEC_POINTER;
        batch_entry.msg_hdr.msg_iovlen = bx->message_iovlen != 0 ? bx->message_iovlen : (size_t)bx->iov_count;
        batch_entry.msg_hdr.msg_controllen = bx->message_control ? 8 : 0;
        memcpy(local->iov_base, &batch_entry, local->iov_len);
        return (ssize_t)local->iov_len;
    }
    if (bx->msg_mode && local->iov_len == sizeof(struct msghdr)) {
        struct msghdr header;
        memset(&header, 0, sizeof(header));
        if (!bx->msg_name_missing) {
            header.msg_name = (void *)FAKE_MESSAGE_NAME_POINTER;
            header.msg_namelen = sizeof(struct sockaddr_in);
        }
        header.msg_iov = (struct iovec *)FAKE_IOVEC_POINTER;
        header.msg_iovlen = bx->message_iovlen != 0 ? bx->message_iovlen : (size_t)bx->iov_count;
        header.msg_controllen = bx->message_control ? 8 : 0;
        memcpy(local->iov_base, &header, local->iov_len);
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
        v4->sin_addr.s_addr = htonl(bx->notif_recv_v4_addr != 0 ? bx->notif_recv_v4_addr : INADDR_LOOPBACK);
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
    if (bx->fcntl_fails) {
        errno = EINVAL;
        return -1;
    }
    return command == F_GETFL ? bx->fcntl_getfl_value : 0;
}

int __wrap_listen(int fd, int backlog) {
    bx->listen_calls++;
    bx->last_listen_descriptor = fd;
    bx->last_listen_backlog = backlog;
    if (bx->listen_result != 0) {
        errno = bx->listen_errno;
        return -1;
    }
    return 0;
}

int __wrap_getsockname(int fd, struct sockaddr *address, socklen_t *length) {
    (void)fd;
    if (bx->getsockname_result != 0) {
        errno = ENOTSOCK;
        return -1;
    }
    memset(address, 0, *length);
    address->sa_family = (sa_family_t)bx->getsockname_family;
    if (bx->getsockname_family == AF_INET) {
        ((struct sockaddr_in *)address)->sin_port = htons(bx->getsockname_port);
    } else if (bx->getsockname_family == AF_INET6) {
        ((struct sockaddr_in6 *)address)->sin6_port = htons(bx->getsockname_port);
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
    bx->last_connect_descriptor = fd;
    bx->connect_calls++;
    if (address != NULL && length >= (socklen_t)sizeof(struct sockaddr_in)) {
        bx->last_connect_family = address->sa_family;
        if (address->sa_family == AF_INET) {
            bx->last_connect_port = ntohs(((const struct sockaddr_in *)address)->sin_port);
        } else if (address->sa_family == AF_INET6) {
            bx->last_connect_port = ntohs(((const struct sockaddr_in6 *)address)->sin6_port);
        }
    }
    if (bx->connect_result == 0) {
        return 0;
    }
    errno = bx->connect_errno;
    return -1;
}

ssize_t __wrap_send(int fd, const void *buffer, size_t length, int flags) {
    (void)fd;
    (void)flags;
    bx->send_calls++;
    if (bx->send_eintr_once) {
        bx->send_eintr_once = 0;
        errno = EINTR;
        return -1;
    }
    if (bx->send_fails) {
        errno = ECONNREFUSED;
        return -1;
    }
    if (bx->dns_active) {
        bx->dns_queries++;
        bx->dns_stray_remaining = bx->dns_strays;
        bx->dns_query_length = length < sizeof(bx->dns_query) ? length : sizeof(bx->dns_query);
        memcpy(bx->dns_query, buffer, bx->dns_query_length);
        return (ssize_t)length;
    }
    size_t take = length;
    if (bx->send_short_once && take > 1) {
        bx->send_short_once = 0;
        take = 1;
    }
    if (bx->captured_header_length + take <= sizeof(bx->captured_header)) {
        memcpy(bx->captured_header + bx->captured_header_length, buffer, take);
        bx->captured_header_length += take;
    }
    return (ssize_t)take;
}

/* The datagram the supervisor sends itself: what it was asked to send is recorded, and the answer
 * is the one a case arranged. */
ssize_t __wrap_sendto(int fd, const void *buffer, size_t length, int flags,
                      const struct sockaddr *address, socklen_t address_length) {
    (void)fd;
    (void)buffer;
    bx->sendto_calls++;
    bx->last_sendto_length = length;
    bx->last_sendto_flags = flags;
    bx->last_sendto_name_length = address == NULL ? 0 : address_length;
    if (address != NULL && address->sa_family == AF_INET) {
        bx->last_sendto_port = ntohs(((const struct sockaddr_in *)address)->sin_port);
    } else if (address != NULL && address->sa_family == AF_INET6) {
        bx->last_sendto_port = ntohs(((const struct sockaddr_in6 *)address)->sin6_port);
    }
    if (bx->sendto_eintr_once) {
        bx->sendto_eintr_once = 0;
        errno = EINTR;
        return -1;
    }
    if (bx->sendto_eagain_first > 0) {
        bx->sendto_eagain_first--;
        errno = EAGAIN;
        return -1;
    }
    if (bx->sendto_result < 0) {
        errno = bx->sendto_errno;
        return -1;
    }
    return bx->sendto_result > 0 ? bx->sendto_result : (ssize_t)length;
}

/* The length of a sent message written back into the command's vector: recorded, in order. */
ssize_t __wrap_process_vm_writev(pid_t pid, const struct iovec *local, unsigned long liovcnt,
                                 const struct iovec *remote, unsigned long riovcnt,
                                 unsigned long flags) {
    (void)pid;
    (void)liovcnt;
    (void)remote;
    (void)riovcnt;
    (void)flags;
    int call = bx->writev_calls++;
    if (bx->writev_fail_at != 0 && call + 1 >= bx->writev_fail_at) {
        errno = EFAULT;
        return -1;
    }
    if (bx->writev_short) {
        return 0;
    }
    if (call < (int)(sizeof(bx->written_lengths) / sizeof(bx->written_lengths[0]))) {
        memcpy(&bx->written_lengths[call], local->iov_base, sizeof(unsigned int));
    }
    return (ssize_t)local->iov_len;
}

/* How long the DNS names in the test answers are: the question, as the query carried it. */
static size_t dns_question_length(void) {
    return bx->dns_query_length - DNS_TEST_HEADER - DNS_TEST_OPT_RECORD;
}

/* Appends one record to a reply: an owner name that points back at the question, the type and
 * class, a time to live and the data. */
static bool dns_use_label_owner = false;
/* When set, the owner of the next records is these bytes, a name written out, not the question. */
static const unsigned char *dns_owner_bytes = NULL;
static size_t dns_owner_length = 0;

static size_t dns_add_record(unsigned char *out, size_t at, uint16_t type, uint16_t klass,
                             const unsigned char *data, size_t data_length) {
    if (dns_owner_bytes != NULL) {
        memcpy(out + at, dns_owner_bytes, dns_owner_length);
        at += dns_owner_length;
    } else if (dns_use_label_owner) {
        size_t name_length = 0;
        while (out[DNS_TEST_HEADER + name_length] != 0) {
            name_length += (size_t)out[DNS_TEST_HEADER + name_length] + 1;
        }
        name_length++;
        memcpy(out + at, out + DNS_TEST_HEADER, name_length);
        at += name_length;
    } else {
        out[at++] = 0xc0;
        out[at++] = DNS_TEST_HEADER;
    }
    out[at++] = (unsigned char)(type >> 8);
    out[at++] = (unsigned char)(type & 0xff);
    out[at++] = (unsigned char)(klass >> 8);
    out[at++] = (unsigned char)(klass & 0xff);
    memset(out + at, 0, 3);
    at += 3;
    out[at++] = 60;
    out[at++] = (unsigned char)(data_length >> 8);
    out[at++] = (unsigned char)(data_length & 0xff);
    memcpy(out + at, data, data_length);
    return at + data_length;
}

/* Builds the answer the case arranged for the query last sent, from that query's own header and
 * question, so that what the guard checks the answer against is what it asked. */
static size_t dns_build_reply(unsigned char *out, size_t size) {
    (void)size;
    int type_index = bx->dns_query[bx->dns_query_length - DNS_TEST_OPT_RECORD - 3] == 28 ? 1 : 0;
    int behaviour = bx->dns_behaviour[type_index];
    uint16_t asked = type_index == 1 ? 28 : 1;
    size_t end = DNS_TEST_HEADER + dns_question_length();
    memcpy(out, bx->dns_query, end);
    out[2] = (unsigned char)(0x80 | (bx->dns_query[2] & 0x01));
    out[3] = 0x80;
    memset(out + 6, 0, 6);
    out[5] = 1;
    size_t at = end;
    unsigned int answers = 0;
    uint16_t klass = bx->dns_record_class != 0 ? (uint16_t)bx->dns_record_class : 1;
    dns_use_label_owner = behaviour == DNS_LABEL_OWNER;
    unsigned char v4_first[4] = { 192, 0, 2, 1 };
    unsigned char v4_second[4] = { 192, 0, 2, 2 };
    unsigned char v6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    switch (behaviour) {
    case DNS_NXDOMAIN:
        out[3] = 0x83;
        break;
    case DNS_SERVFAIL:
        out[3] = 0x82;
        break;
    case DNS_TRUNCATED:
        out[2] |= 0x02;
        break;
    case DNS_WRONG_ID:
        out[0] ^= 0xff;
        break;
    case DNS_WRONG_QUESTION:
        out[DNS_TEST_HEADER + 1] ^= 0x01;
        break;
    case DNS_NOT_A_RESPONSE:
        out[2] &= (unsigned char)~0x80;
        break;
    case DNS_NONSTANDARD_OPCODE:
        out[2] |= 0x10;
        break;
    case DNS_TWO_QUESTIONS:
        out[5] = 2;
        break;
    case DNS_MANY:
        for (unsigned char index = 0; index < 20; index++) {
            unsigned char v4[4] = { 198, 51, 100, (unsigned char)(index + 1) };
            unsigned char many6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (unsigned char)(index + 1) };
            at = asked == 1 ? dns_add_record(out, at, 1, 1, v4, sizeof(v4))
                            : dns_add_record(out, at, 28, 1, many6, sizeof(many6));
            answers++;
        }
        break;
    case DNS_ALIAS: {
        unsigned char alias[] = { 5, 'a', 'l', 'i', 'a', 's', 0 };
        at = dns_add_record(out, at, 5, 1, alias, sizeof(alias));
        answers++;
        dns_owner_bytes = alias;
        dns_owner_length = sizeof(alias);
        at = asked == 1 ? dns_add_record(out, at, 1, 1, v4_first, sizeof(v4_first))
                        : dns_add_record(out, at, 28, 1, v6, sizeof(v6));
        dns_owner_bytes = NULL;
        answers++;
        break;
    }
    case DNS_FOREIGN_OWNER: {
        unsigned char other[] = { 5, 'o', 't', 'h', 'e', 'r', 0 };
        dns_owner_bytes = other;
        dns_owner_length = sizeof(other);
        at = asked == 1 ? dns_add_record(out, at, 1, 1, v4_first, sizeof(v4_first))
                        : dns_add_record(out, at, 28, 1, v6, sizeof(v6));
        dns_owner_bytes = NULL;
        answers++;
        break;
    }
    case DNS_ALIAS_CHAIN: {
        unsigned char first_alias[] = { 3, 'o', 'n', 'e', 0 };
        unsigned char second_alias[] = { 3, 't', 'w', 'o', 0 };
        dns_owner_bytes = second_alias;
        dns_owner_length = sizeof(second_alias);
        at = asked == 1 ? dns_add_record(out, at, 1, 1, v4_first, sizeof(v4_first))
                        : dns_add_record(out, at, 28, 1, v6, sizeof(v6));
        dns_owner_bytes = first_alias;
        dns_owner_length = sizeof(first_alias);
        at = dns_add_record(out, at, 5, 1, second_alias, sizeof(second_alias));
        dns_owner_bytes = NULL;
        at = dns_add_record(out, at, 5, 1, first_alias, sizeof(first_alias));
        answers += 3;
        break;
    }
    case DNS_ALIAS_LOOP: {
        unsigned char first_alias[] = { 3, 'o', 'n', 'e', 0 };
        unsigned char second_alias[] = { 3, 't', 'w', 'o', 0 };
        at = dns_add_record(out, at, 5, 1, first_alias, sizeof(first_alias));
        dns_owner_bytes = first_alias;
        dns_owner_length = sizeof(first_alias);
        at = dns_add_record(out, at, 5, 1, second_alias, sizeof(second_alias));
        dns_owner_bytes = second_alias;
        dns_owner_length = sizeof(second_alias);
        at = dns_add_record(out, at, 5, 1, first_alias, sizeof(first_alias));
        dns_owner_bytes = NULL;
        answers += 3;
        break;
    }
    case DNS_ALIAS_DEEP: {
        unsigned char names[11][5];
        for (unsigned char index = 0; index < 11; index++) {
            names[index][0] = 3;
            names[index][1] = 'n';
            names[index][2] = (unsigned char)('a' + index);
            names[index][3] = 'x';
            names[index][4] = 0;
        }
        at = dns_add_record(out, at, 5, 1, names[0], 5);
        for (int index = 0; index < 10; index++) {
            dns_owner_bytes = names[index];
            dns_owner_length = 5;
            at = dns_add_record(out, at, 5, 1, names[index + 1], 5);
        }
        dns_owner_bytes = names[10];
        at = asked == 1 ? dns_add_record(out, at, 1, 1, v4_first, sizeof(v4_first))
                        : dns_add_record(out, at, 28, 1, v6, sizeof(v6));
        dns_owner_bytes = NULL;
        answers += 12;
        break;
    }
    case DNS_ALIAS_TARGET_CUT: {
        unsigned char cut_target[] = { 40, 'a', 'b' };
        at = dns_add_record(out, at, 5, 1, cut_target, sizeof(cut_target));
        answers++;
        break;
    }
    case DNS_OWNER_WITH_DOT: {
        unsigned char dotted[] = { 12, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 't', 'e', 's', 't', 0 };
        dns_owner_bytes = dotted;
        dns_owner_length = sizeof(dotted);
        at = asked == 1 ? dns_add_record(out, at, 1, 1, v4_first, sizeof(v4_first))
                        : dns_add_record(out, at, 28, 1, v6, sizeof(v6));
        dns_owner_bytes = NULL;
        answers++;
        break;
    }
    case DNS_OWNER_WITH_ZERO: {
        unsigned char zeroed[] = { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 9, 't', 'e', 's', 't', 0, 'e', 'v', 'i', 'l', 0 };
        dns_owner_bytes = zeroed;
        dns_owner_length = sizeof(zeroed);
        at = asked == 1 ? dns_add_record(out, at, 1, 1, v4_first, sizeof(v4_first))
                        : dns_add_record(out, at, 28, 1, v6, sizeof(v6));
        dns_owner_bytes = NULL;
        answers++;
        break;
    }
    case DNS_TOO_MANY_RECORDS:
        for (int index = 0; index < 65; index++) {
            at = asked == 1 ? dns_add_record(out, at, 1, 1, v4_first, sizeof(v4_first))
                            : dns_add_record(out, at, 28, 1, v6, sizeof(v6));
            answers++;
        }
        break;
    case DNS_OTHER_TYPE:
        at = asked == 1 ? dns_add_record(out, at, 28, 1, v6, sizeof(v6))
                        : dns_add_record(out, at, 1, 1, v4_first, sizeof(v4_first));
        answers++;
        at = asked == 1 ? dns_add_record(out, at, 1, klass, v4_first, sizeof(v4_first))
                        : dns_add_record(out, at, 28, klass, v6, sizeof(v6));
        answers++;
        break;
    case DNS_FOREIGN_CLASS:
        at = asked == 1 ? dns_add_record(out, at, 1, 3, v4_first, sizeof(v4_first))
                        : dns_add_record(out, at, 28, 3, v6, sizeof(v6));
        answers++;
        at = asked == 1 ? dns_add_record(out, at, 1, 1, v4_second, sizeof(v4_second))
                        : dns_add_record(out, at, 28, 1, v6, sizeof(v6));
        answers++;
        break;
    case DNS_LABEL_OWNER:
    case DNS_NORMAL:
        if (asked == 1) {
            at = dns_add_record(out, at, 1, klass, v4_first, sizeof(v4_first));
            at = dns_add_record(out, at, 1, klass, v4_second, sizeof(v4_second));
            answers = 2;
        } else {
            at = dns_add_record(out, at, 28, klass, v6, sizeof(v6));
            answers = 1;
        }
        break;
    default:
        break;
    }
    out[6] = (unsigned char)(answers >> 8);
    out[7] = (unsigned char)(answers & 0xff);
    if (bx->dns_count_override >= 0) {
        out[7] = (unsigned char)bx->dns_count_override;
    }
    if (bx->dns_poke_offset >= 0) {
        out[end + (size_t)bx->dns_poke_offset] = (unsigned char)bx->dns_poke_value;
        out[end + (size_t)bx->dns_poke_offset + 1] = (unsigned char)bx->dns_poke_second;
    }
    if (bx->dns_cut_to > 0 && (size_t)bx->dns_cut_to < at) {
        at = (size_t)bx->dns_cut_to;
    }
    return at;
}

/* The wrapped recv, for the resolve mode: first any packets that are not the answer, then the
 * answer the case arranged. */
ssize_t __wrap_recv(int fd, void *buffer, size_t length, int flags) {
    (void)fd;
    (void)flags;
    if (bx->recv_fails) {
        errno = ECONNREFUSED;
        return -1;
    }
    unsigned char reply[1500];
    size_t reply_length = dns_build_reply(reply, sizeof(reply));
    if (bx->dns_stray_remaining > 0) {
        bx->dns_stray_remaining--;
        reply[0] ^= 0xff;
    }
    size_t take = reply_length < length ? reply_length : length;
    memcpy(buffer, reply, take);
    return (ssize_t)take;
}

/* The id every query carries, so a case can build the answer that matches it or one that does not. */
ssize_t __wrap_getrandom(void *buffer, size_t length, unsigned int flags) {
    (void)flags;
    if (bx->getrandom_fails) {
        errno = EAGAIN;
        return -1;
    }
    uint16_t id = FAKE_DNS_ID;
    memcpy(buffer, &id, length < sizeof(id) ? length : sizeof(id));
    return (ssize_t)length;
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
    bx->poll_calls++;
    if (bx->dns_active) {
        int type_index = bx->dns_query[bx->dns_query_length - DNS_TEST_OPT_RECORD - 3] == 28 ? 1 : 0;
        if (bx->dns_behaviour[type_index] == DNS_SILENT) {
            return 0;
        }
        fds[0].revents = POLLIN;
        return 1;
    }
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
        req->data.args[0] = bx->notif_recv_target_fd;
        if (bx->notif_recv_nr == __NR_socket) {
            req->data.args[0] = (uint64_t)bx->notif_socket_domain;
            req->data.args[1] = (uint64_t)bx->notif_socket_type;
            req->data.args[2] = (uint64_t)bx->notif_socket_protocol;
        } else if (bx->notif_recv_nr == __NR_sendto) {
            req->data.args[1] = FAKE_DATA_POINTER;
            req->data.args[2] = bx->sendto_length;
            req->data.args[3] = bx->notif_send_flags;
            req->data.args[4] = bx->notif_recv_family == 0 ? 0 : FAKE_ADDRESS_POINTER;
            req->data.args[5] = bx->notif_recv_family == 0 ? 0
                                : (bx->sendto_address_length != 0 ? bx->sendto_address_length : address_length);
        } else if (bx->notif_recv_nr == __NR_sendmmsg) {
            req->data.args[1] = FAKE_ADDRESS_POINTER;
            req->data.args[2] = bx->mmsg_vlen_zero ? 0 : (bx->mmsg_count ? bx->mmsg_count : 1);
            req->data.args[3] = bx->notif_send_flags;
        } else if (bx->notif_recv_nr == __NR_sendmsg) {
            req->data.args[1] = FAKE_ADDRESS_POINTER;
            req->data.args[2] = bx->notif_send_flags;
        } else if (bx->notif_recv_nr == __NR_listen) {
            req->data.args[0] = bx->notif_recv_target_fd;
            req->data.args[1] = (uint64_t)bx->notif_listen_backlog;
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
        if (bx->notif_send_eintr > 0) {
            bx->notif_send_eintr--;
            errno = EINTR;
            return -1;
        }
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

/* The exit status signals_taken_and_passed_on answers when every signal was taken, passed on while the
 * command existed, and no longer passed on once it was reaped. */
static constexpr int SIGNALS_PASSED_ON = 42;

/* Runs the guard's main in a forked child of the test, as run_main does, with the four signals delivered to
 * the supervisor at the moment it reaps the command, and then, in that same child because the command it
 * remembers is that child's own, delivers them once more after main has returned. Answers SIGNALS_PASSED_ON
 * when the first delivery made one kill of the command for each signal, and the second made none, since the
 * command was gone by then and its number may belong to another process; 1 otherwise. */
static int signals_taken_and_passed_on(char *const argv[]) {
    constexpr unsigned int WANTED = (1u << SIGTERM) | (1u << SIGHUP) | (1u << SIGINT) | (1u << SIGQUIT);
    int count = 0;
    while (argv[count] != NULL) {
        count++;
    }
    bx->signals_at_reap = 1;
    pid_t child = __real_fork();
    if (child == 0) {
        sut_main(count, (char **)argv);
        if (bx->kill_calls != 4 || bx->last_kill_pid != FAKE_CHILD_PID || bx->kill_signal_mask != WANTED) {
            _exit(1);
        }
        for (int number = 1; number < SIGNAL_SLOTS; number++) {
            if (bx->signal_handler[number] != nullptr) {
                bx->signal_handler[number](number);
            }
        }
        _exit(bx->kill_calls == 4 ? SIGNALS_PASSED_ON : 1);
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
    remember_rule("h", "0", false);
    remember_rule("h", "70000", false);
    remember_rule("h", "notanumber", false);
    check("port zero, out of range and non-numeric are dropped", connect_rules_count_for_tests() == 0);
    char big[MAXIMUM_HOST + OVERLONG_HOST_EXCESS];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    remember_rule(big, "443", false);
    check("an over-long host is dropped", connect_rules_count_for_tests() == 0);
    remember_rule("*.example.org", "443", false);
    remember_rule("a*b.example", "443", true);
    remember_rule("name.*", "443", false);
    remember_rule("*/8", "443", false);
    check("a wildcard host name is dropped for either transport", connect_rules_count_for_tests() == 0);
    remember_rule("*", "443", false);
    check("the bare star host is kept", connect_rules_count_for_tests() == 1);
    reset_behaviour();
    remember_rule("256.1.1.1", "443", false);
    remember_rule("1.2.3", "443", false);
    remember_rule("127.1", "443", false);
    remember_rule("2130706433", "443", false);
    remember_rule("::1::2", "443", false);
    remember_rule("fe80::1%eth0", "443", true);
    remember_rule("1.2.3.4.5", "443", false);
    check("a host written like an address that is not one is dropped, never read as a host name", connect_rules_count_for_tests() == 0);
    remember_rule("1password.example", "443", false);
    remember_rule("cafe.example", "443", false);
    remember_rule("10.0.0.0/8", "443", false);
    remember_rule("::1", "443", false);
    remember_rule("127.0.0.1", "443", false);
    check("a host name that holds digits, an address, a range and an IPv6 address are kept", connect_rules_count_for_tests() == 5);
    reset_behaviour();
    for (size_t i = 0; i < MAXIMUM_RULES + RULE_TABLE_OVERFLOW; i++) {
        remember_rule("127.0.0.1", "443", false);
    }
    check("the rule table does not overflow", connect_rules_count_for_tests() == MAXIMUM_RULES);
}

static bool permits_v4(const char *ip, uint16_t port) {
    struct in_addr address;
    inet_pton(AF_INET, ip, &address);
    return connection_permitted(AF_INET, &address, port, false);
}

static void test_policy_matching(void) {
    reset_behaviour();
    check("an empty allow-list denies every connect", !permits_v4("9.9.9.9", 443));

    reset_behaviour();
    remember_rule("256.1.1.1", "443", false);
    check("a rule for an address that is not one admits no address, not every address on its port", !permits_v4("127.0.0.9", 443));

    reset_behaviour();
    remember_rule("127.0.0.1", "443", false);
    check("an allow-listed IP and port is permitted", permits_v4("127.0.0.1", 443));
    check("the same IP on another port is refused", !permits_v4("127.0.0.1", 444));
    check("another IP on the allowed port is refused", !permits_v4("127.0.0.2", 443));

    reset_behaviour();
    remember_rule("example.com", "8080", false);
    check("a hostname rule permits any host on its port", permits_v4("9.9.9.9", 8080));
    check("a hostname rule refuses another port", !permits_v4("9.9.9.9", 80));

    reset_behaviour();
    remember_rule("*.example.org", "443", false);
    check("a wildcard host name permits nothing, not every host on its port", !permits_v4("9.9.9.9", 443));

    reset_behaviour();
    remember_rule("localhost", "*", false);
    check("localhost matches a loopback address", permits_v4("127.0.0.5", 12345));
    check("localhost refuses a non-loopback address", !permits_v4("8.8.8.8", 12345));

    reset_behaviour();
    remember_rule("*", "443", false);
    check("a wildcard host rests on the port", permits_v4("8.8.8.8", 443));

    reset_behaviour();
    remember_rule("::1", "443", false);
    struct in6_addr loop;
    inet_pton(AF_INET6, "::1", &loop);
    check("an IPv6 literal matches its address", connection_permitted(AF_INET6, &loop, 443, false));
    struct in6_addr other;
    inet_pton(AF_INET6, "2001:db8::2", &other);
    check("an IPv6 literal refuses another address", !connection_permitted(AF_INET6, &other, 443, false));

    reset_behaviour();
    remember_rule("2001:db8::1", "443", false);
    check("an IPv6 literal refuses yet another address",
          !connection_permitted(AF_INET6, &loop, 443, false));
    struct in_addr v4;
    inet_pton(AF_INET, "127.0.0.1", &v4);
    check("an IPv6 literal rule does not match an IPv4 destination",
          !connection_permitted(AF_INET, &v4, 443, false));

    reset_behaviour();
    remember_rule("1.2.3.4", "443", false);
    struct in6_addr any6;
    inet_pton(AF_INET6, "2001:db8::1", &any6);
    check("an IPv4 literal rule does not match an IPv6 destination",
          !connection_permitted(AF_INET6, &any6, 443, false));
}

static bool permits_v6(const char *ip, uint16_t port) {
    struct in6_addr address;
    inet_pton(AF_INET6, ip, &address);
    return connection_permitted(AF_INET6, &address, port, false);
}

static void test_connect_ranges(void) {
    reset_behaviour();
    remember_rule("104.16.0.0/12", "443", false);
    check("the range table kept the rule", connect_rules_count_for_tests() == 1);
    check("an IPv4 address inside the range on its port is permitted",
          permits_v4("104.16.5.5", 443));
    check("an IPv4 address inside the range on another port is refused",
          !permits_v4("104.16.5.5", 80));
    check("an IPv4 address outside the range is refused", !permits_v4("8.8.8.8", 443));

    reset_behaviour();
    remember_rule("127.0.0.1/32", "443", false);
    check("a /32 range matches exactly its address", permits_v4("127.0.0.1", 443));
    check("a /32 range refuses the neighbouring address", !permits_v4("127.0.0.2", 443));

    reset_behaviour();
    remember_rule("2001:db8::/32", "443", false);
    check("an IPv6 address inside the range is permitted", permits_v6("2001:db8::5", 443));
    check("an IPv6 address outside the range is refused", !permits_v6("2001:dead::5", 443));

    reset_behaviour();
    remember_rule("10.0.0.0/33", "443", false);
    remember_rule("10.0.0.0/0", "443", false);
    remember_rule("10.0.0.0/x", "443", false);
    remember_rule("nothost/8", "443", false);
    check("a malformed range is dropped", connect_rules_count_for_tests() == 0);

    reset_behaviour();
    remember_rule("::ffff:104.16.0.0/12", "443", false);
    check("an IPv4-mapped range with too short a prefix is dropped",
          connect_rules_count_for_tests() == 0);

    reset_behaviour();
    remember_rule("::ffff:104.16.0.0/108", "443", false);
    check("an IPv4-mapped range with a long-enough prefix is kept", connect_rules_count_for_tests() == 1);
    check("the mapped range matches an in-range IPv4 address", permits_v4("104.16.5.5", 443));
    check("the mapped range refuses an out-of-range IPv4 address", !permits_v4("8.8.8.8", 443));

    reset_behaviour();
    remember_rule("104.16.0.0/12", "*", false);
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

/* format_endpoint writes each family as the guard's log line needs it, cuts short safely and
 * never writes past the size it was given. */
static void test_format_endpoint(void) {
    char text[ENDPOINT_TEXT_SIZE];
    struct in_addr v4;
    inet_pton(AF_INET, "203.0.113.7", &v4);
    struct destination where = { .family = AF_INET, .address = &v4, .port = 443 };
    size_t length = format_endpoint(&where, text, sizeof(text));
    check("an IPv4 endpoint is address colon port", strcmp(text, "203.0.113.7:443") == 0 && length == strlen(text));

    struct in6_addr v6;
    inet_pton(AF_INET6, "2001:db8::1", &v6);
    where = (struct destination){ .family = AF_INET6, .address = &v6, .port = 443 };
    format_endpoint(&where, text, sizeof(text));
    check("an IPv6 endpoint is bracketed", strcmp(text, "[2001:db8::1]:443") == 0);

    inet_pton(AF_INET6, "::ffff:203.0.113.7", &v6);
    format_endpoint(&where, text, sizeof(text));
    check("an IPv4-mapped endpoint keeps the IPv6 spelling in brackets", strcmp(text, "[::ffff:203.0.113.7]:443") == 0);

    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &v6);
    where.port = 65535;
    length = format_endpoint(&where, text, sizeof(text));
    check("the longest IPv6 endpoint fits ENDPOINT_TEXT_SIZE whole",
          strcmp(text, "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535") == 0 && length < sizeof(text));

    where = (struct destination){ .family = AF_UNIX, .address = nullptr, .port = 0 };
    format_endpoint(&where, text, sizeof(text));
    check("another family is named by its number", strcmp(text, "family 1") == 0);

    where = (struct destination){ .family = AF_INET, .address = nullptr, .port = 80 };
    format_endpoint(&where, text, sizeof(text));
    check("an IPv4 destination without an address is named by its family", strcmp(text, "family 2") == 0);

    char small[6];
    memset(small, 'x', sizeof(small));
    where = (struct destination){ .family = AF_INET, .address = &v4, .port = 443 };
    length = format_endpoint(&where, small, sizeof(small));
    check("a short buffer is cut short and terminated", strcmp(small, "203.0") == 0 && length == 5);

    char untouched = 'x';
    check("a zero size writes nothing and answers zero",
          format_endpoint(&where, &untouched, 0) == 0 && untouched == 'x');
}

static void test_exit_code_mapping(void) {
    int status = 0;
    check("a clean exit maps to its code", exit_code_from_status((7 << WAIT_STATUS_EXIT_CODE_SHIFT)) == 7);
    status = SIGKILL;
    check("a signal maps to 128 plus the signal", exit_code_from_status(status) == SIGNAL_EXIT_CODE_BASE + SIGKILL);
    check("an unusual status maps to the setup error", exit_code_from_status(WAIT_STATUS_STOPPED) == EXIT_CODE_SETUP_ERROR);
}

/* The disposition SIGCHLD has right now in this process. */
static void (*child_signal_handler(void))(int) {
    struct sigaction current;
    sigaction(SIGCHLD, NULL, &current);
    return current.sa_handler;
}

/* Sets SIGCHLD's disposition with sigaction, since signal() is faked in this suite. */
static void set_child_signal_handler(void (*handler)(int)) {
    struct sigaction wanted;
    memset(&wanted, 0, sizeof(wanted));
    wanted.sa_handler = handler;
    sigemptyset(&wanted.sa_mask);
    sigaction(SIGCHLD, &wanted, NULL);
}

static void test_child_signal_disposition(void) {
    struct sigaction inherited;
    set_child_signal_handler(SIG_IGN);
    take_default_child_signal(&inherited);
    check("an inherited ignored SIGCHLD is given its default in the supervisor, so its child is not "
          "reaped by the kernel",
          child_signal_handler() == SIG_DFL && inherited.sa_handler == SIG_IGN);
    restore_child_signal(&inherited);
    check("and the child gets the disposition its caller gave back before it becomes the command",
          child_signal_handler() == SIG_IGN);
    set_child_signal_handler(SIG_DFL);
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
static constexpr uint64_t HELD_BOUND_INODE = 9001;               /* a held socket bound to an explicit port */
static constexpr uint64_t HELD_UNBOUND_INODE = 9002;             /* a held socket never bound */
static constexpr uint64_t HELD_UNIX_INODE = 9003;                /* a held UNIX socket */
static constexpr uint64_t NEVER_HELD_INODE = 9004;               /* a socket the supervisor never created */
static constexpr uint64_t CREATED_UNIX_INODE = 9005;             /* the UNIX socket the guard creates */
static constexpr uint64_t CREATED_SEQPACKET_INODE = 9006;        /* the sequenced-packet socket the guard creates */
static constexpr uint64_t HELD_DATAGRAM_INODE = 9101;            /* a held datagram socket the supervisor sends on */
static constexpr int HELD_DESCRIPTOR = 700;                      /* a stand-in for the supervisor's own descriptor */
static constexpr int HELD_DATAGRAM_DESCRIPTOR = 710;             /* a stand-in for its descriptor for that datagram socket */
static constexpr uint16_t FAKE_SOURCE_PORT = 40000;              /* the port a held datagram socket is bound to */
static constexpr int FAKE_BACKLOG = 5;                           /* the backlog a listen asks for */
static constexpr uint16_t FAKE_BOUND_PORT = 8080;                /* the port a held socket is bound to */

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
    remember_rule("127.0.0.2", "443", false);
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
    remember_rule("127.0.0.1", "443", false);
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
    remember_rule("127.0.0.1", "443", false);
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
    remember_rule("2001:db8::1", "443", false);
    service_once();
    check("a permitted IPv6 connect is made on the command's behalf",
          bx->connect_calls == 1 && bx->addfd_calls == 1 && bx->last_answer_error == 0);
}

/* The supervisor decides socket() and the send syscalls, not only connect. These drive the
 * socket kinds it refuses and allows, and a syscall it does not trap, through the dispatcher. The
 * datagram sends have their own cases, in test_datagram_mediation. */
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
    set_verbose(true);
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_UNIX;
    bx->notif_socket_type = SOCK_DGRAM;
    bx->notif_send_result = -1;
    service_once();
    set_verbose(false);
    check("a continue whose notify send fails is tolerated", bx->answers == 1);

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
    check("an answer whose notify send fails is tolerated", bx->answers == 1);
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
    bx->notif_socket_type = SOCK_DGRAM;
    service_once();
    check("a socket that is neither a tracked INET socket nor able to listen is left to the kernel",
          bx->answers == 1 && bx->last_answer_flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE &&
              held_sockets_count_for_tests() == 0);

    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    bx->notif_recv_target_fd = 6;
    bx->process_vm_readv_result = 1;
    bx->readlink_inode = TRACKED_DATAGRAM_INODE;
    bx->getsockname_port = FAKE_SOURCE_PORT;
    record_socket_type(TRACKED_DATAGRAM_INODE, FD_TYPE_DGRAM);
    hold_socket(TRACKED_DATAGRAM_INODE, HELD_DATAGRAM_DESCRIPTOR);
    remember_rule("127.0.0.1", "53", true);
    service_once();
    check("a connect on a datagram socket is made by the supervisor on its own descriptor, not injected or continued",
          bx->answers == 1 && bx->last_answer_error == 0 && bx->connect_calls == 1 &&
              bx->last_connect_descriptor == HELD_DATAGRAM_DESCRIPTOR && bx->addfd_calls == 0 &&
              bx->last_answer_flags != SECCOMP_USER_NOTIF_FLAG_CONTINUE);

    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    bx->notif_recv_target_fd = 9;
    bx->process_vm_readv_result = 1;
    bx->readlink_inode = 8301;
    remember_rule("127.0.0.1", "53", false);
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
    remember_rule("127.0.0.1", "53", false);
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
    remember_rule("127.0.0.1", "53", false);
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
    remember_rule("127.0.0.1", "53", false);
    service_once();
    check("a connect on a tracked stream socket is injected, race-free",
          bx->answers == 1 && bx->connect_calls == 1 && bx->addfd_calls == 1);

    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    bx->notif_recv_target_fd = 6;
    bx->process_vm_readv_result = 1;
    bx->readlink_inode = TRACKED_STREAM_INODE;
    record_socket_type(TRACKED_STREAM_INODE, FD_TYPE_STREAM);
    remember_rule("127.0.0.1", "53", true);
    service_once();
    check("a stream connect is refused when only a udp rule names the destination",
          bx->answers == 1 && bx->connect_calls == 0 && bx->last_answer_error == -EACCES &&
              bx->last_answer_flags != SECCOMP_USER_NOTIF_FLAG_CONTINUE);

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

/* Points the next notification at a listen() on a socket with this inode. */
static void arrange_listen(uint64_t inode) {
    bx->notif_recv_nr = __NR_listen;
    bx->notif_recv_target_fd = 6;
    bx->notif_listen_backlog = FAKE_BACKLOG;
    bx->readlink_inode = inode;
}

static bool answered_not_continued(void) {
    return bx->answers == 1 && bx->last_answer_flags != SECCOMP_USER_NOTIF_FLAG_CONTINUE;
}

/* Every sockets the supervisor creates for a listen, and every way a listen() is answered. */
static void test_listen_closure(void) {
    reset_behaviour();
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_UNIX;
    bx->notif_socket_type = SOCK_STREAM;
    bx->readlink_inode = CREATED_UNIX_INODE;
    service_once();
    check("a UNIX stream socket is created by the guard, held, and not tracked as INET",
          bx->answers == 1 && bx->last_answer_val == FAKE_ADDFD_DESCRIPTOR &&
              held_socket_descriptor(CREATED_UNIX_INODE) == FAKE_OUTWARD_SOCKET_DESCRIPTOR &&
              lookup_socket_type(CREATED_UNIX_INODE) == FD_TYPE_UNKNOWN);

    reset_behaviour();
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_INET;
    bx->notif_socket_type = SOCK_STREAM;
    bx->readlink_inode = CREATED_TCP_INODE;
    service_once();
    check("an INET stream socket is both tracked and held",
          bx->answers == 1 && lookup_socket_type(CREATED_TCP_INODE) == FD_TYPE_STREAM &&
              held_socket_descriptor(CREATED_TCP_INODE) == FAKE_OUTWARD_SOCKET_DESCRIPTOR);

    reset_behaviour();
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_INET6;
    bx->notif_socket_type = SOCK_SEQPACKET;
    bx->readlink_inode = CREATED_SEQPACKET_INODE;
    service_once();
    check("a sequenced-packet socket is held but not tracked, it can listen and never connects here",
          bx->answers == 1 && held_socket_descriptor(CREATED_SEQPACKET_INODE) == FAKE_OUTWARD_SOCKET_DESCRIPTOR &&
              lookup_socket_type(CREATED_SEQPACKET_INODE) == FD_TYPE_UNKNOWN);

    reset_behaviour();
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_INET;
    bx->notif_socket_type = SOCK_DGRAM;
    bx->readlink_inode = CREATED_UDP_INODE;
    service_once();
    check("a datagram socket is tracked and held, because every datagram it sends is sent by the supervisor",
          bx->answers == 1 && lookup_socket_type(CREATED_UDP_INODE) == FD_TYPE_DGRAM &&
              held_socket_descriptor(CREATED_UDP_INODE) == FAKE_OUTWARD_SOCKET_DESCRIPTOR);

    reset_behaviour();
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_INET;
    bx->notif_socket_type = SOCK_STREAM;
    bx->notif_addfd_result = -1;
    service_once();
    check("a stream socket whose injection fails is not held", held_sockets_count_for_tests() == 0);

    reset_behaviour();
    bx->notif_recv_nr = __NR_socket;
    bx->notif_socket_domain = AF_INET;
    bx->notif_socket_type = SOCK_STREAM;
    bx->readlink_kind = READLINK_FAILS;
    service_once();
    check("a stream socket /proc cannot name is created but cannot be held, so it can never listen",
          bx->answers == 1 && bx->last_answer_error == 0 && held_sockets_count_for_tests() == 0);

    reset_behaviour();
    hold_socket(HELD_BOUND_INODE, HELD_DESCRIPTOR);
    arrange_listen(HELD_BOUND_INODE);
    bx->getsockname_port = FAKE_BOUND_PORT;
    service_once();
    check("a held socket bound to an explicit port is made to listen by the supervisor, not continued",
          answered_not_continued() && bx->last_answer_error == 0 && bx->last_answer_val == 0 &&
              bx->listen_calls == 1 && bx->last_listen_descriptor == HELD_DESCRIPTOR &&
              bx->last_listen_backlog == FAKE_BACKLOG);
    check("the supervisor lets go of a socket once it listens, so its port is free when the command closes",
          held_socket_descriptor(HELD_BOUND_INODE) < 0 && was_listened(HELD_BOUND_INODE));
    bx->answers = 0;
    bx->listen_calls = 0;
    service_once();
    check("a repeated listen is answered 0 without calling the kernel again",
          answered_not_continued() && bx->last_answer_error == 0 && bx->listen_calls == 0);

    reset_behaviour();
    hold_socket(HELD_BOUND_INODE, HELD_DESCRIPTOR);
    arrange_listen(HELD_BOUND_INODE);
    bx->getsockname_family = AF_INET6;
    bx->getsockname_port = FAKE_BOUND_PORT;
    service_once();
    check("an IPv6 socket bound to an explicit port may listen",
          answered_not_continued() && bx->last_answer_error == 0 && bx->listen_calls == 1);

    reset_behaviour();
    hold_socket(HELD_UNBOUND_INODE, HELD_DESCRIPTOR);
    arrange_listen(HELD_UNBOUND_INODE);
    service_once();
    check("a held socket that was never bound is refused, the kernel would pick it a port",
          answered_not_continued() && bx->last_answer_error == -EACCES && bx->listen_calls == 0 &&
              held_socket_descriptor(HELD_UNBOUND_INODE) == HELD_DESCRIPTOR);

    reset_behaviour();
    hold_socket(HELD_UNBOUND_INODE, HELD_DESCRIPTOR);
    arrange_listen(HELD_UNBOUND_INODE);
    bx->getsockname_family = AF_INET6;
    service_once();
    check("an unbound IPv6 socket is refused the same way",
          answered_not_continued() && bx->last_answer_error == -EACCES && bx->listen_calls == 0);

    reset_behaviour();
    configure_ephemeral_listen(true);
    hold_socket(HELD_UNBOUND_INODE, HELD_DESCRIPTOR);
    arrange_listen(HELD_UNBOUND_INODE);
    service_once();
    check("a socket that was never bound may listen where the policy grants an ephemeral bind",
          answered_not_continued() && bx->last_answer_error == 0 && bx->listen_calls == 1);

    reset_behaviour();
    hold_socket(HELD_UNIX_INODE, HELD_DESCRIPTOR);
    arrange_listen(HELD_UNIX_INODE);
    bx->getsockname_family = AF_UNIX;
    service_once();
    check("a UNIX socket may listen, Landlock judged where it was bound",
          answered_not_continued() && bx->last_answer_error == 0 && bx->listen_calls == 1);

    reset_behaviour();
    hold_socket(HELD_BOUND_INODE, HELD_DESCRIPTOR);
    arrange_listen(HELD_BOUND_INODE);
    bx->getsockname_family = AF_PACKET;
    service_once();
    check("a held socket of any other family is refused",
          answered_not_continued() && bx->last_answer_error == -EACCES && bx->listen_calls == 0);

    reset_behaviour();
    hold_socket(HELD_BOUND_INODE, HELD_DESCRIPTOR);
    arrange_listen(HELD_BOUND_INODE);
    bx->getsockname_result = -1;
    service_once();
    check("a held socket whose address cannot be read is refused",
          answered_not_continued() && bx->last_answer_error == -EACCES && bx->listen_calls == 0);

    reset_behaviour();
    arrange_listen(NEVER_HELD_INODE);
    bx->getsockname_port = FAKE_BOUND_PORT;
    service_once();
    check("a listen on a socket the supervisor never created is refused, not continued",
          answered_not_continued() && bx->last_answer_error == -EACCES && bx->listen_calls == 0);

    reset_behaviour();
    arrange_listen(NEVER_HELD_INODE);
    bx->readlink_kind = READLINK_FAILS;
    service_once();
    check("a listen on a descriptor /proc cannot name is refused, not continued",
          answered_not_continued() && bx->last_answer_error == -EACCES && bx->listen_calls == 0);

    reset_behaviour();
    hold_socket(HELD_BOUND_INODE, HELD_DESCRIPTOR);
    arrange_listen(HELD_BOUND_INODE);
    bx->getsockname_port = FAKE_BOUND_PORT;
    bx->listen_result = -1;
    bx->listen_errno = EADDRINUSE;
    service_once();
    check("a listen the kernel refuses is answered with its errno and the socket stays held",
          answered_not_continued() && bx->last_answer_error == -EADDRINUSE &&
              held_socket_descriptor(HELD_BOUND_INODE) == HELD_DESCRIPTOR && !was_listened(HELD_BOUND_INODE));

    reset_behaviour();
    hold_socket(HELD_BOUND_INODE, HELD_DESCRIPTOR);
    arrange_listen(HELD_BOUND_INODE);
    bx->getsockname_port = FAKE_BOUND_PORT;
    bx->notif_id_valid_result = -1;
    service_once();
    check("a listen whose notification is no longer valid is dropped before the supervisor listens",
          bx->answers == 0 && bx->listen_calls == 0 && held_socket_descriptor(HELD_BOUND_INODE) == HELD_DESCRIPTOR);

    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    bx->notif_recv_target_fd = 6;
    bx->process_vm_readv_result = 1;
    bx->readlink_inode = TRACKED_STREAM_INODE;
    record_socket_type(TRACKED_STREAM_INODE, FD_TYPE_STREAM);
    hold_socket(TRACKED_STREAM_INODE, HELD_DESCRIPTOR);
    remember_rule("127.0.0.1", "53", false);
    service_once();
    check("a connect that injects the socket lets go of the socket it replaced",
          bx->answers == 1 && bx->connect_calls == 1 && held_socket_descriptor(TRACKED_STREAM_INODE) < 0);

    reset_behaviour();
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    bx->notif_recv_target_fd = 6;
    bx->process_vm_readv_result = 1;
    bx->readlink_inode = TRACKED_STREAM_INODE;
    bx->connect_result = -1;
    bx->connect_errno = ECONNREFUSED;
    record_socket_type(TRACKED_STREAM_INODE, FD_TYPE_STREAM);
    hold_socket(TRACKED_STREAM_INODE, HELD_DESCRIPTOR);
    remember_rule("127.0.0.1", "53", false);
    service_once();
    check("a connect that fails keeps the socket held, so the command can still listen on it",
          bx->answers == 1 && held_socket_descriptor(TRACKED_STREAM_INODE) == HELD_DESCRIPTOR);

    reset_behaviour();
    constexpr int FIRST_TABLE_DESCRIPTOR = 1000;
    constexpr int NEW_TABLE_DESCRIPTOR = 2000;
    for (size_t inode = 1; inode <= HELD_SOCKET_CAPACITY; inode++) {
        hold_socket(inode, FIRST_TABLE_DESCRIPTOR + (int)inode);
    }
    check("the held table takes its capacity", held_sockets_count_for_tests() == HELD_SOCKET_CAPACITY);
    hold_socket(HELD_SOCKET_CAPACITY + 1, NEW_TABLE_DESCRIPTOR);
    check("a full table evicts the oldest socket and keeps the others and the newest",
          held_sockets_count_for_tests() == HELD_SOCKET_CAPACITY && held_socket_descriptor(1) < 0 &&
              held_socket_descriptor(2) == FIRST_TABLE_DESCRIPTOR + 2 &&
              held_socket_descriptor(HELD_SOCKET_CAPACITY + 1) == NEW_TABLE_DESCRIPTOR);
    hold_socket(HELD_SOCKET_CAPACITY + 2, NEW_TABLE_DESCRIPTOR + 1);
    check("the next eviction takes the next oldest, wherever its slot is",
          held_socket_descriptor(2) < 0 && held_socket_descriptor(3) == FIRST_TABLE_DESCRIPTOR + 3 &&
              held_sockets_count_for_tests() == HELD_SOCKET_CAPACITY);

    reset_behaviour();
    for (size_t inode = 1; inode <= HELD_SOCKET_CAPACITY; inode++) {
        hold_socket(inode, FIRST_TABLE_DESCRIPTOR + (int)inode);
    }
    check("using a held socket answers its descriptor",
          use_held_socket(1) == FIRST_TABLE_DESCRIPTOR + 1);
    hold_socket(HELD_SOCKET_CAPACITY + 1, NEW_TABLE_DESCRIPTOR);
    check("a socket in use is the last to be evicted, the least recently used goes instead",
          held_socket_descriptor(1) == FIRST_TABLE_DESCRIPTOR + 1 && held_socket_descriptor(2) < 0 &&
              held_socket_descriptor(3) == FIRST_TABLE_DESCRIPTOR + 3);

    reset_behaviour();
    hold_socket(HELD_BOUND_INODE, HELD_DESCRIPTOR);
    hold_socket(HELD_BOUND_INODE, HELD_DESCRIPTOR + 1);
    check("holding an inode again replaces its entry",
          held_sockets_count_for_tests() == 1 && held_socket_descriptor(HELD_BOUND_INODE) == HELD_DESCRIPTOR + 1);
    hold_socket(0, HELD_DESCRIPTOR + 2);
    release_held_socket(0);
    release_held_socket(NEVER_HELD_INODE);
    check("inode zero is never held, and releasing one that is not held changes nothing",
          held_sockets_count_for_tests() == 1 && held_socket_descriptor(0) < 0);
    release_held_socket(HELD_BOUND_INODE);
    check("releasing a held socket empties its slot", held_sockets_count_for_tests() == 0);

    reset_behaviour();
    remember_listened(0);
    check("inode zero is never remembered as listened", !was_listened(0));
    remember_listened(HELD_BOUND_INODE);
    check("a socket that listened is remembered", was_listened(HELD_BOUND_INODE));
    hold_socket(HELD_BOUND_INODE, HELD_DESCRIPTOR);
    check("a new socket with a recycled inode starts un-listened", !was_listened(HELD_BOUND_INODE));
    constexpr uint64_t FIRST_LISTENED_INODE = 100000;
    for (size_t index = 0; index <= LISTENED_SOCKET_CAPACITY; index++) {
        remember_listened(FIRST_LISTENED_INODE + index);
    }
    check("the listened set is a ring that forgets its oldest entry first",
          !was_listened(FIRST_LISTENED_INODE) && was_listened(FIRST_LISTENED_INODE + 1) &&
              was_listened(FIRST_LISTENED_INODE + LISTENED_SOCKET_CAPACITY));
}

/* A datagram socket the supervisor created and holds, bound to a source port, and the next
 * notification pointed at a send, from the command's descriptor 6, on the socket that inode names. */
static void arrange_held_datagram(int syscall_number) {
    bx->notif_recv_nr = syscall_number;
    bx->notif_recv_target_fd = 6;
    bx->readlink_inode = HELD_DATAGRAM_INODE;
    bx->getsockname_family = AF_INET;
    bx->getsockname_port = FAKE_SOURCE_PORT;
    bx->process_vm_readv_result = 1;
    record_socket_type(HELD_DATAGRAM_INODE, FD_TYPE_DGRAM);
    hold_socket(HELD_DATAGRAM_INODE, HELD_DATAGRAM_DESCRIPTOR);
}

/* The same, sending to 127.0.0.1 on this port, which a UDP rule names. */
static void arrange_datagram_send(int syscall_number, uint16_t port) {
    arrange_held_datagram(syscall_number);
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = port;
    bx->msg_mode = syscall_number == __NR_sendmsg;
    bx->mmsg_mode = syscall_number == __NR_sendmmsg;
    remember_rule("127.0.0.1", "53", true);
}

/* Whether the answer was an error of this kind and the supervisor sent nothing. */
static bool refused_with(int error) {
    return bx->answers == 1 && bx->last_answer_error == -error && bx->sendto_calls == 0 &&
           bx->last_answer_flags != SECCOMP_USER_NOTIF_FLAG_CONTINUE;
}

/* Whether the supervisor sent exactly this many datagrams, answered with this value, and never
 * continued the call in the command. */
static bool sent_and_answered(int datagrams, int64_t value) {
    return bx->answers == 1 && bx->last_answer_error == 0 && bx->last_answer_val == value &&
           bx->sendto_calls == datagrams && bx->last_answer_flags != SECCOMP_USER_NOTIF_FLAG_CONTINUE;
}

static void test_datagram_sendto(void) {
    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    service_once();
    check("a sendto to a listed destination is sent by the supervisor from its own copy, to that port",
          sent_and_answered(1, FAKE_DATAGRAM_LENGTH) && bx->last_sendto_length == FAKE_DATAGRAM_LENGTH &&
              bx->last_sendto_port == 53 && bx->last_sendto_name_length == sizeof(struct sockaddr_in) &&
              (bx->last_sendto_flags & MSG_NOSIGNAL) && (bx->last_sendto_flags & MSG_DONTWAIT));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->notif_recv_family = AF_INET6;
    remember_rule("2001:db8::1", "53", true);
    service_once();
    check("a sendto to a listed IPv6 destination is sent too, to that port",
          sent_and_answered(1, FAKE_DATAGRAM_LENGTH) && bx->last_sendto_port == 53 &&
              bx->last_sendto_name_length == sizeof(struct sockaddr_in6));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->sendto_length = 0;
    service_once();
    check("an empty datagram is sent, and nothing is read from the command for it",
          sent_and_answered(1, 0) && bx->last_sendto_length == 0);

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 9999);
    service_once();
    check("a sendto to a destination the list does not name is refused and nothing is sent",
          refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->notif_recv_family = AF_UNIX;
    service_once();
    check("a sendto to a UNIX address is refused, where it used to be let through", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->notif_send_flags = MSG_FASTOPEN;
    service_once();
    check("a send with TCP Fast Open is refused even to a listed destination", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->notif_send_flags = MSG_OOB;
    service_once();
    check("a send with a flag the supervisor cannot pass on is refused with EOPNOTSUPP",
          refused_with(EOPNOTSUPP));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->notif_send_flags = MSG_MORE | MSG_CONFIRM | MSG_DONTROUTE;
    service_once();
    check("the flags the supervisor can pass on go to its own send",
          sent_and_answered(1, FAKE_DATAGRAM_LENGTH) &&
              (bx->last_sendto_flags & (MSG_MORE | MSG_CONFIRM | MSG_DONTROUTE)) ==
                  (MSG_MORE | MSG_CONFIRM | MSG_DONTROUTE));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->notif_recv_family = 0;
    service_once();
    check("a sendto with no destination is a send on the connected socket, with no name",
          sent_and_answered(1, FAKE_DATAGRAM_LENGTH) && bx->last_sendto_name_length == 0);

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->sendto_address_length = sizeof(struct sockaddr_storage) + 1;
    service_once();
    check("an address longer than any socket address is refused with EINVAL", refused_with(EINVAL));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->process_vm_readv_result = 0;
    service_once();
    check("a sendto whose address cannot be read is refused", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->data_unreadable = 1;
    service_once();
    check("a sendto whose data cannot be read is refused", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->sendto_length = 65536;
    service_once();
    check("a datagram beyond 64 KiB is refused with EMSGSIZE", refused_with(EMSGSIZE));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->sendto_length = 65535;
    service_once();
    check("a datagram of exactly 64 KiB less one is sent",
          sent_and_answered(1, 65535) && bx->last_sendto_length == 65535);
}

static void test_datagram_provenance(void) {
    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    release_held_socket(HELD_DATAGRAM_INODE);
    service_once();
    check("a send on a datagram socket the supervisor no longer holds is refused", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    record_socket_type(HELD_DATAGRAM_INODE, FD_TYPE_STREAM);
    service_once();
    check("a sendto with a destination on a stream socket is refused", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->readlink_kind = READLINK_PIPE;
    service_once();
    check("a send on a descriptor that is not a socket is refused", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->getsockname_port = 0;
    service_once();
    check("a send on a socket bound to no port is refused when the policy grants no ephemeral bind",
          refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->getsockname_port = 0;
    configure_ephemeral_udp_bind(true);
    service_once();
    check("a send on a socket bound to no port goes ahead when the policy grants an ephemeral bind",
          sent_and_answered(1, FAKE_DATAGRAM_LENGTH));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->getsockname_family = AF_INET6;
    bx->getsockname_port = FAKE_SOURCE_PORT;
    service_once();
    check("a socket bound to an IPv6 port may send", sent_and_answered(1, FAKE_DATAGRAM_LENGTH));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->getsockname_family = AF_UNIX;
    service_once();
    check("a socket of another family than IPv4 and IPv6 is refused", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->getsockname_result = -1;
    service_once();
    check("a socket whose address the kernel cannot report is refused", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->notif_recv_family = 0;
    bx->getsockname_port = 0;
    service_once();
    check("a send with no destination on a socket bound to no port is refused too, the kernel would bind it first",
          refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->notif_recv_family = 0;
    configure_ephemeral_udp_bind(true);
    bx->getsockname_port = 0;
    service_once();
    check("a send with no destination on an unbound socket goes ahead when the policy grants an ephemeral bind",
          sent_and_answered(1, FAKE_DATAGRAM_LENGTH));

    reset_behaviour();
    check("a socket nobody holds has no descriptor to use",
          use_held_socket(HELD_DATAGRAM_INODE) == -1 && use_held_socket(0) == -1);
}

static void test_datagram_kernel_answers(void) {
    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->sendto_result = -1;
    bx->sendto_errno = ECONNREFUSED;
    service_once();
    check("an error the kernel gives the supervisor's send is the command's answer",
          bx->answers == 1 && bx->last_answer_error == -ECONNREFUSED && bx->sendto_calls == 1);

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->sendto_result = 7;
    service_once();
    check("a send the kernel took in part is answered with the count it took",
          sent_and_answered(1, 7));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->sendto_eintr_once = 1;
    service_once();
    check("a send the kernel interrupts is repeated", sent_and_answered(2, FAKE_DATAGRAM_LENGTH));

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->sendto_eagain_first = 1;
    bx->poll_result = 1;
    bx->poll_revents = POLLOUT;
    service_once();
    check("a blocking socket that cannot take the datagram is waited on once, then the send is made",
          sent_and_answered(2, FAKE_DATAGRAM_LENGTH) && bx->poll_calls == 1);

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->sendto_eagain_first = 2;
    bx->poll_result = 1;
    bx->poll_revents = POLLOUT;
    service_once();
    check("a socket still full after the wait is answered EAGAIN, with one wait and no second one",
          bx->answers == 1 && bx->last_answer_error == -EAGAIN && bx->sendto_calls == 2 &&
              bx->poll_calls == 1);

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->sendto_eagain_first = 1;
    bx->poll_result = 0;
    service_once();
    check("a socket that stays full for the whole wait is answered EAGAIN",
          bx->answers == 1 && bx->last_answer_error == -EAGAIN && bx->sendto_calls == 1);

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->sendto_eagain_first = 1;
    bx->fcntl_getfl_value = O_NONBLOCK;
    service_once();
    check("a non-blocking socket that cannot take the datagram is answered EAGAIN with no wait",
          bx->answers == 1 && bx->last_answer_error == -EAGAIN && bx->sendto_calls == 1);

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->sendto_eagain_first = 1;
    bx->notif_send_flags = MSG_DONTWAIT;
    service_once();
    check("a send the command asked not to block is answered EAGAIN with no wait",
          bx->answers == 1 && bx->last_answer_error == -EAGAIN && bx->sendto_calls == 1);

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->sendto_eagain_first = 1;
    bx->fcntl_fails = 1;
    service_once();
    check("a socket whose mode cannot be read is never waited on",
          bx->answers == 1 && bx->last_answer_error == -EAGAIN && bx->sendto_calls == 1);

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->sendto_eagain_first = 1;
    bx->poll_eintr_once = 1;
    bx->poll_result = 0;
    service_once();
    check("a wait that is interrupted is answered EAGAIN too, so the supervisor never stalls",
          bx->answers == 1 && bx->last_answer_error == -EAGAIN);

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->id_valid_fail_at = 1;
    service_once();
    check("a sendto whose notification turns invalid after the address read is dropped, nothing sent",
          bx->answers == 0 && bx->sendto_calls == 0);

    reset_behaviour();
    arrange_datagram_send(__NR_sendto, 53);
    bx->id_valid_fail_at = 2;
    service_once();
    check("a sendto whose notification turns invalid after the data read is dropped, nothing sent",
          bx->answers == 0 && bx->sendto_calls == 0);
}

static void test_datagram_sendmsg(void) {
    reset_behaviour();
    arrange_datagram_send(__NR_sendmsg, 53);
    bx->iov_count = 3;
    service_once();
    check("a sendmsg to a listed destination is sent as one datagram of every segment",
          sent_and_answered(1, 3 * FAKE_DATAGRAM_LENGTH) &&
              bx->last_sendto_length == 3 * FAKE_DATAGRAM_LENGTH && bx->last_sendto_port == 53);

    reset_behaviour();
    arrange_datagram_send(__NR_sendmsg, 9999);
    service_once();
    check("a sendmsg to a destination the list does not name is refused", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendmsg, 53);
    bx->msg_name_missing = 1;
    service_once();
    check("a sendmsg with no destination is a send on the connected socket, with no name",
          sent_and_answered(1, FAKE_DATAGRAM_LENGTH) && bx->last_sendto_name_length == 0);

    reset_behaviour();
    arrange_datagram_send(__NR_sendmsg, 53);
    bx->iov_count = 0;
    service_once();
    check("a sendmsg of no segments sends an empty datagram", sent_and_answered(1, 0));

    reset_behaviour();
    arrange_datagram_send(__NR_sendmsg, 53);
    bx->message_control = 1;
    service_once();
    check("a sendmsg with ancillary data is refused, it can steer a datagram", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendmsg, 53);
    bx->message_iovlen = 1025;
    service_once();
    check("a sendmsg of more segments than the kernel takes is refused with EMSGSIZE",
          refused_with(EMSGSIZE));

    reset_behaviour();
    arrange_datagram_send(__NR_sendmsg, 53);
    bx->iov_count = 2;
    bx->segment_length = 40000;
    service_once();
    check("a sendmsg whose segments together exceed 64 KiB is refused with EMSGSIZE",
          refused_with(EMSGSIZE));

    reset_behaviour();
    arrange_datagram_send(__NR_sendmsg, 53);
    bx->iov_unreadable = 1;
    service_once();
    check("a sendmsg whose segment list cannot be read is refused", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendmsg, 53);
    bx->iov_unreadable = 1;
    bx->id_valid_fail_at = 2;
    service_once();
    check("a sendmsg whose notification turns invalid before the segment list is read is dropped",
          bx->answers == 0 && bx->sendto_calls == 0);

    reset_behaviour();
    arrange_datagram_send(__NR_sendmsg, 53);
    bx->notif_send_flags = MSG_FASTOPEN;
    service_once();
    check("a sendmsg with TCP Fast Open is refused even to a listed destination", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendmsg, 53);
    bx->process_vm_readv_result = 0;
    service_once();
    check("a sendmsg whose header cannot be read is refused", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendmsg, 53);
    bx->id_valid_fail_at = 1;
    service_once();
    check("a sendmsg whose notification turns invalid after the header read is dropped",
          bx->answers == 0 && bx->sendto_calls == 0);

    reset_behaviour();
    arrange_datagram_send(__NR_sendmsg, 53);
    release_held_socket(HELD_DATAGRAM_INODE);
    service_once();
    check("a sendmsg on a socket the supervisor does not hold is refused, not continued",
          refused_with(EACCES));
}

static void test_datagram_sendmmsg(void) {
    reset_behaviour();
    arrange_datagram_send(__NR_sendmmsg, 53);
    bx->mmsg_count = 3;
    service_once();
    check("a sendmmsg batch to a listed destination is sent message by message, and the count answered",
          sent_and_answered(3, 3) && bx->writev_calls == 3 &&
              bx->written_lengths[0] == FAKE_DATAGRAM_LENGTH &&
              bx->written_lengths[2] == FAKE_DATAGRAM_LENGTH);

    reset_behaviour();
    arrange_datagram_send(__NR_sendmmsg, 53);
    bx->mmsg_count = 2000;
    bx->mmsg_name_missing = 1;
    service_once();
        check("a sendmmsg count beyond the kernel's limit is cut down to it", sent_and_answered(1024, 1024));

    reset_behaviour();
    arrange_datagram_send(__NR_sendmmsg, 53);
    bx->mmsg_count = 3;
    bx->writev_fail_at = 1;
    service_once();
    check("a first length that cannot be written back is the batch's error, EFAULT, as in the kernel",
          bx->answers == 1 && bx->last_answer_error == -EFAULT && bx->sendto_calls == 1 &&
              bx->writev_calls == 1);

    reset_behaviour();
    arrange_datagram_send(__NR_sendmmsg, 53);
    bx->mmsg_count = 3;
    bx->writev_fail_at = 2;
    service_once();
    check("a later length that cannot be written back ends the batch, and that message is not counted",
          bx->answers == 1 && bx->last_answer_error == 0 && bx->last_answer_val == 1 &&
              bx->sendto_calls == 2 && bx->writev_calls == 2);

    reset_behaviour();
    arrange_datagram_send(__NR_sendmmsg, 53);
    bx->mmsg_count = 2;
    bx->writev_short = 1;
    service_once();
    check("a length written in part counts as not written",
          bx->answers == 1 && bx->last_answer_error == -EFAULT && bx->sendto_calls == 1);

    reset_behaviour();
    arrange_datagram_send(__NR_sendmmsg, 53);
    bx->mmsg_count = 9;
    service_once();
    check("only the first eight written lengths are recorded by the test, all nine are written",
          sent_and_answered(9, 9) && bx->writev_calls == 9);

    reset_behaviour();
    arrange_datagram_send(__NR_sendmmsg, 53);
    bx->mmsg_hetero = 1;
    bx->mmsg_count = 2;
    service_once();
    check("a later message to a destination the list does not name ends the batch, the count stands",
          bx->answers == 1 && bx->last_answer_error == 0 && bx->last_answer_val == 1 &&
              bx->sendto_calls == 1);

    reset_behaviour();
    arrange_datagram_send(__NR_sendmmsg, 9999);
    service_once();
    check("a first message to a destination the list does not name is the batch's error",
          refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendmmsg, 53);
    bx->mmsg_vlen_zero = 1;
    service_once();
    check("a batch of no messages sends nothing and answers zero",
          bx->answers == 1 && bx->last_answer_error == 0 && bx->last_answer_val == 0 &&
              bx->sendto_calls == 0);

    reset_behaviour();
    arrange_datagram_send(__NR_sendmmsg, 53);
    bx->process_vm_readv_result = 0;
    service_once();
    check("a sendmmsg whose entry cannot be read is refused", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendmmsg, 53);
    bx->id_valid_fail_at = 1;
    service_once();
    check("a sendmmsg whose notification turns invalid after an entry read is dropped",
          bx->answers == 0 && bx->sendto_calls == 0);

    reset_behaviour();
    arrange_datagram_send(__NR_sendmmsg, 53);
    bx->id_valid_fail_at = 2;
    service_once();
    check("a sendmmsg whose notification turns invalid while its message is judged is dropped",
          bx->answers == 0 && bx->sendto_calls == 0);

    reset_behaviour();
    arrange_datagram_send(__NR_sendmmsg, 53);
    bx->message_control = 1;
    service_once();
    check("a sendmmsg message with ancillary data is refused", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendmmsg, 53);
    bx->notif_send_flags = MSG_FASTOPEN;
    service_once();
    check("a sendmmsg with TCP Fast Open is refused", refused_with(EACCES));

    reset_behaviour();
    arrange_datagram_send(__NR_sendmmsg, 53);
    release_held_socket(HELD_DATAGRAM_INODE);
    service_once();
    check("a sendmmsg on a socket the supervisor does not hold is refused", refused_with(EACCES));
}

static void test_datagram_connect(void) {
    reset_behaviour();
    arrange_held_datagram(__NR_connect);
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    remember_rule("127.0.0.1", "53", true);
    service_once();
    check("a datagram connect to a listed destination is made on the supervisor's own descriptor",
          bx->answers == 1 && bx->last_answer_error == 0 && bx->connect_calls == 1 &&
              bx->last_connect_descriptor == HELD_DATAGRAM_DESCRIPTOR && bx->last_connect_port == 53 &&
              bx->addfd_calls == 0 && bx->last_answer_flags != SECCOMP_USER_NOTIF_FLAG_CONTINUE);

    reset_behaviour();
    arrange_held_datagram(__NR_connect);
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 9999;
    remember_rule("127.0.0.1", "53", true);
    service_once();
    check("a datagram connect to a destination the list does not name is refused",
          bx->answers == 1 && bx->last_answer_error == -EACCES && bx->connect_calls == 0);

    reset_behaviour();
    arrange_held_datagram(__NR_connect);
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    bx->connect_result = -1;
    bx->connect_errno = ENETUNREACH;
    remember_rule("127.0.0.1", "53", true);
    service_once();
    check("an error the kernel gives the supervisor's connect is the command's answer",
          bx->answers == 1 && bx->last_answer_error == -ENETUNREACH && bx->connect_calls == 1);

    reset_behaviour();
    arrange_held_datagram(__NR_connect);
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    remember_rule("127.0.0.1", "53", true);
    release_held_socket(HELD_DATAGRAM_INODE);
    service_once();
    check("a datagram connect on a socket the supervisor does not hold is refused, not continued",
          bx->answers == 1 && bx->last_answer_error == -EACCES && bx->connect_calls == 0 &&
              bx->last_answer_flags != SECCOMP_USER_NOTIF_FLAG_CONTINUE);

    reset_behaviour();
    arrange_held_datagram(__NR_connect);
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    bx->getsockname_port = 0;
    remember_rule("127.0.0.1", "53", true);
    service_once();
    check("a datagram connect on a socket bound to no port is refused without an ephemeral bind grant",
          bx->answers == 1 && bx->last_answer_error == -EACCES && bx->connect_calls == 0);

    reset_behaviour();
    arrange_held_datagram(__NR_connect);
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 53;
    bx->getsockname_port = 0;
    configure_ephemeral_udp_bind(true);
    remember_rule("127.0.0.1", "53", true);
    service_once();
    check("a datagram connect on a socket bound to no port goes ahead with an ephemeral bind grant",
          bx->answers == 1 && bx->last_answer_error == 0 && bx->connect_calls == 1);
}

/* The output the last resolve case wrote, and the status it ended with. */
static char dns_output[8192];

static int run_resolve(const char *resolver, char *const *names) {
    bx->dns_active = 1;
    FILE *out = tmpfile();
    if (out == NULL) {
        perror("tmpfile");
        exit(HARNESS_SETUP_FAILURE);
    }
    int status = run_resolve_mode(resolver, names, out);
    rewind(out);
    size_t length = fread(dns_output, 1, sizeof(dns_output) - 1, out);
    dns_output[length] = '\0';
    fclose(out);
    bx->dns_active = 0;
    return status;
}

static size_t count_lines(const char *text) {
    size_t lines = 0;
    for (; *text != '\0'; text++) {
        if (*text == '\n') {
            lines++;
        }
    }
    return lines;
}

/* A resolve case that must end with the setup status and write nothing. */
static bool resolve_refused(const char *name) {
    char *names[] = { (char *)name, NULL };
    int status = run_resolve("192.0.2.53", names);
    return status == EXIT_CODE_SETUP_ERROR && dns_output[0] == '\0';
}

static void test_resolver_endpoints(void) {
    struct sockaddr_storage address;
    socklen_t length = 0;
    check("a resolver address alone takes port 53",
          parse_resolver_endpoint("192.0.2.53", &address, &length) && address.ss_family == AF_INET &&
              ntohs(((struct sockaddr_in *)&address)->sin_port) == 53 && length == sizeof(struct sockaddr_in));
    check("a resolver address with a port keeps it",
          parse_resolver_endpoint("192.0.2.53:5353", &address, &length) &&
              ntohs(((struct sockaddr_in *)&address)->sin_port) == 5353);
    check("a bracketed IPv6 resolver with a port is read",
          parse_resolver_endpoint("[2001:db8::53]:5353", &address, &length) && address.ss_family == AF_INET6 &&
              ntohs(((struct sockaddr_in6 *)&address)->sin6_port) == 5353 && length == sizeof(struct sockaddr_in6));
    check("a bracketed IPv6 resolver with no port takes port 53",
          parse_resolver_endpoint("[2001:db8::53]", &address, &length) &&
              ntohs(((struct sockaddr_in6 *)&address)->sin6_port) == 53);
    const char *refused[] = {
        "", "example.com", "2001:db8::53", "[2001:db8::53", "[]:53", "[2001:db8::53]x", "192.0.2.53:0",
        "192.0.2.53:abc", "192.0.2.53:", "192.0.2.53:70000", "[2001:db8::53]:", "[2001:db8::53]:0", "[not-an-ip]:53",
        "[192.0.2.53]:53", ":53", "999.0.0.1", "[2001:db8:2001:db8:2001:db8:2001:db8:2001:db8:2001:db8]:53",
        "1111111111111111111111111111111111111111111111111111:53"
    };
    bool all_refused = true;
    for (size_t index = 0; index < sizeof(refused) / sizeof(refused[0]); index++) {
        if (parse_resolver_endpoint(refused[index], &address, &length)) {
            printf("      accepted: %s\n", refused[index]);
            all_refused = false;
        }
    }
    check("a resolver that is empty, a name, a bare IPv6 address, unclosed, portless or out of range is refused",
          all_refused);
}

static void test_resolve_mode(void) {
    test_resolver_endpoints();
    char *one[] = { "example.test", NULL };

    reset_behaviour();
    check("a name with two IPv4 addresses and one IPv6 address is written, one line each",
          run_resolve("192.0.2.53:5353", one) == 0 &&
              strcmp(dns_output, "example.test 192.0.2.1\nexample.test 192.0.2.2\nexample.test 2001:db8::1\n") == 0);
    check("the resolver is connected to at its port, and asked twice, once for each record type",
          bx->last_connect_port == 5353 && bx->last_connect_family == AF_INET && bx->dns_queries == 2);
    const unsigned char *query = bx->dns_query;
    check("the query carries a random id, asks for recursion, one question and one EDNS0 record",
          query[0] == 0xBE && query[1] == 0xEF && query[2] == 0x01 && query[5] == 1 && query[11] == 1);
    check("the question is the name as labels, the type, the Internet class, then the EDNS0 record",
          memcmp(query + 12, "\x07" "example\x04" "test", 13) == 0 && query[25] == 0 && query[26] == 0 &&
              query[27] == 28 && query[28] == 0 && query[29] == 1 && query[31] == 0 && query[32] == 41 &&
              bx->dns_query_length == 12 + 18 + 11);

    reset_behaviour();
    check("a bracketed IPv6 resolver is connected to over IPv6",
          run_resolve("[2001:db8::53]:5353", one) == 0 && bx->last_connect_family == AF_INET6 &&
              bx->last_connect_port == 5353);
    reset_behaviour();
    check("a resolver with no port is asked on port 53",
          run_resolve("192.0.2.53", one) == 0 && bx->last_connect_port == 53);

    reset_behaviour();
    bx->dns_behaviour[1] = DNS_NO_RECORDS;
    check("an empty AAAA answer is not a failure when A gave addresses",
          run_resolve("192.0.2.53", one) == 0 && count_lines(dns_output) == 2);
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_NO_RECORDS;
    check("an empty A answer is not a failure when AAAA gave an address",
          run_resolve("192.0.2.53", one) == 0 && strcmp(dns_output, "example.test 2001:db8::1\n") == 0);
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_NXDOMAIN;
    check("a name error for one record type is not a failure when the other type gave an address",
          run_resolve("192.0.2.53", one) == 0 && count_lines(dns_output) == 1);
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_NO_RECORDS;
    bx->dns_behaviour[1] = DNS_NO_RECORDS;
    check("a name with no address of either type is refused, and nothing is written", resolve_refused("example.test"));
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_NXDOMAIN;
    bx->dns_behaviour[1] = DNS_NXDOMAIN;
    check("a name that does not exist is refused", resolve_refused("example.test"));

    reset_behaviour();
    bx->dns_behaviour[0] = DNS_SERVFAIL;
    check("a resolver failure on the A query is refused", resolve_refused("example.test"));
    reset_behaviour();
    bx->dns_behaviour[1] = DNS_SERVFAIL;
    check("a resolver failure on the AAAA query is refused, however good the A answer was",
          resolve_refused("example.test"));
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_TRUNCATED;
    check("a truncated answer is refused rather than used in part", resolve_refused("example.test"));

    struct {
        int behaviour;
        const char *what;
    } unanswered[] = {
        { DNS_SILENT, "a resolver that never answers" },
        { DNS_WRONG_ID, "an answer with another query's id" },
        { DNS_WRONG_QUESTION, "an answer to another question" },
        { DNS_NOT_A_RESPONSE, "a packet that is not marked as a response" },
        { DNS_NONSTANDARD_OPCODE, "a response with an opcode that is not a query" },
        { DNS_TWO_QUESTIONS, "a response that claims two questions" },
    };
    for (size_t index = 0; index < sizeof(unanswered) / sizeof(unanswered[0]); index++) {
        reset_behaviour();
        bx->dns_behaviour[0] = unanswered[index].behaviour;
        char label[160];
        snprintf(label, sizeof(label), "%s is refused as timed out, after both tries", unanswered[index].what);
        check(label, resolve_refused("example.test") && bx->dns_queries == 2);
    }

    reset_behaviour();
    bx->dns_strays = 4;
    check("four packets that are not the answer are set aside and the answer after them is taken",
          run_resolve("192.0.2.53", one) == 0 && bx->dns_queries == 2);
    reset_behaviour();
    bx->dns_strays = 5;
    check("five packets that are not the answer count as no answer, in both tries",
          resolve_refused("example.test") && bx->dns_queries == 2);
    reset_behaviour();
    bx->recv_fails = 1;
    check("a receive that fails is no answer either", resolve_refused("example.test"));

    reset_behaviour();
    set_verbose(true);
    bx->dns_behaviour[0] = DNS_MANY;
    check("twenty addresses are cut to sixteen, the rest dropped",
          run_resolve("192.0.2.53", one) == 0 && count_lines(dns_output) == 16);
    reset_behaviour();
    bx->dns_behaviour[1] = DNS_MANY;
    check("sixteen is the limit for the name as a whole, IPv4 and IPv6 together",
          run_resolve("192.0.2.53", one) == 0 && count_lines(dns_output) == 16);
    set_verbose(false);

    reset_behaviour();
    bx->dns_behaviour[0] = DNS_ALIAS;
    bx->dns_behaviour[1] = DNS_ALIAS;
    check("an alias record is stepped over and the address after it is kept",
          run_resolve("192.0.2.53", one) == 0 && strcmp(dns_output, "example.test 192.0.2.1\nexample.test 2001:db8::1\n") == 0);
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_FOREIGN_OWNER;
    check("an address record that belongs to another name is not an address of the name asked",
          run_resolve("192.0.2.53", one) == 0 && strcmp(dns_output, "example.test 2001:db8::1\n") == 0);
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_FOREIGN_OWNER;
    bx->dns_behaviour[1] = DNS_FOREIGN_OWNER;
    check("an answer holding only records of another name leaves no address, and the run is refused",
          resolve_refused("example.test"));
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_ALIAS_CHAIN;
    bx->dns_behaviour[1] = DNS_ALIAS_CHAIN;
    check("a chain of aliases is followed to its address, whatever order the resolver wrote it in",
          run_resolve("192.0.2.53", one) == 0 && strcmp(dns_output, "example.test 192.0.2.1\nexample.test 2001:db8::1\n") == 0);
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_ALIAS_LOOP;
    bx->dns_behaviour[1] = DNS_ALIAS_LOOP;
    check("aliases that lead to each other end the lookup with no address", resolve_refused("example.test") && bx->dns_queries == 2);
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_ALIAS_DEEP;
    bx->dns_behaviour[1] = DNS_ALIAS_DEEP;
    check("a chain of aliases longer than eight is not followed to its end, so its address is not taken",
          resolve_refused("example.test"));
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_OWNER_WITH_DOT;
    check("a record whose one label holds a dot is refused, not read as the name it spells",
          resolve_refused("example.test") && bx->dns_queries == 1);
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_OWNER_WITH_ZERO;
    check("a record whose label holds a zero byte is refused, not read as a shorter name",
          resolve_refused("example.test") && bx->dns_queries == 1);
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_ALIAS_TARGET_CUT;
    check("an alias whose target runs past its data is refused", resolve_refused("example.test") && bx->dns_queries == 1);
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_TOO_MANY_RECORDS;
    check("an answer with more records than the limit is refused", resolve_refused("example.test") && bx->dns_queries == 1);
    reset_behaviour();
    bx->dns_poke_offset = 0;
    bx->dns_poke_value = 0xc0;
    bx->dns_poke_second = 30;
    check("a record name that points at itself is refused, not followed for ever",
          resolve_refused("example.test") && bx->dns_queries == 1);
    reset_behaviour();
    bx->dns_poke_offset = 0;
    bx->dns_poke_value = 0xc0;
    bx->dns_poke_second = 0xff;
    check("a record name that points past the end of the message is refused", resolve_refused("example.test") && bx->dns_queries == 1);
    reset_behaviour();
    bx->dns_poke_offset = 0;
    bx->dns_poke_value = 63;
    bx->dns_poke_second = 'x';
    check("a record name whose label runs past the end of the message is refused", resolve_refused("example.test") && bx->dns_queries == 1);
    reset_behaviour();
    bx->dns_poke_offset = 0;
    bx->dns_poke_value = 0;
    bx->dns_poke_second = 0;
    check("a record whose name is the root is not a record of the name asked", resolve_refused("example.test"));

    reset_behaviour();
    bx->dns_behaviour[0] = DNS_FOREIGN_CLASS;
    bx->dns_behaviour[1] = DNS_NO_RECORDS;
    check("a record of another class than the Internet one is not an address",
          run_resolve("192.0.2.53", one) == 0 && strcmp(dns_output, "example.test 192.0.2.2\n") == 0);
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_OTHER_TYPE;
    bx->dns_behaviour[1] = DNS_OTHER_TYPE;
    check("a record of another type in the answer is not an address of the asked type",
          run_resolve("192.0.2.53", one) == 0 && strcmp(dns_output, "example.test 192.0.2.1\nexample.test 2001:db8::1\n") == 0);
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_LABEL_OWNER;
    bx->dns_behaviour[1] = DNS_LABEL_OWNER;
    check("records named by labels, not a pointer, are read too", run_resolve("192.0.2.53", one) == 0 && count_lines(dns_output) == 3);

    reset_behaviour();
    bx->dns_cut_to = 20;
    check("a reply too short to hold the question is no answer, in both tries",
          resolve_refused("example.test") && bx->dns_queries == 2);

    reset_behaviour();
    bx->dns_count_override = 5;
    check("an answer that claims more records than it holds is refused", resolve_refused("example.test") && bx->dns_queries == 1);
    reset_behaviour();
    bx->dns_cut_to = 30 + 1;
    check("an answer cut inside a record's name is refused", resolve_refused("example.test") && bx->dns_queries == 1);
    reset_behaviour();
    bx->dns_cut_to = 30 + 2;
    check("an answer cut before a record's fixed part is refused", resolve_refused("example.test") && bx->dns_queries == 1);
    reset_behaviour();
    bx->dns_cut_to = 30 + 12 + 2;
    check("an answer cut inside a record's data is refused", resolve_refused("example.test") && bx->dns_queries == 1);
    reset_behaviour();
    bx->dns_poke_offset = 0;
    bx->dns_poke_value = 0x40;
    check("a record name with a label type nobody uses is refused", resolve_refused("example.test") && bx->dns_queries == 1);
    reset_behaviour();
    bx->dns_poke_offset = 11;
    bx->dns_poke_value = 3;
    check("an IPv4 record that is not four bytes long is refused", resolve_refused("example.test") && bx->dns_queries == 1);
    reset_behaviour();
    bx->dns_behaviour[0] = DNS_NO_RECORDS;
    bx->dns_poke_offset = 11;
    bx->dns_poke_value = 15;
    check("an IPv6 record that is not sixteen bytes long is refused", resolve_refused("example.test") && bx->dns_queries == 2);

    reset_behaviour();
    bx->socket_result = -1;
    check("a resolver socket that cannot be made is refused", resolve_refused("example.test"));
    reset_behaviour();
    bx->connect_result = -1;
    bx->connect_errno = ENETUNREACH;
    check("a resolver that cannot be connected to is refused", resolve_refused("example.test"));
    reset_behaviour();
    bx->send_fails = 1;
    check("a query that cannot be sent is refused", resolve_refused("example.test"));
    reset_behaviour();
    bx->getrandom_fails = 1;
    check("no random id is no query", resolve_refused("example.test"));

    const char *invalid[] = { "", "a..b", "bad!name.test", "-", ".", "x.", };
    bool invalid_all = true;
    for (size_t index = 0; index < 3; index++) {
        reset_behaviour();
        if (!resolve_refused(invalid[index])) {
            printf("      sent: %s\n", invalid[index]);
            invalid_all = false;
        }
    }
    check("an empty name, an empty label and a character no label may hold are never put in a query",
          invalid_all);
    char long_label[80];
    memset(long_label, 'a', 64);
    long_label[64] = '\0';
    reset_behaviour();
    check("a label of 64 characters is refused", resolve_refused(long_label));
    char long_name[300];
    memset(long_name, 'a', sizeof(long_name));
    for (size_t at = 50; at < sizeof(long_name); at += 50) {
        long_name[at] = '.';
    }
    long_name[sizeof(long_name) - 1] = '\0';
    reset_behaviour();
    check("a name beyond 253 characters is refused", resolve_refused(long_name));
    char *dotted[] = { "example.test.", NULL };
    reset_behaviour();
    check("a name with a trailing dot is sent as the same question", run_resolve("192.0.2.53", dotted) == 0 &&
              memcmp(bx->dns_query + 12, "\x07" "example\x04" "test", 13) == 0 && bx->dns_query[25] == 0);
    char *underscored[] = { "_sip._udp.example-1.test", NULL };
    reset_behaviour();
    check("a service name with underscores and a hyphen in a label is sent",
          run_resolve("192.0.2.53", underscored) == 0);

    reset_behaviour();
    char *two[] = { "first.test", "second.test", NULL };
    check("several names are resolved in one call, each line naming its name",
          run_resolve("192.0.2.53", two) == 0 && count_lines(dns_output) == 6 &&
              strstr(dns_output, "second.test 192.0.2.2") != NULL && bx->dns_queries == 4);
    reset_behaviour();
    bx->dns_behaviour[1] = DNS_SERVFAIL;
    check("when a later name fails, nothing is written, the earlier names included",
          !(run_resolve("192.0.2.53", two) == 0) && dns_output[0] == '\0');

    reset_behaviour();
    char *many_names[RESOLVE_NAMES_MAXIMUM + 2];
    for (size_t index = 0; index < RESOLVE_NAMES_MAXIMUM + 1; index++) {
        many_names[index] = "example.test";
    }
    many_names[RESOLVE_NAMES_MAXIMUM + 1] = NULL;
    check("more names than the limit are refused before any is asked",
          run_resolve("192.0.2.53", many_names) == EXIT_CODE_SETUP_ERROR && bx->dns_queries == 0);
    char *exactly_limit[RESOLVE_NAMES_MAXIMUM + 1];
    for (size_t index = 0; index < RESOLVE_NAMES_MAXIMUM; index++) {
        exactly_limit[index] = "example.test";
    }
    exactly_limit[RESOLVE_NAMES_MAXIMUM] = NULL;
    reset_behaviour();
    check("exactly the limit of names is resolved", run_resolve("192.0.2.53", exactly_limit) == 0);

    reset_behaviour();
    check("a resolver that cannot be read is refused before any query",
          run_resolve("example.com", one) == EXIT_CODE_SETUP_ERROR && bx->dns_queries == 0);
    reset_behaviour();
    check("no resolver at all is refused", run_resolve(NULL, one) == EXIT_CODE_SETUP_ERROR);

    struct guard_options parsed;
    char *resolving[] = { "guard", "--resolve", "--resolver", "192.0.2.53:5353", "--", "example.test", NULL };
    parse_arguments(6, resolving, &parsed);
    check("--resolve with --resolver keeps the names after -- as the arguments",
          parsed.resolve && strcmp(parsed.resolver_endpoint, "192.0.2.53:5353") == 0 &&
              strcmp(parsed.command[0], "example.test") == 0);
    char *dangling_resolver[] = { "guard", "--resolver", NULL };
    check("a --resolver with no value is a usage error", run_main(dangling_resolver) == EXIT_CODE_USAGE);
    reset_behaviour();
    bx->dns_active = 1;
    check("the program in resolve mode ends with the status of the lookup",
          run_main(resolving) == 0);
    bx->dns_active = 0;
    char *plain_parse[] = { "guard", "--", "cmd", NULL };
    parse_arguments(3, plain_parse, &parsed);
    check("a normal call is not in resolve mode", !parsed.resolve && parsed.resolver_endpoint == NULL);
}

/* The datagram sends and connects are made by the supervisor and never continued in the command,
 * so a second thread cannot change the destination after it was judged. */
static void test_datagram_mediation(void) {
    test_datagram_sendto();
    test_datagram_provenance();
    test_datagram_kernel_answers();
    test_datagram_sendmsg();
    test_datagram_sendmmsg();
    test_datagram_connect();
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

    reset_behaviour();
    bx->notif_send_eintr = 2;
    answer(FAKE_NOTIFY_DESCRIPTOR, &response, 1, 0, -EACCES);
    check("an answer a signal interrupts is sent again until it is delivered",
          bx->answers == 3 && bx->notif_send_eintr == 0 && bx->last_answer_error == -EACCES
              && bx->last_answer_flags == 0);

    reset_behaviour();
    memset(&response, 0, sizeof(response));
    response.error = -EACCES;
    bx->notif_send_eintr = 1;
    bool refusal_sent = send_notification_response(FAKE_NOTIFY_DESCRIPTOR, &response);
    check("the shared send sends a refusal exactly as given, never adding the continue flag",
          refusal_sent && bx->answers == 2 && bx->last_answer_flags == 0
              && bx->last_answer_error == -EACCES && response.flags == 0);
    reset_behaviour();
    response.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    response.error = 0;
    bool continue_sent = send_notification_response(FAKE_NOTIFY_DESCRIPTOR, &response);
    check("and a continue exactly as given",
          continue_sent && bx->last_answer_flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);
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
    struct guard_options parsed;
    char *ephemeral[] = { "guard", "--allow-ephemeral-listen", "--", "cmd", NULL };
    parse_arguments(4, ephemeral, &parsed);
    check("--allow-ephemeral-listen is read", parsed.allow_ephemeral_listen);
    char *ephemeral_udp[] = { "guard", "--allow-ephemeral-udp-bind", "--", "cmd", NULL };
    parse_arguments(4, ephemeral_udp, &parsed);
    check("--allow-ephemeral-udp-bind is read", parsed.allow_ephemeral_udp_bind);
    char *plain[] = { "guard", "--", "cmd", NULL };
    parse_arguments(3, plain, &parsed);
    check("an unbound socket may not listen unless the option is given", !parsed.allow_ephemeral_listen);
    check("an unbound datagram socket may not connect or send unless the option is given",
          !parsed.allow_ephemeral_udp_bind);

    char *dangling_broker[] = { "guard", "--broker", NULL };
    check("a --broker with no value is a usage error", run_main(dangling_broker) == EXIT_CODE_USAGE);
    char *bad_broker[] = { "guard", "--broker", "not-an-endpoint", "--", "cmd", NULL };
    check("a broker endpoint that will not parse refuses the run",
          run_main(bad_broker) == EXIT_CODE_SETUP_ERROR);
}

/* Setup failures before the command runs. A fork result of 0 takes the child path. */
/* Runs the filter the child installed against one seccomp_data and answers what it returns.
 * A classic BPF program of this shape is four instruction forms: load a word of the data,
 * compare the accumulator with a constant, test bits of it, and return. Anything else is a
 * form this filter does not use, and answering zero for it makes the case fail rather than
 * quietly pass. Assumes a case has already run the child, so a filter was captured. */
static uint64_t filter_fifth_argument = 0;

static uint32_t run_captured_filter(const struct sock_filter *program, unsigned short length,
                                    uint32_t audit_arch, int syscall_number,
                                    uint64_t first_argument) {
    struct seccomp_data data;
    memset(&data, 0, sizeof(data));
    data.arch = audit_arch;
    data.nr = syscall_number;
    data.args[0] = first_argument;
    data.args[4] = filter_fifth_argument;
    uint32_t accumulator = 0;
    for (unsigned short at = 0; at < length; at++) {
        const struct sock_filter *instruction = &program[at];
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

/* The first filter's answer for a call under the given ABI, with the first argument zero. */
static uint32_t filter_answer(uint32_t audit_arch, int syscall_number) {
    return run_captured_filter(bx->installed_filter, bx->installed_filter_length, audit_arch,
                               syscall_number, 0);
}

/* The first filter's answer for a call whose first argument, a descriptor, decides it: the
 * sendmsg exception is allowed only on the bootstrap descriptor and trapped on every other. */
static uint32_t filter_answer_fd(uint32_t audit_arch, int syscall_number, uint64_t first_argument) {
    return run_captured_filter(bx->installed_filter, bx->installed_filter_length, audit_arch,
                               syscall_number, first_argument);
}

/* The lockout filter's answer for a native-ABI call whose first argument is a descriptor. */
static uint32_t lockout_answer(int syscall_number, uint64_t first_argument) {
    return run_captured_filter(bx->installed_filter2, bx->installed_filter2_length,
                               GUARD_NATIVE_AUDIT_ARCH, syscall_number, first_argument);
}

/* What the two stacked filters answer together for a native-ABI call: the kernel takes the
 * action with the lowest value, so the composition is the smaller of the two answers. */
static uint32_t combined_answer(int syscall_number, uint64_t first_argument) {
    uint32_t first = filter_answer_fd(GUARD_NATIVE_AUDIT_ARCH, syscall_number, first_argument);
    uint32_t second = lockout_answer(syscall_number, first_argument);
    return first < second ? first : second;
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
/* The twelve-byte PROXY protocol version 2 signature, a copy so the test can recognise the
 * header the guard builds without reaching into the module's own constant. */
static const unsigned char PROXY_V2_SIGNATURE_FOR_TEST[12] = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
};

/* Drives one allowed stream connect with a broker configured, so connect_on_behalf redirects it,
 * and returns after service_once. The destination is 127.0.0.1 or 2001:db8::1 by the family. */
static void drive_broker_stream_connect(int family, uint16_t port, const char *rule_host) {
    reset_behaviour();
    configure_broker("127.0.0.1:3128");
    bx->notif_recv_family = family;
    bx->notif_recv_port = port;
    bx->notif_recv_target_fd = 6;
    bx->process_vm_readv_result = 1;
    bx->readlink_inode = TRACKED_STREAM_INODE;
    record_socket_type(TRACKED_STREAM_INODE, FD_TYPE_STREAM);
    remember_rule(rule_host, "443", false);
    service_once();
}

/* The broker handoff: with a broker configured, an allowed stream connect goes to the broker
 * rather than the destination, and a PROXY protocol v2 header naming the destination is sent
 * before the command's own bytes. */
static void test_broker_handoff(void) {
    check("a broker endpoint with an IPv4 address and port is accepted",
          configure_broker("127.0.0.1:3128"));
    check("a broker endpoint with a bracketed IPv6 address is accepted",
          configure_broker("[::1]:3128"));
    check("a broker endpoint with no port is refused", !configure_broker("127.0.0.1"));
    check("a broker endpoint whose bracket does not close is refused", !configure_broker("[::1"));
    check("a broker endpoint with an empty bracketed host is refused", !configure_broker("[]:3128"));
    check("a broker endpoint on port zero is refused", !configure_broker("127.0.0.1:0"));
    check("a broker endpoint whose port is not a number is refused",
          !configure_broker("127.0.0.1:abc"));
    check("a broker endpoint whose host is not an address is refused",
          !configure_broker("notanip:3128"));

    reset_behaviour();
    configure_broker("127.0.0.1:3128");
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 443;
    bx->notif_recv_v4_addr = 0xC0000207; /* 192.0.2.7, a documentation address distinct from loopback */
    bx->notif_recv_target_fd = 6;
    bx->process_vm_readv_result = 1;
    bx->readlink_inode = TRACKED_STREAM_INODE;
    record_socket_type(TRACKED_STREAM_INODE, FD_TYPE_STREAM);
    remember_rule("192.0.2.7", "443", false);
    service_once();
    check("an allowed stream connect goes to the broker, not the destination",
          bx->connect_calls == 1 && bx->last_connect_port == 3128 &&
              bx->last_connect_family == AF_INET && bx->addfd_calls == 1 &&
              bx->last_answer_error == 0);
    uint16_t header_dst_port = 0;
    memcpy(&header_dst_port, &bx->captured_header[26], 2);
    check("the header names the IPv4 destination and port over a loopback source, not swapped",
          bx->captured_header_length == 28 &&
              memcmp(bx->captured_header, PROXY_V2_SIGNATURE_FOR_TEST, 12) == 0 &&
              bx->captured_header[13] == 0x11 &&
              bx->captured_header[16] == 127 && bx->captured_header[17] == 0 &&
              bx->captured_header[18] == 0 && bx->captured_header[19] == 1 &&
              bx->captured_header[20] == 192 && bx->captured_header[21] == 0 &&
              bx->captured_header[22] == 2 && bx->captured_header[23] == 7 &&
              ntohs(header_dst_port) == 443);

    drive_broker_stream_connect(AF_INET6, 443, "2001:db8::1");
    check("an IPv6 destination is carried in an IPv6 PROXY v2 header, distinct from the loopback source",
          bx->addfd_calls == 1 && bx->last_answer_error == 0 &&
              bx->captured_header_length == 52 && bx->captured_header[13] == 0x21 &&
              bx->captured_header[16] == 0 && bx->captured_header[31] == 1 &&
              bx->captured_header[32] == 0x20 && bx->captured_header[33] == 0x01 &&
              bx->captured_header[34] == 0x0d && bx->captured_header[35] == 0xb8 &&
              bx->captured_header[47] == 1);

    reset_behaviour();
    configure_broker("127.0.0.1:3128");
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 443;
    bx->notif_recv_target_fd = 6;
    bx->process_vm_readv_result = 1;
    bx->readlink_inode = TRACKED_STREAM_INODE;
    record_socket_type(TRACKED_STREAM_INODE, FD_TYPE_STREAM);
    remember_rule("127.0.0.1", "443", false);
    bx->send_fails = 1;
    service_once();
    check("a broker whose header cannot be sent refuses the connect and injects nothing",
          bx->last_answer_error == -ECONNREFUSED && bx->addfd_calls == 0);

    reset_behaviour();
    configure_broker("127.0.0.1:3128");
    bx->notif_recv_family = AF_INET;
    bx->notif_recv_port = 443;
    bx->notif_recv_target_fd = 6;
    bx->process_vm_readv_result = 1;
    bx->readlink_inode = TRACKED_STREAM_INODE;
    record_socket_type(TRACKED_STREAM_INODE, FD_TYPE_STREAM);
    remember_rule("127.0.0.1", "443", false);
    bx->send_short_once = 1;
    bx->send_eintr_once = 1;
    service_once();
    check("the header send retries a short write and an interruption, then completes",
          bx->addfd_calls == 1 && bx->last_answer_error == 0 && bx->send_calls >= 3 &&
              bx->captured_header_length == 28);
}

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
    check("listen is trapped to the supervisor, which runs it itself",
          filter_answer(GUARD_NATIVE_AUDIT_ARCH, __NR_listen) == SECCOMP_RET_USER_NOTIF);
    filter_fifth_argument = FAKE_ADDRESS_POINTER;
    check("a sendto that names a destination is trapped to the supervisor",
          filter_answer(GUARD_NATIVE_AUDIT_ARCH, __NR_sendto) == SECCOMP_RET_USER_NOTIF);
    filter_fifth_argument = (uint64_t)1 << 32;
    check("a sendto whose address pointer has only its high word set is trapped, not read as null",
          filter_answer(GUARD_NATIVE_AUDIT_ARCH, __NR_sendto) == SECCOMP_RET_USER_NOTIF);
    filter_fifth_argument = 0;
    check("a sendto with no destination is the send of a connected socket and is allowed",
          filter_answer(GUARD_NATIVE_AUDIT_ARCH, __NR_sendto) == SECCOMP_RET_ALLOW);
    check("sendmmsg is trapped to the supervisor",
          filter_answer(GUARD_NATIVE_AUDIT_ARCH, __NR_sendmmsg) == SECCOMP_RET_USER_NOTIF);
    check("sendmsg on the bootstrap descriptor is allowed, so the handoff is not parked",
          filter_answer_fd(GUARD_NATIVE_AUDIT_ARCH, __NR_sendmsg, FAKE_BOOTSTRAP_DESCRIPTOR)
              == SECCOMP_RET_ALLOW);
    check("sendmsg on any other descriptor is trapped to the supervisor",
          filter_answer_fd(GUARD_NATIVE_AUDIT_ARCH, __NR_sendmsg, FAKE_BOOTSTRAP_DESCRIPTOR + 1)
              == SECCOMP_RET_USER_NOTIF);
    check("sendmsg whose descriptor has a high word set is trapped, not read as the bootstrap one",
          filter_answer_fd(GUARD_NATIVE_AUDIT_ARCH, __NR_sendmsg,
                           ((uint64_t)1 << 32) | (uint64_t)FAKE_BOOTSTRAP_DESCRIPTOR)
              == SECCOMP_RET_USER_NOTIF);

    check("the lockout filter denies sendmsg on the bootstrap descriptor",
          lockout_answer(__NR_sendmsg, FAKE_BOOTSTRAP_DESCRIPTOR) == deny);
    check("the lockout filter leaves the trap in force on any other descriptor",
          lockout_answer(__NR_sendmsg, FAKE_BOOTSTRAP_DESCRIPTOR + 1) == SECCOMP_RET_ALLOW);
    check("the lockout filter reads the descriptor as two words, so a high word is not the bootstrap one",
          lockout_answer(__NR_sendmsg, ((uint64_t)1 << 32) | (uint64_t)FAKE_BOOTSTRAP_DESCRIPTOR)
              == SECCOMP_RET_ALLOW);
    check("the lockout filter does not touch a non-sendmsg call",
          lockout_answer(__NR_read, 0) == SECCOMP_RET_ALLOW);

    check("the two filters compose to a refusal on the bootstrap descriptor",
          combined_answer(__NR_sendmsg, FAKE_BOOTSTRAP_DESCRIPTOR) == deny);
    check("the two filters compose to a trap on any other descriptor",
          combined_answer(__NR_sendmsg, FAKE_BOOTSTRAP_DESCRIPTOR + 1) == SECCOMP_RET_USER_NOTIF);

    reset_behaviour();
    bx->dup2_fails = 1;
    bx->execvp_returns = 1;
    bx->fork_result = 0;
    (void)run_main((char *[]){ "guard", "--", "cmd", NULL });
    check("when the bootstrap descriptor cannot be moved, the original number is used",
          filter_answer_fd(GUARD_NATIVE_AUDIT_ARCH, __NR_sendmsg, FAKE_SOCKETPAIR_SECOND_END)
              == SECCOMP_RET_ALLOW);

    reset_behaviour();
    bx->getrlimit_result = -1;
    bx->execvp_returns = 1;
    bx->fork_result = 0;
    (void)run_main((char *[]){ "guard", "--", "cmd", NULL });
    check("with no descriptor limit to read, the bootstrap descriptor moves to the floor",
          filter_answer_fd(GUARD_NATIVE_AUDIT_ARCH, __NR_sendmsg, FAKE_BOOTSTRAP_DESCRIPTOR)
              == SECCOMP_RET_ALLOW);

    reset_behaviour();
    bx->rlimit_nofile_cur = FAKE_SMALL_NOFILE;
    bx->execvp_returns = 1;
    bx->fork_result = 0;
    (void)run_main((char *[]){ "guard", "--", "cmd", NULL });
    check("under a descriptor limit below the floor, the bootstrap descriptor stays within it",
          filter_answer_fd(GUARD_NATIVE_AUDIT_ARCH, __NR_sendmsg, FAKE_SMALL_BOOTSTRAP)
              == SECCOMP_RET_ALLOW);
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
    bx->sendmsg_lockout_result = -1;
    check("a sendmsg lockout that will not install fails the child closed",
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

    reset_behaviour();
    bx->fork_result = FAKE_CHILD_PID;
    bx->waitpid_echild = 1;
    check("a status that cannot be read ends the run with PHB-ESTATUS, never with 0",
          run_main(argv) == EXIT_CODE_STATUS_UNREAD);

    reset_behaviour();
    bx->fork_result = FAKE_CHILD_PID;
    (void)run_main(argv);
    check("the supervisor takes SIGCHLD's default before it forks, and gives nothing back itself",
          bx->child_signal_taken == 1 && bx->child_signal_restored == 0);

    reset_behaviour();
    bx->fork_result = 0;
    (void)run_main(argv);
    check("and the child gives back the disposition it inherited before it becomes the command",
          bx->child_signal_taken == 1 && bx->child_signal_restored == 1);

    reset_behaviour();
    bx->fork_result = FAKE_CHILD_PID;
    bx->recvmsg_result = -1;
    bx->waitpid_echild = 1;
    check("and a run refused before supervision with an unread status still ends refused",
          run_main(argv) == EXIT_CODE_SETUP_ERROR);

    reset_behaviour();
    bx->fork_result = FAKE_CHILD_PID;
    check("the supervisor takes SIGTERM, SIGHUP, SIGINT and SIGQUIT, passes each on to the command while it exists and to no one once it is reaped",
          signals_taken_and_passed_on(argv) == SIGNALS_PASSED_ON);
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
    test_format_endpoint();
    test_exit_code_mapping();
    test_child_signal_disposition();
    test_verbose_logging();
    test_read_peer_address_edges();
    test_receive_descriptor();
    test_service_paths();
    test_egress_syscalls();
    test_socket_tracking();
    test_listen_closure();
    test_datagram_mediation();
    test_resolve_mode();
    test_connect_on_behalf_paths();
    test_broker_handoff();
    test_supervise_loop();
    test_argument_errors();
    test_egress_filter();
    test_child_setup_failures();
    test_parent_paths();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
