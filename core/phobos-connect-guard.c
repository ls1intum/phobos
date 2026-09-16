/*
 * phobos-connect-guard -- supervise every connect() a sandboxed command makes,
 * so egress can be allowed or refused by host address, which Landlock, enforcing
 * by port alone, cannot do.
 *
 * Usage:
 *   phobos-connect-guard [--verbose] [--rules FILE] -- COMMAND [ARGUMENTS...]
 *
 * It is one process that becomes two. It forks: the child is the sandboxed
 * lineage and the parent is the supervisor beside it.
 *
 *   parent  the supervisor. Never restricted. Reads each connect notification,
 *           decides against the allow-list, and for an allowed connection makes
 *           the connection itself and hands the connected socket back. Ignores
 *           SIGTERM and waits for the child, so an outer timeout's kill escalation
 *           reaches the command, then exits with the child's status.
 *   child   installs a seccomp filter that traps connect() to a user-notification
 *           file descriptor, sends that descriptor up to the supervisor, and execs
 *           the rest of the layer chain. The filter, and so the supervision,
 *           survives every exec down to the command.
 *
 * Why the supervisor connects on the command's behalf rather than letting the
 * kernel continue the trapped call (SECCOMP_USER_NOTIF_FLAG_CONTINUE): a continue
 * re-runs the original syscall against whatever is in the command's memory at that
 * later moment, so a command could show one address to the check and connect to
 * another once it passes. Making the connection here, from the address the check
 * read, closes that window. The command never runs connect() itself.
 *
 * seccomp intercepts a connect at the syscall boundary, before the kernel path
 * where Landlock would check the port, and this supervisor then connects outside
 * Landlock. So where this guard runs it is the whole connect boundary, host and
 * port, and it enforces both from the allow-list rather than leaving the port to
 * Landlock. What it can enforce that a submission cannot step around is limited by
 * what it sees: it reads the destination address of the connect, so it holds a
 * rule that names an IP literal (and the loopback name) to that exact address, and
 * a rule that names a DNS hostname it cannot tie to an address here to the port
 * alone. The host of a hostname rule stays libnetblocker's softer, in-process job.
 *
 * It needs no privileges: with no_new_privs set, an ordinary process may install a
 * user-notification filter, and it reads the peer address and injects the socket
 * with process_vm_readv(2) and SECCOMP_IOCTL_NOTIF_ADDFD, both of which a parent
 * may do to its own child in an ordinary container. No CAP_SYS_ADMIN, no
 * capability, no container flag.
 *
 * It fails closed. If the filter cannot be installed, or the supervisor cannot be
 * handed the notification descriptor, the run is refused rather than left to run
 * with connect() unsupervised. A connect of a family it does not carry (a
 * UNIX-domain socket, say) is refused rather than made outside the Landlock view
 * the command is held to.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

/* Older kernel headers describe user-notification without the addfd ioctl that
 * lets the supervisor inject a socket. The run-phase image is new enough, but the
 * fallbacks keep the file buildable where the headers are not, matching how the
 * Landlock sources define what they use rather than assuming the headers carry it. */
#ifndef SECCOMP_ADDFD_FLAG_SETFD
#define SECCOMP_ADDFD_FLAG_SETFD (1UL << 0)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_ADDFD
struct seccomp_notif_addfd {
    __u64 id;
    __u32 flags;
    __u32 srcfd;
    __u32 newfd;
    __u32 newfd_flags;
};
#define SECCOMP_IOCTL_NOTIF_ADDFD _IOW('!', 3, struct seccomp_notif_addfd)
#endif

/* The one native ABI this build's connect number belongs to. The filter denies every other
 * ABI, so a connect made through an alternate one (i386 int 0x80, or x32) cannot slip past the
 * native-number comparison unwatched. */
#if defined(__x86_64__)
#define GUARD_NATIVE_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define GUARD_NATIVE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "phobos-connect-guard supports x86-64 and aarch64 only"
#endif

static constexpr int EXIT_SETUP_ERROR = 125;
static constexpr int CONNECT_TIMEOUT_MS = 10000;
static constexpr size_t MAXIMUM_RULES = 256;
static constexpr size_t MAXIMUM_HOST = 256;

static bool verbose = false;

static void log_verbose(const char *format, ...) __attribute__((format(printf, 1, 2)));

static void log_verbose(const char *format, ...)
{
    if (!verbose) {
        return;
    }
    va_list arguments;
    va_start(arguments, format);
    fputs("[phobos-connect-guard] ", stderr);
    vfprintf(stderr, format, arguments);
    fputc('\n', stderr);
    va_end(arguments);
}

/* ------------------------------------------------- the allow-list, read once */

/* One line of the outbound allow-list: a host and the port it is allowed on. */
struct connect_rule {
    char host[MAXIMUM_HOST];
    bool any_port;
    uint16_t port;
};

static struct connect_rule connect_rules[MAXIMUM_RULES];
static size_t connect_rule_count = 0;

/* Records one "host port" line, unless the table is full or the line is malformed. */
static void remember_rule(const char *host, const char *port_text)
{
    if (connect_rule_count >= MAXIMUM_RULES || strlen(host) >= MAXIMUM_HOST) {
        return;
    }
    struct connect_rule *rule = &connect_rules[connect_rule_count];
    memset(rule, 0, sizeof(*rule));
    snprintf(rule->host, sizeof(rule->host), "%s", host);
    if (strcmp(port_text, "*") == 0) {
        rule->any_port = true;
        connect_rule_count++;
        return;
    }
    char *unconverted = nullptr;
    unsigned long value = strtoul(port_text, &unconverted, 10);
    if (*unconverted != '\0' || value == 0 || value > 65535) {
        return;
    }
    rule->any_port = false;
    rule->port = (uint16_t)value;
    connect_rule_count++;
}

/* Reads the allow-list from the spec's net.rules, one "host port" line each. An absent file
 * leaves the list empty, which means no restriction, the way libnetblocker treats an empty
 * outbound policy. Returns false only when a rules file was named but could not be read for a
 * reason other than its absence, so the caller refuses the run rather than fall open to
 * allow-all on an unreadable policy. */
static bool load_rules(const char *path)
{
    if (path == nullptr) {
        return true;
    }
    FILE *file = fopen(path, "re");
    if (file == nullptr) {
        return errno == ENOENT;
    }
    char line[512];
    while (fgets(line, sizeof(line), file) != nullptr) {
        char host[MAXIMUM_HOST] = "";
        char port_text[16] = "";
        if (sscanf(line, "%255s %15s", host, port_text) == 2) {
            remember_rule(host, port_text);
        }
    }
    fclose(file);
    return true;
}

/* -------------------------------------------------------- the address decision */

static bool address_is_loopback(int family, const void *address)
{
    if (family == AF_INET) {
        const struct in_addr *v4 = address;
        return (ntohl(v4->s_addr) >> 24) == 127;
    }
    if (family == AF_INET6) {
        const struct in6_addr *v6 = address;
        return IN6_IS_ADDR_LOOPBACK(v6);
    }
    return false;
}

/* Whether one rule's host covers this destination address. An IP literal, and the
 * name "localhost", are held to the exact address; any other hostname is one this
 * guard cannot tie to an address, so its host is not enforced here and the rule
 * rests on its port alone. */
static bool rule_host_matches(const struct connect_rule *rule, int family, const void *address)
{
    if (strcmp(rule->host, "*") == 0) {
        return true;
    }
    struct in_addr v4;
    if (inet_pton(AF_INET, rule->host, &v4) == 1) {
        return family == AF_INET && memcmp(address, &v4, sizeof(v4)) == 0;
    }
    struct in6_addr v6;
    if (inet_pton(AF_INET6, rule->host, &v6) == 1) {
        return family == AF_INET6 && memcmp(address, &v6, sizeof(v6)) == 0;
    }
    if (strcmp(rule->host, "localhost") == 0) {
        return address_is_loopback(family, address);
    }
    return true;
}

/* Whether the allow-list permits a connection to this destination. An empty list
 * is no restriction; otherwise a rule permits it when its port covers the port and
 * its host covers the address. */
static bool connection_permitted(int family, const void *address, uint16_t port)
{
    if (connect_rule_count == 0) {
        return true;
    }
    for (size_t index = 0; index < connect_rule_count; index++) {
        const struct connect_rule *rule = &connect_rules[index];
        if (!rule->any_port && rule->port != port) {
            continue;
        }
        if (rule_host_matches(rule, family, address)) {
            return true;
        }
    }
    return false;
}

/* ------------------------------------------- the child: install and hand over */

/* The filter: refuse a syscall made on any but the native ABI, trap connect() to the
 * supervisor, and allow everything else. The arch check is what makes the trap cover every
 * connect: without it an i386 (int 0x80) socketcall or an x32 connect arrives under a different
 * arch or with the x32 bit set, does not equal the native connect number, and would fall
 * through to ALLOW unwatched. The program cannot read the address (it is behind a pointer the
 * filter may not follow), so it traps every connect and leaves the address to the supervisor,
 * which can read the child's memory. */
static int install_connect_filter(void)
{
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, GUARD_NATIVE_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#ifdef __X32_SYSCALL_BIT
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, __X32_SYSCALL_BIT, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA)),
#endif
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
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
static bool send_descriptor(int socket_descriptor, int descriptor_to_send)
{
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

/* The child. Installs the filter, sends its notification descriptor up, then
 * becomes the rest of the chain. Never returns: it execs, or it exits. */
[[noreturn]] static void run_child(int send_descriptor_to_parent, char *const command[])
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "[phobos-connect-guard] prctl(NO_NEW_PRIVS): %s\n", strerror(errno));
        _exit(EXIT_SETUP_ERROR);
    }
    int notify_descriptor = install_connect_filter();
    if (notify_descriptor < 0) {
        fprintf(stderr, "[phobos-connect-guard] seccomp NEW_LISTENER: %s\n", strerror(errno));
        _exit(EXIT_SETUP_ERROR);
    }
    if (!send_descriptor(send_descriptor_to_parent, notify_descriptor)) {
        fprintf(stderr, "[phobos-connect-guard] handing the notification descriptor up: %s\n",
                strerror(errno));
        _exit(EXIT_SETUP_ERROR);
    }
    close(notify_descriptor);
    close(send_descriptor_to_parent);

    execvp(command[0], command);
    fprintf(stderr, "[phobos-connect-guard] exec %s: %s\n", command[0], strerror(errno));
    _exit(127);
}

/* -------------------------------------------- the parent: receive and service */

/* Receive the one descriptor the child sends. Returns it, or -1 on any failure,
 * including the child exiting before it sent one (an end of file here). */
static int receive_descriptor(int socket_descriptor)
{
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

/* Complete one trapped connect: tell the kernel the answer for this notification.
 * A negative error is returned to the command as connect()'s errno; error 0 with
 * value 0 is a success. A send that finds the command already gone is not a failure
 * of ours. */
static void answer(int notify_descriptor, struct seccomp_notif_resp *response, __u64 id,
                   __s64 value, __s32 error)
{
    memset(response, 0, sizeof(*response));
    response->id = id;
    response->val = value;
    response->error = error;
    response->flags = 0;
    if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_SEND, response) != 0 && errno != ENOENT) {
        log_verbose("notify send: %s", strerror(errno));
    }
}

/* Read the peer address out of the command's memory. Returns the length read, or 0
 * if it could not be read or is too short to carry a family. */
static socklen_t read_peer_address(pid_t command_pid, uintptr_t address_pointer,
                                   socklen_t claimed_length, struct sockaddr_storage *out)
{
    socklen_t length = claimed_length;
    if (length > sizeof(*out)) {
        length = sizeof(*out);
    }
    if (length < sizeof(sa_family_t)) {
        return 0;
    }
    struct iovec local = { .iov_base = out, .iov_len = length };
    struct iovec remote = { .iov_base = (void *)address_pointer, .iov_len = length };
    ssize_t read_count = process_vm_readv(command_pid, &local, 1, &remote, 1, 0);
    if (read_count < 0 || (socklen_t)read_count != length) {
        return 0;
    }
    return length;
}

/* Connect a fresh socket to the destination, within a bounded wait so one slow connection
 * cannot stall the supervisor. Returns the connected descriptor, cleared back to blocking as
 * an ordinary socket is, or a negative errno. This is a fresh socket, so options the command
 * set on its own before connecting, and a non-blocking mode, are not carried onto it: that is
 * the documented limit of connecting on the command's behalf rather than letting it connect. */
static int connect_within_deadline(int family, const struct sockaddr *address, socklen_t length)
{
    int outward = socket(family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (outward < 0) {
        return -errno;
    }
    if (connect(outward, address, length) == 0) {
        (void)fcntl(outward, F_SETFL, fcntl(outward, F_GETFL) & ~O_NONBLOCK);
        return outward;
    }
    if (errno != EINPROGRESS) {
        int failure = errno;
        close(outward);
        return -failure;
    }
    struct pollfd waiting = { .fd = outward, .events = POLLOUT, .revents = 0 };
    int ready;
    do {
        ready = poll(&waiting, 1, CONNECT_TIMEOUT_MS);
    } while (ready < 0 && errno == EINTR);
    if (ready <= 0) {
        int failure = errno;
        close(outward);
        return ready == 0 ? -ETIMEDOUT : -failure;
    }
    int socket_error = 0;
    socklen_t error_length = sizeof(socket_error);
    if (getsockopt(outward, SOL_SOCKET, SO_ERROR, &socket_error, &error_length) != 0) {
        int failure = errno;
        close(outward);
        return -failure;
    }
    if (socket_error != 0) {
        close(outward);
        return -socket_error;
    }
    (void)fcntl(outward, F_SETFL, fcntl(outward, F_GETFL) & ~O_NONBLOCK);
    return outward;
}

/* Make the allowed connection here and inject the connected socket back over the
 * descriptor number the command called connect() on, so the command's connect()
 * returns 0 with a socket already connected to the address the check saw. */
static void connect_on_behalf(int notify_descriptor, struct seccomp_notif_resp *response,
                              __u64 id, int target_descriptor, int family,
                              const struct sockaddr *address, socklen_t length)
{
    int outward = connect_within_deadline(family, address, length);
    if (outward < 0) {
        answer(notify_descriptor, response, id, 0, outward);
        return;
    }
    struct seccomp_notif_addfd addfd;
    memset(&addfd, 0, sizeof(addfd));
    addfd.id = id;
    addfd.flags = SECCOMP_ADDFD_FLAG_SETFD;
    addfd.srcfd = (__u32)outward;
    addfd.newfd = (__u32)target_descriptor;
    addfd.newfd_flags = 0;
    if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd) < 0) {
        if (errno != ENOENT) {
            answer(notify_descriptor, response, id, 0, -errno);
        }
        close(outward);
        return;
    }
    close(outward);
    answer(notify_descriptor, response, id, 0, 0);
}

/* The family, address pointer and port of a destination read from the command. */
struct destination {
    int family;
    const void *address;
    uint16_t port;
};

static struct destination read_destination(const struct sockaddr_storage *storage)
{
    struct destination where = { .family = storage->ss_family, .address = nullptr, .port = 0 };
    if (storage->ss_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)storage;
        where.address = &v4->sin_addr;
        where.port = ntohs(v4->sin_port);
    } else if (storage->ss_family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)storage;
        where.address = &v6->sin6_addr;
        where.port = ntohs(v6->sin6_port);
    }
    return where;
}

/* Service one connect notification end to end. */
static void service_one(int notify_descriptor, struct seccomp_notif *request,
                        struct seccomp_notif_resp *response, size_t request_size)
{
    memset(request, 0, request_size);
    if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_RECV, request) != 0) {
        return;
    }

    int target_descriptor = (int)request->data.args[0];
    uintptr_t address_pointer = (uintptr_t)request->data.args[1];
    socklen_t claimed_length = (socklen_t)request->data.args[2];

    struct sockaddr_storage storage;
    memset(&storage, 0, sizeof(storage));
    socklen_t length = read_peer_address(request->pid, address_pointer, claimed_length, &storage);

    /* Confirm the command is still parked on this exact call before acting on what
     * was read: if the notification is no longer valid the memory read may be of
     * another call's making, so it is not trusted. */
    if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_ID_VALID, &request->id) != 0) {
        return;
    }
    if (length == 0) {
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }

    struct destination where = read_destination(&storage);
    if (where.family != AF_INET && where.family != AF_INET6) {
        log_verbose("refusing connect of family %d, which this guard does not carry", where.family);
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }
    if (!connection_permitted(where.family, where.address, where.port)) {
        log_verbose("refusing connect to a destination the allow-list does not name, port %u",
                    (unsigned)where.port);
        answer(notify_descriptor, response, request->id, 0, -EACCES);
        return;
    }
    connect_on_behalf(notify_descriptor, response, request->id, target_descriptor, where.family,
                      (const struct sockaddr *)&storage, length);
}

/* Wait on the notification descriptor and service it until the sandboxed lineage is
 * gone, which the kernel signals as a hangup once every process the filter covers
 * has exited. */
static void supervise(int notify_descriptor)
{
    struct seccomp_notif_sizes sizes;
    memset(&sizes, 0, sizeof(sizes));
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0) {
        sizes.seccomp_notif = sizeof(struct seccomp_notif);
        sizes.seccomp_notif_resp = sizeof(struct seccomp_notif_resp);
    }
    size_t request_size = sizes.seccomp_notif;
    if (request_size < sizeof(struct seccomp_notif)) {
        request_size = sizeof(struct seccomp_notif);
    }
    size_t response_size = sizes.seccomp_notif_resp;
    if (response_size < sizeof(struct seccomp_notif_resp)) {
        response_size = sizeof(struct seccomp_notif_resp);
    }
    struct seccomp_notif *request = calloc(1, request_size);
    struct seccomp_notif_resp *response = calloc(1, response_size);
    if (request == nullptr || response == nullptr) {
        free(request);
        free(response);
        return;
    }

    for (;;) {
        struct pollfd watch = { .fd = notify_descriptor, .events = POLLIN, .revents = 0 };
        int ready = poll(&watch, 1, -1);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (watch.revents & POLLIN) {
            service_one(notify_descriptor, request, response, request_size);
        }
        if (watch.revents & (POLLHUP | POLLERR)) {
            break;
        }
    }
    free(request);
    free(response);
}

/* The child's wait status, turned into an exit code the way a shell would: the
 * command's own code, or 128 plus the signal that ended it. */
static int exit_code_from_status(int status)
{
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return EXIT_SETUP_ERROR;
}

/* ------------------------------------------------- the command line, read once */

struct guard_options {
    char **command;
    const char *rules_path;
    bool verbose;
};

[[noreturn]] static void print_usage_and_exit(void)
{
    fprintf(stderr,
            "Usage: phobos-connect-guard [--verbose] [--rules FILE] -- COMMAND [ARGUMENTS...]\n");
    exit(2);
}

static void parse_arguments(int argument_count, char *arguments[], struct guard_options *options)
{
    memset(options, 0, sizeof(*options));
    int index = 1;
    for (; index < argument_count; index++) {
        if (strcmp(arguments[index], "--verbose") == 0) {
            options->verbose = true;
            continue;
        }
        if (strcmp(arguments[index], "--rules") == 0) {
            index++;
            if (index >= argument_count) {
                print_usage_and_exit();
            }
            options->rules_path = arguments[index];
            continue;
        }
        if (strcmp(arguments[index], "--") == 0) {
            index++;
            break;
        }
        print_usage_and_exit();
    }
    if (index >= argument_count) {
        print_usage_and_exit();
    }
    options->command = &arguments[index];
}

/* ------------------------------------------------------------------ the call */

int main(int argument_count, char *arguments[])
{
    struct guard_options options;
    parse_arguments(argument_count, arguments, &options);
    verbose = options.verbose;
    if (!load_rules(options.rules_path)) {
        fprintf(stderr, "[phobos-connect-guard] cannot read the rules file '%s': %s; refusing "
                        "to run rather than fall open to allow-all\n",
                options.rules_path, strerror(errno));
        return EXIT_SETUP_ERROR;
    }

    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
        fprintf(stderr, "[phobos-connect-guard] socketpair: %s\n", strerror(errno));
        return EXIT_SETUP_ERROR;
    }

    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "[phobos-connect-guard] fork: %s\n", strerror(errno));
        return EXIT_SETUP_ERROR;
    }
    if (child == 0) {
        close(pair[0]);
        run_child(pair[1], options.command);
    }

    /* The supervisor ignores SIGTERM so that, as an outer timeout's direct child, it
     * stays alive until the command it waits on is gone. The kill escalation then
     * reaches the command, which was forked before this and so keeps the default
     * disposition. SIGTERM is set here, after the fork, for that reason. */
    signal(SIGTERM, SIG_IGN);

    close(pair[1]);
    int notify_descriptor = receive_descriptor(pair[0]);
    close(pair[0]);
    if (notify_descriptor < 0) {
        int status = 0;
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
        fprintf(stderr, "[phobos-connect-guard] the sandboxed command could not be supervised; "
                        "refusing to run it\n");
        int code = exit_code_from_status(status);
        return code == 0 ? EXIT_SETUP_ERROR : code;
    }

    supervise(notify_descriptor);
    close(notify_descriptor);

    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
    return exit_code_from_status(status);
}
