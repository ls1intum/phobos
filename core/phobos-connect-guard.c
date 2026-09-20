/*
 * phobos-connect-guard -- supervise the egress a sandboxed command makes, so it can be
 * allowed or refused by host address, which Landlock, enforcing by port alone, cannot do.
 *
 * The name is narrower than the program. connect() is what it decides against the
 * allow-list and connects on behalf of, and around that it closes the ways a command
 * could reach the network without one: socket(), so a raw, packet or ICMP socket is
 * refused before it exists; sendto() and sendmmsg(), so a datagram carrying its own
 * destination is judged like a connect and TCP Fast Open cannot open a connection past
 * one; io_uring, a second syscall interface that would reach connect unseen; and
 * setsid/setpgid, which would take the command out of the group an outer timeout kills.
 * phobos-connect-guard-child.h holds the filter and says why sendmsg is not among them.
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
 * Why the supervisor connects on the command's behalf, for a stream socket, rather than
 * letting the kernel continue the trapped call (SECCOMP_USER_NOTIF_FLAG_CONTINUE): a continue
 * re-runs the original syscall against whatever is in the command's memory at that later
 * moment, so a command could show one address to the check and connect to another once it
 * passes. Making the connection here, from the address the check read, closes that window for
 * a stream connect. A datagram connect only sets a default peer, which cannot be injected, so
 * it is checked and then let through; the boundary for a datagram is the checked send that
 * follows and the no-network container. The command never runs a stream connect() itself.
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
 * This file is the sequence of stages and nothing else. What each stage works with lives
 * beside it:
 *
 *   phobos-connect-guard-options.h         the command line, read into one object
 *   phobos-connect-guard-rules.h           the allow-list and the decision on a destination
 *   phobos-connect-guard-child.h           the sandboxed half: install the filter, hand over
 *   phobos-connect-guard-supervisor.h      the supervising half: decide every trapped call
 *   phobos-connect-guard-destination.h     a destination read out of the command's memory
 *   phobos-connect-guard-socket-types.h    the type of every socket, remembered by inode
 *   phobos-connect-guard-seccomp-compat.h  the seccomp names older headers lack
 *   phobos-connect-guard-diagnostics.h     the setup exit status and the --verbose lines
 *
 * It fails closed. If the filter cannot be installed, or the supervisor cannot be
 * handed the notification descriptor, the run is refused rather than left to run
 * with connect() unsupervised. A connect of a family it does not carry (a
 * UNIX-domain socket, say) is refused rather than made outside the Landlock view
 * the command is held to.
 */

#define _GNU_SOURCE
#include "phobos-connect-guard-child.h"
#include "phobos-connect-guard-diagnostics.h"
#include "phobos-connect-guard-options.h"
#include "phobos-connect-guard-rules.h"
#include "phobos-connect-guard-supervisor.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/wait.h>

/* ------------------------------------------------------------------ the call */

/* Loads the rules, forks the sandboxed child and supervises it until it is gone, then ends
 * with its status. The supervisor ignores SIGTERM so that, as an outer timeout's direct child,
 * it stays alive until the command it waits on is gone. The kill escalation then reaches the
 * command, which was forked before and so keeps the default disposition; SIGTERM is ignored
 * only after the fork for that reason. */
int main(int argument_count, char *arguments[]) {
    struct guard_options options;
    parse_arguments(argument_count, arguments, &options);
    set_verbose(options.verbose);
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
