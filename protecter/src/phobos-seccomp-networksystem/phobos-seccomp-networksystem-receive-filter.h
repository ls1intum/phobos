/*
 * The receive filter: a classic BPF socket filter the guard attaches and locks on every datagram
 * socket it creates, before the command holds it, so that the socket receives only what came from
 * the host itself or from a peer a UDP rule names.
 *
 * The guard makes every datagram send itself, so what a datagram socket sends is held to the
 * allow-list; what it receives is not, because a bound datagram socket takes a datagram from
 * anyone. Without an outer container that has no network, a sender outside could reach it. The
 * filter closes that from inside: the kernel runs it on every datagram before the socket queues it.
 *
 * A source in 127.0.0.0/8 or ::1 is accepted if and only if it arrived on the loopback interface,
 * whatever a rule says, because a routing configuration with route_localnet can admit such a
 * source from outside. Any other source is accepted only when a UDP rule names it, by address or
 * range, on any interface; loopback addresses never reach that branch, so no rule can readmit a
 * loopback source. The port is not judged: the guard already holds what the socket sends to.
 *
 * A UDP rule whose host the guard cannot tie to an address (a wildcard, or a name it was not
 * given resolved) allows an answer from anywhere, so no filter is attached then. A locked filter
 * cannot be detached, replaced or unlocked, by root either, and it belongs to the socket, not to
 * a descriptor, so it stays when the command duplicates or closes its descriptor and when the
 * guard lets go of the socket. Errors and path-MTU feedback reach a socket outside the filter;
 * the guard's own filter refuses IP_RECVERR and IPV6_RECVERR, so no quoted payload does.
 *
 * Classic socket filters on TCP need CAP_NET_ADMIN since kernel commit 5d39580f68e6, so a
 * listener is pinned to the loopback device instead (phobos-seccomp-networksystem-socket-types.h).
 */
#ifndef PHOBOS_CONNECT_GUARD_RECEIVE_FILTER_H
#define PHOBOS_CONNECT_GUARD_RECEIVE_FILTER_H

#include <stddef.h>

#include <linux/filter.h>

/* The longest program the kernel accepts for a socket filter, BPF_MAXINSNS. */
static constexpr size_t RECEIVE_FILTER_MAXIMUM = 4096;

/* What start-up decided about the datagram sockets of this run. */
enum receive_filter_state {
    RECEIVE_FILTER_UNDECIDED,   /* start-up has not decided, so no datagram socket is handed out */
    RECEIVE_FILTER_ATTACHED,    /* every datagram socket is filtered */
    RECEIVE_FILTER_NEEDLESS,    /* a UDP rule allows an answer from anywhere, so none is */
    RECEIVE_FILTER_REFUSED,     /* the kernel or a security module refuses socket filters on UDP */
};

/* Writes the program for the rules the guard holds into out, which has room for
 * RECEIVE_FILTER_MAXIMUM instructions, accepting loopback sources only on the interface with
 * loopback_index. Answers the number of instructions, or 0 when the rules need no filter. The
 * program for a full rules table fits, which the source holds with a static assertion. */
size_t build_receive_filter(struct sock_filter *out, unsigned int loopback_index);

/* Whether the rules the guard holds need a filter: false when a UDP rule allows an answer from a
 * source the guard cannot tie to an address. */
bool needs_receive_filter(void);

/* Decides, once and before the command starts, whether datagram sockets are filtered: builds the
 * program, and attaches and locks it on an IPv4 and an IPv6 probe socket. A refusal with EPERM,
 * EACCES or ENOPROTOOPT means the kernel or a security module refuses socket filters on UDP, which
 * is said on stderr and leaves the run unfiltered, the best effort a kernel without a Landlock
 * right gets too. Answers false for anything else (no loopback interface, a program the kernel
 * rejects, a shortage), on which the run must not start, so that a defect never becomes an
 * unfiltered run. Assumes the rules are loaded. */
bool configure_receive_filter(void);

/* Attaches and locks the program on a datagram socket the guard created and the command does not
 * hold yet. Answers true when it is attached or this run needs or allows none, and false when
 * attaching failed or start-up has not decided, on which the socket must not reach the command. */
bool attach_receive_filter(int descriptor);

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
/* Sets what start-up decided, so a case can stand for a run of either kind. */
void receive_filter_set_for_tests(enum receive_filter_state state);
#endif

#endif
