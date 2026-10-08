/*
 * The supervising half of the guard: it receives the notification descriptor and decides every
 * trapped socket, connect and send of the sandboxed lineage until that lineage is gone.
 */
#ifndef PHOBOS_CONNECT_GUARD_SUPERVISOR_H
#define PHOBOS_CONNECT_GUARD_SUPERVISOR_H

#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>

/* Point every allowed stream connection at a broker on the given "address:port" instead of at
 * the destination the command named, so the broker can enforce by host name what the guard
 * cannot see. The address is an IP literal, bracketed for IPv6. Returns whether it parsed. With
 * no broker set, the guard connects to the destination itself as before. */
bool configure_broker(const char *endpoint);

/* Allow, or refuse, a listen() on a socket that was never bound. The kernel gives such a socket a
 * port of its own choosing, which no bind rule judged, so it is refused unless the policy
 * grants an ephemeral bind; a socket bound to an explicit port, which Landlock already judged,
 * may always listen. */
void configure_ephemeral_listen(bool allowed);

/* Says which layer the calls the guard's filter refuses, other than io_uring, are counted for in
 * the summary: the timeout layer when its group lock is above the guard and was found, the network
 * layer otherwise. This changes what a line counts for and nothing the guard answers. */
void configure_group_lock_attribution(bool timeout_layer);

/* Gives the guard the pipe the egress broker logs its refusals to, which supervise reads beside the
 * notification descriptor. A negative descriptor means there is no broker. */
void configure_broker_log(int descriptor);

/* The transport of one of the command's sockets: SOCK_STREAM or SOCK_DGRAM for a socket this guard
 * recorded the type of, -1 for any other. The denial reporter asks it to name the transport of a
 * bind. */
int tracked_socket_type(pid_t owner, int descriptor);

/* Tells the denial reporter the enforcer's path, if there is one, which it compares with the caller of the arming
 * call, and the Landlock version its models are built for, and gives it the guard's socket table so
 * that it can name the transport of a bind. */
void configure_reporting(const char *landlock_bin, int landlock_version);

/* Complete one trapped connect: tell the kernel the answer for this notification.
 * A negative error is returned to the command as connect()'s errno; error 0 with
 * value 0 is a success. A send that finds the command already gone is not a failure
 * of ours. */
void answer(int notify_descriptor, struct seccomp_notif_resp *response, __u64 id,
            __s64 value, __s32 error);

/* Connect a fresh socket to the destination, within a bounded wait so one slow connection
 * cannot stall the supervisor. Returns the connected descriptor, cleared back to blocking as
 * an ordinary socket is, or a negative errno. This is a fresh socket, so options the command
 * set on its own before connecting, and a non-blocking mode, are not carried onto it: that is
 * the documented limit of connecting on the command's behalf rather than letting it connect. */
int connect_within_deadline(int family, const struct sockaddr *address, socklen_t length);

/* Make the allowed connection here and inject the connected socket back over the
 * descriptor number the command called connect() on, so the command's connect()
 * returns 0 with a socket already connected to the address the check saw. Answers whether the
 * connected socket was injected, so the caller can let go of the socket it replaced. */
bool connect_on_behalf(int notify_descriptor, struct seccomp_notif_resp *response,
                       __u64 id, int target_descriptor, int family,
                       const struct sockaddr *address, socklen_t length);

/* Service one notification: receive it, then decide it by the syscall it trapped. Only the
 * syscalls the filter traps arrive here; any other is refused closed. */
void service_one(int notify_descriptor, struct seccomp_notif *request,
                 struct seccomp_notif_resp *response, size_t request_size);

/* Wait on the notification descriptor and service it until the sandboxed lineage is
 * gone, which the kernel signals as a hangup once every process the filter covers
 * has exited. */
void supervise(int notify_descriptor);

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
/* Forgets any configured broker, so each test case starts with the guard connecting to the
 * destination itself unless it configures a broker of its own. */
void broker_reset_for_tests(void);

/* Forgets the ephemeral-listen setting, so each test case starts with an unbound socket refused
 * unless it allows one itself. */
void ephemeral_listen_reset_for_tests(void);

/* Forgets the reporting configuration, so each case starts with the network layer counting every
 * refusal and no broker pipe. */
void reporting_reset_for_tests(void);
#endif

#endif
