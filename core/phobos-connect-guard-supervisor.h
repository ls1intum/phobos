/*
 * The supervising half of the guard: it receives the notification descriptor and decides every
 * trapped socket, connect and send of the sandboxed lineage until that lineage is gone.
 */
#ifndef PHOBOS_CONNECT_GUARD_SUPERVISOR_H
#define PHOBOS_CONNECT_GUARD_SUPERVISOR_H

#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/socket.h>

/* Point every allowed stream connection at a broker on the given "address:port" instead of at
 * the destination the command named, so the broker can enforce by host name what the guard
 * cannot see. The address is an IP literal, bracketed for IPv6. Returns whether it parsed. With
 * no broker set, the guard connects to the destination itself as before. */
bool configure_broker(const char *endpoint);

/* Receive the one descriptor the child sends. Returns it, or -1 on any failure,
 * including the child exiting before it sent one (an end of file here). */
int receive_descriptor(int socket_descriptor);

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
 * returns 0 with a socket already connected to the address the check saw. */
void connect_on_behalf(int notify_descriptor, struct seccomp_notif_resp *response,
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

/* The child's wait status, turned into an exit code the way a shell would: the
 * command's own code, or 128 plus the signal that ended it. */
int exit_code_from_status(int status);

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
/* Forgets any configured broker, so each test case starts with the guard connecting to the
 * destination itself unless it configures a broker of its own. */
void broker_reset_for_tests(void);
#endif

#endif
