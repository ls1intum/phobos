/*
 * The datagram half of the guard: it makes every datagram connect and send itself, on a socket it
 * created and still holds, and never lets one of them continue in the command.
 *
 * A destination behind a pointer cannot be checked and then left to the kernel. SECCOMP_USER_NOTIF_
 * FLAG_CONTINUE re-runs the call, which reads the pointer again, so a second thread of the command
 * can show the check one address and the kernel another; measured, that sends about one datagram
 * in six to a destination the allow-list does not name. So the supervisor copies the address,
 * the data and the lengths out of the command once, checks the copies, and sends from them. The
 * socket it sends on is its own descriptor for the very open file description the command holds,
 * so a connect it makes is the command's connect, and the command's own address-less send then
 * reaches the peer the guard vetted.
 */
#ifndef PHOBOS_CONNECT_GUARD_DATAGRAM_H
#define PHOBOS_CONNECT_GUARD_DATAGRAM_H

#include <linux/seccomp.h>
#include <stdint.h>
#include <sys/socket.h>

/* Allow, or refuse, a connect or a send that the kernel would give a source port of its own
 * choosing, because the socket was never bound. Landlock gates that automatic bind for the
 * command, but the supervisor runs outside Landlock, so it judges the bind itself: the call is
 * refused unless the policy grants an ephemeral UDP bind, a udp port 0 row in [bind] or any udp
 * [connect] rule. A socket bound to an explicit port, which Landlock already judged, is always
 * allowed. */
void configure_ephemeral_udp_bind(bool allowed);

/* Make one datagram connect, after the supervisor has judged its destination: connect the
 * socket the inode names, on the supervisor's own descriptor for it, and answer with the result.
 * The call is never continued. A socket the supervisor does not hold, which is one it did not
 * create, one evicted from the full table or an inherited descriptor, is refused. */
void service_datagram_connect(int notify_descriptor, struct seccomp_notif_resp *response,
                              __u64 id, uint64_t inode, const struct sockaddr_storage *address,
                              socklen_t length);

/* Make one trapped sendto, sendmsg or sendmmsg: copy everything it names out of the command,
 * judge the destination of each message, send from the copies on the supervisor's own descriptor
 * and answer with what the kernel answered. Nothing is ever continued. Refused with EACCES are a
 * send on a socket the supervisor does not hold, a destination that is not an IPv4 or IPv6
 * address the allow-list names, ancillary data, MSG_FASTOPEN and a send that would give the socket
 * a source port nobody granted; refused with EMSGSIZE is a datagram beyond 64 KiB. A blocking
 * socket that cannot take the datagram is waited on for one second at most and then answered
 * EAGAIN, so one slow socket cannot stall every other notification. */
void service_datagram_send(int notify_descriptor, struct seccomp_notif *request,
                           struct seccomp_notif_resp *response);

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
/* Forgets the ephemeral-bind setting, so each test case starts with an unbound socket refused
 * unless it allows one itself. */
void ephemeral_udp_bind_reset_for_tests(void);
#endif

#endif
