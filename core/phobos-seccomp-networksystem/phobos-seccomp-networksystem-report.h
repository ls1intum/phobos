/*
 * The lines the connect guard prints for the refusals it makes itself.
 *
 * Every policy refusal with a valid object says so through here, in the words the filesystem
 * reporter uses (../phobos-seccomp-filesystem/phobos-seccomp-filesystem-message.h), so one
 * de-duplication table, one cap and one summary serve the whole run. A refusal with no object the
 * guard decided on (an address that could not be read, a socket it never created, a destination
 * that refused the onward connection) prints nothing here and stays a --verbose line.
 *
 * Printing a line decides nothing: the guard has already answered, or is about to answer, the call.
 */
#ifndef PHOBOS_CONNECT_GUARD_REPORT_H
#define PHOBOS_CONNECT_GUARD_REPORT_H

#include "phobos-seccomp-networksystem-destination.h"

#include <sys/socket.h>

/* Reports a refused destination: "<verb> the Endpoint <address:port> over TCP" or "... over UDP". */
void report_refused_endpoint(const char *verb, const struct destination *where, bool datagram);

/* Reports a refused connect to a UNIX socket by the path it names, as "connect to the Socket File".
 * An address with no path, or an abstract name that has no file, is not reported. */
void report_refused_socket_file(const struct sockaddr_storage *address, socklen_t length);

/* Reports a refused socket(), as "open the Socket Type raw (AF_INET, SOCK_RAW)". The kind (raw,
 * packet or icmp) is the reason the guard refused it: a packet socket by its domain, a raw socket
 * by its type, and any other refused socket is an ICMP one. */
void report_refused_socket_kind(int domain, int type);

/* Reports a refused listen() on a socket bound to no port: "listen on the Port chosen by the
 * kernel over TCP". */
void report_refused_listen(void);

#endif
