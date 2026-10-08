/*
 * The guard's resolve mode: it looks up the addresses of the host names a policy names for UDP, once,
 * before the command starts, so a datagram rule can hold a name to the addresses it had then.
 *
 * UDP has no host name on the wire to check, as TLS has for TCP, so the guard cannot enforce a name
 * at send time. It can enforce what a name meant at the start of the run: the network layer asks this
 * mode for the addresses, hands the guard a rule for each, and maps the name to the same addresses
 * for the command, so the command and the guard can never disagree about where a name leads. The
 * lookup goes to the resolver the operator gave and nowhere else, never through /etc/resolv.conf,
 * which the command could have been shown a different copy of.
 *
 * This mode runs outside the sandbox, before the command, and reads an answer that whoever controls
 * the name's domain influences, so every length it reads is checked and the parsing is libc's.
 */
#ifndef PHOBOS_CONNECT_GUARD_RESOLVE_H
#define PHOBOS_CONNECT_GUARD_RESOLVE_H

#include <stdio.h>
#include <sys/socket.h>

/* The most addresses kept for one name: more would only widen the rule, and the command is shown
 * the same ones, so cutting the answer short narrows what it can reach rather than letting the two
 * disagree. */
static constexpr size_t RESOLVE_ADDRESSES_PER_NAME = 16;

/* The most names one call resolves. */
static constexpr size_t RESOLVE_NAMES_MAXIMUM = 64;

/* Reads a resolver as "address", "address:port" for IPv4 or "[address]:port" for IPv6, with the
 * port 53 when none is given. Answers whether it parsed, and fills the address and its length. A
 * port of 0, a bare IPv6 address with no brackets and a host name are refused. */
bool parse_resolver_endpoint(const char *endpoint, struct sockaddr_storage *address, socklen_t *length);

/* Resolves every name through the resolver and writes one "NAME ADDRESS" line per address to out,
 * IPv4 and IPv6 alike, at most RESOLVE_ADDRESSES_PER_NAME for a name. It writes nothing unless
 * every name resolved: a name with no address at all, a lookup that times out or fails, an answer
 * that is truncated or does not match the question, and a resolver that cannot be parsed each end
 * the run with the setup status and a line on standard error naming the cause. An NXDOMAIN or an
 * empty answer for one record type is normal and not a failure, as long as the other type gave an
 * address. Answers 0 on success. */
int run_resolve_mode(const char *resolver_endpoint, char *const *names, FILE *out);

#endif
