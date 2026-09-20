/*
 * libnetblocker -- refuse the network access an allow-list does not name.
 *
 * Preloaded into every process of a graded run, it interposes getaddrinfo, connect,
 * bind, sendto, sendmsg and sendmmsg. A lookup of a host no rule covers fails with EAI_FAIL, an
 * outbound connection or datagram to an address no rule covers fails with EACCES, and a
 * TCP bind to a local address no [bind] rule covers fails with EACCES too. It is defence
 * in depth that a process can step around, as SECURITY.md says.
 *
 * connect covers TCP and a connected UDP socket. sendto, sendmsg and sendmmsg cover the
 * other way a UDP datagram names its destination, on a socket that was never connected, which
 * connect would never see; sendmmsg carries a batch, each message with its own destination.
 * bind covers the local address a service asks to listen on:
 * Landlock enforces a bind only by port, so this host filter narrows it to the local
 * addresses the policy names. Only a TCP bind under an actual [bind] rule is filtered, so
 * a run whose policy names no bind port keeps binding freely, exactly as it does under
 * Landlock. The C library's own name resolution reaches the network through calls this
 * library cannot interpose, so this does not disturb DNS; it filters the calls a
 * submission makes itself.
 *
 * This file is the six hooks and the loading of the library, and nothing else. What
 * they work with lives beside it:
 *
 *   netblocker-policy.h         the allow-list, its lock and its answers
 *   netblocker-rule.h           one line of the allow-list
 *   netblocker-address-cache.h  the addresses name lookups authorised
 *   netblocker-address.h        one address in the form it is compared in
 *
 * Only the six hooks are visible outside the library. It is built with
 * -fvisibility=hidden, so no other function of it can take the place of one a program
 * or another library defines under the same name.
 */

/* dlsym's RTLD_NEXT needs this first. */
#define _GNU_SOURCE
#include "netblocker-policy.h"

#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/socket.h>

/* The environment variable naming the outbound rules file. */
static const char RULES_VARIABLE[] = "NETBLOCKER_CONF";

/* The environment variable naming the local-bind rules file. */
static const char BIND_RULES_VARIABLE[] = "NETBLOCKER_BIND_CONF";

static constexpr int DECIMAL = 10;

typedef int getaddrinfo_function(const char *, const char *, const struct addrinfo *,
                                 struct addrinfo **);
typedef int connect_function(int, const struct sockaddr *, socklen_t);
typedef int bind_function(int, const struct sockaddr *, socklen_t);
typedef ssize_t sendto_function(int, const void *, size_t, int, const struct sockaddr *,
                                socklen_t);
typedef ssize_t sendmsg_function(int, const struct msghdr *, int);
typedef int sendmmsg_function(int, struct mmsghdr *, unsigned int, int);

/* The outbound allow-list of this process. Initialised statically, so that a hook running
 * before this library's constructor, from another library's, finds it empty and
 * refuses. */
static struct policy policy = POLICY_INITIALISER;

/* The local-bind allow-list. Unlike the outbound policy, an empty bind list does not
 * refuse: with no [bind] rule Landlock leaves binding unrestricted, so the hook narrows a
 * bind only once the policy names a local address and port. */
static struct policy bind_policy = POLICY_INITIALISER;

static getaddrinfo_function *real_getaddrinfo = nullptr;
static connect_function *real_connect = nullptr;
static bind_function *real_bind = nullptr;
static sendto_function *real_sendto = nullptr;
static sendmsg_function *real_sendmsg = nullptr;
static sendmmsg_function *real_sendmmsg = nullptr;

/* Reads a service as a port: a whole number up to 65535. Anything else, a service name
 * and an empty text included, counts as no port. */
static uint16_t service_port(const char *service) {
    char *first_unconverted = nullptr;
    if (service == nullptr) {
        return 0;
    }
    unsigned long value = strtoul(service, &first_unconverted, DECIMAL);
    if (*first_unconverted != '\0' || value > HIGHEST_PORT) {
        return 0;
    }
    return (uint16_t)value;
}

/* Records the addresses a permitted lookup returned, under the ports the rules grant
 * the host. An address that cannot be written as text is skipped. */
static void record_results(const char *host, struct addrinfo *results) {
    for (struct addrinfo *result = results; result != nullptr; result = result->ai_next) {
        char text[INET6_ADDRSTRLEN] = "";
        if (getnameinfo(result->ai_addr, result->ai_addrlen, text, sizeof(text), nullptr, 0,
                        NI_NUMERICHOST) == 0) {
            policy_record_resolution(&policy, host, text);
        }
    }
}

/* Writes the destination of a socket address as text and its port. Any family but
 * IPv4 and IPv6 leaves an empty text and port 0. */
static void describe_destination(const struct sockaddr *destination, char *text, socklen_t size,
                                 uint16_t *port) {
    if (destination->sa_family == AF_INET) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)destination;
        inet_ntop(AF_INET, &ipv4->sin_addr, text, size);
        *port = ntohs(ipv4->sin_port);
    } else if (destination->sa_family == AF_INET6) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)destination;
        inet_ntop(AF_INET6, &ipv6->sin6_addr, text, size);
        *port = ntohs(ipv6->sin6_port);
    }
}

/* Whether a datagram or connection to this destination is one the network policy allows
 * through. A family that is not IPv4 or IPv6, an AF_UNIX socket among them, is not the
 * network this library filters and passes: the filesystem layer governs a UNIX socket,
 * and a raw or unknown family names no host or port to check. An IPv4 or IPv6
 * destination passes only when the allow-list names its address and port. */
static bool destination_permitted(const struct sockaddr *destination) {
    char text[INET6_ADDRSTRLEN] = "";
    uint16_t port = 0;
    if (destination->sa_family != AF_INET && destination->sa_family != AF_INET6) {
        return true;
    }
    describe_destination(destination, text, sizeof(text), &port);
    return policy_permits_connection(&policy, text, port);
}

/* Refuses a lookup of a host no rule covers, with EAI_FAIL, and records the addresses a
 * permitted lookup returned under the ports the rules grant the host. */
[[gnu::visibility("default")]]
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                struct addrinfo **results) {
    if (real_getaddrinfo == nullptr) {
        real_getaddrinfo = (getaddrinfo_function *)dlsym(RTLD_NEXT, "getaddrinfo");
    }
    uint16_t port = service_port(service);
    if (node != nullptr && !policy_permits_lookup(&policy, node, port)) {
        return EAI_FAIL;
    }
    int status = real_getaddrinfo(node, service, hints, results);
    if (status == 0 && node != nullptr && policy_permits_lookup(&policy, node, port)) {
        record_results(node, *results);
    }
    return status;
}

/* Refuses a connection to an address no rule covers and no permitted lookup recorded, with
 * EACCES. */
[[gnu::visibility("default")]]
int connect(int descriptor, const struct sockaddr *destination, socklen_t length) {
    char text[INET6_ADDRSTRLEN] = "";
    uint16_t port = 0;
    if (real_connect == nullptr) {
        real_connect = (connect_function *)dlsym(RTLD_NEXT, "connect");
    }
    describe_destination(destination, text, sizeof(text), &port);
    if (policy_permits_connection(&policy, text, port)) {
        return real_connect(descriptor, destination, length);
    }
    errno = EACCES;
    return -1;
}

/* Whether the local-bind list speaks about this bind at all. Without a [bind] rule binding is
 * unrestricted, matching the absence of a Landlock bind-port rule; a list whose every line was
 * refused is not such a case, and keeps binding filtered, so that a malformed rule narrows to
 * nothing rather than opening everything. bind_policy is loaded once at start-up and never
 * replaced, so reading it without the lock is safe. Only an IPv4 or
 * IPv6 local bind is filtered: any other family, an AF_UNIX socket among them, names no local
 * address this list governs and is left to the filesystem layer. And Landlock enforces a bind
 * only for TCP, so the filter keeps that scope: a datagram or any other socket type, or one whose
 * type cannot be read, is not what a [bind] rule speaks about. */
static bool bind_is_filtered(int descriptor, const struct sockaddr *address) {
    int socket_type = 0;
    socklen_t type_length = sizeof(socket_type);
    if (policy_is_silent(&bind_policy)) {
        return false;
    }
    if (address->sa_family != AF_INET && address->sa_family != AF_INET6) {
        return false;
    }
    return getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &socket_type, &type_length) == 0
           && socket_type == SOCK_STREAM;
}

/* Refuses a TCP bind to a local address no [bind] rule covers, with EACCES, and passes every
 * bind bind_is_filtered leaves alone. */
[[gnu::visibility("default")]]
int bind(int descriptor, const struct sockaddr *address, socklen_t length) {
    char text[INET6_ADDRSTRLEN] = "";
    uint16_t port = 0;
    if (real_bind == nullptr) {
        real_bind = (bind_function *)dlsym(RTLD_NEXT, "bind");
    }
    if (!bind_is_filtered(descriptor, address)) {
        return real_bind(descriptor, address, length);
    }
    describe_destination(address, text, sizeof(text), &port);
    if (policy_permits_connection(&bind_policy, text, port)) {
        return real_bind(descriptor, address, length);
    }
    errno = EACCES;
    return -1;
}

/* Refuses a datagram whose destination no rule covers, with EACCES. A null destination is a
 * datagram on a connected socket, which connect already vetted, so it passes untouched. */
[[gnu::visibility("default")]]
ssize_t sendto(int descriptor, const void *buffer, size_t length, int flags,
               const struct sockaddr *destination, socklen_t address_length) {
    if (real_sendto == nullptr) {
        real_sendto = (sendto_function *)dlsym(RTLD_NEXT, "sendto");
    }
    if (destination != nullptr && !destination_permitted(destination)) {
        errno = EACCES;
        return -1;
    }
    return real_sendto(descriptor, buffer, length, flags, destination, address_length);
}

/* Refuses a message whose destination no rule covers, with EACCES. msg_name carries the
 * destination of a datagram on an unconnected socket; it is null on a connected one, which
 * connect already vetted, and such a message passes untouched. */
[[gnu::visibility("default")]]
ssize_t sendmsg(int descriptor, const struct msghdr *message, int flags) {
    if (real_sendmsg == nullptr) {
        real_sendmsg = (sendmsg_function *)dlsym(RTLD_NEXT, "sendmsg");
    }
    if (message->msg_name != nullptr && !destination_permitted(message->msg_name)) {
        errno = EACCES;
        return -1;
    }
    return real_sendmsg(descriptor, message, flags);
}

/* Sends a batch only as far as its destinations are allowed. Each message carries its own
 * destination in msg_name, null on a connected socket. The kernel sends the batch in order and
 * stops at the first message that fails, returning how many it sent, so a disallowed destination
 * stops the batch there: the first message is refused outright, a later one lets the allowed
 * prefix through and leaves the rest for the caller to retry, where it is refused again. */
[[gnu::visibility("default")]]
int sendmmsg(int descriptor, struct mmsghdr *messages, unsigned int count, int flags) {
    if (real_sendmmsg == nullptr) {
        real_sendmmsg = (sendmmsg_function *)dlsym(RTLD_NEXT, "sendmmsg");
    }
    for (unsigned int index = 0; index < count; index++) {
        const struct msghdr *header = &messages[index].msg_hdr;
        if (header->msg_name != nullptr && !destination_permitted(header->msg_name)) {
            if (index == 0) {
                errno = EACCES;
                return -1;
            }
            return real_sendmmsg(descriptor, messages, index, flags);
        }
    }
    return real_sendmmsg(descriptor, messages, count, flags);
}

/* Loads the allow-list and finds the functions the hooks hand permitted calls to. */
static void netblocker_initialise(void) {
    policy_load(&policy, getenv(RULES_VARIABLE));
    policy_load(&bind_policy, getenv(BIND_RULES_VARIABLE));
    real_getaddrinfo = (getaddrinfo_function *)dlsym(RTLD_NEXT, "getaddrinfo");
    real_connect = (connect_function *)dlsym(RTLD_NEXT, "connect");
    real_bind = (bind_function *)dlsym(RTLD_NEXT, "bind");
    real_sendto = (sendto_function *)dlsym(RTLD_NEXT, "sendto");
    real_sendmsg = (sendmsg_function *)dlsym(RTLD_NEXT, "sendmsg");
    real_sendmmsg = (sendmmsg_function *)dlsym(RTLD_NEXT, "sendmmsg");
}

/* The unit tests include this file and call netblocker_initialise themselves, once
 * their stand-ins are in place, so they build it without the constructor. */
#ifndef NETBLOCKER_UNIT_TEST
/* Runs when the loader maps the library, before the program's main. */
[[gnu::constructor]] static void initialise_on_load(void) {
    netblocker_initialise();
}
#endif
