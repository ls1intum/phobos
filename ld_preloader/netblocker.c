/*
 * libnetblocker -- refuse the network access an allow-list does not name.
 *
 * Preloaded into every process of a graded run, it interposes getaddrinfo and connect.
 * A lookup of a host no rule covers fails with EAI_FAIL, and a connection to an address
 * no rule covers fails with EACCES. It is defence in depth that a process can step
 * around, as SECURITY.md says.
 *
 * This file is the two hooks and the loading of the library, and nothing else. What
 * they work with lives beside it:
 *
 *   netblocker-policy.h         the allow-list, its lock and its answers
 *   netblocker-rule.h           one line of the allow-list
 *   netblocker-address-cache.h  the addresses name lookups authorised
 *   netblocker-address.h        one address in the form it is compared in
 *
 * Only getaddrinfo and connect are visible outside the library. It is built with
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

/* The environment variable naming the rules file. */
static const char RULES_VARIABLE[] = "NETBLOCKER_CONF";

static constexpr int DECIMAL = 10;

typedef int getaddrinfo_function(const char *, const char *, const struct addrinfo *,
                                 struct addrinfo **);
typedef int connect_function(int, const struct sockaddr *, socklen_t);

/* The allow-list of this process. Initialised statically, so that a hook running
 * before this library's constructor, from another library's, finds it empty and
 * refuses. */
static struct policy policy = POLICY_INITIALISER;

static getaddrinfo_function *real_getaddrinfo = nullptr;
static connect_function *real_connect = nullptr;

/* Reads a service as a port: a whole number up to 65535. Anything else, a service name
 * and an empty text included, counts as no port. */
static uint16_t service_port(const char *service) {
    char *first_unconverted = nullptr;
    if (service == nullptr) {
        return 0;
    }
    unsigned long value = strtoul(service, &first_unconverted, DECIMAL);
    if (*first_unconverted != '\0' || value > PORT_MAX) {
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
    }
    else if (destination->sa_family == AF_INET6) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)destination;
        inet_ntop(AF_INET6, &ipv6->sin6_addr, text, size);
        *port = ntohs(ipv6->sin6_port);
    }
}

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

/* Loads the allow-list and finds the functions the hooks hand permitted calls to. */
static void netblocker_initialise(void) {
    policy_load(&policy, getenv(RULES_VARIABLE));
    real_getaddrinfo = (getaddrinfo_function *)dlsym(RTLD_NEXT, "getaddrinfo");
    real_connect = (connect_function *)dlsym(RTLD_NEXT, "connect");
}

/* The unit tests include this file and call netblocker_initialise themselves, once
 * their stand-ins are in place, so they build it without the constructor. */
#ifndef NETBLOCKER_UNIT_TEST
/* Runs when the loader maps the library, before the program's main. */
[[gnu::constructor]] static void initialise_on_load(void) {
    netblocker_initialise();
}
#endif
