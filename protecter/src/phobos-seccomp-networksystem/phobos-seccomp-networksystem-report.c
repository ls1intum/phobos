#define _GNU_SOURCE
#include "phobos-seccomp-networksystem-report.h"

#include "../phobos-seccomp-filesystem/phobos-seccomp-filesystem-message.h"

#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/un.h>

/* Room for the text of one object: an endpoint, or a socket kind with its two names. */
static constexpr size_t OBJECT_TEXT_SIZE = ENDPOINT_TEXT_SIZE + sizeof(" over TCP");

/* Room for "domain <number>" or "type <number>". */
static constexpr size_t DOMAIN_TEXT_SIZE = 24;

/* Room for a UNIX socket path as the command wrote it, and its terminating NUL. */
static constexpr size_t SOCKET_PATH_SIZE = sizeof(((struct sockaddr_un *)nullptr)->sun_path) + 1;

/* The bits of socket()'s type argument that name the type itself, the rest being SOCK_CLOEXEC and
 * SOCK_NONBLOCK. */
static constexpr int BASE_TYPE_MASK = 0xf;

/* The name of an address family, or nullptr for one the report does not name. */
static const char *domain_name(int domain) {
    switch (domain) {
    case AF_INET:
        return "AF_INET";
    case AF_INET6:
        return "AF_INET6";
    case AF_PACKET:
        return "AF_PACKET";
    default:
        return nullptr;
    }
}

/* The name of a socket type, or nullptr for one the report does not name. */
static const char *type_name(int base_type) {
    switch (base_type) {
    case SOCK_RAW:
        return "SOCK_RAW";
    case SOCK_DGRAM:
        return "SOCK_DGRAM";
    default:
        return nullptr;
    }
}

void report_refused_endpoint(const char *verb, const struct destination *where, bool datagram) {
    char endpoint[ENDPOINT_TEXT_SIZE];
    char object[OBJECT_TEXT_SIZE];
    format_endpoint(where, endpoint, sizeof(endpoint));
    snprintf(object, sizeof(object), "%s over %s", endpoint, datagram ? "UDP" : "TCP");
    report_blocked(REPORT_LAYER_NETWORK, verb, "Endpoint", object, false, nullptr);
}

void report_refused_socket_file(const struct sockaddr_storage *address, socklen_t length) {
    const struct sockaddr_un *unix_address = (const struct sockaddr_un *)address;
    size_t path_offset = offsetof(struct sockaddr_un, sun_path);
    if (length <= path_offset || unix_address->sun_path[0] == '\0') {
        return;
    }
    char path[SOCKET_PATH_SIZE];
    size_t available = length - path_offset;
    size_t size = available < sizeof(unix_address->sun_path) ? available : sizeof(unix_address->sun_path);
    memcpy(path, unix_address->sun_path, size);
    path[size] = '\0';
    report_blocked(REPORT_LAYER_NETWORK, "connect to", "Socket File", path, true, nullptr);
}

/* Why the guard refuses a socket of this domain, type and protocol: a packet socket by its domain,
 * a raw socket by its type, and otherwise an ICMP one by its protocol. */
static const char *socket_kind(int domain, int base_type) {
    if (domain == AF_PACKET) {
        return "packet";
    }
    return base_type == SOCK_RAW ? "raw" : "icmp";
}

void report_refused_socket_kind(int domain, int type) {
    int base_type = type & BASE_TYPE_MASK;
    char domain_text[DOMAIN_TEXT_SIZE];
    char type_text[DOMAIN_TEXT_SIZE];
    char object[OBJECT_TEXT_SIZE];
    const char *known_domain = domain_name(domain);
    const char *known_type = type_name(base_type);
    snprintf(domain_text, sizeof(domain_text), "domain %d", domain);
    snprintf(type_text, sizeof(type_text), "type %d", base_type);
    snprintf(object, sizeof(object), "%s (%s, %s)", socket_kind(domain, base_type),
             known_domain != nullptr ? known_domain : domain_text,
             known_type != nullptr ? known_type : type_text);
    report_blocked(REPORT_LAYER_NETWORK, "open", "Socket Type", object, false, nullptr);
}

void report_refused_listen(void) {
    report_blocked(REPORT_LAYER_NETWORK, "listen on", "Port", "chosen by the kernel over TCP", false, nullptr);
}
