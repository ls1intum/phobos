#define _GNU_SOURCE
#include "phobos-seccomp-networksystem-broker-log.h"

#include "phobos-seccomp-networksystem-destination.h"
#include "phobos-seccomp-networksystem-report.h"

#include "../phobos-seccomp-filesystem/phobos-seccomp-filesystem-message.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The marker every line of the broker's log begins with, and the two fields that mark a refusal. */
static const char LINE_MARKER[] = "PHB-BROKER";
static const char REFUSING_BACKEND[] = "refuse";
static const char REFUSED_BY_PROXY[] = "PR";

/* A line is split into this many space-separated fields: the marker, the backend, the termination
 * state, the host name, the address and the port. */
static constexpr size_t FIELD_COUNT = 6;

/* The longest host name, in bytes, and the hex that spells it. */
static constexpr size_t HOST_NAME_MAXIMUM = 253;
static constexpr size_t HOST_HEX_MAXIMUM = 2 * HOST_NAME_MAXIMUM;

/* The text of a port, and the largest port. */
static constexpr size_t PORT_DIGITS_MAXIMUM = 5;
static constexpr unsigned long PORT_MAXIMUM = 65535;

/* Room for the object "'<quoted host name>' on Port <port>". */
static constexpr size_t HOST_OBJECT_SIZE = REPORT_QUOTED_MAXIMUM + sizeof(" on Port 65535");

/* How many bytes one read takes from the pipe. */
static constexpr size_t READ_SIZE = 1024;

/* The line being gathered across reads, and whether the rest of an overlong one is being dropped. */
static char pending[BROKER_LOG_LINE_MAXIMUM];
static size_t pending_length = 0;
static bool dropping = false;

/* The value of one hex digit, or -1 when the byte is not one. */
static int hex_value(char digit) {
    if (digit >= '0' && digit <= '9') {
        return digit - '0';
    }
    if (digit >= 'a' && digit <= 'f') {
        return digit - 'a' + 10;
    }
    if (digit >= 'A' && digit <= 'F') {
        return digit - 'A' + 10;
    }
    return -1;
}

/* Decodes the hex spelling of a host name into text, a C string. Answers false for an odd length, a
 * byte that is not a hex digit, a name of no bytes or one longer than a host name, and a name that
 * holds a NUL, which no host name does. */
static bool decode_host_name(const char *hex, char *text) {
    size_t hex_length = strlen(hex);
    if (hex_length == 0 || hex_length % 2 != 0 || hex_length > HOST_HEX_MAXIMUM) {
        return false;
    }
    for (size_t index = 0; index < hex_length; index += 2) {
        int high = hex_value(hex[index]);
        int low = hex_value(hex[index + 1]);
        if (high < 0 || low < 0 || (high == 0 && low == 0)) {
            return false;
        }
        text[index / 2] = (char)(high * 16 + low);
    }
    text[hex_length / 2] = '\0';
    return true;
}

/* Reads a port: one to five digits, from 1 to 65535. */
static bool read_port(const char *text, uint16_t *port) {
    size_t length = strlen(text);
    if (length == 0 || length > PORT_DIGITS_MAXIMUM || strspn(text, "0123456789") != length) {
        return false;
    }
    unsigned long value = strtoul(text, nullptr, 10);
    if (value == 0 || value > PORT_MAXIMUM) {
        return false;
    }
    *port = (uint16_t)value;
    return true;
}

/* Reports a refusal that named a host name: "connect to the Host '<name>' on Port <port>". */
static void report_refused_host(const char *host, uint16_t port) {
    char quoted[REPORT_QUOTED_MAXIMUM];
    char object[HOST_OBJECT_SIZE];
    quote_like_bash(host, quoted, sizeof(quoted));
    snprintf(object, sizeof(object), "%s on Port %u", quoted, (unsigned)port);
    report_blocked(REPORT_LAYER_NETWORK, "connect to", "Host", object, false, nullptr);
}

/* Reports a refusal that named no host name, by the address the guard handed over. Answers false
 * when the address is neither IPv4 nor IPv6 text. */
static bool report_refused_address(const char *address_text, uint16_t port) {
    struct sockaddr_storage storage;
    memset(&storage, 0, sizeof(storage));
    struct sockaddr_in *v4 = (struct sockaddr_in *)&storage;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&storage;
    if (inet_pton(AF_INET, address_text, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
    } else if (inet_pton(AF_INET6, address_text, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
    } else {
        return false;
    }
    struct destination where = read_destination(&storage);
    report_refused_endpoint("connect to", &where, false);
    return true;
}

void handle_broker_log_line(const char *line, size_t length) {
    char copy[BROKER_LOG_LINE_MAXIMUM + 1];
    char *fields[FIELD_COUNT];
    if (length > BROKER_LOG_LINE_MAXIMUM) {
        return;
    }
    memcpy(copy, line, length);
    copy[length] = '\0';
    char *cursor = copy;
    for (size_t index = 0; index < FIELD_COUNT; index++) {
        fields[index] = cursor;
        char *space = strchr(cursor, ' ');
        if (index + 1 < FIELD_COUNT) {
            if (space == nullptr) {
                return;
            }
            *space = '\0';
            cursor = space + 1;
        } else if (space != nullptr) {
            return;
        }
    }
    bool refused = strcmp(fields[1], REFUSING_BACKEND) == 0
                   || strncmp(fields[2], REFUSED_BY_PROXY, strlen(REFUSED_BY_PROXY)) == 0;
    uint16_t port;
    if (strcmp(fields[0], LINE_MARKER) != 0 || !refused || !read_port(fields[5], &port)) {
        return;
    }
    if (strcmp(fields[3], "-") == 0) {
        report_refused_address(fields[4], port);
        return;
    }
    char host[HOST_NAME_MAXIMUM + 1];
    if (decode_host_name(fields[3], host)) {
        report_refused_host(host, port);
    }
}

/* Hands the complete lines of a chunk to the line handler, keeping what follows the last newline
 * for the next chunk. A line that outgrows its limit before its newline is dropped whole. */
static void take_chunk(const char *chunk, size_t length) {
    for (size_t index = 0; index < length; index++) {
        if (chunk[index] == '\n') {
            if (!dropping) {
                handle_broker_log_line(pending, pending_length);
            }
            pending_length = 0;
            dropping = false;
        } else if (!dropping && pending_length < BROKER_LOG_LINE_MAXIMUM) {
            pending[pending_length] = chunk[index];
            pending_length++;
        } else {
            dropping = true;
            pending_length = 0;
        }
    }
}

void drain_broker_log(int descriptor) {
    char chunk[READ_SIZE];
    for (;;) {
        ssize_t count = read(descriptor, chunk, sizeof(chunk));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return;
        }
        take_chunk(chunk, (size_t)count);
    }
}

bool adopt_broker_log(int descriptor) {
    struct stat details;
    if (fstat(descriptor, &details) != 0 || !S_ISFIFO(details.st_mode)) {
        return false;
    }
    int descriptor_flags = fcntl(descriptor, F_GETFD);
    int status_flags = fcntl(descriptor, F_GETFL);
    return descriptor_flags >= 0 && status_flags >= 0
           && fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) == 0
           && fcntl(descriptor, F_SETFL, status_flags | O_NONBLOCK) == 0;
}

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
void broker_log_reset_for_tests(void) {
    pending_length = 0;
    dropping = false;
}
#endif
