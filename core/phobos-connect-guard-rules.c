#define _GNU_SOURCE
#include "phobos-connect-guard-rules.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* strtoul's base for the ports and prefix lengths a rule names. */
static constexpr int DECIMAL = 10;
/* The address widths a prefix length may reach, IPv4 and IPv6. */
static constexpr unsigned long IPV4_ADDRESS_BITS = 32;
static constexpr unsigned long IPV6_ADDRESS_BITS = 128;
static constexpr int BITS_PER_BYTE = 8;
/* The IPv4-mapped IPv6 form ::ffff:a.b.c.d: two marker bytes of 0xff, then the four bytes of
 * the IPv4 address, the same layout as ld_preloader/netblocker-address.c. */
static constexpr size_t MAPPED_MARKER_FIRST_BYTE = 10;
static constexpr size_t MAPPED_MARKER_SECOND_BYTE = 11;
static constexpr size_t MAPPED_IPV4_FIRST_BYTE = 12;
static constexpr uint8_t MAPPED_MARKER = 0xff;
/* The highest TCP or UDP port; the lowest is 1. */
static constexpr unsigned long HIGHEST_PORT = 65535;
/* The longest line of the rules file read at once, and the longest port word. */
static constexpr size_t RULE_LINE_LENGTH = 512;
static constexpr size_t PORT_TEXT_LENGTH = 16;
/* A rules line is two words, the host and the port. */
static constexpr int RULE_WORDS = 2;
/* The field widths of the sscanf format in load_rules are MAXIMUM_HOST - 1 and
 * PORT_TEXT_LENGTH - 1. A format cannot name a constant, so the two are tied together here. */
static_assert(MAXIMUM_HOST == 256 && PORT_TEXT_LENGTH == 16,
              "the widths in load_rules' sscanf format must follow the buffer sizes");
/* 127.0.0.0/8 is IPv4 loopback: the first octet, the top eight of the address's 32 bits. */
static constexpr uint32_t IPV4_LOOPBACK_FIRST_OCTET = 127;
static constexpr int IPV4_FIRST_OCTET_SHIFT = 24;

static struct connect_rule connect_rules[MAXIMUM_RULES];
static size_t connect_rule_count = 0;

void remember_rule(const char *host, const char *port_text) {
    if (connect_rule_count >= MAXIMUM_RULES || strlen(host) >= MAXIMUM_HOST) {
        return;
    }
    struct connect_rule *rule = &connect_rules[connect_rule_count];
    memset(rule, 0, sizeof(*rule));
    snprintf(rule->host, sizeof(rule->host), "%s", host);
    char *slash = strchr(rule->host, '/');
    if (slash != nullptr) {
        *slash = '\0';
        const char *length_text = slash + 1;
        struct in_addr v4;
        bool ipv4 = inet_pton(AF_INET, rule->host, &v4) == 1;
        char *length_unconverted = nullptr;
        unsigned long length = strtoul(length_text, &length_unconverted, DECIMAL);
        unsigned long longest = ipv4 ? IPV4_ADDRESS_BITS : IPV6_ADDRESS_BITS;
        if (*length_unconverted != '\0' || length == 0 || length > longest) {
            return;
        }
        if (ipv4) {
            rule->network.s6_addr[MAPPED_MARKER_FIRST_BYTE] = MAPPED_MARKER;
            rule->network.s6_addr[MAPPED_MARKER_SECOND_BYTE] = MAPPED_MARKER;
            memcpy(&rule->network.s6_addr[MAPPED_IPV4_FIRST_BYTE], &v4, sizeof(v4));
            rule->prefix_length = IPV4_MAPPED_PREFIX_BITS + (int)length;
        } else if (inet_pton(AF_INET6, rule->host, &rule->network) == 1) {
            if (IN6_IS_ADDR_V4MAPPED(&rule->network) && length < (unsigned long)IPV4_MAPPED_PREFIX_BITS) {
                return;
            }
            rule->prefix_length = (int)length;
        } else {
            return;
        }
        rule->is_range = true;
    }
    if (strcmp(port_text, "*") == 0) {
        rule->any_port = true;
        connect_rule_count++;
        return;
    }
    char *unconverted = nullptr;
    unsigned long value = strtoul(port_text, &unconverted, DECIMAL);
    if (*unconverted != '\0' || value == 0 || value > HIGHEST_PORT) {
        return;
    }
    rule->any_port = false;
    rule->port = (uint16_t)value;
    connect_rule_count++;
}

bool load_rules(const char *path) {
    if (path == nullptr) {
        return true;
    }
    FILE *file = fopen(path, "re");
    if (file == nullptr) {
        return errno == ENOENT;
    }
    char line[RULE_LINE_LENGTH];
    while (fgets(line, sizeof(line), file) != nullptr) {
        char host[MAXIMUM_HOST] = "";
        char port_text[PORT_TEXT_LENGTH] = "";
        if (sscanf(line, "%255s %15s", host, port_text) == RULE_WORDS) {
            remember_rule(host, port_text);
        }
    }
    fclose(file);
    return true;
}

bool address_is_loopback(int family, const void *address) {
    if (family == AF_INET) {
        const struct in_addr *v4 = address;
        return (ntohl(v4->s_addr) >> IPV4_FIRST_OCTET_SHIFT) == IPV4_LOOPBACK_FIRST_OCTET;
    }
    if (family == AF_INET6) {
        const struct in6_addr *v6 = address;
        return IN6_IS_ADDR_LOOPBACK(v6);
    }
    return false;
}

struct in6_addr canonical_destination(int family, const void *address) {
    struct in6_addr canonical;
    memset(&canonical, 0, sizeof(canonical));
    if (family == AF_INET6) {
        memcpy(&canonical, address, sizeof(canonical));
    } else if (family == AF_INET) {
        canonical.s6_addr[MAPPED_MARKER_FIRST_BYTE] = MAPPED_MARKER;
        canonical.s6_addr[MAPPED_MARKER_SECOND_BYTE] = MAPPED_MARKER;
        memcpy(&canonical.s6_addr[MAPPED_IPV4_FIRST_BYTE], address, sizeof(struct in_addr));
    }
    return canonical;
}

bool address_within(const struct in6_addr *address, const struct in6_addr *network,
                    int prefix_length) {
    if (prefix_length <= 0 || prefix_length > (int)IPV6_ADDRESS_BITS) {
        return false;
    }
    int whole_bytes = prefix_length / BITS_PER_BYTE;
    int remaining_bits = prefix_length % BITS_PER_BYTE;
    if (memcmp(address, network, (size_t)whole_bytes) != 0) {
        return false;
    }
    if (remaining_bits == 0) {
        return true;
    }
    uint8_t mask = (uint8_t)~((1U << (BITS_PER_BYTE - remaining_bits)) - 1U);
    return (address->s6_addr[whole_bytes] & mask) == (network->s6_addr[whole_bytes] & mask);
}

bool rule_host_matches(const struct connect_rule *rule, int family, const void *address) {
    if (rule->is_range) {
        if (family != AF_INET && family != AF_INET6) {
            return false;
        }
        struct in6_addr canonical = canonical_destination(family, address);
        return address_within(&canonical, &rule->network, rule->prefix_length);
    }
    if (strcmp(rule->host, "*") == 0) {
        return true;
    }
    struct in_addr v4;
    if (inet_pton(AF_INET, rule->host, &v4) == 1) {
        return family == AF_INET && memcmp(address, &v4, sizeof(v4)) == 0;
    }
    struct in6_addr v6;
    if (inet_pton(AF_INET6, rule->host, &v6) == 1) {
        return family == AF_INET6 && memcmp(address, &v6, sizeof(v6)) == 0;
    }
    if (strcmp(rule->host, "localhost") == 0) {
        return address_is_loopback(family, address);
    }
    return true;
}

bool connection_permitted(int family, const void *address, uint16_t port) {
    if (connect_rule_count == 0) {
        return false;
    }
    for (size_t index = 0; index < connect_rule_count; index++) {
        const struct connect_rule *rule = &connect_rules[index];
        if (!rule->any_port && rule->port != port) {
            continue;
        }
        if (rule_host_matches(rule, family, address)) {
            return true;
        }
    }
    return false;
}

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
void connect_rules_reset_for_tests(void) {
    connect_rule_count = 0;
}

size_t connect_rules_count_for_tests(void) {
    return connect_rule_count;
}
#endif
