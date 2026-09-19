#define _GNU_SOURCE
#include "phobos-connect-guard-rules.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

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
        unsigned long length = strtoul(length_text, &length_unconverted, 10);
        unsigned long longest = ipv4 ? 32 : 128;
        if (*length_unconverted != '\0' || length == 0 || length > longest) {
            return;
        }
        if (ipv4) {
            rule->network.s6_addr[10] = 0xff;
            rule->network.s6_addr[11] = 0xff;
            memcpy(&rule->network.s6_addr[12], &v4, sizeof(v4));
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
    unsigned long value = strtoul(port_text, &unconverted, 10);
    if (*unconverted != '\0' || value == 0 || value > 65535) {
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
    char line[512];
    while (fgets(line, sizeof(line), file) != nullptr) {
        char host[MAXIMUM_HOST] = "";
        char port_text[16] = "";
        if (sscanf(line, "%255s %15s", host, port_text) == 2) {
            remember_rule(host, port_text);
        }
    }
    fclose(file);
    return true;
}

bool address_is_loopback(int family, const void *address) {
    if (family == AF_INET) {
        const struct in_addr *v4 = address;
        return (ntohl(v4->s_addr) >> 24) == 127;
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
        canonical.s6_addr[10] = 0xff;
        canonical.s6_addr[11] = 0xff;
        memcpy(&canonical.s6_addr[12], address, sizeof(struct in_addr));
    }
    return canonical;
}

bool address_within(const struct in6_addr *address, const struct in6_addr *network,
                    int prefix_length) {
    if (prefix_length <= 0 || prefix_length > 128) {
        return false;
    }
    int whole_bytes = prefix_length / 8;
    int remaining_bits = prefix_length % 8;
    if (memcmp(address, network, (size_t)whole_bytes) != 0) {
        return false;
    }
    if (remaining_bits == 0) {
        return true;
    }
    uint8_t mask = (uint8_t)~((1U << (8 - remaining_bits)) - 1U);
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
