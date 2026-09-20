/* strdup and strtok_r need this first. */
#define _GNU_SOURCE
#include "netblocker-rule.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* What separates the words of a line. */
static const char WORD_SEPARATORS[] = " \t\r\n";

/* The word that means any host, or every port. */
static const char ANY[] = "*";

static constexpr char COMMENT_START = '#';
static constexpr char RANGE_SEPARATOR = '/';
static constexpr char WILDCARD = '*';
static constexpr char LABEL_SEPARATOR = '.';
static constexpr int DECIMAL = 10;

/* Reads the port word of a line into port. No word and "*" grant every port, which is what
 * a port of zero stands for inside a rule. Answers false for anything but a whole number
 * from 1 to 65535, which drops the rule. A literal "0" is dropped rather than read as every
 * port: it names no port the protocol has, the connect guard drops such a rule, and a rule
 * that widens here while it disappears there would mean two different things in one run. */
static bool parse_port(const char *word, uint16_t *port) {
    char *first_unconverted = nullptr;
    *port = 0;
    if (word == nullptr || strcmp(word, ANY) == 0) {
        return true;
    }
    unsigned long value = strtoul(word, &first_unconverted, DECIMAL);
    if (*first_unconverted != '\0' || value == 0 || value > PORT_MAX) {
        return false;
    }
    *port = (uint16_t)value;
    return true;
}

/* Reads a range from the address before its "/" and the length after it. Answers
 * false for a length the address cannot have, for an address that is not a literal,
 * and for an IPv4-mapped address in IPv6 notation shorter than 96 bits. */
static bool parse_range(const char *address_text, const char *length_text,
                        struct in6_addr *network, int *prefix_length) {
    char *first_unconverted = nullptr;
    struct canonical_address address;
    unsigned long length = strtoul(length_text, &first_unconverted, DECIMAL);
    bool ipv4 = address_text_is_ipv4(address_text);
    unsigned long longest = ipv4 ? IPV4_PREFIX_BITS_MAX : IPV6_PREFIX_BITS_MAX;
    if (*first_unconverted != '\0' || length == 0 || length > longest) {
        return false;
    }
    if (!canonical_address_parse(address_text, &address)) {
        return false;
    }
    if (!ipv4 && canonical_address_is_ipv4_mapped(&address) && length < IPV4_MAPPED_PREFIX_BITS) {
        return false;
    }
    *network = address.bytes;
    *prefix_length = (int)(ipv4 ? IPV4_MAPPED_PREFIX_BITS + length : length);
    return true;
}

/* Allocates a rule holding a copy of the host. Answers nullptr when either allocation
 * fails, so the line grants nothing. */
static struct rule *rule_create(const char *host, struct in6_addr network, int prefix_length,
                                uint16_t port) {
    struct rule *rule = calloc(1, sizeof(*rule));
    if (rule == nullptr) {
        return nullptr;
    }
    rule->host = strdup(host);
    if (rule->host == nullptr) {
        free(rule);
        return nullptr;
    }
    rule->network = network;
    rule->prefix_length = prefix_length;
    rule->port = port;
    return rule;
}

/* True when the host ends with the suffix, in any case. */
static bool host_ends_with(const char *host, const char *suffix) {
    size_t host_length = strlen(host);
    size_t suffix_length = strlen(suffix);
    return host_length >= suffix_length
           && strcasecmp(host + host_length - suffix_length, suffix) == 0;
}

struct rule *rule_parse(char *line) {
    char *position = nullptr;
    char *comment = strchr(line, COMMENT_START);
    if (comment != nullptr) {
        *comment = '\0';
    }
    char *host = strtok_r(line, WORD_SEPARATORS, &position);
    if (host == nullptr) {
        return nullptr;
    }
    uint16_t port = 0;
    if (!parse_port(strtok_r(nullptr, WORD_SEPARATORS, &position), &port)) {
        return nullptr;
    }
    struct in6_addr network = {};
    int prefix_length = 0;
    char *range = strchr(host, RANGE_SEPARATOR);
    if (range != nullptr) {
        *range = '\0';
        if (!parse_range(host, range + 1, &network, &prefix_length)) {
            return nullptr;
        }
    }
    return rule_create(host, network, prefix_length, port);
}

void rule_destroy(struct rule *rule) {
    free(rule->host);
    free(rule);
}

bool rule_is_address_range(const struct rule *rule) {
    return rule->prefix_length != 0;
}

bool rule_is_any_host(const struct rule *rule) {
    return strcasecmp(rule->host, ANY) == 0;
}

bool rule_is_domain_wildcard(const struct rule *rule) {
    return rule->host[0] == WILDCARD && rule->host[1] == LABEL_SEPARATOR;
}

const char *rule_domain_suffix(const struct rule *rule) {
    return rule->host + 1;
}

bool rule_matches_host(const struct rule *rule, const char *host) {
    if (rule_is_any_host(rule)) {
        return rule->port == 0;
    }
    if (rule_is_domain_wildcard(rule)) {
        return host_ends_with(host, rule_domain_suffix(rule));
    }
    return strcasecmp(host, rule->host) == 0;
}

bool rule_permits_lookup_port(const struct rule *rule, uint16_t port) {
    return port == 0 || rule_permits_port(rule, port);
}

bool rule_permits_port(const struct rule *rule, uint16_t port) {
    return rule->port == 0 || rule->port == port;
}

bool rule_names_address(const struct rule *rule, const struct canonical_address *address) {
    struct canonical_address named;
    return canonical_address_parse(rule->host, &named) && canonical_address_equals(&named, address);
}

bool rule_range_contains(const struct rule *rule, const struct canonical_address *address) {
    return canonical_address_within(address, &rule->network, rule->prefix_length);
}
