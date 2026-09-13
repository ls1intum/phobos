/*
 * One line of the allow-list.
 *
 * This becomes a class: a host, an address or an address range with the port it
 * grants, and the questions the policy asks about it: which host names it covers,
 * which addresses, and on which ports.
 *
 * A line names one of four things. "*" is any host, "*.example.org" any name ending in
 * ".example.org", an address literal that address, and any other word that host name.
 * An address followed by "/length" is a range. The second word is the port: a number,
 * with 0 or "*" or no second word meaning every port. Further words are ignored, and
 * so is everything from a "#".
 */
#ifndef NETBLOCKER_RULE_H
#define NETBLOCKER_RULE_H

#include "netblocker-address.h"

#include <stddef.h>
#include <stdint.h>

/* The longest piece of a line read at once. A longer line is read as several. */
static constexpr size_t RULE_LINE_LENGTH = 512;

/* The highest port a rule or a lookup can name. */
static constexpr unsigned long PORT_MAX = 65535;

/* An IPv4 address is compared as the IPv4-mapped IPv6 address ::ffff:a.b.c.d, whose
 * first 96 bits are that fixed prefix, so an IPv4 prefix length counts from there. An
 * IPv4-mapped address written in IPv6 notation with a shorter prefix, such as
 * ::ffff:10.0.0.0/8, reads like an IPv4 range but covers every IPv4 address and ::1,
 * so such a rule is refused rather than taken at its word. */
static constexpr unsigned long IPV4_MAPPED_PREFIX_BITS = 96;
static constexpr unsigned long IPV4_PREFIX_BITS_MAX = 32;
static constexpr unsigned long IPV6_PREFIX_BITS_MAX = 128;

struct rule {
    char *host;
    struct in6_addr network; /* the start of a range; zero for any other rule */
    int prefix_length;       /* bits of the range, counted in IPv6 form; 0 for no range */
    uint16_t port;           /* 0 for every port */
    struct rule *next;
};

/* Reads one line into a new rule, cutting the line up as it goes. Answers nullptr for
 * a line that names nothing, a line that cannot be a rule, and a rule that could not be
 * allocated: each of those grants nothing, which is the safe direction. */
struct rule *rule_parse(char *line);

/* Frees a rule made by rule_parse. */
void rule_destroy(struct rule *rule);

/* True when the rule is an address range. */
bool rule_is_address_range(const struct rule *rule);

/* True when the rule is "*". */
bool rule_is_any_host(const struct rule *rule);

/* True when the rule is a domain wildcard such as "*.example.org". */
bool rule_is_domain_wildcard(const struct rule *rule);

/* The part of a domain wildcard a name has to end with, its leading dot included. */
const char *rule_domain_suffix(const struct rule *rule);

/* True when the rule covers the host name. "*" covers every name only when the rule
 * grants every port, a domain wildcard every name ending in its suffix, and any other
 * rule the one name it holds, in any case. */
bool rule_matches_host(const struct rule *rule, const char *host);

/* True when a lookup for the port may use the rule: a lookup naming no port, 0, may
 * use any rule. */
bool rule_permits_lookup_port(const struct rule *rule, uint16_t port);

/* True when a connection to the port may use the rule. */
bool rule_permits_port(const struct rule *rule, uint16_t port);

/* True when the rule is an address literal equal to the address. */
bool rule_names_address(const struct rule *rule, const struct canonical_address *address);

/* True when the rule is a range that holds the address. */
bool rule_range_contains(const struct rule *rule, const struct canonical_address *address);

#endif
