/*
 * The outbound allow-list the guard holds every connect and datagram to: read once from the
 * specification's net.rules, then asked whether a destination is permitted.
 */
#ifndef PHOBOS_CONNECT_GUARD_RULES_H
#define PHOBOS_CONNECT_GUARD_RULES_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

/* The most rules the table holds; a further line is dropped. */
static constexpr size_t MAXIMUM_RULES = 256;
/* The longest host a rule may name, its terminating zero included. */
static constexpr size_t MAXIMUM_HOST = 256;

/* The bit position at which an IPv4-mapped IPv6 address holds its four IPv4 bytes. A range
 * must match libnetblocker's, so an IPv4 range's prefix is offset by this and a range written
 * in IPv6 notation for a mapped address with a shorter prefix is refused, exactly as
 * ld_preloader/netblocker-rule.c does; keep the two in step. */
static constexpr int IPV4_MAPPED_PREFIX_BITS = 96;

/* One line of the outbound allow-list: a host, or an IP range, and the port it is allowed on.
 * A range keeps its network and prefix length in the canonical IPv6 form an IPv4 address maps
 * to, so one comparison covers both families. */
struct connect_rule {
    char host[MAXIMUM_HOST];
    bool any_port;
    uint16_t port;
    bool is_range;
    struct in6_addr network;
    int prefix_length;
};

/* Records one "host port" line, unless the table is full or the line is malformed. */
void remember_rule(const char *host, const char *port_text);

/* Reads the allow-list from the spec's net.rules, one "host port" line each. An absent file
 * leaves the list empty, which denies every destination, the way libnetblocker treats an empty
 * outbound policy. Returns false only when a rules file was named but could not be read for a
 * reason other than its absence, so the caller refuses the run rather than fall open to
 * allow-all on an unreadable policy. */
bool load_rules(const char *path);

/* Whether the address of the given family is a loopback address. */
bool address_is_loopback(int family, const void *address);

/* Writes the destination into the canonical IPv6 form ranges are compared in: an IPv6 address
 * as itself, an IPv4 address as ::ffff:a.b.c.d, matching how a range's network was stored. */
struct in6_addr canonical_destination(int family, const void *address);

/* Whether an address falls within a network of the given prefix length, comparing whole bytes
 * and then the remaining bits of the last byte under a mask. */
bool address_within(const struct in6_addr *address, const struct in6_addr *network,
                    int prefix_length);

/* Whether one rule's host covers this destination address. A range holds the address to its
 * network. An IP literal, and the name "localhost", are held to the exact address; any other
 * hostname is one this guard cannot tie to an address, so its host is not enforced here and the
 * rule rests on its port alone, with libnetblocker checking the host of a dynamic command. */
bool rule_host_matches(const struct connect_rule *rule, int family, const void *address);

/* Whether the allow-list permits a connection to this destination. An empty list denies
 * everything: the policy grants egress by naming it, so a run whose policy names no
 * destination reaches none, matching the deny-first model and libnetblocker's own empty
 * outbound policy. Otherwise a rule permits it when its port covers the port and its host
 * covers the address. */
bool connection_permitted(int family, const void *address, uint16_t port);

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
/* Forgets every rule, so each test case starts from an empty table. */
void connect_rules_reset_for_tests(void);

/* How many rules the table holds. */
size_t connect_rules_count_for_tests(void);
#endif

#endif
