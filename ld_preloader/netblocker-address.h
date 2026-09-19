/*
 * One network address in the form the filter compares it in.
 *
 * It holds the address as the 128 bits of an IPv6 address plus the text
 * it is compared by, and answers the questions asked about it: whether it equals another,
 * whether it lies in a range, and whether it is an IPv4 address in IPv6 form.
 *
 * An IPv4 address is held as the IPv4-mapped IPv6 address ::ffff:a.b.c.d, so that one
 * comparison serves both families. Its text is the dotted IPv4 form; an IPv6 address
 * keeps the text it was written with.
 */
#ifndef NETBLOCKER_ADDRESS_H
#define NETBLOCKER_ADDRESS_H

#include <arpa/inet.h>
#include <netinet/in.h>

struct canonical_address {
    struct in6_addr bytes;
    char text[INET6_ADDRSTRLEN];
};

/* Reads an IPv4 or IPv6 address literal. Answers false for anything else, a host
 * name and an empty text included. */
bool canonical_address_parse(const char *text, struct canonical_address *address);

/* True when both hold the same 128 bits, whatever text they were written with. */
bool canonical_address_equals(const struct canonical_address *first,
                              const struct canonical_address *second);

/* True when the first prefix_length bits of the address equal those of the network.
 * A length outside 1 to 128 matches nothing. */
bool canonical_address_within(const struct canonical_address *address,
                              const struct in6_addr *network, int prefix_length);

/* True when the address is an IPv4 address in its IPv6-mapped form. */
bool canonical_address_is_ipv4_mapped(const struct canonical_address *address);

/* True when the text is an IPv4 address literal rather than an IPv6 one. */
bool address_text_is_ipv4(const char *text);

#endif
