#include "netblocker-address.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static constexpr int BITS_PER_BYTE = 8;
static constexpr int ADDRESS_BITS = 128;

/* The IPv4-mapped IPv6 form ::ffff:a.b.c.d: ten zero bytes, two bytes of 0xff, then
 * the four bytes of the IPv4 address. */
static constexpr size_t MAPPED_MARKER_FIRST_BYTE = 10;
static constexpr size_t MAPPED_MARKER_SECOND_BYTE = 11;
static constexpr size_t MAPPED_IPV4_FIRST_BYTE = 12;
static constexpr uint8_t MAPPED_MARKER = 0xff;

/* Writes the IPv4 address into the address in its mapped form, with the dotted text. */
static void hold_ipv4(struct canonical_address *address, const struct in_addr *ipv4) {
    memset(&address->bytes, 0, sizeof(address->bytes));
    address->bytes.s6_addr[MAPPED_MARKER_FIRST_BYTE] = MAPPED_MARKER;
    address->bytes.s6_addr[MAPPED_MARKER_SECOND_BYTE] = MAPPED_MARKER;
    memcpy(&address->bytes.s6_addr[MAPPED_IPV4_FIRST_BYTE], ipv4, sizeof(*ipv4));
    inet_ntop(AF_INET, ipv4, address->text, sizeof(address->text));
}

bool canonical_address_parse(const char *text, struct canonical_address *address) {
    struct in_addr ipv4;
    memset(address, 0, sizeof(*address));
    if (inet_pton(AF_INET6, text, &address->bytes) == 1) {
        strncpy(address->text, text, sizeof(address->text) - 1);
        return true;
    }
    if (inet_pton(AF_INET, text, &ipv4) != 1) {
        return false;
    }
    hold_ipv4(address, &ipv4);
    return true;
}

bool canonical_address_equals(const struct canonical_address *first,
                              const struct canonical_address *second) {
    return memcmp(&first->bytes, &second->bytes, sizeof(first->bytes)) == 0;
}

bool canonical_address_within(const struct canonical_address *address,
                              const struct in6_addr *network, int prefix_length) {
    if (prefix_length <= 0 || prefix_length > ADDRESS_BITS) {
        return false;
    }
    int whole_bytes = prefix_length / BITS_PER_BYTE;
    int remaining_bits = prefix_length % BITS_PER_BYTE;
    if (memcmp(&address->bytes, network, (size_t)whole_bytes) != 0) {
        return false;
    }
    if (remaining_bits == 0) {
        return true;
    }
    uint8_t mask = (uint8_t)~((1U << (BITS_PER_BYTE - remaining_bits)) - 1U);
    return (address->bytes.s6_addr[whole_bytes] & mask) == (network->s6_addr[whole_bytes] & mask);
}

bool canonical_address_is_ipv4_mapped(const struct canonical_address *address) {
    return IN6_IS_ADDR_V4MAPPED(&address->bytes);
}

bool address_text_is_ipv4(const char *text) {
    struct in_addr ipv4;
    return inet_pton(AF_INET, text, &ipv4) == 1;
}
