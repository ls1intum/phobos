#define _GNU_SOURCE
#include "phobos-seccomp-networksystem-receive-filter.h"

#include "phobos-seccomp-networksystem-diagnostics.h"
#include "phobos-seccomp-networksystem-rules.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>

/* Where the network header's fields lie from its start: the version is the first byte's high
 * nibble, the IPv4 source begins at byte 12 and the IPv6 source at byte 8. */
static constexpr uint32_t VERSION_SHIFT = 4;
static constexpr uint32_t IPV4_VERSION = 4;
static constexpr uint32_t IPV6_VERSION = 6;
static constexpr int32_t IPV4_SOURCE_OFFSET = 12;
static constexpr int32_t IPV6_SOURCE_OFFSET = 8;
/* An IPv6 address as the program compares it: four 32-bit words, kept in the scratch slots
 * M[0] to M[3]; an IPv4 address is one word, kept in M[0]. */
static constexpr size_t IPV6_WORDS = 4;
static constexpr size_t WORD_BYTES = 4;
static constexpr int WORD_BITS = 32;
static constexpr int IPV6_ADDRESS_BITS = 128;
/* Where an IPv4-mapped IPv6 address, ::ffff:a.b.c.d, holds its four IPv4 bytes. */
static constexpr size_t MAPPED_IPV4_FIRST_BYTE = 12;
/* 127.0.0.0/8, the IPv4 loopback network: the first octet under its mask. */
static constexpr uint32_t IPV4_LOOPBACK_NETWORK = 0x7f000000;
static constexpr uint32_t IPV4_FIRST_OCTET_MASK = 0xff000000;
/* The third word of an IPv4-mapped IPv6 address, ::ffff:a.b.c.d, and the last word of ::1. */
static constexpr uint32_t MAPPED_MARKER_WORD = 0x0000ffff;
static constexpr uint32_t IPV6_LOOPBACK_LAST_WORD = 1;
/* What the program answers: the whole datagram, never trimmed (a GRO aggregate is long), or none. */
static constexpr uint32_t ACCEPT_WHOLE = 0xffffffff;
static constexpr uint32_t DROP = 0;
/* The loopback interface every network namespace has. */
static const char LOOPBACK_INTERFACE[] = "lo";
/* The most sources one rule yields: a native IPv6 range wide enough to hold every IPv4-mapped
 * address yields itself and every IPv4 source. */
static constexpr size_t SOURCES_PER_RULE = 2;
/* The most instructions one rule adds: four words loaded, masked and compared, a jump to the
 * accept, and for the second source of a wide range one more jump. And the instructions every
 * program has whatever its rules, rounded up. The program for a full table fits, so the writer
 * never runs out of room. */
static constexpr size_t MOST_INSTRUCTIONS_PER_RULE = 14;
static constexpr size_t FIXED_INSTRUCTIONS = 64;
static_assert(MAXIMUM_RULES * MOST_INSTRUCTIONS_PER_RULE + FIXED_INSTRUCTIONS <= RECEIVE_FILTER_MAXIMUM,
              "the receive filter for a full rules table must fit the kernel's limit");

/* One source a rule allows an answer from: an IPv4 or IPv6 network, its words in host order, and
 * how many leading bits of it count. */
struct receive_source {
    bool ipv4;
    uint32_t words[IPV6_WORDS];
    int prefix_length;
};

/* Where a jump whose distance is only known once the program is written goes. */
enum jump_target {
    TO_ACCEPT,
    TO_DROP,
    TO_GATE,
    TO_IPV6,
};

/* A jump written before its target, to be filled in once the target is placed. */
struct pending_jump {
    size_t at;
    enum jump_target target;
};

/* The program being written: its instructions, the jumps still to fill in and where each target
 * begins. Kept in static storage, because the guard writes it once, before it forks. */
struct program_writer {
    struct sock_filter *code;
    size_t used;
    struct pending_jump jumps[RECEIVE_FILTER_MAXIMUM];
    size_t jump_count;
    size_t targets[TO_IPV6 + 1];
};

static struct program_writer writer;

/* What start-up decided, and the program it attaches. Undecided until configure_receive_filter
 * ran, which attach_receive_filter refuses rather than reads as needing no filter. */
static enum receive_filter_state decided = RECEIVE_FILTER_UNDECIDED;
static struct sock_filter program_code[RECEIVE_FILTER_MAXIMUM];
static struct sock_fprog program = {.len = 0, .filter = program_code};

/* Appends one instruction. */
static void emit(struct sock_filter instruction) {
    writer.code[writer.used++] = instruction;
}

/* Appends a jump to a target placed later, recorded to be filled in by fill_in_jumps. */
static void emit_jump_to(enum jump_target target) {
    writer.jumps[writer.jump_count].at = writer.used;
    writer.jumps[writer.jump_count].target = target;
    writer.jump_count++;
    emit((struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JA, 0, 0, 0));
}

/* Appends a load of a 32-bit word of the network header, offset bytes from its start. */
static void emit_load_header_word(int32_t offset) {
    emit((struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)(SKF_NET_OFF + offset)));
}

/* Notes that the target begins at the next instruction. */
static void place_target(enum jump_target target) {
    writer.targets[target] = writer.used;
}

/* Fills in every recorded jump, now that each target is placed. Classic BPF jumps forward only,
 * and every target is placed after every jump to it. */
static void fill_in_jumps(void) {
    for (size_t index = 0; index < writer.jump_count; index++) {
        const struct pending_jump *jump = &writer.jumps[index];
        writer.code[jump->at].k = (uint32_t)(writer.targets[jump->target] - jump->at - 1);
    }
}

/* The mask of the leading bits of one 32-bit word that a prefix covers, word being the word's
 * index within the address. */
static uint32_t word_mask(int prefix_length, size_t word) {
    int bits = prefix_length - (int)word * WORD_BITS;
    if (bits >= WORD_BITS) {
        return 0xffffffff;
    }
    if (bits <= 0) {
        return 0;
    }
    return ~(uint32_t)0 << (WORD_BITS - bits);
}

/* Sets source to the network an address and prefix name: an IPv4-mapped address with a prefix of
 * at least the mapped block's as the IPv4 network it stands for, any other as an IPv6 one. */
static void set_source(struct receive_source *source, const struct in6_addr *address, int prefix_length) {
    memset(source, 0, sizeof(*source));
    source->ipv4 = IN6_IS_ADDR_V4MAPPED(address) && prefix_length >= IPV4_MAPPED_PREFIX_BITS;
    if (source->ipv4) {
        uint32_t word;
        memcpy(&word, &address->s6_addr[MAPPED_IPV4_FIRST_BYTE], WORD_BYTES);
        source->words[0] = ntohl(word);
        source->prefix_length = prefix_length - IPV4_MAPPED_PREFIX_BITS;
        return;
    }
    for (size_t index = 0; index < IPV6_WORDS; index++) {
        uint32_t word;
        memcpy(&word, &address->s6_addr[index * WORD_BYTES], WORD_BYTES);
        source->words[index] = ntohl(word);
    }
    source->prefix_length = prefix_length;
}

/* Whether a native IPv6 network is wide enough to hold every IPv4-mapped address, as ::/80 is, so
 * that the sends it allows include every IPv4 peer and its answers must be let in too. */
static bool holds_every_mapped_address(const struct in6_addr *network, int prefix_length) {
    struct in_addr any;
    memset(&any, 0, sizeof(any));
    struct in6_addr mapped_block = canonical_destination(AF_INET, &any);
    return prefix_length <= IPV4_MAPPED_PREFIX_BITS && address_within(&mapped_block, network, prefix_length);
}

/* Writes into sources what one rule allows an answer from, and answers how many: none for a TCP
 * rule and for "localhost", whose loopback answers the interface check admits; one or two for an
 * address or a range; and SIZE_MAX for a host the guard cannot tie to an address, which allows an
 * answer from anywhere. */
static size_t rule_sources(const struct connect_rule *rule, struct receive_source sources[SOURCES_PER_RULE]) {
    struct in_addr v4;
    struct in6_addr v6;
    if (!rule->is_udp || strcmp(rule->host, "localhost") == 0) {
        return 0;
    }
    if (rule->is_range) {
        set_source(&sources[0], &rule->network, rule->prefix_length);
        if (sources[0].ipv4 || !holds_every_mapped_address(&rule->network, rule->prefix_length)) {
            return 1;
        }
        memset(&sources[1], 0, sizeof(sources[1]));
        sources[1].ipv4 = true;
        return 2;
    }
    if (inet_pton(AF_INET, rule->host, &v4) == 1) {
        v6 = canonical_destination(AF_INET, &v4);
        set_source(&sources[0], &v6, IPV6_ADDRESS_BITS);
        return 1;
    }
    if (inet_pton(AF_INET6, rule->host, &v6) == 1) {
        set_source(&sources[0], &v6, IPV6_ADDRESS_BITS);
        return 1;
    }
    return SIZE_MAX;
}

bool needs_receive_filter(void) {
    struct receive_source sources[SOURCES_PER_RULE];
    for (size_t index = 0; index < connect_rule_count_held(); index++) {
        if (rule_sources(connect_rule_at(index), sources) == SIZE_MAX) {
            return false;
        }
    }
    return true;
}

/* Appends a comparison of the address in the scratch slots with words under masks, a word whose
 * mask is 0 being skipped, that jumps to target when every compared word matches and falls through
 * past that jump otherwise. With no word compared it jumps to target unconditionally. */
static void emit_scratch_match(const uint32_t words[IPV6_WORDS], const uint32_t masks[IPV6_WORDS],
                               size_t count, enum jump_target target) {
    size_t first = writer.used;
    for (size_t index = 0; index < count; index++) {
        if (masks[index] == 0) {
            continue;
        }
        emit((struct sock_filter)BPF_STMT(BPF_LD | BPF_MEM, (uint32_t)index));
        if (masks[index] != 0xffffffff) {
            emit((struct sock_filter)BPF_STMT(BPF_ALU | BPF_AND | BPF_K, masks[index]));
        }
        emit((struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, words[index] & masks[index], 0, 0));
    }
    emit_jump_to(target);
    for (size_t at = first; at < writer.used; at++) {
        if (writer.code[at].code == (BPF_JMP | BPF_JEQ | BPF_K)) {
            writer.code[at].jf = (uint8_t)(writer.used - at - 1);
        }
    }
}

/* Appends the comparison of one source with the address in the scratch slots, jumping to the
 * accept on a match. Only the words its prefix reaches are compared, each under its mask, so a
 * prefix of 0 matches every address of its family. */
static void emit_source_match(const struct receive_source *source) {
    uint32_t masks[IPV6_WORDS];
    for (size_t index = 0; index < IPV6_WORDS; index++) {
        masks[index] = word_mask(source->prefix_length, index);
    }
    emit_scratch_match(source->words, masks, source->ipv4 ? 1 : IPV6_WORDS, TO_ACCEPT);
}

/* Appends every source of every rule of one family. */
static void emit_rule_sources(bool ipv4) {
    struct receive_source sources[SOURCES_PER_RULE];
    for (size_t index = 0; index < connect_rule_count_held(); index++) {
        size_t count = rule_sources(connect_rule_at(index), sources);
        for (size_t source = 0; source < count; source++) {
            if (sources[source].ipv4 == ipv4) {
                emit_source_match(&sources[source]);
            }
        }
    }
}

/* Appends the IPv4 branch: the source into M[0], a loopback source to the interface check, and
 * any other to the rules. */
static void emit_ipv4_branch(void) {
    emit_load_header_word(IPV4_SOURCE_OFFSET);
    emit((struct sock_filter)BPF_STMT(BPF_ST, 0));
    emit((struct sock_filter)BPF_STMT(BPF_ALU | BPF_AND | BPF_K, IPV4_FIRST_OCTET_MASK));
    emit((struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPV4_LOOPBACK_NETWORK, 0, 1));
    emit_jump_to(TO_GATE);
    emit_rule_sources(true);
    emit_jump_to(TO_DROP);
}

/* The IPv6 sources that are loopback: ::1, and an IPv4-mapped loopback address in an IPv6 header,
 * ::ffff:127.0.0.0/104, each as words under masks. */
static const uint32_t IPV6_LOOPBACK_WORDS[IPV6_WORDS] = {0, 0, 0, IPV6_LOOPBACK_LAST_WORD};
static const uint32_t IPV6_LOOPBACK_MASKS[IPV6_WORDS] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
static const uint32_t MAPPED_LOOPBACK_WORDS[IPV6_WORDS] = {0, 0, MAPPED_MARKER_WORD, IPV4_LOOPBACK_NETWORK};
static const uint32_t MAPPED_LOOPBACK_MASKS[IPV6_WORDS] = {0xffffffff, 0xffffffff, 0xffffffff, IPV4_FIRST_OCTET_MASK};

/* Appends the IPv6 branch: the version checked, the four source words into M[0] to M[3], a
 * loopback source to the interface check, and any other to the rules. */
static void emit_ipv6_branch(void) {
    place_target(TO_IPV6);
    emit((struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPV6_VERSION, 1, 0));
    emit_jump_to(TO_DROP);
    for (size_t index = 0; index < IPV6_WORDS; index++) {
        emit_load_header_word(IPV6_SOURCE_OFFSET + (int32_t)(index * WORD_BYTES));
        emit((struct sock_filter)BPF_STMT(BPF_ST, (uint32_t)index));
    }
    emit_scratch_match(IPV6_LOOPBACK_WORDS, IPV6_LOOPBACK_MASKS, IPV6_WORDS, TO_GATE);
    emit_scratch_match(MAPPED_LOOPBACK_WORDS, MAPPED_LOOPBACK_MASKS, IPV6_WORDS, TO_GATE);
    emit_rule_sources(false);
    emit_jump_to(TO_DROP);
}

/* Appends the interface check a loopback source must pass, then the two answers. */
static void emit_gate_and_answers(unsigned int loopback_index) {
    place_target(TO_GATE);
    emit((struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)(SKF_AD_OFF + SKF_AD_IFINDEX)));
    emit((struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, loopback_index, 0, 1));
    place_target(TO_ACCEPT);
    emit((struct sock_filter)BPF_STMT(BPF_RET | BPF_K, ACCEPT_WHOLE));
    place_target(TO_DROP);
    emit((struct sock_filter)BPF_STMT(BPF_RET | BPF_K, DROP));
}

size_t build_receive_filter(struct sock_filter *out, unsigned int loopback_index) {
    memset(&writer, 0, sizeof(writer));
    writer.code = out;
    if (!needs_receive_filter()) {
        return 0;
    }
    emit((struct sock_filter)BPF_STMT(BPF_LD | BPF_B | BPF_ABS, (uint32_t)SKF_NET_OFF));
    emit((struct sock_filter)BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, VERSION_SHIFT));
    emit((struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPV4_VERSION, 1, 0));
    emit_jump_to(TO_IPV6);
    emit_ipv4_branch();
    emit_ipv6_branch();
    emit_gate_and_answers(loopback_index);
    fill_in_jumps();
    return writer.used;
}

/* Attaches the program to a socket and locks it there. Answers 0, or the errno of the step that
 * failed. */
static int lock_program_on(int descriptor) {
    int locked = 1;
    if (setsockopt(descriptor, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) != 0
        || setsockopt(descriptor, SOL_SOCKET, SO_LOCK_FILTER, &locked, sizeof(locked)) != 0) {
        return errno;
    }
    return 0;
}

/* Whether an attach failed because the kernel or a security module refuses socket filters on
 * datagram sockets, rather than because of this program or a shortage. */
static bool refused_by_the_system(int failure) {
    return failure == EPERM || failure == EACCES || failure == ENOPROTOOPT;
}

/* Attaches the program to a fresh datagram socket of one family and lets it go, and stores the
 * errno of the attach, or 0, in attach_failure. Answers false when the probe socket cannot be opened,
 * which says nothing about socket filters and so is never read as their refusal; a kernel without
 * the family stores 0 and answers true, since then the command can open no such socket either. */
static bool probe_family(int family, int *attach_failure) {
    *attach_failure = 0;
    int probe = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (probe < 0) {
        return errno == EAFNOSUPPORT;
    }
    *attach_failure = lock_program_on(probe);
    close(probe);
    return true;
}

bool configure_receive_filter(void) {
    if (!needs_receive_filter()) {
        decided = RECEIVE_FILTER_NEEDLESS;
        return true;
    }
    unsigned int loopback_index = if_nametoindex(LOOPBACK_INTERFACE);
    if (loopback_index == 0) {
        report_failure("there is no loopback interface to accept local datagrams on (%s); refusing "
                       "to run rather than leave datagram sockets unfiltered", strerror(errno));
        return false;
    }
    program.len = (unsigned short)build_receive_filter(program_code, loopback_index);
    int failure = 0;
    bool opened = probe_family(AF_INET, &failure);
    if (opened && failure == 0) {
        opened = probe_family(AF_INET6, &failure);
    }
    if (!opened) {
        report_failure("a socket to probe the receive filter on cannot be opened (%s); refusing to run "
                       "rather than leave datagram sockets unfiltered", strerror(errno));
        return false;
    }
    if (refused_by_the_system(failure)) {
        decided = RECEIVE_FILTER_REFUSED;
        fprintf(stderr, "Phobos: datagram sockets are not filtered by their source in this run, because "
                        "this kernel refuses socket filters on them (%s).\n", strerror(failure));
        return true;
    }
    if (failure != 0) {
        report_failure("the receive filter cannot be attached (%s); refusing to run rather than leave "
                       "datagram sockets unfiltered", strerror(failure));
        return false;
    }
    decided = RECEIVE_FILTER_ATTACHED;
    return true;
}

bool attach_receive_filter(int descriptor) {
    if (decided == RECEIVE_FILTER_NEEDLESS || decided == RECEIVE_FILTER_REFUSED) {
        return true;
    }
    if (decided != RECEIVE_FILTER_ATTACHED) {
        log_verbose("refusing a datagram socket: no receive filter was decided for this run");
        return false;
    }
    int failure = lock_program_on(descriptor);
    if (failure != 0) {
        log_verbose("cannot attach the receive filter to a datagram socket: %s", strerror(failure));
    }
    return failure == 0;
}

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
void receive_filter_set_for_tests(enum receive_filter_state state) {
    decided = state;
}
#endif
