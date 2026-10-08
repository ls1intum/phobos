#define _GNU_SOURCE
#include "phobos-seccomp-networksystem-resolve.h"

#include "phobos-seccomp-networksystem-diagnostics.h"

#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/random.h>
#include <sys/socket.h>

/* How long one try waits for the resolver, and how many tries a lookup makes: a lookup ends within
 * RESOLVE_TRY_MS * RESOLVE_TRIES, two seconds. */
static constexpr int RESOLVE_TRY_MS = 1000;
static constexpr int RESOLVE_TRIES = 2;
/* How many packets that are not the answer one try reads and sets aside before it counts as
 * timed out, so a stream of stray packets cannot hold the lookup up, and no clock is needed. */
static constexpr int RESOLVE_STRAY_PACKETS_MAXIMUM = 4;
/* The port a resolver listens on when the endpoint names none. */
static constexpr unsigned long RESOLVE_DEFAULT_PORT = 53;
/* A DNS message begins with twelve bytes of header. */
static constexpr size_t DNS_HEADER_LENGTH = 12;
/* The longest a name may be in text and in a label, and the room one query and one answer need. The
 * answer buffer is the size an EDNS0 requester says it accepts, so a conforming resolver never sends
 * more. */
static constexpr size_t DNS_NAME_MAXIMUM = 253;
static constexpr size_t DNS_LABEL_MAXIMUM = 63;
static constexpr size_t DNS_QUERY_MAXIMUM = 512;
static constexpr uint16_t DNS_ANSWER_MAXIMUM = 1232;
/* The header bits and codes read: recursion desired in the query, the response and truncation bits
 * and the opcode in the answer, and the response codes that are not a failure. */
static constexpr unsigned char DNS_FLAG_RECURSION_DESIRED = 0x01;
static constexpr unsigned char DNS_FLAG_RESPONSE = 0x80;
static constexpr unsigned char DNS_FLAG_TRUNCATED = 0x02;
static constexpr unsigned char DNS_OPCODE_MASK = 0x78;
static constexpr unsigned char DNS_RCODE_MASK = 0x0f;
static constexpr unsigned char DNS_RCODE_NO_ERROR = 0;
static constexpr unsigned char DNS_RCODE_NAME_ERROR = 3;
/* The record types and class read and written: A and AAAA, the EDNS0 pseudo-record, and the
 * Internet class. */
static constexpr uint16_t DNS_TYPE_A = 1;
static constexpr uint16_t DNS_TYPE_AAAA = 28;
static constexpr uint16_t DNS_TYPE_OPT = 41;
static constexpr uint16_t DNS_CLASS_INTERNET = 1;
/* The top two bits of a name's length byte: both set marks a pointer to an earlier name, and either
 * one alone is a label type this reader does not know. The fixed part of a record after its name:
 * type, class, time to live and the length of its data. */
static constexpr unsigned char DNS_NAME_POINTER_BITS = 0xc0;
static constexpr unsigned char DNS_NAME_OFFSET_MASK = 0x3f;
static constexpr size_t DNS_RECORD_FIXED_LENGTH = 10;

/* One name and the addresses it led to, an IPv4 address in four bytes and an IPv6 one in sixteen. */
struct resolved_address {
    int family;
    unsigned char bytes[16];
};

struct resolved_name {
    const char *name;
    struct resolved_address addresses[RESOLVE_ADDRESSES_PER_NAME];
    size_t count;
};

/* Why a lookup did not give an answer. */
enum lookup_failure {
    LOOKUP_OK = 0,
    LOOKUP_TIMED_OUT,
    LOOKUP_SOCKET_ERROR,
    LOOKUP_REFUSED_BY_RESOLVER,
    LOOKUP_TRUNCATED,
    LOOKUP_MALFORMED,
    LOOKUP_NAME_INVALID,
    LOOKUP_NO_ADDRESS
};

static struct resolved_name resolved_names[RESOLVE_NAMES_MAXIMUM];

bool parse_resolver_endpoint(const char *endpoint, struct sockaddr_storage *address, socklen_t *length) {
    char host[INET6_ADDRSTRLEN + 1];
    const char *port_text = nullptr;
    bool bracketed = endpoint[0] == '[';
    if (bracketed) {
        const char *closing = strchr(endpoint, ']');
        if (closing == nullptr || (closing[1] != ':' && closing[1] != '\0')) {
            return false;
        }
        size_t host_length = (size_t)(closing - endpoint - 1);
        if (host_length == 0 || host_length >= sizeof(host)) {
            return false;
        }
        memcpy(host, endpoint + 1, host_length);
        host[host_length] = '\0';
        port_text = closing[1] == ':' ? closing + 2 : nullptr;
    } else {
        const char *colon = strchr(endpoint, ':');
        if (colon != nullptr && strchr(colon + 1, ':') != nullptr) {
            return false;
        }
        size_t host_length = colon == nullptr ? strlen(endpoint) : (size_t)(colon - endpoint);
        if (host_length == 0 || host_length >= sizeof(host)) {
            return false;
        }
        memcpy(host, endpoint, host_length);
        host[host_length] = '\0';
        port_text = colon == nullptr ? nullptr : colon + 1;
    }
    unsigned long port = RESOLVE_DEFAULT_PORT;
    if (port_text != nullptr) {
        char *unconverted = nullptr;
        port = strtoul(port_text, &unconverted, 10);
        if (*port_text == '\0' || *unconverted != '\0' || port == 0 || port > UINT16_MAX) {
            return false;
        }
    }
    memset(address, 0, sizeof(*address));
    struct in_addr v4;
    struct in6_addr v6;
    if (!bracketed && inet_pton(AF_INET, host, &v4) == 1) {
        struct sockaddr_in *sin = (struct sockaddr_in *)address;
        sin->sin_family = AF_INET;
        sin->sin_port = htons((uint16_t)port);
        sin->sin_addr = v4;
        *length = sizeof(*sin);
        return true;
    }
    if (bracketed && inet_pton(AF_INET6, host, &v6) == 1) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((uint16_t)port);
        sin6->sin6_addr = v6;
        *length = sizeof(*sin6);
        return true;
    }
    return false;
}

/* Whether one character may stand in a host name's label: a letter, a digit, a hyphen or an
 * underscore, which service names use. Anything else is refused rather than put into a query. */
static bool label_character_allowed(unsigned char character) {
    return isalnum(character) || character == '-' || character == '_';
}

/* Writes the query for one name and record type into the buffer: the header with one question
 * and one EDNS0 pseudo-record, the question, and the pseudo-record that lifts the answer's size
 * past 512 bytes. Answers the length written and, through question_length, how long the question
 * is, or 0 for a name that cannot be sent: an empty one, one with an empty or overlong label, one
 * with a character a label may not hold, or one too long. A trailing dot is allowed and means
 * nothing more. */
static size_t build_query(unsigned char *buffer, uint16_t id, const char *name, uint16_t type,
                          size_t *question_length) {
    size_t name_length = strlen(name);
    if (name_length == 0 || name_length > DNS_NAME_MAXIMUM) {
        return 0;
    }
    memset(buffer, 0, DNS_HEADER_LENGTH);
    buffer[0] = (unsigned char)(id >> 8);
    buffer[1] = (unsigned char)(id & 0xff);
    buffer[2] = DNS_FLAG_RECURSION_DESIRED;
    buffer[5] = 1;
    buffer[11] = 1;
    size_t at = DNS_HEADER_LENGTH;
    const char *label = name;
    while (*label != '\0') {
        const char *dot = strchr(label, '.');
        size_t length = dot == nullptr ? strlen(label) : (size_t)(dot - label);
        if (length == 0 || length > DNS_LABEL_MAXIMUM) {
            return 0;
        }
        buffer[at++] = (unsigned char)length;
        for (size_t index = 0; index < length; index++) {
            if (!label_character_allowed((unsigned char)label[index])) {
                return 0;
            }
            buffer[at++] = (unsigned char)label[index];
        }
        label += length;
        if (*label == '.') {
            label++;
        }
    }
    buffer[at++] = 0;
    buffer[at++] = (unsigned char)(type >> 8);
    buffer[at++] = (unsigned char)(type & 0xff);
    buffer[at++] = 0;
    buffer[at++] = DNS_CLASS_INTERNET;
    *question_length = at - DNS_HEADER_LENGTH;
    buffer[at++] = 0;
    buffer[at++] = (unsigned char)(DNS_TYPE_OPT >> 8);
    buffer[at++] = (unsigned char)(DNS_TYPE_OPT & 0xff);
    buffer[at++] = (unsigned char)(DNS_ANSWER_MAXIMUM >> 8);
    buffer[at++] = (unsigned char)(DNS_ANSWER_MAXIMUM & 0xff);
    memset(buffer + at, 0, 6);
    at += 6;
    return at;
}

/* Whether a packet is the answer to this query: a response of the standard kind carrying the id the
 * query had and the one question the query asked, compared without regard to the case of the name,
 * which a resolver may change. The resolver answers on a socket connected to it, so a packet from any
 * other address never arrives; the id and the question stop one that was meant for another query. */
static bool reply_matches(const unsigned char *query, size_t question_length,
                          const unsigned char *reply, size_t reply_length) {
    if (reply_length < DNS_HEADER_LENGTH + question_length) {
        return false;
    }
    if (reply[0] != query[0] || reply[1] != query[1] || !(reply[2] & DNS_FLAG_RESPONSE)
        || (reply[2] & DNS_OPCODE_MASK) != 0 || reply[4] != 0 || reply[5] != 1) {
        return false;
    }
    for (size_t index = 0; index < question_length; index++) {
        if (tolower(reply[DNS_HEADER_LENGTH + index]) != tolower(query[DNS_HEADER_LENGTH + index])) {
            return false;
        }
    }
    return true;
}

/* Asks the resolver once and waits for the answer, RESOLVE_TRIES times at most, each for
 * RESOLVE_TRY_MS. A packet that is not the answer is set aside and the wait goes on, up to
 * RESOLVE_STRAY_PACKETS_MAXIMUM of them in one try. Fills the reply and its length and answers
 * LOOKUP_OK, or says why there is none. */
static enum lookup_failure exchange(const struct sockaddr_storage *resolver, socklen_t resolver_length,
                                    const unsigned char *query, size_t query_length,
                                    size_t question_length, unsigned char *reply,
                                    size_t reply_size, size_t *reply_length) {
    int descriptor = socket(resolver->ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        return LOOKUP_SOCKET_ERROR;
    }
    if (connect(descriptor, (const struct sockaddr *)resolver, resolver_length) != 0) {
        close(descriptor);
        return LOOKUP_SOCKET_ERROR;
    }
    for (int attempt = 0; attempt < RESOLVE_TRIES; attempt++) {
        if (send(descriptor, query, query_length, 0) != (ssize_t)query_length) {
            close(descriptor);
            return LOOKUP_SOCKET_ERROR;
        }
        for (int stray = 0; stray <= RESOLVE_STRAY_PACKETS_MAXIMUM; stray++) {
            struct pollfd waiting = { .fd = descriptor, .events = POLLIN, .revents = 0 };
            if (poll(&waiting, 1, RESOLVE_TRY_MS) <= 0) {
                break;
            }
            ssize_t received = recv(descriptor, reply, reply_size, 0);
            if (received >= 0 && reply_matches(query, question_length, reply, (size_t)received)) {
                *reply_length = (size_t)received;
                close(descriptor);
                return LOOKUP_OK;
            }
        }
    }
    close(descriptor);
    return LOOKUP_TIMED_OUT;
}

/* Adds one address to a name's list, unless the list is full, which cuts the answer short. */
static void add_address(struct resolved_name *entry, int family, const void *bytes, size_t length) {
    if (entry->count >= RESOLVE_ADDRESSES_PER_NAME) {
        log_verbose("%s has more than %zu addresses, the rest are dropped", entry->name,
                    RESOLVE_ADDRESSES_PER_NAME);
        return;
    }
    entry->addresses[entry->count].family = family;
    memcpy(entry->addresses[entry->count].bytes, bytes, length);
    entry->count++;
}

/* How many jumps through compression pointers one name may take, so a pointer that leads back to
 * itself ends the read, and how many records of one answer and how many names, the asked one and
 * its aliases, are kept. An answer with more records than the first is refused, and aliases beyond
 * the second are not followed, which only narrows what the rule allows. */
static constexpr size_t DNS_POINTER_JUMPS_MAXIMUM = 16;
static constexpr size_t RESOLVE_RECORDS_MAXIMUM = 64;
static constexpr size_t RESOLVE_ACCEPTED_NAMES = 9;
/* The record type of an alias. */
static constexpr uint16_t DNS_TYPE_CNAME = 5;

/* One record of an answer, as far as it is read: the name it belongs to, its type and class, and
 * where its data is. */
struct answer_record {
    char owner[DNS_NAME_MAXIMUM + 1];
    uint16_t type;
    uint16_t klass;
    size_t data;
    size_t data_length;
};

static struct answer_record answer_records[RESOLVE_RECORDS_MAXIMUM];

/* Reads the name that begins at an offset of a message into text, in lower case with its labels
 * joined by dots, following compression pointers. Answers whether the name was whole: every label
 * and pointer inside the message, no label longer than 63, the text no longer than 253, no more than
 * DNS_POINTER_JUMPS_MAXIMUM jumps, and no label byte that the text could not tell from a label
 * boundary or the end of the text, which is any byte a host name label may not hold: a label with a
 * dot or a zero inside would otherwise read as two labels or as a shorter name, and compare equal to
 * a name it is not. Sets consumed to how many bytes the name takes where it
 * stands, up to and including its first pointer, which is what a caller steps over. The root name
 * reads as the empty text. */
static bool read_name(const unsigned char *message, size_t length, size_t offset, char *out, size_t *consumed) {
    size_t at = offset;
    size_t written = 0;
    size_t jumps = 0;
    bool jumped = false;
    *consumed = 0;
    for (;;) {
        if (at >= length) {
            return false;
        }
        unsigned char first = message[at];
        if ((first & DNS_NAME_POINTER_BITS) == DNS_NAME_POINTER_BITS) {
            if (at + 1 >= length || ++jumps > DNS_POINTER_JUMPS_MAXIMUM) {
                return false;
            }
            if (!jumped) {
                *consumed = at + 2 - offset;
                jumped = true;
            }
            at = (size_t)(first & DNS_NAME_OFFSET_MASK) << 8 | message[at + 1];
            continue;
        }
        if (first & DNS_NAME_POINTER_BITS) {
            return false;
        }
        if (first == 0) {
            if (!jumped) {
                *consumed = at + 1 - offset;
            }
            out[written] = '\0';
            return true;
        }
        size_t needed = written + (written > 0 ? 1 : 0) + first;
        if (first > DNS_LABEL_MAXIMUM || at + 1 + first > length || needed > DNS_NAME_MAXIMUM) {
            return false;
        }
        if (written > 0) {
            out[written++] = '.';
        }
        for (size_t index = 0; index < first; index++) {
            if (!label_character_allowed(message[at + 1 + index])) {
                return false;
            }
            out[written++] = (char)tolower(message[at + 1 + index]);
        }
        at += (size_t)first + 1;
    }
}

/* Whether a name is one of the names the answer may speak of. */
static bool name_accepted(char accepted[][DNS_NAME_MAXIMUM + 1], size_t count, const char *name) {
    for (size_t index = 0; index < count; index++) {
        if (strcmp(accepted[index], name) == 0) {
            return true;
        }
    }
    return false;
}

/* Reads the records of an answer into answer_records, each with the name it belongs to. Answers
 * whether every name and record lay whole inside the message and there were no more than
 * RESOLVE_RECORDS_MAXIMUM of them. */
static bool read_records(const unsigned char *reply, size_t reply_length, size_t offset, unsigned int answers) {
    if (answers > RESOLVE_RECORDS_MAXIMUM) {
        return false;
    }
    for (unsigned int index = 0; index < answers; index++) {
        struct answer_record *record = &answer_records[index];
        size_t consumed;
        if (!read_name(reply, reply_length, offset, record->owner, &consumed)) {
            return false;
        }
        offset += consumed;
        if (offset + DNS_RECORD_FIXED_LENGTH > reply_length) {
            return false;
        }
        record->type = (uint16_t)(reply[offset] << 8 | reply[offset + 1]);
        record->klass = (uint16_t)(reply[offset + 2] << 8 | reply[offset + 3]);
        record->data_length = (size_t)(reply[offset + 8] << 8 | reply[offset + 9]);
        offset += DNS_RECORD_FIXED_LENGTH;
        if (record->data_length > reply_length - offset) {
            return false;
        }
        record->data = offset;
        offset += record->data_length;
    }
    return true;
}

/* Adds to the accepted names the target of every alias record that belongs to a name already
 * accepted, until no alias adds one. The first accepted name is the one that was asked, in lower
 * case and without a trailing dot, so an address is only ever taken from a record that belongs to
 * that name or to a chain of aliases that leads from it, however the resolver ordered the records.
 * Answers the number of names accepted, or 0 where an alias target could not be read. */
static size_t follow_aliases(const unsigned char *reply, size_t reply_length, unsigned int answers,
                             const char *asked, char accepted[][DNS_NAME_MAXIMUM + 1]) {
    size_t length = strlen(asked);
    if (length > 0 && asked[length - 1] == '.') {
        length--;
    }
    for (size_t index = 0; index < length; index++) {
        accepted[0][index] = (char)tolower((unsigned char)asked[index]);
    }
    accepted[0][length] = '\0';
    size_t count = 1;
    size_t consumed;
    for (size_t round = 0; round < RESOLVE_ACCEPTED_NAMES; round++) {
        bool grew = false;
        for (unsigned int index = 0; index < answers; index++) {
            const struct answer_record *record = &answer_records[index];
            if (record->klass != DNS_CLASS_INTERNET || record->type != DNS_TYPE_CNAME
                || !name_accepted(accepted, count, record->owner)) {
                continue;
            }
            char target[DNS_NAME_MAXIMUM + 1];
            if (!read_name(reply, reply_length, record->data, target, &consumed) || consumed > record->data_length) {
                return 0;
            }
            if (!name_accepted(accepted, count, target) && count < RESOLVE_ACCEPTED_NAMES) {
                memcpy(accepted[count++], target, sizeof(target));
                grew = true;
            }
        }
        if (!grew) {
            break;
        }
    }
    return count;
}

/* Reads the answer section of a reply for the addresses of one record type. An address is taken
 * only from a record that belongs to the name asked, or to a name a chain of alias records leads to
 * from it: a record for any other name is not an answer to the question, and is left out however
 * well formed. The question is skipped by its length, which reply_matches has already shown to be
 * present and the one that was asked. A name that does not exist and an answer with no record of
 * the type give no address and are not a failure. Answers LOOKUP_TRUNCATED for a truncated reply,
 * LOOKUP_REFUSED_BY_RESOLVER for any other error code, and LOOKUP_MALFORMED where a name or record
 * runs past the end of the message, a name loops, or an address record has the wrong length. */
static enum lookup_failure read_answers(struct resolved_name *entry, const unsigned char *reply,
                                        size_t reply_length, size_t question_length, uint16_t type) {
    unsigned char code = reply[3] & DNS_RCODE_MASK;
    if (reply[2] & DNS_FLAG_TRUNCATED) {
        return LOOKUP_TRUNCATED;
    }
    if (code == DNS_RCODE_NAME_ERROR) {
        return LOOKUP_OK;
    }
    if (code != DNS_RCODE_NO_ERROR) {
        return LOOKUP_REFUSED_BY_RESOLVER;
    }
    unsigned int answers = (unsigned int)(reply[6] << 8 | reply[7]);
    if (!read_records(reply, reply_length, DNS_HEADER_LENGTH + question_length, answers)) {
        return LOOKUP_MALFORMED;
    }
    char accepted[RESOLVE_ACCEPTED_NAMES][DNS_NAME_MAXIMUM + 1];
    size_t accepted_count = follow_aliases(reply, reply_length, answers, entry->name, accepted);
    if (accepted_count == 0) {
        return LOOKUP_MALFORMED;
    }
    size_t wanted = type == DNS_TYPE_A ? sizeof(struct in_addr) : sizeof(struct in6_addr);
    for (unsigned int index = 0; index < answers; index++) {
        const struct answer_record *record = &answer_records[index];
        if (record->klass != DNS_CLASS_INTERNET || record->type != type
            || !name_accepted(accepted, accepted_count, record->owner)) {
            continue;
        }
        if (record->data_length != wanted) {
            return LOOKUP_MALFORMED;
        }
        add_address(entry, type == DNS_TYPE_A ? AF_INET : AF_INET6, reply + record->data, wanted);
    }
    return LOOKUP_OK;
}

/* Looks up one record type of one name and adds what it finds to the entry. */
static enum lookup_failure look_up(const struct sockaddr_storage *resolver, socklen_t resolver_length,
                                   struct resolved_name *entry, uint16_t type) {
    uint16_t id;
    if (getrandom(&id, sizeof(id), 0) != (ssize_t)sizeof(id)) {
        return LOOKUP_SOCKET_ERROR;
    }
    unsigned char query[DNS_QUERY_MAXIMUM];
    size_t question_length = 0;
    size_t query_length = build_query(query, id, entry->name, type, &question_length);
    if (query_length == 0) {
        return LOOKUP_NAME_INVALID;
    }
    unsigned char reply[DNS_ANSWER_MAXIMUM];
    size_t reply_length = 0;
    enum lookup_failure outcome = exchange(resolver, resolver_length, query, query_length,
                                           question_length, reply, sizeof(reply), &reply_length);
    if (outcome != LOOKUP_OK) {
        return outcome;
    }
    return read_answers(entry, reply, reply_length, question_length, type);
}

/* The sentence a failure is reported with. */
static const char *failure_text(enum lookup_failure failure) {
    switch (failure) {
    case LOOKUP_TIMED_OUT:
        return "the resolver did not answer in time";
    case LOOKUP_SOCKET_ERROR:
        return "the resolver could not be reached";
    case LOOKUP_REFUSED_BY_RESOLVER:
        return "the resolver answered with an error";
    case LOOKUP_TRUNCATED:
        return "the answer was truncated";
    case LOOKUP_MALFORMED:
        return "the answer could not be read";
    case LOOKUP_NAME_INVALID:
        return "the name cannot be sent as a DNS question";
    case LOOKUP_NO_ADDRESS:
    case LOOKUP_OK:
        break;
    }
    return "no address was found";
}

/* Writes one "NAME ADDRESS" line for every address of every name. */
static void print_results(size_t count, FILE *out) {
    for (size_t index = 0; index < count; index++) {
        for (size_t at = 0; at < resolved_names[index].count; at++) {
            char text[INET6_ADDRSTRLEN];
            const struct resolved_address *address = &resolved_names[index].addresses[at];
            inet_ntop(address->family, address->bytes, text, sizeof(text));
            fprintf(out, "%s %s\n", resolved_names[index].name, text);
        }
    }
}

int run_resolve_mode(const char *resolver_endpoint, char *const *names, FILE *out) {
    struct sockaddr_storage resolver;
    socklen_t resolver_length = 0;
    if (resolver_endpoint == nullptr || !parse_resolver_endpoint(resolver_endpoint, &resolver, &resolver_length)) {
        report_failure("the resolver '%s' is not an address, address:port or [address]:port",
                       resolver_endpoint == nullptr ? "" : resolver_endpoint);
        return EXIT_CODE_SETUP_ERROR;
    }
    size_t count = 0;
    for (; names[count] != nullptr; count++) {
        if (count >= RESOLVE_NAMES_MAXIMUM) {
            report_failure("more than %zu names to resolve", RESOLVE_NAMES_MAXIMUM);
            return EXIT_CODE_SETUP_ERROR;
        }
    }
    for (size_t index = 0; index < count; index++) {
        struct resolved_name *entry = &resolved_names[index];
        memset(entry, 0, sizeof(*entry));
        entry->name = names[index];
        enum lookup_failure failure = look_up(&resolver, resolver_length, entry, DNS_TYPE_A);
        if (failure == LOOKUP_OK) {
            failure = look_up(&resolver, resolver_length, entry, DNS_TYPE_AAAA);
        }
        if (failure == LOOKUP_OK && entry->count == 0) {
            failure = LOOKUP_NO_ADDRESS;
        }
        if (failure != LOOKUP_OK) {
            report_failure("cannot resolve %s: %s", entry->name, failure_text(failure));
            return EXIT_CODE_SETUP_ERROR;
        }
    }
    print_results(count, out);
    return 0;
}
