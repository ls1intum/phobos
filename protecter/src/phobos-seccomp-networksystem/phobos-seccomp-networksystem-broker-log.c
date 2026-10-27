#define _GNU_SOURCE
#include "phobos-seccomp-networksystem-broker-log.h"

#include "phobos-seccomp-networksystem-destination.h"
#include "phobos-seccomp-networksystem-handoff.h"
#include "phobos-seccomp-networksystem-report.h"

#include "../phobos-seccomp-filesystem/phobos-seccomp-filesystem-message.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* The marker every line of the broker's log begins with, and the two fields that mark a refusal. */
static const char LINE_MARKER[] = "PHB-BROKER";
static const char REFUSING_BACKEND[] = "refuse";
static const char REFUSED_BY_PROXY[] = "PR";

/* A line is split into this many space-separated fields: the marker, the backend, the termination
 * state, the host name, the address, the port and the token. */
static constexpr size_t FIELD_COUNT = 7;
static constexpr size_t TOKEN_FIELD = 6;

/* A token's sequence number and its random part, in bytes, and the hex that spells a whole token. */
static constexpr size_t TOKEN_SEQUENCE_SIZE = 8;
static constexpr size_t TOKEN_NONCE_SIZE = BROKER_TOKEN_SIZE - TOKEN_SEQUENCE_SIZE;
static constexpr size_t TOKEN_HEX_LENGTH = 2 * BROKER_TOKEN_SIZE;

/* The most handoffs a run keeps count of, and the room first made for them. Past the most, the wait at
 * the end lasts the whole grace rather than the guard's memory growing without bound. */
static constexpr uint64_t HANDOFF_MAXIMUM = 65536;
static constexpr size_t HANDOFF_FIRST_CAPACITY = 64;

/* Where a handoff stands: its token drawn, its header sent whole, its line read back. */
static constexpr uint8_t HANDOFF_RESERVED = 0;
static constexpr uint8_t HANDOFF_OUTSTANDING = 1;
static constexpr uint8_t HANDOFF_ANSWERED = 2;

/* The most reads one drain makes, so a broker that keeps writing cannot hold the guard in a drain. */
static constexpr int READS_PER_DRAIN = 64;

/* The units the grace is reckoned in from the monotonic clock. */
static constexpr long long MILLISECONDS_PER_SECOND = 1000;
static constexpr long long NANOSECONDS_PER_MILLISECOND = 1000000;

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

/* One handoff the guard made to the broker: the random part of its token and where it stands. */
struct handoff {
    uint8_t nonce[TOKEN_NONCE_SIZE];
    uint8_t state;
};

/* Every handoff of the run, indexed by its sequence number, and the counts the wait at the end reads.
 * Once counting is lost it stays lost for the run, and the wait lasts the whole grace. */
static struct handoff *handoffs = nullptr;
static size_t handoff_capacity = 0;
static uint64_t handoffs_reserved = 0;
static uint64_t handoffs_handed = 0;
static uint64_t handoffs_answered = 0;
static bool counting_lost = false;
static uint64_t handoff_limit = HANDOFF_MAXIMUM;
static int grace_milliseconds = BROKER_LOG_GRACE_MILLISECONDS;

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

/* Reads a token's hex into its sequence number and its random part. Answers false unless it is exactly
 * BROKER_TOKEN_SIZE bytes of hex, so "-", the broker's spelling of no token, is never one. */
static bool read_token(const char *hex, uint64_t *sequence, uint8_t *nonce) {
    uint8_t bytes[BROKER_TOKEN_SIZE];
    if (strlen(hex) != TOKEN_HEX_LENGTH) {
        return false;
    }
    for (size_t index = 0; index < BROKER_TOKEN_SIZE; index++) {
        int high = hex_value(hex[2 * index]);
        int low = hex_value(hex[2 * index + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        bytes[index] = (uint8_t)(high * 16 + low);
    }
    *sequence = 0;
    for (size_t index = 0; index < TOKEN_SEQUENCE_SIZE; index++) {
        *sequence = (*sequence << 8) | bytes[index];
    }
    memcpy(nonce, bytes + TOKEN_SEQUENCE_SIZE, TOKEN_NONCE_SIZE);
    return true;
}

/* Counts the handoff a line's token names as answered, when the guard handed it over, has not seen it
 * answered yet, and the random part matches the one it drew. Any other token changes nothing. */
static void answer_token(const char *hex) {
    uint64_t sequence = 0;
    uint8_t nonce[TOKEN_NONCE_SIZE];
    if (!read_token(hex, &sequence, nonce) || sequence >= handoffs_reserved) {
        return;
    }
    struct handoff *handoff = &handoffs[sequence];
    if (handoff->state != HANDOFF_OUTSTANDING || memcmp(handoff->nonce, nonce, TOKEN_NONCE_SIZE) != 0) {
        return;
    }
    handoff->state = HANDOFF_ANSWERED;
    handoffs_answered++;
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
    answer_token(fields[TOKEN_FIELD]);
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

bool drain_broker_log(int descriptor) {
    char chunk[READ_SIZE];
    for (int reads = 0; reads < READS_PER_DRAIN; reads++) {
        ssize_t count = read(descriptor, chunk, sizeof(chunk));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        take_chunk(chunk, (size_t)count);
    }
    return true;
}

/* Makes room for the handoff with the given sequence number, doubling what there is. Answers false
 * when no room can be had. */
static bool make_room_for(uint64_t sequence) {
    if (sequence < handoff_capacity) {
        return true;
    }
    size_t capacity = handoff_capacity == 0 ? HANDOFF_FIRST_CAPACITY : 2 * handoff_capacity;
    struct handoff *grown = realloc(handoffs, capacity * sizeof(*grown));
    if (grown == nullptr) {
        return false;
    }
    handoffs = grown;
    handoff_capacity = capacity;
    return true;
}

/* Fills nonce with fresh random bytes from the kernel, retrying an interruption and a short read.
 * Answers false when the kernel gives none. */
static bool draw_nonce(uint8_t *nonce) {
    size_t drawn = 0;
    while (drawn < TOKEN_NONCE_SIZE) {
        ssize_t got = getrandom(nonce + drawn, TOKEN_NONCE_SIZE - drawn, 0);
        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got <= 0) {
            return false;
        }
        drawn += (size_t)got;
    }
    return true;
}

bool reserve_broker_token(uint8_t token[BROKER_TOKEN_SIZE]) {
    uint64_t sequence = handoffs_reserved;
    if (counting_lost || sequence >= handoff_limit || !make_room_for(sequence)
        || !draw_nonce(handoffs[sequence].nonce)) {
        counting_lost = true;
        return false;
    }
    handoffs[sequence].state = HANDOFF_RESERVED;
    for (size_t index = 0; index < TOKEN_SEQUENCE_SIZE; index++) {
        token[index] = (uint8_t)(sequence >> (8 * (TOKEN_SEQUENCE_SIZE - 1 - index)));
    }
    memcpy(token + TOKEN_SEQUENCE_SIZE, handoffs[sequence].nonce, TOKEN_NONCE_SIZE);
    handoffs_reserved++;
    return true;
}

void hand_broker_token(void) {
    handoffs[handoffs_reserved - 1].state = HANDOFF_OUTSTANDING;
    handoffs_handed++;
}

/* Whether the guard still has reason to read on: a handoff not yet answered, or a count it lost, and no
 * forwarded signal that says the run is being ended. */
static bool worth_waiting(void) {
    bool all_answered = !counting_lost && handoffs_answered == handoffs_handed;
    return !all_answered && !forwarded_signal_arrived();
}

/* The milliseconds left of the grace that began at start, or none when the clock cannot be read. */
static int milliseconds_left(const struct timespec *start) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    long long elapsed = (long long)(now.tv_sec - start->tv_sec) * MILLISECONDS_PER_SECOND
                        + (now.tv_nsec - start->tv_nsec) / NANOSECONDS_PER_MILLISECOND;
    long long left = grace_milliseconds - elapsed;
    return left > 0 ? (int)left : 0;
}

/* Waits for the pipe for what is left of the grace and drains it once when it is readable, even when it
 * has also hung up. The forwarded signals are blocked by the caller and let in only for the wait itself,
 * with the mask from outside, so a signal that comes after the caller looked for one interrupts the
 * wait rather than going unseen until the grace is over. Answers whether to wait again: after a drain
 * or an interruption, but not when the grace is gone, the pipe stayed silent, or it failed or hung up
 * with nothing left in it. */
static bool wait_for_lines(int descriptor, const struct timespec *start, const sigset_t *outside) {
    int left = milliseconds_left(start);
    if (left == 0) {
        return false;
    }
    struct timespec wait = {
        .tv_sec = left / MILLISECONDS_PER_SECOND,
        .tv_nsec = (left % MILLISECONDS_PER_SECOND) * NANOSECONDS_PER_MILLISECOND,
    };
    struct pollfd watch = { .fd = descriptor, .events = POLLIN, .revents = 0 };
    int ready = ppoll(&watch, 1, &wait, outside);
    if (ready < 0) {
        return errno == EINTR;
    }
    if (ready == 0 || (watch.revents & POLLIN) == 0) {
        return false;
    }
    drain_broker_log(descriptor);
    return true;
}

void settle_broker_log(int descriptor) {
    struct timespec start;
    sigset_t forwarded;
    sigset_t outside;
    bool timed = clock_gettime(CLOCK_MONOTONIC, &start) == 0;
    drain_broker_log(descriptor);
    block_forwarded_signals(&forwarded, &outside);
    while (timed && worth_waiting() && wait_for_lines(descriptor, &start, &outside)) {
    }
    sigprocmask(SIG_SETMASK, &outside, nullptr);
    drain_broker_log(descriptor);
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
    free(handoffs);
    handoffs = nullptr;
    handoff_capacity = 0;
    handoffs_reserved = 0;
    handoffs_handed = 0;
    handoffs_answered = 0;
    counting_lost = false;
    handoff_limit = HANDOFF_MAXIMUM;
    grace_milliseconds = BROKER_LOG_GRACE_MILLISECONDS;
}

void broker_log_grace_for_tests(int milliseconds) {
    grace_milliseconds = milliseconds;
}

void broker_token_limit_for_tests(uint64_t limit) {
    handoff_limit = limit;
}
#endif
