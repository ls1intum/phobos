#include "phobos-seccomp-filesystem-message.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The fixed parts of every line. They are byte exact, because a log search keys on them. */
static const char PREFIX[] = "Phobos Security Error: the program tried to illegally ";
static const char SUFFIX[] = " but was blocked by Phobos.";
static const char OVERFLOW_NOTICE[] = "Phobos: further blocked actions are counted but not shown.\n";

/* The 64-bit FNV-1a parameters, and the byte that ends each part of a key, which no verb or noun
 * holds, so that "ab" and "a" + "b" are different keys. */
static constexpr uint64_t FNV_OFFSET_BASIS = 1469598103934665603ULL;
static constexpr uint64_t FNV_PRIME = 1099511628211ULL;
static constexpr unsigned char KEY_PART_SEPARATOR = 0xff;

/* How many layers the summary counts. */
static constexpr size_t REPORT_LAYER_COUNT = REPORT_LAYER_TIMEOUT + 1;

/* Room for one whole line: an object of two quoted paths, a quoted detail, and the fixed parts. */
static constexpr size_t REPORT_LINE_MAXIMUM = 4 * REPORT_QUOTED_MAXIMUM;

/* Room for the longest object built here, a quoted detail with the words around it. */
static constexpr size_t REPORT_DETAIL_MAXIMUM = REPORT_QUOTED_MAXIMUM + 32;

/* The smallest buffer quote_like_bash writes anything into: the opening $' and a NUL. */
static constexpr size_t QUOTE_SMALLEST_BUFFER = 3;

/* The most bytes one input byte becomes inside the quotes, '\'' or a three-digit octal escape,
 * plus the closing quote and the NUL that must still fit after it. */
static constexpr size_t QUOTE_PIECE_ROOM = 8;

/* The printable ASCII range, the only bytes a path may show unescaped. */
static constexpr unsigned char FIRST_PRINTABLE = 0x20;
static constexpr unsigned char LAST_PRINTABLE = 0x7e;
static constexpr unsigned char ESCAPE_BYTE = 0x1b;

static uint64_t seen_keys[REPORT_KEYS_MAXIMUM];
static bool seen_used[REPORT_KEYS_MAXIMUM];
static size_t lines_shown = 0;
static unsigned long blocked_by_layer[REPORT_LAYER_COUNT];
static unsigned long withheld_repeats = 0;
static unsigned long withheld_beyond_limit = 0;
static bool overflow_said = false;
static char line[REPORT_LINE_MAXIMUM];

/* The ANSI-C escape bash writes for one byte inside $'...', or NULL for a byte it writes in octal
 * or as it is. */
static const char *ansi_c_escape(unsigned char byte) {
    switch (byte) {
    case '\'':
        return "\\'";
    case '\\':
        return "\\\\";
    case '\a':
        return "\\a";
    case '\b':
        return "\\b";
    case '\t':
        return "\\t";
    case '\n':
        return "\\n";
    case '\v':
        return "\\v";
    case '\f':
        return "\\f";
    case '\r':
        return "\\r";
    case ESCAPE_BYTE:
        return "\\E";
    default:
        return NULL;
    }
}

static bool printable(unsigned char byte) {
    return byte >= FIRST_PRINTABLE && byte <= LAST_PRINTABLE;
}

void quote_like_bash(const char *value, char *out, size_t size) {
    if (size < QUOTE_SMALLEST_BUFFER) {
        if (size > 0) {
            out[0] = '\0';
        }
        return;
    }
    size_t length = strnlen(value, REPORT_PATH_SHOWN_MAXIMUM);
    bool truncated = value[length] != '\0';
    bool plain = true;
    for (size_t index = 0; index < length; index++) {
        if (!printable((unsigned char)value[index])) {
            plain = false;
        }
    }
    size_t used = (size_t)snprintf(out, size, "%s", plain ? "'" : "$'");
    for (size_t index = 0; index < length && used + QUOTE_PIECE_ROOM < size; index++) {
        unsigned char byte = (unsigned char)value[index];
        const char *escape = NULL;
        if (plain && byte == '\'') {
            escape = "'\\''";
        } else if (!plain) {
            escape = ansi_c_escape(byte);
        }
        if (escape != NULL) {
            used += (size_t)snprintf(out + used, size - used, "%s", escape);
        } else if (!printable(byte)) {
            used += (size_t)snprintf(out + used, size - used, "\\%03o", byte);
        } else {
            out[used] = (char)byte;
            used++;
            out[used] = '\0';
        }
    }
    used += (size_t)snprintf(out + used, size - used, "'");
    if (truncated && used < size) {
        snprintf(out + used, size - used, " (truncated)");
    }
}

/* Folds one part of a key, and the separator after it, into the hash. */
static uint64_t hash_part(uint64_t hash, const char *part) {
    for (const unsigned char *cursor = (const unsigned char *)part; *cursor != '\0'; cursor++) {
        hash = (hash ^ *cursor) * FNV_PRIME;
    }
    return (hash ^ KEY_PART_SEPARATOR) * FNV_PRIME;
}

/* Answers true the first time a key is seen, and false for a repeat. Open addressing over the
 * table; once it is full a new key is not recorded and answers true every time, so a distinct
 * line is never hidden by a full table, only no longer recognised when it repeats. */
static bool first_time(uint64_t key) {
    size_t start = (size_t)(key % REPORT_KEYS_MAXIMUM);
    for (size_t probe = 0; probe < REPORT_KEYS_MAXIMUM; probe++) {
        size_t slot = (start + probe) % REPORT_KEYS_MAXIMUM;
        if (!seen_used[slot]) {
            seen_used[slot] = true;
            seen_keys[slot] = key;
            return true;
        }
        if (seen_keys[slot] == key) {
            return false;
        }
    }
    return true;
}

/* Words the line and writes it with one call, so two supervisors or a supervisor and the program
 * writing at once cannot interleave inside it. */
static void print_line(const char *verb, const char *noun, const char *object, bool object_is_path,
                       const char *detail_path) {
    static char shown_object[REPORT_QUOTED_MAXIMUM];
    static char quoted_detail[REPORT_QUOTED_MAXIMUM];
    static char detail[REPORT_DETAIL_MAXIMUM];
    const char *object_text = object;
    if (object_is_path) {
        quote_like_bash(object, shown_object, sizeof(shown_object));
        object_text = shown_object;
    }
    detail[0] = '\0';
    if (detail_path != NULL) {
        quote_like_bash(detail_path, quoted_detail, sizeof(quoted_detail));
        snprintf(detail, sizeof(detail), " (named as %s)", quoted_detail);
    }
    snprintf(line, sizeof(line), "%s%s the %s%s%s%s%s\n", PREFIX, verb, noun,
             object_text[0] == '\0' ? "" : " ", object_text, detail, SUFFIX);
    fputs(line, stderr);
}

void report_blocked(enum report_layer layer, const char *verb, const char *noun,
                    const char *object, bool object_is_path, const char *detail_path) {
    blocked_by_layer[layer]++;
    uint64_t key = hash_part(hash_part(hash_part(FNV_OFFSET_BASIS, verb), noun), object);
    if (!first_time(key)) {
        withheld_repeats++;
        return;
    }
    if (lines_shown == REPORT_LINES_MAXIMUM) {
        withheld_beyond_limit++;
        if (!overflow_said) {
            fputs(OVERFLOW_NOTICE, stderr);
            overflow_said = true;
        }
        return;
    }
    lines_shown++;
    print_line(verb, noun, object, object_is_path, detail_path);
}

void report_summary(void) {
    unsigned long filesystem = blocked_by_layer[REPORT_LAYER_FILESYSTEM];
    unsigned long network = blocked_by_layer[REPORT_LAYER_NETWORK];
    unsigned long timeout = blocked_by_layer[REPORT_LAYER_TIMEOUT];
    unsigned long total = filesystem + network + timeout;
    if (total == 0) {
        return;
    }
    fprintf(stderr,
            "Phobos Security Summary: Phobos blocked %lu %s of the program, %lu in the filesystem "
            "layer, %lu in the network layer and %lu in the timeout layer; %zu %s shown above, %lu "
            "%s and %lu beyond the limit of %zu lines were not. (PHB-EDENY)\n",
            total, total == 1 ? "action" : "actions", filesystem, network, timeout, lines_shown,
            lines_shown == 1 ? "was" : "were", withheld_repeats,
            withheld_repeats == 1 ? "repeat" : "repeats", withheld_beyond_limit,
            REPORT_LINES_MAXIMUM);
}

#ifdef PHOBOS_REPORTER_UNIT_TEST
void reset_report_for_tests(void) {
    memset(seen_keys, 0, sizeof(seen_keys));
    memset(seen_used, 0, sizeof(seen_used));
    memset(blocked_by_layer, 0, sizeof(blocked_by_layer));
    lines_shown = 0;
    withheld_repeats = 0;
    withheld_beyond_limit = 0;
    overflow_said = false;
}
#endif
