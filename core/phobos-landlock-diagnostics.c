#include "phobos-landlock-diagnostics.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool verbose = false;

/* Both printers share this, so every line of this tool is recognisable by the
 * same prefix no matter which one produced it. */
static void print_prefixed(const char *format, va_list argument_list) {
    fprintf(stderr, "[phobos-landlock] ");
    vfprintf(stderr, format, argument_list);
    fprintf(stderr, "\n");
}

void log_verbose(const char *format, ...) {
    if (!verbose) {
        return;
    }
    va_list argument_list;
    va_start(argument_list, format);
    print_prefixed(format, argument_list);
    va_end(argument_list);
}

void warn_always(const char *format, ...) {
    va_list argument_list;
    va_start(argument_list, format);
    print_prefixed(format, argument_list);
    va_end(argument_list);
}

[[noreturn]] void exit_with_system_error(const char *message) {
    fprintf(stderr, "[phobos-landlock] %s: %s\n", message, strerror(errno));
    exit(EXIT_CODE_POLICY_ERROR);
}

[[noreturn]] void exit_with_message(const char *message) {
    fprintf(stderr, "[phobos-landlock] %s\n", message);
    exit(EXIT_CODE_POLICY_ERROR);
}
