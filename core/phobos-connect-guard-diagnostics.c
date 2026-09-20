#define _GNU_SOURCE
#include "phobos-connect-guard-diagnostics.h"

#include <stdarg.h>
#include <stdio.h>

static bool verbose = false;

void set_verbose(bool enabled) {
    verbose = enabled;
}

/* Both printers share this, so every line of the guard carries the same prefix no matter
 * which one produced it. */
static void print_prefixed(const char *format, va_list arguments) {
    fputs("[phobos-connect-guard] ", stderr);
    vfprintf(stderr, format, arguments);
    fputc('\n', stderr);
}

void log_verbose(const char *format, ...) {
    if (!verbose) {
        return;
    }
    va_list arguments;
    va_start(arguments, format);
    print_prefixed(format, arguments);
    va_end(arguments);
}

void report_failure(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    print_prefixed(format, arguments);
    va_end(arguments);
}
