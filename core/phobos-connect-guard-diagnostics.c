#define _GNU_SOURCE
#include "phobos-connect-guard-diagnostics.h"

#include <stdarg.h>
#include <stdio.h>

static bool verbose = false;

void set_verbose(bool enabled) {
    verbose = enabled;
}

void log_verbose(const char *format, ...) {
    if (!verbose) {
        return;
    }
    va_list arguments;
    va_start(arguments, format);
    fputs("[phobos-connect-guard] ", stderr);
    vfprintf(stderr, format, arguments);
    fputc('\n', stderr);
    va_end(arguments);
}
