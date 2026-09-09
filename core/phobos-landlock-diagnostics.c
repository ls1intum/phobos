#include "phobos-landlock-diagnostics.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int verbose = 0;

void log_verbose(const char *format, ...) {
    if (!verbose) {
        return;
    }
    va_list argument_list;
    va_start(argument_list, format);
    fprintf(stderr, "[phobos-landlock] ");
    vfprintf(stderr, format, argument_list);
    fprintf(stderr, "\n");
    va_end(argument_list);
}

_Noreturn void exit_with_system_error(const char *message) {
    fprintf(stderr, "[phobos-landlock] %s: %s\n", message, strerror(errno));
    exit(EXIT_CODE_POLICY_ERROR);
}

_Noreturn void exit_with_message(const char *message) {
    fprintf(stderr, "[phobos-landlock] %s\n", message);
    exit(EXIT_CODE_POLICY_ERROR);
}
