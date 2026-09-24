#define _GNU_SOURCE
#include "phobos-seccomp-networksystem-options.h"

#include "phobos-seccomp-networksystem-diagnostics.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

[[noreturn]] void print_usage_and_exit(void) {
    fprintf(stderr,
            "Usage: phobos-seccomp-networksystem [--verbose] [--rules FILE] [--broker ADDRESS:PORT] "
            "-- COMMAND [ARGUMENTS...]\n");
    exit(EXIT_CODE_USAGE);
}

void parse_arguments(int argument_count, char *arguments[], struct guard_options *options) {
    memset(options, 0, sizeof(*options));
    int index = 1;
    for (; index < argument_count; index++) {
        if (strcmp(arguments[index], "--verbose") == 0) {
            options->verbose = true;
            continue;
        }
        if (strcmp(arguments[index], "--rules") == 0) {
            index++;
            if (index >= argument_count) {
                print_usage_and_exit();
            }
            options->rules_path = arguments[index];
            continue;
        }
        if (strcmp(arguments[index], "--broker") == 0) {
            index++;
            if (index >= argument_count) {
                print_usage_and_exit();
            }
            options->broker_endpoint = arguments[index];
            continue;
        }
        if (strcmp(arguments[index], "--") == 0) {
            index++;
            break;
        }
        print_usage_and_exit();
    }
    if (index >= argument_count) {
        print_usage_and_exit();
    }
    options->command = &arguments[index];
}
