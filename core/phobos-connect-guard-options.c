#define _GNU_SOURCE
#include "phobos-connect-guard-options.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

[[noreturn]] void print_usage_and_exit(void) {
    fprintf(stderr,
            "Usage: phobos-connect-guard [--verbose] [--rules FILE] -- COMMAND [ARGUMENTS...]\n");
    exit(2);
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
