#define _GNU_SOURCE
#include "phobos-seccomp-networksystem-options.h"

#include "phobos-seccomp-networksystem-diagnostics.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

[[noreturn]] void print_usage_and_exit(void) {
    fprintf(stderr,
            "Usage: phobos-seccomp-networksystem [--verbose] [--rules FILE] [--broker ADDRESS:PORT] "
            "[--allow-ephemeral-listen] [--allow-ephemeral-udp-bind] [--landlock-bin PATH] "
            "[--report-filesystem] [--group-lock-above] [--broker-log-fd N] "
            "-- COMMAND [ARGUMENTS...]\n"
            "       phobos-seccomp-networksystem [--verbose] --resolve --resolver ADDRESS[:PORT] -- NAME...\n");
    exit(EXIT_CODE_USAGE);
}

/* Reads the descriptor number --broker-log-fd names: digits only and above the standard streams, so a pipe the layer opened. */
static bool read_descriptor_number(const char *text, int *descriptor) {
    char *unconverted = nullptr;
    long number = strtol(text, &unconverted, 10);
    if (*text < '0' || *text > '9' || *unconverted != '\0' || number <= STDERR_FILENO || number > INT_MAX) {
        return false;
    }
    *descriptor = (int)number;
    return true;
}

void parse_arguments(int argument_count, char *arguments[], struct guard_options *options) {
    memset(options, 0, sizeof(*options));
    options->broker_log_descriptor = NO_BROKER_LOG;
    int index = 1;
    for (; index < argument_count; index++) {
        if (strcmp(arguments[index], "--verbose") == 0) {
            options->verbose = true;
            continue;
        }
        if (strcmp(arguments[index], "--allow-ephemeral-listen") == 0) {
            options->allow_ephemeral_listen = true;
            continue;
        }
        if (strcmp(arguments[index], "--allow-ephemeral-udp-bind") == 0) {
            options->allow_ephemeral_udp_bind = true;
            continue;
        }
        if (strcmp(arguments[index], "--report-filesystem") == 0) {
            options->report_filesystem = true;
            continue;
        }
        if (strcmp(arguments[index], "--group-lock-above") == 0) {
            options->group_lock_above = true;
            continue;
        }
        if (strcmp(arguments[index], "--landlock-bin") == 0) {
            index++;
            if (index >= argument_count) {
                print_usage_and_exit();
            }
            options->landlock_bin = arguments[index];
            continue;
        }
        if (strcmp(arguments[index], "--broker-log-fd") == 0) {
            index++;
            if (index >= argument_count || !read_descriptor_number(arguments[index],
                                                                     &options->broker_log_descriptor)) {
                print_usage_and_exit();
            }
            continue;
        }
        if (strcmp(arguments[index], "--resolve") == 0) {
            options->resolve = true;
            continue;
        }
        if (strcmp(arguments[index], "--resolver") == 0) {
            index++;
            if (index >= argument_count) {
                print_usage_and_exit();
            }
            options->resolver_endpoint = arguments[index];
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
