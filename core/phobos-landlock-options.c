#include "phobos-landlock-options.h"

#include "phobos-landlock-diagnostics.h"
#include "phobos-landlock-ruleset.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Noreturn void print_usage_and_exit(void) {
    fprintf(stderr,
            "Usage: phobos-landlock [--ro PATH] [--rox PATH] [--rw PATH] [--rwx PATH]\n"
            "                       [--connect-tcp PORT] [--bind-tcp PORT]\n"
            "                       [--chdir DIRECTORY]\n"
            "                       [--minimum-landlock-version NUMBER] [--verbose]\n"
            "                       -- COMMAND [ARGUMENTS...]\n");
    exit(2);
}

/* atoi and a bare strtoull both answer 0 for input that is not a number at
 * all, which would turn a typo into a weaker policy without saying so. Every
 * number this tool accepts goes through here instead. */
unsigned long parse_number(const char *text, unsigned long lowest, unsigned long highest,
                           const char *what) {
    if (text[0] == '\0') {
        fprintf(stderr, "[phobos-landlock] %s: empty value\n", what);
        exit(EXIT_CODE_POLICY_ERROR);
    }
    errno = 0;
    char *first_unconverted = NULL;
    unsigned long value = strtoul(text, &first_unconverted, 10);
    if (errno != 0 || *first_unconverted != '\0' || value < lowest || value > highest) {
        fprintf(stderr, "[phobos-landlock] %s: '%s'\n", what, text);
        exit(EXIT_CODE_POLICY_ERROR);
    }
    return value;
}

/* The flags are --ro, --rox, --rw and --rwx, so position 3 is the one that
 * says writable and a trailing x says executable. */
void remember_path_rule(struct options *options, const char *flag_name, const char *path) {
    if (options->path_rule_count >= MAXIMUM_PATH_RULES) {
        exit_with_message("too many path rules");
    }
    size_t flag_length = strlen(flag_name);
    if (flag_length < 4) {
        exit_with_message("internal error: a path rule flag is shorter than --ro");
    }
    struct path_rule *rule = &options->rules[options->path_rule_count];
    rule->path = path;
    rule->writable = (flag_name[3] == 'w');
    rule->executable = (flag_name[flag_length - 1] == 'x');
    options->path_rule_count++;
}

static void remember_port(uint64_t *ports, size_t *count, const char *value, const char *what) {
    if (*count >= MAXIMUM_PORT_RULES) {
        exit_with_message(what);
    }
    /* A port outside 1..65535 is a policy mistake, not something to pass on. */
    ports[*count] = (uint64_t)parse_number(value, 1, 65535, "not a TCP port");
    (*count)++;
}

void parse_arguments(int argument_count, char *arguments[], struct options *options) {
    memset(options, 0, sizeof(*options));
    options->minimum_landlock_version = 1;

    int argument_index = 1;
    while (argument_index < argument_count) {
        if (strcmp(arguments[argument_index], "--") == 0) {
            argument_index++;
            break;
        }
        if (strcmp(arguments[argument_index], "--verbose") == 0) {
            verbose = 1;
            argument_index++;
            continue;
        }
        /* Every remaining option takes a value, so it must not be the last word. */
        if (argument_index + 1 >= argument_count) {
            print_usage_and_exit();
        }
        if (strcmp(arguments[argument_index], "--ro") == 0 ||
            strcmp(arguments[argument_index], "--rox") == 0 ||
            strcmp(arguments[argument_index], "--rw") == 0 ||
            strcmp(arguments[argument_index], "--rwx") == 0) {
            remember_path_rule(options, arguments[argument_index],
                               arguments[argument_index + 1]);
        }
        else if (strcmp(arguments[argument_index], "--connect-tcp") == 0) {
            remember_port(options->connect_tcp_ports, &options->connect_tcp_port_count,
                          arguments[argument_index + 1], "too many --connect-tcp ports");
        }
        else if (strcmp(arguments[argument_index], "--bind-tcp") == 0) {
            remember_port(options->bind_tcp_ports, &options->bind_tcp_port_count,
                          arguments[argument_index + 1], "too many --bind-tcp ports");
        }
        else if (strcmp(arguments[argument_index], "--chdir") == 0) {
            options->working_directory = arguments[argument_index + 1];
        }
        else if (strcmp(arguments[argument_index], "--minimum-landlock-version") == 0) {
            options->minimum_landlock_version =
                (int)parse_number(arguments[argument_index + 1], 1,
                                  HIGHEST_KNOWN_LANDLOCK_VERSION,
                                  "not a usable Landlock version");
        }
        else {
            print_usage_and_exit();
        }
        argument_index += 2;
    }
    if (argument_index >= argument_count) {
        print_usage_and_exit();
    }
    options->command = &arguments[argument_index];
}

int network_rules_wanted(const struct options *options) {
    return options->connect_tcp_port_count > 0 || options->bind_tcp_port_count > 0;
}
