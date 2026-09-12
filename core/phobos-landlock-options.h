/*
 * Everything the command line asked for.
 *
 * This becomes a class: the collected policy plus the reading of it, so that
 * each stage of the run takes one object rather than eight loose values.
 */
#ifndef PHOBOS_LANDLOCK_OPTIONS_H
#define PHOBOS_LANDLOCK_OPTIONS_H

#include "phobos-landlock-path-rule.h"

#include <stddef.h>
#include <stdint.h>

static constexpr size_t MAXIMUM_PATH_RULES = 4096;
static constexpr size_t MAXIMUM_PORT_RULES = 64;

/* The letters a --rights= option may carry, one per field of path_rule. */
static constexpr char RIGHTS_LETTER_READ = 'r';
static constexpr char RIGHTS_LETTER_WRITE = 'w';
static constexpr char RIGHTS_LETTER_EXECUTE = 'x';
static constexpr char RIGHTS_LETTER_MAKE = 'm';
static constexpr char RIGHTS_LETTER_DELETE = 'd';
static constexpr char RIGHTS_LETTER_IOCTL = 'i';

struct options {
    struct path_rule rules[MAXIMUM_PATH_RULES];
    size_t path_rule_count;
    uint64_t connect_tcp_ports[MAXIMUM_PORT_RULES];
    size_t connect_tcp_port_count;
    uint64_t bind_tcp_ports[MAXIMUM_PORT_RULES];
    size_t bind_tcp_port_count;
    const char *working_directory;
    int minimum_landlock_version;
    char **command;
};

/* Reads the command line into options, or refuses the call. */
void parse_arguments(int argument_count, char *arguments[], struct options *options);

/* True when any network rule was asked for, which decides whether the run needs
 * a kernel new enough to know about network access at all. */
bool network_rules_wanted(const struct options *options);

/* The directions the command line actually spoke about. Only these are handed
 * to the kernel as handled, because a handled direction with no rule is a
 * blanket denial nobody asked for. */
uint64_t handled_network_access(const struct options *options);

/* Records one --rights=LETTERS option. Exposed for the tests. */
void remember_path_rule(struct options *options, const char *letters, const char *path);

/* Reads a number and refuses anything that is not one, or is outside the range
 * the option can mean. Exposed for the tests. */
unsigned long parse_number(const char *text, unsigned long lowest, unsigned long highest,
                           const char *what);

/* Prints how to call this tool and gives up. */
[[noreturn]] void print_usage_and_exit(void);

#endif
