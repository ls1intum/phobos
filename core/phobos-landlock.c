/*
 * phobos-landlock -- apply a Landlock filesystem policy, then exec a command.
 *
 * Replaces bubblewrap as the enforcement mechanism of the Phobos filesystem
 * layer. Needs no privileges, no capabilities and no container flags: a task
 * may always restrict itself further.
 *
 * Usage:
 *   phobos-landlock [--ro PATH] [--rox PATH] [--rw PATH] [--rwx PATH]
 *                   [--connect-tcp PORT] [--bind-tcp PORT]
 *                   [--chdir DIRECTORY] [--minimum-landlock-version NUMBER]
 *                   [--verbose] -- COMMAND [ARGUMENTS...]
 *
 * This file is the sequence of stages and nothing else. What each stage works
 * with lives beside it:
 *
 *   phobos-landlock-options.h      the command line, read into one object
 *   phobos-landlock-path-rule.h    one allow-listed path and its rights
 *   phobos-landlock-ruleset.h      the kernel object and the operations on it
 *   phobos-landlock-diagnostics.h  reporting and giving up
 *
 * Exits 125 on any policy error. It never degrades silently: if the running
 * kernel cannot enforce the requested minimum, it refuses to run the command.
 */

#define _GNU_SOURCE
#include "phobos-landlock-diagnostics.h"
#include "phobos-landlock-options.h"
#include "phobos-landlock-path-rule.h"
#include "phobos-landlock-ruleset.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------ stage: add the path rules */

static void add_path_rules(int ruleset_descriptor, int landlock_version,
                           const struct options *options) {
    for (size_t rule_index = 0; rule_index < options->path_rule_count; rule_index++) {
        add_path_rule(ruleset_descriptor, landlock_version, &options->rules[rule_index]);
    }
}

/* ------------------------------------------------ stage: add the port rules */

static void add_port_rules(int ruleset_descriptor, const struct options *options) {
    for (size_t port_index = 0; port_index < options->connect_tcp_port_count; port_index++) {
        add_port_rule(ruleset_descriptor, options->connect_tcp_ports[port_index],
                      LANDLOCK_ACCESS_NETWORK_CONNECT_TCP, "connect");
    }
    for (size_t port_index = 0; port_index < options->bind_tcp_port_count; port_index++) {
        add_port_rule(ruleset_descriptor, options->bind_tcp_ports[port_index],
                      LANDLOCK_ACCESS_NETWORK_BIND_TCP, "bind");
    }
}

/* ------------------------------------------------------- stage: move, first */

/* Before the restriction, because the working directory itself may be outside
 * the allow-list while the paths reached from it are inside it. */
static void enter_working_directory(const struct options *options) {
    if (options->working_directory == NULL) {
        return;
    }
    if (chdir(options->working_directory) != 0) {
        fprintf(stderr, "[phobos-landlock] chdir %s: %s\n", options->working_directory,
                strerror(errno));
        exit(EXIT_CODE_POLICY_ERROR);
    }
}

/* ---------------------------------------------------- stage: run the command */

_Noreturn static void exec_command(const struct options *options) {
    execvp(options->command[0], options->command);
    fprintf(stderr, "[phobos-landlock] exec %s: %s\n", options->command[0], strerror(errno));
    exit(127);
}

/* ------------------------------------------------------------------ the call */

int main(int argument_count, char *arguments[]) {
    static struct options options;

    parse_arguments(argument_count, arguments, &options);
    int landlock_version =
        detect_landlock_version(options.minimum_landlock_version, network_rules_wanted(&options));
    int ruleset_descriptor = create_ruleset(landlock_version, network_rules_wanted(&options));
    add_path_rules(ruleset_descriptor, landlock_version, &options);
    add_port_rules(ruleset_descriptor, &options);
    enter_working_directory(&options);
    apply_restriction(ruleset_descriptor);
    exec_command(&options);
}
