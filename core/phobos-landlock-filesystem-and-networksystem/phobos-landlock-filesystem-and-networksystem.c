/*
 * phobos-landlock-filesystem-and-networksystem -- apply a Landlock filesystem policy, then exec a command.
 *
 * Replaces bubblewrap as the enforcement mechanism of the Phobos filesystem
 * layer. Needs no privileges, no capabilities and no container flags: a task
 * may always restrict itself further.
 *
 * Usage:
 *   phobos-landlock-filesystem-and-networksystem --rights=LETTERS PATH [--rights=LETTERS PATH ...]
 *                   [--connect-tcp PORT] [--bind-tcp PORT]
 *                   [--connect-udp PORT] [--bind-udp PORT]
 *                   [--close-bind] [--ephemeral-bind-tcp] [--ephemeral-bind-udp]
 *                   [--chdir DIRECTORY] [--minimum-landlock-version NUMBER]
 *                   [--verbose] -- COMMAND [ARGUMENTS...]
 *
 * LETTERS is any combination of r (read), w (write), x (execute), m (create
 * regular files and directories), p (create sockets and named pipes), l (create
 * symbolic links), f (move or rename across directories), d (delete) and i
 * (ioctl on a device), each at most once.
 *
 * This file is the sequence of stages and nothing else. What each stage works
 * with lives beside it:
 *
 *   phobos-landlock-filesystem-and-networksystem-options.h      the command line, read into one object
 *   phobos-landlock-filesystem-and-networksystem-path-rule.h    one allow-listed path and its rights
 *   phobos-landlock-filesystem-and-networksystem-ruleset.h      the kernel object and the operations on it
 *   phobos-landlock-filesystem-and-networksystem-diagnostics.h  reporting and giving up
 *
 * Exits 125 on any policy error. It never degrades silently: if the running
 * kernel cannot enforce the requested minimum, it refuses to run the command,
 * and a right the kernel is too old to handle at all is reported before the
 * command starts rather than left to be discovered.
 */

#define _GNU_SOURCE
#include "phobos-landlock-filesystem-and-networksystem-diagnostics.h"
#include "phobos-landlock-filesystem-and-networksystem-options.h"
#include "phobos-landlock-filesystem-and-networksystem-path-rule.h"
#include "phobos-landlock-filesystem-and-networksystem-ruleset.h"

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

/* ------------------------------------- stage: let the filesystem ruleset beside this one decide */

/* To the kernel, a layer that handles no filesystem right also handles no REFER, and a layer that
 * does not handle REFER refuses every rename and hard link between two directories, whatever the
 * layers above it allow: stacked under a filesystem ruleset it turned every such call into EXDEV.
 * So a network-only ruleset handles REFER and nothing else of the filesystem, and grants it on the
 * root, which leaves it enforcing exactly what it enforced before and leaves the decision to the
 * filesystem ruleset. */
static void allow_reparenting_everywhere(int ruleset_descriptor, int landlock_version) {
    struct path_rule root = {.path = "/", .referable = true};
    add_path_rule(ruleset_descriptor, landlock_version, &root);
}

/* ------------------------------------------------ stage: add the port rules */

static void add_port_rules(int ruleset_descriptor, const struct options *options) {
    for (size_t port_index = 0; port_index < options->connect_tcp_port_count; port_index++) {
        add_port_rule(ruleset_descriptor, options->connect_tcp_ports[port_index],
                      LANDLOCK_ACCESS_NETWORK_CONNECT_TCP, "connect", "tcp");
    }
    for (size_t port_index = 0; port_index < options->bind_tcp_port_count; port_index++) {
        add_port_rule(ruleset_descriptor, options->bind_tcp_ports[port_index],
                      LANDLOCK_ACCESS_NETWORK_BIND_TCP, "bind", "tcp");
    }
    for (size_t port_index = 0; port_index < options->connect_udp_port_count; port_index++) {
        add_port_rule(ruleset_descriptor, options->connect_udp_ports[port_index],
                      LANDLOCK_ACCESS_NETWORK_CONNECT_SEND_UDP, "connect", "udp");
    }
    for (size_t port_index = 0; port_index < options->bind_udp_port_count; port_index++) {
        add_port_rule(ruleset_descriptor, options->bind_udp_ports[port_index],
                      LANDLOCK_ACCESS_NETWORK_BIND_UDP, "bind", "udp");
    }
}

/* ------------------------------------------- stage: add the ephemeral bind grants */

/* Port 0 asks the kernel to pick the port. It is granted only for a direction the ruleset
 * handles, because a rule for an access the ruleset does not handle is refused by the kernel,
 * and a direction an old kernel cannot handle is already reported by report_bind_not_closed.
 * It never refuses: it is a grant, not a demand for a kernel feature. */
static void add_ephemeral_bind_rules(int ruleset_descriptor, const struct options *options,
                                     uint64_t handled_network) {
    if (options->ephemeral_bind_tcp && (handled_network & LANDLOCK_ACCESS_NETWORK_BIND_TCP) != 0) {
        add_port_rule(ruleset_descriptor, 0, LANDLOCK_ACCESS_NETWORK_BIND_TCP, "bind", "tcp");
    }
    if (options->ephemeral_bind_udp && (handled_network & LANDLOCK_ACCESS_NETWORK_BIND_UDP) != 0) {
        add_port_rule(ruleset_descriptor, 0, LANDLOCK_ACCESS_NETWORK_BIND_UDP, "bind", "udp");
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
        exit_with_format("chdir %s: %s", options->working_directory, strerror(errno));
    }
}

/* ---------------------------------------------------- stage: run the command */

[[noreturn]] static void exec_command(const struct options *options) {
    execvp(options->command[0], options->command);
    fprintf(stderr, "[phobos-landlock-filesystem-and-networksystem] exec %s: %s\n", options->command[0], strerror(errno));
    exit(EXIT_CODE_COMMAND_NOT_EXECUTABLE);
}

/* ------------------------------------------------------------------ the call */

int main(int argument_count, char *arguments[]) {
    static struct options options;

    parse_arguments(argument_count, arguments, &options);
    int landlock_version =
        detect_landlock_version(options.minimum_landlock_version, network_rules_wanted(&options),
                                udp_rules_wanted(&options));

    /* With --no-filesystem this ruleset governs the network alone, so it handles no filesystem
     * right but REFER, which it grants everywhere (see allow_reparenting_everywhere), and carries
     * no other path rule; it composes by intersection with a separate filesystem
     * ruleset a later layer applies. Otherwise it handles the filesystem as before. Scoping is
     * applied either way, inside create_ruleset. */
    uint64_t handled_filesystem =
        options.no_filesystem ? 0 : filesystem_rights_for_version(landlock_version);
    uint64_t handled_network =
        handled_network_access(&options) | close_bind_access(&options, landlock_version);

    report_unenforceable_rights(landlock_version, handled_filesystem != 0);

    /* Only a ruleset that exists for another reason needs REFER: one with nothing else to hold is
     * not created at all, and a layer that is never created cannot refuse anything. */
    bool reparenting_only = options.no_filesystem && landlock_version >= FIRST_VERSION_WITH_REFER &&
                            (handled_network != 0 || scoped_for_version(landlock_version) != 0);
    if (reparenting_only) {
        handled_filesystem = LANDLOCK_ACCESS_FILESYSTEM_REFER;
    }
    if (options.close_bind) {
        report_bind_not_closed(landlock_version);
    }

    /* A ruleset the kernel would reject as empty: no filesystem right, no network direction, and
     * a kernel too old to scope. Nothing is left for Landlock to hold, so enter the working
     * directory and run the command rather than fail creating an empty ruleset. Only reachable
     * with --no-filesystem and no port rules on a pre-scoping kernel, since a filesystem ruleset
     * always handles a non-zero right. */
    if (handled_filesystem == 0 && handled_network == 0 && scoped_for_version(landlock_version) == 0) {
        enter_working_directory(&options);
        exec_command(&options);
    }

    int ruleset_descriptor = create_ruleset(landlock_version, handled_filesystem, handled_network);
    if (!options.no_filesystem) {
        add_path_rules(ruleset_descriptor, landlock_version, &options);
    } else if (reparenting_only) {
        allow_reparenting_everywhere(ruleset_descriptor, landlock_version);
    }
    add_port_rules(ruleset_descriptor, &options);
    add_ephemeral_bind_rules(ruleset_descriptor, &options, handled_network);
    enter_working_directory(&options);
    apply_restriction(ruleset_descriptor);
    exec_command(&options);
}
