/*
 * Everything the guard's command line asked for.
 */
#ifndef PHOBOS_CONNECT_GUARD_OPTIONS_H
#define PHOBOS_CONNECT_GUARD_OPTIONS_H

/* The command to supervise, the rules file, the optional broker endpoint, --verbose, whether
 * a socket that was never bound may listen (--allow-ephemeral-listen) and whether one may connect
 * or send a datagram (--allow-ephemeral-udp-bind), which the kernel then gives a port of its own
 * choosing. With --resolve the guard supervises nothing: it looks up the host names that follow
 * the -- through the resolver --resolver names, and command then holds those names.
 *
 * The rest is what the denial reporter needs. landlock_bin is the enforcer the layers named
 * (--landlock-bin), which arms the reporter. report_filesystem (--report-filesystem) has the guard
 * report the filesystem layer's denials too, and group_lock_above (--group-lock-above) says the
 * timeout layer's group lock is above the guard, for the attribution of the calls it refuses.
 * broker_log_descriptor (--broker-log-fd) is the pipe the egress broker logs its refusals to, or
 * NO_BROKER_LOG. */
struct guard_options {
    char **command;
    const char *rules_path;
    const char *broker_endpoint;
    bool verbose;
    bool allow_ephemeral_listen;
    bool allow_ephemeral_udp_bind;
    bool resolve;
    const char *resolver_endpoint;
    const char *landlock_bin;
    bool report_filesystem;
    bool group_lock_above;
    int broker_log_descriptor;
};

/* The value of broker_log_descriptor when no --broker-log-fd was given. */
static constexpr int NO_BROKER_LOG = -1;

/* Prints how to call the guard and gives up. */
[[noreturn]] void print_usage_and_exit(void);

/* Reads the command line into options, or refuses the call. */
void parse_arguments(int argument_count, char *arguments[], struct guard_options *options);

#endif
