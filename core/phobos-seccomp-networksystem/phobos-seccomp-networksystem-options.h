/*
 * Everything the guard's command line asked for.
 */
#ifndef PHOBOS_CONNECT_GUARD_OPTIONS_H
#define PHOBOS_CONNECT_GUARD_OPTIONS_H

/* The command to supervise, the rules file, the optional broker endpoint, --verbose, whether
 * a socket that was never bound may listen (--allow-ephemeral-listen) and whether one may connect
 * or send a datagram (--allow-ephemeral-udp-bind), which the kernel then gives a port of its own
 * choosing. With --resolve the guard supervises nothing: it looks up the host names that follow
 * the -- through the resolver --resolver names, and command then holds those names. */
struct guard_options {
    char **command;
    const char *rules_path;
    const char *broker_endpoint;
    bool verbose;
    bool allow_ephemeral_listen;
    bool allow_ephemeral_udp_bind;
    bool resolve;
    const char *resolver_endpoint;
};

/* Prints how to call the guard and gives up. */
[[noreturn]] void print_usage_and_exit(void);

/* Reads the command line into options, or refuses the call. */
void parse_arguments(int argument_count, char *arguments[], struct guard_options *options);

#endif
