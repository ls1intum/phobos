/*
 * Everything the guard's command line asked for.
 */
#ifndef PHOBOS_CONNECT_GUARD_OPTIONS_H
#define PHOBOS_CONNECT_GUARD_OPTIONS_H

/* The command to supervise, the rules file and --verbose. */
struct guard_options {
    char **command;
    const char *rules_path;
    bool verbose;
};

/* Prints how to call the guard and gives up. */
[[noreturn]] void print_usage_and_exit(void);

/* Reads the command line into options, or refuses the call. */
void parse_arguments(int argument_count, char *arguments[], struct guard_options *options);

#endif
