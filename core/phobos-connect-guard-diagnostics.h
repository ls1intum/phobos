/*
 * Reporting from the connect guard: the exit status of a setup failure, and the lines
 * --verbose adds.
 */
#ifndef PHOBOS_CONNECT_GUARD_DIAGNOSTICS_H
#define PHOBOS_CONNECT_GUARD_DIAGNOSTICS_H

/* The exit status of every failure to set the supervision up, distinct from the command's own. */
static constexpr int EXIT_SETUP_ERROR = 125;

/* The exit status of a call made the wrong way. */
static constexpr int EXIT_USAGE = 2;

/* The exit status when the command itself cannot be executed, as a shell reports it. */
static constexpr int EXIT_COMMAND_NOT_EXECUTABLE = 127;

/* Switches the --verbose lines on or off. */
void set_verbose(bool enabled);

/* Prints one line prefixed with the guard's name on stderr, only under --verbose. */
void log_verbose(const char *format, ...) __attribute__((format(printf, 1, 2)));

#endif
