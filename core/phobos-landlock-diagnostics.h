/*
 * Reporting and giving up.
 *
 * Every failure in this tool ends the process: it applies a security policy,
 * so continuing after a step did not work would mean running with less
 * protection than was asked for, without saying so.
 */
#ifndef PHOBOS_LANDLOCK_DIAGNOSTICS_H
#define PHOBOS_LANDLOCK_DIAGNOSTICS_H

/* Exit code for every policy failure, distinct from the command's own. */
#define EXIT_CODE_POLICY_ERROR 125

/* Set by --verbose. */
extern int verbose;

/* Prints one line, only when --verbose was given. */
void log_verbose(const char *format, ...);

/* Reports the message with the current errno and gives up. */
_Noreturn void exit_with_system_error(const char *message);

/* Reports the message and gives up. */
_Noreturn void exit_with_message(const char *message);

#endif
