/*
 * Reporting and giving up.
 *
 * Every failure in this tool ends the process: it applies a security policy,
 * so continuing after a step did not work would mean running with less
 * protection than was asked for, without saying so.
 *
 * The one deliberate exception is a kernel too old to handle a right this
 * policy uses. Landlock offers no hook there, so nothing can be enforced in
 * its place. That gap is reported instead, unconditionally, and the operator
 * raises --minimum-landlock-version when the guarantee is needed.
 */
#ifndef PHOBOS_LANDLOCK_DIAGNOSTICS_H
#define PHOBOS_LANDLOCK_DIAGNOSTICS_H

/* Exit code for every policy failure, distinct from the command's own. */
static constexpr int EXIT_CODE_POLICY_ERROR = 125;

/* Set by --verbose. */
extern bool verbose;

/* Prints one line, only when --verbose was given. */
void log_verbose(const char *format, ...);

/* Prints one line whether or not --verbose was given. For the gaps a person
 * has to know about even when nobody asked for detail. */
void warn_always(const char *format, ...);

/* Reports the message with the current errno and gives up. */
[[noreturn]] void exit_with_system_error(const char *message);

/* Reports the message and gives up. */
[[noreturn]] void exit_with_message(const char *message);

#endif
