/*
 * The policy the command line describes, read without ever giving up.
 *
 * Everything here answers rather than exits, and nothing here prints. The enforcer wraps these
 * functions in the exiting forms of -options.c, because a policy it cannot read must stop the run.
 * A supervisor that only reports what the enforcer enforces links them too, through the model of
 * -model.c, and must never end because of a command line it could not read: its listener would
 * close with it and every trapped call of the run would fail. So this file, -path-rule.c and
 * -model.c call no function of -diagnostics.c, which is what lets a second program link them
 * beside a diagnostics module of its own.
 */
#ifndef PHOBOS_LANDLOCK_POLICY_H
#define PHOBOS_LANDLOCK_POLICY_H

#include <stddef.h>
#include <stdint.h>

struct options;

/* Reads the command line into options, or answers false with the reason in error. An empty
 * error means the call was made the wrong way and the caller prints how to call it. Never
 * exits and never prints. */
bool parse_arguments_checked(int argument_count, char *arguments[], struct options *options,
                             char *error, size_t error_size);

/* Records one --rights=LETTERS option, or answers false with the reason in error. */
bool remember_path_rule_checked(struct options *options, const char *letters, const char *path,
                                char *error, size_t error_size);

/* Reads a number into value and refuses anything that is not one, or is outside the range the
 * option can mean, with the reason in error. */
bool parse_number_checked(const char *text, unsigned long lowest, unsigned long highest,
                          const char *what, unsigned long *value, char *error, size_t error_size);

/* Rights available at the given Landlock version. */
uint64_t filesystem_rights_for_version(int landlock_version);

/* The directions the command line actually spoke about. Only these are handed
 * to the kernel as handled, because a handled direction with no rule is a
 * blanket denial nobody asked for. */
uint64_t handled_network_access(const struct options *options);

/* The bind directions --close-bind asks for that this kernel can handle: TCP from Landlock
 * version 4, UDP from version 10. Nothing is granted by them, so a direction that is handled
 * here and named by no port rule denies every bind. A direction the kernel is too old for is
 * left out, and report_bind_not_closed says so; it is never a refusal, which only an explicit
 * port rule is. Zero when --close-bind was not given. */
uint64_t close_bind_access(const struct options *options, int landlock_version);

/* The kernel's Landlock version: 1 or more when it has Landlock, 0 when it answers with no
 * version, and -1 when it has no Landlock at all, which the enforcer reports differently from a
 * version that is merely too old. Never exits. */
int query_landlock_version(void);

#endif
