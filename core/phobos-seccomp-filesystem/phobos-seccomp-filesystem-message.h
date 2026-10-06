/*
 * The words Phobos prints for an action it blocked.
 *
 * Every layer that can tell a blocked action reports it through here, so the line is worded,
 * quoted, de-duplicated and counted in one place:
 *
 *   Phobos Security Error: the program tried to illegally <verb> the <noun> <object> but was
 *   blocked by Phobos.
 *
 * A line is printed the first time its verb, noun and object come together; every later
 * occurrence is counted and not printed, and at most REPORT_LINES_MAXIMUM distinct lines are
 * printed in a run. The summary counts every report, printed or not, per layer.
 *
 * Reporting decides nothing. It is told about a decision that has already been made, by Landlock,
 * by the connect guard or by a seccomp filter, and it only words it.
 *
 * It keeps its table and counts in static storage without a lock, because it runs in exactly one
 * thread: the supervisor's, which services one notification at a time however many threads the
 * supervised program runs. The program's threads never call it; they only wait in their trapped
 * calls until the supervisor has answered.
 */
#ifndef PHOBOS_SECCOMP_FILESYSTEM_MESSAGE_H
#define PHOBOS_SECCOMP_FILESYSTEM_MESSAGE_H

#include <stddef.h>

/* The layer a blocked action is counted for in the summary. */
enum report_layer {
    REPORT_LAYER_FILESYSTEM,
    REPORT_LAYER_NETWORK,
    REPORT_LAYER_TIMEOUT,
};

/* At most this many distinct lines are printed per supervisor and run; the rest are counted. */
static constexpr size_t REPORT_LINES_MAXIMUM = 100;

/* The de-duplication table holds this many keys; once it is full, a new distinct line is still
 * printed up to the cap but no longer recognised when it repeats. */
static constexpr size_t REPORT_KEYS_MAXIMUM = 4096;

/* A path longer than this many bytes is cut before it is quoted, and marked as cut. */
static constexpr size_t REPORT_PATH_SHOWN_MAXIMUM = 1024;

/* Room for the longest quoted path: every byte of the shown part as a four-byte escape, the
 * quotes around it and the mark of a cut one. */
static constexpr size_t REPORT_QUOTED_MAXIMUM = 4 * REPORT_PATH_SHOWN_MAXIMUM + 32;

/* Prints "Phobos Security Error: the program tried to illegally <verb> the <noun> <object>
 * <detail> but was blocked by Phobos." the first time verb, noun and object come together, counts
 * every call for the layer, and respects the cap. object_is_path quotes object (and detail_path,
 * when not NULL, as " (named as ...)") the bash ${v@Q} way; otherwise object is printed as it is.
 * An empty object prints no space, so "leave the Session" ends right before
 * " but was blocked by Phobos.". */
void report_blocked(enum report_layer layer, const char *verb, const char *noun,
                    const char *object, bool object_is_path, const char *detail_path);

/* Prints the one summary line, "Phobos Security Summary: Phobos blocked <T> actions of the
 * program, <F> in the filesystem layer, <N> in the network layer and <O> in the timeout layer;
 * <S> were shown above, <R> repeats and <C> beyond the limit of 100 lines were not. (PHB-EDENY)",
 * with singulars for a count of one, when anything was counted, and nothing otherwise. */
void report_summary(void);

/* Writes value quoted like bash ${value@Q} under LC_ALL=C into out, cutting value at
 * REPORT_PATH_SHOWN_MAXIMUM bytes and appending " (truncated)" outside the quotes. out holds
 * REPORT_QUOTED_MAXIMUM bytes or more. Exposed for the tests and for objects of two paths. */
void quote_like_bash(const char *value, char *out, size_t size);

#ifdef PHOBOS_REPORTER_UNIT_TEST
/* Forgets every line and count, so each case starts from an empty run. */
void reset_report_for_tests(void);
#endif

#endif
