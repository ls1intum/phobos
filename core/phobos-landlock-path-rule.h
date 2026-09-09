/*
 * One allow-listed path and the rights it grants.
 *
 * This becomes a class: the path plus what may be done with it, and the two
 * questions that are asked about it, which rights it grants at a given
 * Landlock version, and how it has to be opened.
 */
#ifndef PHOBOS_LANDLOCK_PATH_RULE_H
#define PHOBOS_LANDLOCK_PATH_RULE_H

#include <stdint.h>

struct path_rule {
    const char *path;
    int writable;
    int executable;
};

/* Rights granted for this path, never more than the version can handle. */
uint64_t rights_granted_for(const struct path_rule *rule, int landlock_version);

/* Flags this path has to be opened with before a rule can be anchored on it. */
int open_flags_for_rule(const struct path_rule *rule);

#endif
