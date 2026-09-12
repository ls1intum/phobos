/*
 * One allow-listed path and the rights it grants.
 *
 * This becomes a class: the path plus what may be done with it, and the three
 * questions that are asked about it, which rights it grants at a given
 * Landlock version, whether it may change anything, and how it has to be
 * opened.
 *
 * Each right is its own field. A single "writable" that also meant create,
 * delete, rename and make device nodes granted thirteen kernel rights at once
 * and could not be narrowed by any policy.
 */
#ifndef PHOBOS_LANDLOCK_PATH_RULE_H
#define PHOBOS_LANDLOCK_PATH_RULE_H

#include <stdint.h>

struct path_rule {
    const char *path;
    bool readable;    /* r: read a file, list a directory */
    bool writable;    /* w: write into an existing file, and shorten it */
    bool executable;  /* x: execute a file, map it executable */
    bool makeable;    /* m: create files, directories, sockets, pipes */
    bool removable;   /* d: delete files and directories */
    bool ioctl_device; /* i: ioctl on a character or block device */
};

/* Rights granted for this path, never more than the version can handle. */
uint64_t rights_granted_for(const struct path_rule *rule, int landlock_version);

/* True when the rule permits changing anything at the path, ioctl on a device
 * included. Those are the rules an attacker profits from redirecting, so they
 * are opened and checked more strictly than a purely reading one. */
bool rule_can_change_anything(const struct path_rule *rule);

/* Flags this path has to be opened with before a rule can be anchored on it. */
int open_flags_for_rule(const struct path_rule *rule);

#endif
