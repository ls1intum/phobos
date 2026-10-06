/*
 * A model of the ruleset the enforcer builds, for a supervisor that only reports.
 *
 * It is built from the enforcer's own command line by the enforcer's own parser and rights
 * tables, so it describes what the enforcer enforces rather than a second computation that could
 * drift from it. It never decides anything: Landlock decides, and the model only says whether a
 * refusal is to be expected, so that a supervisor can word it. Where the model is wrong, a report
 * is wrong or missing, and nothing else changes.
 *
 * Like -policy.c, this module never exits and never prints.
 */
#ifndef PHOBOS_LANDLOCK_MODEL_H
#define PHOBOS_LANDLOCK_MODEL_H

#include "phobos-landlock-filesystem-and-networksystem-options.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* One rule as Landlock holds it: the inode it is anchored on and the rights it grants there. */
struct model_rule {
    dev_t device;
    ino_t inode;
    uint64_t rights;
};

/* The whole ruleset: every rule, the rights the ruleset handles, and the options it came from. */
struct policy_model {
    struct model_rule rules[MAXIMUM_PATH_RULES];
    size_t rule_count;
    uint64_t handled_filesystem;
    uint64_t handled_network;
    struct options options;
};

/* Builds the model of the ruleset the enforcer builds from these arguments at this version:
 * every rule's inode and rights, exactly as add_path_rule computes them, and the handled rights.
 * Answers false with the reason in error when the arguments do not parse or a rule path cannot
 * be opened, or when the enforcer would refuse the rule. The model keeps pointers into the
 * arguments, which must therefore outlive it. Never exits. */
bool build_policy_model(int argument_count, char *arguments[], int landlock_version,
                        struct policy_model *model, char *error, size_t error_size);

/* The union of the rights every rule along the ancestors of an absolute, resolved path grants,
 * walked by inode the way Landlock walks its dentries. */
uint64_t model_rights_along(const struct policy_model *model, const char *resolved_path);

/* Whether a bind to this port and transport passes the network ruleset this model describes. */
bool model_bind_permitted(const struct policy_model *model, bool datagram, uint16_t port);

#endif
