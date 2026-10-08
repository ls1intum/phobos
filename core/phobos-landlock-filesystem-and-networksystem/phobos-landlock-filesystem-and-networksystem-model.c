/* O_PATH and the other GNU extensions used below need this first. */
#define _GNU_SOURCE
#include "phobos-landlock-filesystem-and-networksystem-model.h"

#include "phobos-landlock-filesystem-and-networksystem-path-rule.h"
#include "phobos-landlock-filesystem-and-networksystem-policy.h"
#include "phobos-landlock-filesystem-and-networksystem-ruleset.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Opens the rule's path the way add_path_rule opens it, records the inode it lands on and the
 * rights the enforcer grants there, and refuses what add_path_rule refuses: a path that cannot be
 * opened, and a changeable rule anchored on a symbolic link. */
static bool remember_model_rule(struct policy_model *model, const struct path_rule *rule,
                                int landlock_version, char *error, size_t error_size) {
    int descriptor = open(rule->path, open_flags_for_rule(rule));
    if (descriptor < 0) {
        snprintf(error, error_size, "cannot open %s: %s", rule->path, strerror(errno));
        return false;
    }
    struct stat status;
    bool stated = fstat(descriptor, &status) == 0;
    int stat_error = errno;
    close(descriptor);
    if (!stated) {
        snprintf(error, error_size, "cannot stat %s: %s", rule->path, strerror(stat_error));
        return false;
    }
    if (rule_can_change_anything(rule) && S_ISLNK(status.st_mode)) {
        snprintf(error, error_size, "refusing changeable path %s: it is a symbolic link",
                 rule->path);
        return false;
    }
    uint64_t rights = rights_granted_for(rule, landlock_version);
    if (!S_ISDIR(status.st_mode)) {
        rights &= ~DIRECTORY_ONLY_ACCESS_RIGHTS;
    }
    struct model_rule *slot = &model->rules[model->rule_count];
    slot->device = status.st_dev;
    slot->inode = status.st_ino;
    slot->rights = rights;
    model->rule_count++;
    return true;
}

bool build_policy_model(int argument_count, char *arguments[], int landlock_version,
                        struct policy_model *model, char *error, size_t error_size) {
    model->rule_count = 0;
    model->handled_filesystem = 0;
    model->handled_network = 0;
    if (!parse_arguments_checked(argument_count, arguments, &model->options, error,
                                 error_size)) {
        if (error[0] == '\0') {
            snprintf(error, error_size, "the arguments are not a call the enforcer accepts");
        }
        return false;
    }
    if (!model->options.no_filesystem) {
        model->handled_filesystem = filesystem_rights_for_version(landlock_version);
    }
    model->handled_network = handled_network_access(&model->options)
                             | close_bind_access(&model->options, landlock_version);
    for (size_t index = 0; index < model->options.path_rule_count; index++) {
        if (!remember_model_rule(model, &model->options.rules[index], landlock_version, error,
                                 error_size)) {
            return false;
        }
    }
    return true;
}

/* The rights of every rule anchored on exactly this inode. */
static uint64_t rights_anchored_on(const struct policy_model *model, const struct stat *status) {
    uint64_t granted = 0;
    for (size_t index = 0; index < model->rule_count; index++) {
        if (model->rules[index].device == status->st_dev
            && model->rules[index].inode == status->st_ino) {
            granted |= model->rules[index].rights;
        }
    }
    return granted;
}

uint64_t model_rights_along(const struct policy_model *model, const char *resolved_path) {
    char walk[PATH_MAX];
    uint64_t granted = 0;
    if (resolved_path[0] != '/'
        || snprintf(walk, sizeof(walk), "%s", resolved_path) >= (int)sizeof(walk)) {
        return 0;
    }
    for (;;) {
        struct stat status;
        if (stat(walk, &status) == 0) {
            granted |= rights_anchored_on(model, &status);
        }
        if (strcmp(walk, "/") == 0) {
            return granted;
        }
        char *slash = strrchr(walk, '/');
        if (slash == walk) {
            walk[1] = '\0';
        } else {
            *slash = '\0';
        }
    }
}

/* Whether the port is one of the ports a rule names. */
static bool port_named(const uint64_t *ports, size_t count, uint16_t port) {
    for (size_t index = 0; index < count; index++) {
        if (ports[index] == port) {
            return true;
        }
    }
    return false;
}

bool model_bind_permitted(const struct policy_model *model, bool datagram, uint16_t port) {
    uint64_t direction =
        datagram ? LANDLOCK_ACCESS_NETWORK_BIND_UDP : LANDLOCK_ACCESS_NETWORK_BIND_TCP;
    if ((model->handled_network & direction) == 0) {
        return true;
    }
    const struct options *options = &model->options;
    if (datagram) {
        return port_named(options->bind_udp_ports, options->bind_udp_port_count, port)
               || (port == 0 && options->ephemeral_bind_udp);
    }
    return port_named(options->bind_tcp_ports, options->bind_tcp_port_count, port)
           || (port == 0 && options->ephemeral_bind_tcp);
}
