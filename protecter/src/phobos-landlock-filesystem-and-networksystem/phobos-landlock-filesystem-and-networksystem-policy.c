#include "phobos-landlock-filesystem-and-networksystem-policy.h"

#include "phobos-landlock-filesystem-and-networksystem-options.h"
#include "phobos-landlock-filesystem-and-networksystem-ruleset.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Everything after this prefix is the set of rights; the next word is the path.
 * Keeping the letters in the flag rather than in a second word preserves the
 * rule that every option takes exactly one value. */
static const char RIGHTS_PREFIX[] = "--rights=";
static constexpr size_t RIGHTS_PREFIX_LENGTH = sizeof(RIGHTS_PREFIX) - 1;

/* strtoul's base for every number this tool reads. */
static constexpr int DECIMAL = 10;

/* The highest TCP port; the lowest is 1. */
static constexpr unsigned long HIGHEST_PORT = 65535;

/* An option and the one value it takes. */
static constexpr int OPTION_AND_VALUE_WORDS = 2;

/* What query_landlock_version answers for a kernel without Landlock. */
static constexpr int NO_LANDLOCK = -1;

/* atoi and a bare strtoull both answer 0 for input that is not a number at
 * all, which would turn a typo into a weaker policy without saying so. Every
 * number this tool accepts goes through here instead. */
bool parse_number_checked(const char *text, unsigned long lowest, unsigned long highest,
                          const char *what, unsigned long *value, char *error, size_t error_size) {
    if (text[0] == '\0') {
        snprintf(error, error_size, "%s: empty value", what);
        return false;
    }
    errno = 0;
    char *first_unconverted = nullptr;
    unsigned long converted = strtoul(text, &first_unconverted, DECIMAL);
    if (errno != 0 || *first_unconverted != '\0' || converted < lowest || converted > highest) {
        snprintf(error, error_size, "%s: '%s'", what, text);
        return false;
    }
    *value = converted;
    return true;
}

/* Sets the one field the letter stands for. Answers false for a letter that
 * means nothing here, so the caller can name it in the refusal. */
static bool apply_rights_letter(struct path_rule *rule, char letter) {
    switch (letter) {
    case RIGHTS_LETTER_READ: rule->readable = true; return true;
    case RIGHTS_LETTER_WRITE: rule->writable = true; return true;
    case RIGHTS_LETTER_EXECUTE: rule->executable = true; return true;
    case RIGHTS_LETTER_MAKE: rule->makeable = true; return true;
    case RIGHTS_LETTER_IPC: rule->makeable_ipc = true; return true;
    case RIGHTS_LETTER_SYMLINK: rule->makeable_symlink = true; return true;
    case RIGHTS_LETTER_REFER: rule->referable = true; return true;
    case RIGHTS_LETTER_DELETE: rule->removable = true; return true;
    case RIGHTS_LETTER_IOCTL: rule->ioctl_device = true; return true;
    default: return false;
    }
}

/* Answers whether the letter was already set, which is how a repeated letter is
 * caught. A repetition is never meaningful and is far more likely a typo in a
 * policy than an intention, so it is refused rather than quietly absorbed. */
static bool rights_letter_already_set(const struct path_rule *rule, char letter) {
    switch (letter) {
    case RIGHTS_LETTER_READ: return rule->readable;
    case RIGHTS_LETTER_WRITE: return rule->writable;
    case RIGHTS_LETTER_EXECUTE: return rule->executable;
    case RIGHTS_LETTER_MAKE: return rule->makeable;
    case RIGHTS_LETTER_IPC: return rule->makeable_ipc;
    case RIGHTS_LETTER_SYMLINK: return rule->makeable_symlink;
    case RIGHTS_LETTER_REFER: return rule->referable;
    case RIGHTS_LETTER_DELETE: return rule->removable;
    case RIGHTS_LETTER_IOCTL: return rule->ioctl_device;
    default: return false;
    }
}

bool remember_path_rule_checked(struct options *options, const char *letters, const char *path,
                                char *error, size_t error_size) {
    if (options->path_rule_count >= MAXIMUM_PATH_RULES) {
        snprintf(error, error_size, "too many path rules");
        return false;
    }
    if (letters[0] == '\0') {
        snprintf(error, error_size, "--rights= names no rights at all");
        return false;
    }
    struct path_rule *rule = &options->rules[options->path_rule_count];
    memset(rule, 0, sizeof(*rule));
    rule->path = path;
    for (const char *letter = letters; *letter != '\0'; letter++) {
        if (rights_letter_already_set(rule, *letter)) {
            snprintf(error, error_size, "--rights=%s repeats '%c'", letters, *letter);
            return false;
        }
        if (!apply_rights_letter(rule, *letter)) {
            snprintf(error, error_size, "--rights=%s: '%c' is not a right", letters, *letter);
            return false;
        }
    }
    options->path_rule_count++;
    return true;
}

/* Records one connect or bind port. A port outside lowest..65535 is a policy mistake, not
 * something to pass on, and is refused. lowest is 1 for every rule but --bind-udp, which accepts 0
 * to mean "any local port": the kernel auto-binds an ephemeral UDP source port, and a port-0
 * BIND_UDP rule is how that auto-bind is permitted when both UDP directions are handled. */
static bool remember_port(uint64_t *ports, size_t *count, const char *value, unsigned long lowest,
                          const char *overflow_message, const char *number_message, char *error,
                          size_t error_size) {
    if (*count >= MAXIMUM_PORT_RULES) {
        snprintf(error, error_size, "%s", overflow_message);
        return false;
    }
    unsigned long port = 0;
    if (!parse_number_checked(value, lowest, HIGHEST_PORT, number_message, &port, error,
                              error_size)) {
        return false;
    }
    ports[*count] = (uint64_t)port;
    (*count)++;
    return true;
}

/* Reads one option that takes no value. Answers false when the word is not one of them. */
static bool remember_switch(struct options *options, const char *argument) {
    if (strcmp(argument, "--verbose") == 0) {
        options->verbose = true;
    } else if (strcmp(argument, "--no-filesystem") == 0) {
        options->no_filesystem = true;
    } else if (strcmp(argument, "--close-bind") == 0) {
        options->close_bind = true;
    } else if (strcmp(argument, "--ephemeral-bind-tcp") == 0) {
        options->ephemeral_bind_tcp = true;
    } else if (strcmp(argument, "--ephemeral-bind-udp") == 0) {
        options->ephemeral_bind_udp = true;
    } else if (strcmp(argument, "--mark-reported-domain") == 0) {
        options->mark_reported_domain = true;
    } else {
        return false;
    }
    return true;
}

/* Reads one option and the value after it. An unknown option leaves error empty, which is how
 * the caller tells a call made the wrong way from a value that was refused. */
static bool remember_option(struct options *options, const char *argument, const char *value,
                            char *error, size_t error_size) {
    if (strncmp(argument, RIGHTS_PREFIX, RIGHTS_PREFIX_LENGTH) == 0) {
        return remember_path_rule_checked(options, argument + RIGHTS_PREFIX_LENGTH, value, error,
                                          error_size);
    }
    if (strcmp(argument, "--connect-tcp") == 0) {
        return remember_port(options->connect_tcp_ports, &options->connect_tcp_port_count, value,
                             1, "too many --connect-tcp ports", "not a TCP port", error,
                             error_size);
    }
    if (strcmp(argument, "--bind-tcp") == 0) {
        return remember_port(options->bind_tcp_ports, &options->bind_tcp_port_count, value, 1,
                             "too many --bind-tcp ports", "not a TCP port", error, error_size);
    }
    if (strcmp(argument, "--connect-udp") == 0) {
        return remember_port(options->connect_udp_ports, &options->connect_udp_port_count, value,
                             1, "too many --connect-udp ports", "not a UDP port", error,
                             error_size);
    }
    if (strcmp(argument, "--bind-udp") == 0) {
        return remember_port(options->bind_udp_ports, &options->bind_udp_port_count, value, 0,
                             "too many --bind-udp ports", "not a UDP port", error, error_size);
    }
    if (strcmp(argument, "--chdir") == 0) {
        options->working_directory = value;
        return true;
    }
    if (strcmp(argument, "--minimum-landlock-version") == 0) {
        unsigned long version = 0;
        if (!parse_number_checked(value, 1, HIGHEST_KNOWN_LANDLOCK_VERSION,
                                  "not a usable Landlock version", &version, error, error_size)) {
            return false;
        }
        options->minimum_landlock_version = (int)version;
        return true;
    }
    error[0] = '\0';
    return false;
}

bool parse_arguments_checked(int argument_count, char *arguments[], struct options *options,
                             char *error, size_t error_size) {
    memset(options, 0, sizeof(*options));
    options->minimum_landlock_version = 1;
    error[0] = '\0';

    int argument_index = 1;
    while (argument_index < argument_count) {
        const char *argument = arguments[argument_index];
        if (strcmp(argument, "--") == 0) {
            argument_index++;
            break;
        }
        if (remember_switch(options, argument)) {
            argument_index++;
            continue;
        }
        if (argument_index + 1 >= argument_count) {
            return false;
        }
        if (!remember_option(options, argument, arguments[argument_index + 1], error,
                             error_size)) {
            return false;
        }
        argument_index += OPTION_AND_VALUE_WORDS;
    }
    if (argument_index >= argument_count) {
        return false;
    }
    if (options->no_filesystem && options->path_rule_count > 0) {
        snprintf(error, error_size,
                 "--no-filesystem carries no filesystem rules, but %zu --rights= path(s) "
                 "were given; a network-only ruleset names ports only",
                 options->path_rule_count);
        return false;
    }
    options->command = &arguments[argument_index];
    return true;
}

uint64_t filesystem_rights_for_version(int landlock_version) {
    uint64_t rights =
        LANDLOCK_ACCESS_FILESYSTEM_EXECUTE | LANDLOCK_ACCESS_FILESYSTEM_WRITE_FILE |
        LANDLOCK_ACCESS_FILESYSTEM_READ_FILE | LANDLOCK_ACCESS_FILESYSTEM_READ_DIRECTORY |
        LANDLOCK_ACCESS_FILESYSTEM_REMOVE_DIRECTORY | LANDLOCK_ACCESS_FILESYSTEM_REMOVE_FILE |
        LANDLOCK_ACCESS_FILESYSTEM_MAKE_CHARACTER_DEVICE |
        LANDLOCK_ACCESS_FILESYSTEM_MAKE_DIRECTORY | LANDLOCK_ACCESS_FILESYSTEM_MAKE_REGULAR_FILE |
        LANDLOCK_ACCESS_FILESYSTEM_MAKE_SOCKET | LANDLOCK_ACCESS_FILESYSTEM_MAKE_NAMED_PIPE |
        LANDLOCK_ACCESS_FILESYSTEM_MAKE_BLOCK_DEVICE |
        LANDLOCK_ACCESS_FILESYSTEM_MAKE_SYMBOLIC_LINK;
    if (landlock_version >= FIRST_VERSION_WITH_REFER) {
        rights |= LANDLOCK_ACCESS_FILESYSTEM_REFER;
    }
    if (landlock_version >= FIRST_VERSION_WITH_TRUNCATE) {
        rights |= LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE;
    }
    if (landlock_version >= FIRST_VERSION_WITH_IOCTL_DEVICE) {
        rights |= LANDLOCK_ACCESS_FILESYSTEM_IOCTL_DEVICE;
    }
    if (landlock_version >= FIRST_VERSION_WITH_RESOLVE_UNIX) {
        rights |= LANDLOCK_ACCESS_FILESYSTEM_RESOLVE_UNIX;
    }
    return rights;
}

uint64_t handled_network_access(const struct options *options) {
    uint64_t handled = 0;
    if (options->connect_tcp_port_count > 0) {
        handled |= LANDLOCK_ACCESS_NETWORK_CONNECT_TCP;
    }
    if (options->bind_tcp_port_count > 0) {
        handled |= LANDLOCK_ACCESS_NETWORK_BIND_TCP;
    }
    if (options->connect_udp_port_count > 0) {
        handled |= LANDLOCK_ACCESS_NETWORK_CONNECT_SEND_UDP;
    }
    if (options->bind_udp_port_count > 0) {
        handled |= LANDLOCK_ACCESS_NETWORK_BIND_UDP;
    }
    return handled;
}

uint64_t close_bind_access(const struct options *options, int landlock_version) {
    uint64_t handled = 0;
    if (!options->close_bind) {
        return handled;
    }
    if (landlock_version >= FIRST_VERSION_WITH_NETWORK) {
        handled |= LANDLOCK_ACCESS_NETWORK_BIND_TCP;
    }
    if (landlock_version >= FIRST_VERSION_WITH_UDP) {
        handled |= LANDLOCK_ACCESS_NETWORK_BIND_UDP;
    }
    return handled;
}

int query_landlock_version(void) {
    long landlock_version =
        syscall(SYSCALL_NUMBER_LANDLOCK_CREATE_RULESET, nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (landlock_version < 0) {
        return NO_LANDLOCK;
    }
    return (int)landlock_version;
}
