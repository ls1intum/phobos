#include "phobos-landlock-options.h"

#include "phobos-landlock-diagnostics.h"
#include "phobos-landlock-ruleset.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Everything after this prefix is the set of rights; the next word is the path.
 * Keeping the letters in the flag rather than in a second word preserves the
 * rule that every option takes exactly one value. */
static const char RIGHTS_PREFIX[] = "--rights=";
static constexpr size_t RIGHTS_PREFIX_LENGTH = sizeof(RIGHTS_PREFIX) - 1;

[[noreturn]] void print_usage_and_exit(void) {
    fprintf(stderr,
            "Usage: phobos-landlock --rights=LETTERS PATH [--rights=LETTERS PATH ...]\n"
            "                       [--connect-tcp PORT] [--bind-tcp PORT]\n"
            "                       [--chdir DIRECTORY]\n"
            "                       [--minimum-landlock-version NUMBER] [--verbose]\n"
            "                       -- COMMAND [ARGUMENTS...]\n"
            "\n"
            "LETTERS is any combination of, each at most once:\n"
            "  r  read a file, list a directory\n"
            "  w  write into an existing file, and shorten it\n"
            "  x  execute a file\n"
            "  m  create files, directories, sockets and pipes\n"
            "  d  delete files and directories\n"
            "  i  ioctl on a character or block device\n"
            "\n"
            "Creating device nodes and symbolic links is never granted.\n");
    exit(2);
}

/* atoi and a bare strtoull both answer 0 for input that is not a number at
 * all, which would turn a typo into a weaker policy without saying so. Every
 * number this tool accepts goes through here instead. */
unsigned long parse_number(const char *text, unsigned long lowest, unsigned long highest,
                           const char *what) {
    if (text[0] == '\0') {
        fprintf(stderr, "[phobos-landlock] %s: empty value\n", what);
        exit(EXIT_CODE_POLICY_ERROR);
    }
    errno = 0;
    char *first_unconverted = nullptr;
    unsigned long value = strtoul(text, &first_unconverted, 10);
    if (errno != 0 || *first_unconverted != '\0' || value < lowest || value > highest) {
        fprintf(stderr, "[phobos-landlock] %s: '%s'\n", what, text);
        exit(EXIT_CODE_POLICY_ERROR);
    }
    return value;
}

/* Sets the one field the letter stands for. Answers false for a letter that
 * means nothing here, so the caller can name it in the refusal. */
static bool apply_rights_letter(struct path_rule *rule, char letter) {
    switch (letter) {
    case RIGHTS_LETTER_READ: rule->readable = true; return true;
    case RIGHTS_LETTER_WRITE: rule->writable = true; return true;
    case RIGHTS_LETTER_EXECUTE: rule->executable = true; return true;
    case RIGHTS_LETTER_MAKE: rule->makeable = true; return true;
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
    case RIGHTS_LETTER_DELETE: return rule->removable;
    case RIGHTS_LETTER_IOCTL: return rule->ioctl_device;
    default: return false;
    }
}

void remember_path_rule(struct options *options, const char *letters, const char *path) {
    if (options->path_rule_count >= MAXIMUM_PATH_RULES) {
        exit_with_message("too many path rules");
    }
    if (letters[0] == '\0') {
        exit_with_message("--rights= names no rights at all");
    }
    struct path_rule *rule = &options->rules[options->path_rule_count];
    memset(rule, 0, sizeof(*rule));
    rule->path = path;
    for (const char *letter = letters; *letter != '\0'; letter++) {
        if (rights_letter_already_set(rule, *letter)) {
            fprintf(stderr, "[phobos-landlock] --rights=%s repeats '%c'\n", letters, *letter);
            exit(EXIT_CODE_POLICY_ERROR);
        }
        if (!apply_rights_letter(rule, *letter)) {
            fprintf(stderr, "[phobos-landlock] --rights=%s: '%c' is not a right\n", letters,
                    *letter);
            exit(EXIT_CODE_POLICY_ERROR);
        }
    }
    options->path_rule_count++;
}

static void remember_port(uint64_t *ports, size_t *count, const char *value, const char *what) {
    if (*count >= MAXIMUM_PORT_RULES) {
        exit_with_message(what);
    }
    /* A port outside 1..65535 is a policy mistake, not something to pass on. */
    ports[*count] = (uint64_t)parse_number(value, 1, 65535, "not a TCP port");
    (*count)++;
}

void parse_arguments(int argument_count, char *arguments[], struct options *options) {
    memset(options, 0, sizeof(*options));
    options->minimum_landlock_version = 1;

    int argument_index = 1;
    while (argument_index < argument_count) {
        const char *argument = arguments[argument_index];
        if (strcmp(argument, "--") == 0) {
            argument_index++;
            break;
        }
        if (strcmp(argument, "--verbose") == 0) {
            verbose = true;
            argument_index++;
            continue;
        }
        /* Every remaining option takes a value, so it must not be the last word. */
        if (argument_index + 1 >= argument_count) {
            print_usage_and_exit();
        }
        const char *value = arguments[argument_index + 1];
        if (strncmp(argument, RIGHTS_PREFIX, RIGHTS_PREFIX_LENGTH) == 0) {
            remember_path_rule(options, argument + RIGHTS_PREFIX_LENGTH, value);
        }
        else if (strcmp(argument, "--connect-tcp") == 0) {
            remember_port(options->connect_tcp_ports, &options->connect_tcp_port_count, value,
                          "too many --connect-tcp ports");
        }
        else if (strcmp(argument, "--bind-tcp") == 0) {
            remember_port(options->bind_tcp_ports, &options->bind_tcp_port_count, value,
                          "too many --bind-tcp ports");
        }
        else if (strcmp(argument, "--chdir") == 0) {
            options->working_directory = value;
        }
        else if (strcmp(argument, "--minimum-landlock-version") == 0) {
            options->minimum_landlock_version =
                (int)parse_number(value, 1, HIGHEST_KNOWN_LANDLOCK_VERSION,
                                  "not a usable Landlock version");
        }
        else {
            print_usage_and_exit();
        }
        argument_index += 2;
    }
    if (argument_index >= argument_count) {
        print_usage_and_exit();
    }
    options->command = &arguments[argument_index];
}

bool network_rules_wanted(const struct options *options) {
    return options->connect_tcp_port_count > 0 || options->bind_tcp_port_count > 0;
}

uint64_t handled_network_access(const struct options *options) {
    uint64_t handled = 0;
    if (options->connect_tcp_port_count > 0) {
        handled |= LANDLOCK_ACCESS_NETWORK_CONNECT_TCP;
    }
    if (options->bind_tcp_port_count > 0) {
        handled |= LANDLOCK_ACCESS_NETWORK_BIND_TCP;
    }
    return handled;
}
