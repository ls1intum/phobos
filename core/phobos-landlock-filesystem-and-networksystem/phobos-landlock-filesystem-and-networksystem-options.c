#include "phobos-landlock-filesystem-and-networksystem-options.h"

#include "phobos-landlock-filesystem-and-networksystem-diagnostics.h"

#include <stdio.h>
#include <stdlib.h>

/* Room for the longest refusal the policy module words. */
static constexpr size_t REFUSAL_LENGTH = 512;

[[noreturn]] void print_usage_and_exit(void) {
    fprintf(stderr,
            "Usage: phobos-landlock-filesystem-and-networksystem --rights=LETTERS PATH [--rights=LETTERS PATH ...]\n"
            "                       [--connect-tcp PORT] [--bind-tcp PORT]\n"
            "                       [--connect-udp PORT] [--bind-udp PORT]\n"
            "                       [--close-bind] [--ephemeral-bind-tcp] [--ephemeral-bind-udp]\n"
            "                       [--chdir DIRECTORY] [--no-filesystem]\n"
            "                       [--minimum-landlock-version NUMBER] [--verbose]\n"
            "                       -- COMMAND [ARGUMENTS...]\n"
            "\n"
            "LETTERS is any combination of, each at most once:\n"
            "  r  read a file, list a directory\n"
            "  w  write into an existing file, and shorten it\n"
            "  x  execute a file\n"
            "  m  create regular files and directories\n"
            "  p  create sockets and named pipes\n"
            "  l  create symbolic links\n"
            "  f  move or rename across directories (REFER)\n"
            "  d  delete files and directories\n"
            "  i  ioctl on a character or block device\n"
            "\n"
            "Creating device nodes is never granted.\n");
    exit(EXIT_CODE_USAGE);
}

unsigned long parse_number(const char *text, unsigned long lowest, unsigned long highest,
                           const char *what) {
    char error[REFUSAL_LENGTH];
    unsigned long value = 0;
    if (!parse_number_checked(text, lowest, highest, what, &value, error, sizeof(error))) {
        exit_with_message(error);
    }
    return value;
}

void remember_path_rule(struct options *options, const char *letters, const char *path) {
    char error[REFUSAL_LENGTH];
    if (!remember_path_rule_checked(options, letters, path, error, sizeof(error))) {
        exit_with_message(error);
    }
}

/* A refusal with no reason is a call made the wrong way, which is answered with the usage
 * rather than with an empty message. */
void parse_arguments(int argument_count, char *arguments[], struct options *options) {
    char error[REFUSAL_LENGTH];
    if (!parse_arguments_checked(argument_count, arguments, options, error, sizeof(error))) {
        if (error[0] == '\0') {
            print_usage_and_exit();
        }
        exit_with_message(error);
    }
    verbose = options->verbose;
}

bool network_rules_wanted(const struct options *options) {
    return options->connect_tcp_port_count > 0 || options->bind_tcp_port_count > 0 ||
           options->connect_udp_port_count > 0 || options->bind_udp_port_count > 0;
}

bool udp_rules_wanted(const struct options *options) {
    return options->connect_udp_port_count > 0 || options->bind_udp_port_count > 0;
}
