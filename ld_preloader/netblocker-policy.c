/* O_NOFOLLOW and fdopen need this first. */
#define _GNU_SOURCE
#include "netblocker-policy.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

/* Opens the rules file for reading, or answers nullptr. A symbolic link as the last
 * component is not followed, and anything but a regular file is refused, so the name
 * cannot be pointed at another file or at a FIFO. O_NONBLOCK is what lets a FIFO be
 * opened, and so refused, at all: without it the open would block every process this
 * library is loaded into. It is cleared again before reading. */
static FILE *open_rules_file(const char *path) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        return nullptr;
    }
    struct stat status;
    if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode)) {
        close(descriptor);
        return nullptr;
    }
    int flags = fcntl(descriptor, F_GETFL);
    if (flags < 0 || fcntl(descriptor, F_SETFL, flags & ~O_NONBLOCK) != 0) {
        close(descriptor);
        return nullptr;
    }
    FILE *file = fdopen(descriptor, "r");
    if (file == nullptr) {
        close(descriptor);
    }
    return file;
}

/* Frees every rule. Assumes the write lock is held. */
static void free_rules(struct policy *policy) {
    while (policy->first_rule != nullptr) {
        struct rule *next = policy->first_rule->next;
        rule_destroy(policy->first_rule);
        policy->first_rule = next;
    }
}

/* Whether the line held anything but a comment and whitespace, so that a line the parser
 * refused can be told from a blank one. */
static bool line_names_something(const char *line) {
    for (const char *character = line; *character != '\0'; character++) {
        if (*character == '#') {
            return false;
        }
        if (!isspace((unsigned char)*character)) {
            return true;
        }
    }
    return false;
}

/* Reads every rule of the file, each put in front of the ones before it, and remembers
 * whether anything was refused: a line that named something the parser would not take, or
 * the whole file, when one was named and could not be opened. Only an unnamed file leaves
 * the policy silent, which is the one case that means "this list says nothing". Assumes
 * the write lock is held and the policy holds no rules. */
static void read_rules(struct policy *policy, const char *path) {
    char line[RULE_LINE_LENGTH];
    if (path == nullptr) {
        return;
    }
    FILE *file = open_rules_file(path);
    if (file == nullptr) {
        policy->refused_a_line = true;
        return;
    }
    while (fgets(line, sizeof(line), file) != nullptr) {
        bool names_something = line_names_something(line);
        struct rule *rule = rule_parse(line);
        if (rule != nullptr) {
            rule->next = policy->first_rule;
            policy->first_rule = rule;
        } else if (names_something) {
            policy->refused_a_line = true;
        }
    }
    fclose(file);
}

/* True when the rule decides the connection by itself: it grants the port and is "*",
 * names the address, or is a range holding it. */
static bool rule_permits_connection(const struct rule *rule, const struct canonical_address *address,
                                    uint16_t port) {
    if (!rule_permits_port(rule, port)) {
        return false;
    }
    if (rule_is_address_range(rule)) {
        return rule_range_contains(rule, address);
    }
    return rule_is_any_host(rule) || rule_names_address(rule, address);
}

bool policy_is_silent(const struct policy *policy) {
    return policy->first_rule == nullptr && !policy->refused_a_line;
}

void policy_load(struct policy *policy, const char *path) {
    pthread_rwlock_wrlock(&policy->lock);
    free_rules(policy);
    policy->refused_a_line = false;
    read_rules(policy, path);
    address_cache_clear(&policy->cache);
    pthread_rwlock_unlock(&policy->lock);
}

bool policy_permits_lookup(struct policy *policy, const char *host, uint16_t port) {
    bool permitted = false;
    pthread_rwlock_rdlock(&policy->lock);
    for (struct rule *rule = policy->first_rule; rule != nullptr && !permitted; rule = rule->next) {
        permitted = !rule_is_address_range(rule) && rule_permits_lookup_port(rule, port)
                    && rule_matches_host(rule, host);
    }
    pthread_rwlock_unlock(&policy->lock);
    return permitted;
}

void policy_record_resolution(struct policy *policy, const char *host, const char *address) {
    pthread_rwlock_rdlock(&policy->lock);
    for (struct rule *rule = policy->first_rule; rule != nullptr; rule = rule->next) {
        if (!rule_is_address_range(rule) && rule_matches_host(rule, host)) {
            address_cache_record(&policy->cache, address, rule->port, rule->port == 0);
        }
    }
    pthread_rwlock_unlock(&policy->lock);
}

bool policy_permits_connection(struct policy *policy, const char *address, uint16_t port) {
    struct canonical_address canonical;
    bool permitted = false;
    if (address_cache_permits(&policy->cache, address, port)) {
        return true;
    }
    if (!canonical_address_parse(address, &canonical)) {
        return false;
    }
    pthread_rwlock_rdlock(&policy->lock);
    for (struct rule *rule = policy->first_rule; rule != nullptr && !permitted; rule = rule->next) {
        permitted = rule_permits_connection(rule, &canonical, port);
    }
    pthread_rwlock_unlock(&policy->lock);
    return permitted;
}
