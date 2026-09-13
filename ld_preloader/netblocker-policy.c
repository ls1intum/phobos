/* O_NOFOLLOW, fdopen and getnameinfo need this first. */
#define _GNU_SOURCE
#include "netblocker-policy.h"

#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
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

/* Reads every rule of the file, each put in front of the ones before it. Assumes the
 * write lock is held and the policy holds no rules. */
static void read_rules(struct policy *policy, const char *path) {
    char line[RULE_LINE_LENGTH];
    if (path == nullptr) {
        return;
    }
    FILE *file = open_rules_file(path);
    if (file == nullptr) {
        return;
    }
    while (fgets(line, sizeof(line), file) != nullptr) {
        struct rule *rule = rule_parse(line);
        if (rule != nullptr) {
            rule->next = policy->first_rule;
            policy->first_rule = rule;
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

/* True when the rule is a domain wildcard that grants the port. */
static bool wildcard_applies(const struct rule *rule, uint16_t port) {
    return !rule_is_address_range(rule) && rule_is_domain_wildcard(rule) && rule_permits_port(rule, port);
}

/* Looks up the suffix of a domain wildcard, records every address the lookup yields
 * under the rule's port, and answers whether one of them is the address. The suffix
 * keeps its leading dot, as it always has, and the lookup goes through this library's
 * own getaddrinfo. Assumes the read lock is held. */
static bool wildcard_resolves_to(struct policy *policy, const struct rule *rule,
                                 const struct canonical_address *address) {
    struct addrinfo *results = nullptr;
    bool found = false;
    if (getaddrinfo(rule_domain_suffix(rule), nullptr, nullptr, &results) != 0) {
        return false;
    }
    for (struct addrinfo *result = results; result != nullptr && !found; result = result->ai_next) {
        char text[INET6_ADDRSTRLEN] = "";
        getnameinfo(result->ai_addr, result->ai_addrlen, text, sizeof(text), nullptr, 0,
                    NI_NUMERICHOST);
        address_cache_record(&policy->cache, text, rule->port, rule->port == 0);
        found = strcasecmp(text, address->text) == 0;
    }
    freeaddrinfo(results);
    return found;
}

void policy_load(struct policy *policy, const char *path) {
    pthread_rwlock_wrlock(&policy->lock);
    free_rules(policy);
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
    for (struct rule *rule = policy->first_rule; rule != nullptr && !permitted; rule = rule->next) {
        permitted = wildcard_applies(rule, port) && wildcard_resolves_to(policy, rule, &canonical);
    }
    pthread_rwlock_unlock(&policy->lock);
    return permitted;
}
