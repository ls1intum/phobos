/*
 * The allow-list a process runs under.
 *
 * It holds the rules read from one file, the addresses name lookups
 * authorised under them, and the lock that lets every thread ask while the rules are
 * replaced. What it answers is whether a host may be looked up for a port, and whether
 * an address may be connected to on a port.
 */
#ifndef NETBLOCKER_POLICY_H
#define NETBLOCKER_POLICY_H

#include "netblocker-address-cache.h"
#include "netblocker-rule.h"

#include <pthread.h>
#include <stdint.h>

struct policy {
    struct rule *first_rule;
    bool refused_a_line;
    pthread_rwlock_t lock;
    struct address_cache cache;
};

/* An initialiser rather than a function, for the same reason as the cache's: a hook
 * can run before this library's constructor and has to find an empty policy, which
 * refuses everything. */
#define POLICY_INITIALISER                                                             \
    { .first_rule = nullptr, .refused_a_line = false, .lock = PTHREAD_RWLOCK_INITIALIZER, \
      .cache = ADDRESS_CACHE_INITIALISER }

/* Replaces the rules with those in the file at path and forgets every authorisation.
 * No path, a path that is not a regular file, a symbolic link as its last component
 * and a file that cannot be read all leave no rules, which refuses every connection.
 * A line the rule parser refuses, and a file that was named but could not be opened, are
 * both remembered in refused_a_line, so that a policy which granted nothing can be told
 * from one that names nothing: for the bind list, where an empty policy means "not
 * restricted", the difference decides whether binding is filtered at all. */
void policy_load(struct policy *policy, const char *path);

/* True when the policy holds no rule at all and refused no line, which is the one case
 * that means "this list says nothing" rather than "this list allows nothing". */
bool policy_is_silent(const struct policy *policy);

/* True when a rule lets the host be looked up for the port, 0 meaning no port. */
bool policy_permits_lookup(struct policy *policy, const char *host, uint16_t port);

/* Records, against one address the host resolved to, the ports the rules grant the
 * host. A resolver reply carries no port of its own, so the authorisation is read from
 * the rules. */
void policy_record_resolution(struct policy *policy, const char *host, const char *address);

/* True when the address may be connected to on the port: through an authorisation a
 * lookup recorded, "*", a rule naming the address, or a range holding it. A domain wildcard
 * permits an address only through a lookup of a name below it, which records what that name
 * resolved to. Text that is not an address literal, the empty text a socket of another
 * family yields included, is refused unless a lookup recorded it. */
bool policy_permits_connection(struct policy *policy, const char *address, uint16_t port);

#endif
