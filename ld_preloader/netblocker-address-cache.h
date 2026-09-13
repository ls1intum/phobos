/*
 * The addresses name lookups authorised, with the ports the policy grants them.
 *
 * This becomes a class: a bounded list of authorisations behind a lock, and the three
 * things done with it: asking whether an address may be reached on a port, recording
 * an authorisation, and forgetting them all.
 *
 * An entry carries the port a rule granted, a single port or every port. The port a
 * lookup happens to report is never an authorisation in itself, so resolving a host
 * can never widen a single-port rule into access on every port. An address and an
 * any-port authorisation and a single-port one for it stay distinct entries.
 */
#ifndef NETBLOCKER_ADDRESS_CACHE_H
#define NETBLOCKER_ADDRESS_CACHE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

/* Entries kept before the oldest is forgotten. */
static constexpr size_t ADDRESS_CACHE_CAPACITY = 1024;

/* One authorisation. Private to the cache. */
struct address_cache_entry;

struct address_cache {
    struct address_cache_entry *newest;
    size_t entry_count;
    pthread_mutex_t lock;
};

/* An initialiser rather than a function, because a hook can run before any
 * constructor, from another library's, and the cache has to work by then. A macro,
 * because the lock's own initialiser is one. */
#define ADDRESS_CACHE_INITIALISER                                                      \
    { .newest = nullptr, .entry_count = 0, .lock = PTHREAD_MUTEX_INITIALIZER }

/* True when an entry for the address, in any case, grants every port or the port. */
bool address_cache_permits(struct address_cache *cache, const char *address, uint16_t port);

/* Records an authorisation unless the same one is already there, forgetting the oldest
 * entry when the cache is full. An allocation that fails records nothing, so the
 * address is judged by the rules again next time rather than authorised. */
void address_cache_record(struct address_cache *cache, const char *address, uint16_t port,
                          bool any_port);

/* Forgets every authorisation. */
void address_cache_clear(struct address_cache *cache);

#endif
