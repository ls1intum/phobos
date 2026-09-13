#include "netblocker-address-cache.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

struct address_cache_entry {
    char address[INET6_ADDRSTRLEN];
    uint16_t port;
    bool any_port;
    struct address_cache_entry *next;
};

/* Forgetting the oldest entry assumes there is one to keep before it. */
static_assert(ADDRESS_CACHE_CAPACITY >= 1);

/* True when exactly this authorisation is recorded. Asked before recording, so that an
 * any-port and a single-port authorisation for one address stay distinguishable instead
 * of one hiding the other. */
static bool address_cache_holds(struct address_cache *cache, const char *address, uint16_t port,
                                bool any_port) {
    bool held = false;
    pthread_mutex_lock(&cache->lock);
    for (struct address_cache_entry *entry = cache->newest; entry != nullptr && !held;
         entry = entry->next) {
        held = strcasecmp(entry->address, address) == 0 && entry->any_port == any_port
               && entry->port == port;
    }
    pthread_mutex_unlock(&cache->lock);
    return held;
}

/* Frees the oldest entry. Assumes the lock is held and the cache holds more entries
 * than its capacity, so there is an entry before the oldest. */
static void forget_oldest(struct address_cache *cache) {
    struct address_cache_entry *before_oldest = cache->newest;
    while (before_oldest->next->next != nullptr) {
        before_oldest = before_oldest->next;
    }
    free(before_oldest->next);
    before_oldest->next = nullptr;
    cache->entry_count--;
}

bool address_cache_permits(struct address_cache *cache, const char *address, uint16_t port) {
    bool permitted = false;
    pthread_mutex_lock(&cache->lock);
    for (struct address_cache_entry *entry = cache->newest; entry != nullptr && !permitted;
         entry = entry->next) {
        permitted = strcasecmp(entry->address, address) == 0 && (entry->any_port || entry->port == port);
    }
    pthread_mutex_unlock(&cache->lock);
    return permitted;
}

void address_cache_record(struct address_cache *cache, const char *address, uint16_t port,
                          bool any_port) {
    if (address_cache_holds(cache, address, port, any_port)) {
        return;
    }
    struct address_cache_entry *entry = calloc(1, sizeof(*entry));
    if (entry == nullptr) {
        return;
    }
    strncpy(entry->address, address, sizeof(entry->address) - 1);
    entry->port = port;
    entry->any_port = any_port;
    pthread_mutex_lock(&cache->lock);
    entry->next = cache->newest;
    cache->newest = entry;
    cache->entry_count++;
    if (cache->entry_count > ADDRESS_CACHE_CAPACITY) {
        forget_oldest(cache);
    }
    pthread_mutex_unlock(&cache->lock);
}

void address_cache_clear(struct address_cache *cache) {
    pthread_mutex_lock(&cache->lock);
    while (cache->newest != nullptr) {
        struct address_cache_entry *next = cache->newest->next;
        free(cache->newest);
        cache->newest = next;
    }
    cache->entry_count = 0;
    pthread_mutex_unlock(&cache->lock);
}
