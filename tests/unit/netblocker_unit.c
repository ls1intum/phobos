/*
 * Unit tests for libnetblocker.
 *
 * tests/network_cache_ports.sh runs the library preloaded into real processes, which is
 * what proves it filters. It cannot reach the failure paths: an allocation that fails,
 * a rules file that cannot be opened or read, a resolver answer that cannot be printed,
 * a reload between the two checks of one lookup. Those decide whether the filter fails
 * closed, so they are covered here, and tests/unit/netblocker_run.sh --coverage fails
 * unless every line and every branch of the library ran.
 *
 * netblocker.c is included rather than linked, so that its static functions and its
 * policy are reachable, and it is built without its constructor. The modules beside it
 * are linked. The calls into the C library that can fail are interposed through the
 * linker's --wrap and pass straight through unless a case arms a failure, because the
 * coverage runtime linked into the same binary makes the same calls on the way out.
 * dlsym is interposed too, so that the hooks hand permitted calls to a resolver and a
 * connect that touch no network.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define NETBLOCKER_UNIT_TEST
#include "../../ld_preloader/netblocker.c"

/* ------------------------------------------------------------ failures to inject */

static bool fail_next_calloc = false;
static bool fail_next_strdup = false;
static bool fail_next_fstat = false;
static bool fail_next_get_flags = false;
static bool fail_next_set_flags = false;
static bool fail_next_fdopen = false;

void *__real_calloc(size_t count, size_t size);
void *__wrap_calloc(size_t count, size_t size) {
    if (fail_next_calloc) {
        fail_next_calloc = false;
        errno = ENOMEM;
        return nullptr;
    }
    return __real_calloc(count, size);
}

char *__real_strdup(const char *text);
char *__wrap_strdup(const char *text) {
    if (fail_next_strdup) {
        fail_next_strdup = false;
        errno = ENOMEM;
        return nullptr;
    }
    return __real_strdup(text);
}

int __real_fstat(int descriptor, struct stat *status);
int __wrap_fstat(int descriptor, struct stat *status) {
    if (fail_next_fstat) {
        fail_next_fstat = false;
        errno = EIO;
        return -1;
    }
    return __real_fstat(descriptor, status);
}

/* Every command's argument is passed on as a pointer, as the C library's own fcntl
 * reads it, whether the command takes one or not. */
int __real_fcntl(int descriptor, int command, ...);
int __wrap_fcntl(int descriptor, int command, ...) {
    va_list arguments;
    va_start(arguments, command);
    void *argument = va_arg(arguments, void *);
    va_end(arguments);
    if (command == F_GETFL && fail_next_get_flags) {
        fail_next_get_flags = false;
        errno = EBADF;
        return -1;
    }
    if (command == F_SETFL && fail_next_set_flags) {
        fail_next_set_flags = false;
        errno = EBADF;
        return -1;
    }
    return __real_fcntl(descriptor, command, argument);
}

FILE *__real_fdopen(int descriptor, const char *mode);
FILE *__wrap_fdopen(int descriptor, const char *mode) {
    if (fail_next_fdopen) {
        fail_next_fdopen = false;
        errno = ENOMEM;
        return nullptr;
    }
    return __real_fdopen(descriptor, mode);
}

/* -------------------------------------------------- a resolver and a connect */

/* What the stand-in resolver answers for a name. "unprintable" is an address of a
 * family getnameinfo cannot write as text. ".wild.test" keeps its leading dot because
 * that is the name the filter asks for when it looks up the suffix of "*.wild.test",
 * a behaviour it keeps rather than one this suite endorses. */
struct fake_host {
    const char *name;
    const char *addresses[3];
};

static const struct fake_host FAKE_HOSTS[] = {
    { "service.test", { "192.0.2.10", "2001:db8::10", nullptr } },
    { "mixed.test", { "unprintable", "192.0.2.20", nullptr } },
    { ".wild.test", { "unprintable", "203.0.113.7", "203.0.113.8" } },
};

/* One answer, its address in the same allocation, as the C library lays one out, so
 * that freeaddrinfo frees it. */
struct fake_answer {
    struct addrinfo information;
    struct sockaddr_storage address;
};

static int resolver_calls = 0;
static int connect_calls = 0;
static int bind_calls = 0;
static int sendto_calls = 0;
static int sendmsg_calls = 0;
static bool reload_during_lookup = false;

static struct addrinfo *fake_answer_for(const char *text) {
    struct fake_answer *answer = malloc(sizeof(*answer));
    if (answer == nullptr) {
        perror("malloc");
        exit(2);
    }
    memset(answer, 0, sizeof(*answer));
    answer->information.ai_addr = (struct sockaddr *)&answer->address;
    if (strcmp(text, "unprintable") == 0) {
        answer->address.ss_family = AF_UNSPEC;
        answer->information.ai_addrlen = sizeof(sa_family_t);
    }
    else if (strchr(text, ':') != nullptr) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&answer->address;
        ipv6->sin6_family = AF_INET6;
        inet_pton(AF_INET6, text, &ipv6->sin6_addr);
        answer->information.ai_addrlen = sizeof(*ipv6);
    }
    else {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&answer->address;
        ipv4->sin_family = AF_INET;
        inet_pton(AF_INET, text, &ipv4->sin_addr);
        answer->information.ai_addrlen = sizeof(*ipv4);
    }
    answer->information.ai_family = answer->address.ss_family;
    return &answer->information;
}

static int fake_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                            struct addrinfo **results) {
    (void)service;
    (void)hints;
    resolver_calls++;
    *results = nullptr;
    if (reload_during_lookup) {
        reload_during_lookup = false;
        policy_load(&policy, nullptr);
    }
    if (node == nullptr) {
        return 0;
    }
    for (size_t host = 0; host < sizeof(FAKE_HOSTS) / sizeof(FAKE_HOSTS[0]); host++) {
        if (strcmp(FAKE_HOSTS[host].name, node) != 0) {
            continue;
        }
        struct addrinfo **tail = results;
        for (size_t index = 0; index < 3 && FAKE_HOSTS[host].addresses[index] != nullptr; index++) {
            *tail = fake_answer_for(FAKE_HOSTS[host].addresses[index]);
            tail = &(*tail)->ai_next;
        }
        return 0;
    }
    return EAI_NONAME;
}

static int fake_connect(int descriptor, const struct sockaddr *destination, socklen_t length) {
    (void)descriptor;
    (void)destination;
    (void)length;
    connect_calls++;
    return 0;
}

static int fake_bind(int descriptor, const struct sockaddr *address, socklen_t length) {
    (void)descriptor;
    (void)address;
    (void)length;
    bind_calls++;
    return 0;
}

static ssize_t fake_sendto(int descriptor, const void *buffer, size_t length, int flags,
                           const struct sockaddr *destination, socklen_t address_length) {
    (void)descriptor;
    (void)buffer;
    (void)flags;
    (void)destination;
    (void)address_length;
    sendto_calls++;
    return (ssize_t)length;
}

static ssize_t fake_sendmsg(int descriptor, const struct msghdr *message, int flags) {
    (void)descriptor;
    (void)message;
    (void)flags;
    sendmsg_calls++;
    return 0;
}

void *__real_dlsym(void *handle, const char *name);
void *__wrap_dlsym(void *handle, const char *name) {
    if (strcmp(name, "getaddrinfo") == 0) {
        return fake_getaddrinfo;
    }
    if (strcmp(name, "connect") == 0) {
        return fake_connect;
    }
    if (strcmp(name, "bind") == 0) {
        return fake_bind;
    }
    if (strcmp(name, "sendto") == 0) {
        return fake_sendto;
    }
    if (strcmp(name, "sendmsg") == 0) {
        return fake_sendmsg;
    }
    return __real_dlsym(handle, name);
}

/* ------------------------------------------------------------------ test driver */

static int passed = 0;
static int failed = 0;

static char rules_directory[] = "/tmp/netblocker-unit.XXXXXX";
static char rules_path[PATH_MAX];
static char link_path[PATH_MAX];

static void check(const char *what, bool condition) {
    if (condition) {
        printf("  ok    %s\n", what);
        passed++;
    }
    else {
        printf("  FAIL  %s\n", what);
        failed++;
    }
}

/* Writes the rules file inside the private rules directory, readable and writable by its
 * owner only, and without following a link planted in its place. */
static void write_rules(const char *body) {
    int descriptor = open(rules_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        perror("rules");
        exit(2);
    }
    FILE *file = fdopen(descriptor, "w");
    if (file == nullptr) {
        perror("rules");
        close(descriptor);
        exit(2);
    }
    fputs(body, file);
    fclose(file);
}

static void load_rules(const char *body) {
    write_rules(body);
    policy_load(&policy, rules_path);
}

static void load_bind_rules(const char *body) {
    write_rules(body);
    policy_load(&bind_policy, rules_path);
}

static size_t rule_count(void) {
    size_t count = 0;
    for (struct rule *rule = policy.first_rule; rule != nullptr; rule = rule->next) {
        count++;
    }
    return count;
}

/* rule_parse cuts up the line it is given, so each case hands it a copy. */
static struct rule *parse(const char *text) {
    static char line[RULE_LINE_LENGTH];
    snprintf(line, sizeof(line), "%s", text);
    return rule_parse(line);
}

static int lookup(const char *node, const char *service) {
    struct addrinfo *results = nullptr;
    int status = getaddrinfo(node, service, nullptr, &results);
    freeaddrinfo(results);
    return status;
}

/* What a connection through the hook did. */
enum connection_outcome {
    CONNECTION_ALLOWED,   /* it reached the connect the hook guards */
    CONNECTION_DENIED,    /* it was refused with EACCES without reaching it */
    CONNECTION_UNEXPECTED /* anything else, which no check accepts */
};

/* Connects through the hook to an IPv4 or IPv6 address and reports what happened. */
static enum connection_outcome connection_outcome(const char *address, uint16_t port) {
    struct sockaddr_storage destination;
    socklen_t length = 0;
    int calls_before = connect_calls;
    memset(&destination, 0, sizeof(destination));
    if (strchr(address, ':') != nullptr) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&destination;
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(port);
        inet_pton(AF_INET6, address, &ipv6->sin6_addr);
        length = sizeof(*ipv6);
    }
    else {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&destination;
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons(port);
        inet_pton(AF_INET, address, &ipv4->sin_addr);
        length = sizeof(*ipv4);
    }
    errno = 0;
    int status = connect(3, (struct sockaddr *)&destination, length);
    if (status == 0 && connect_calls == calls_before + 1) {
        return CONNECTION_ALLOWED;
    }
    if (status == -1 && errno == EACCES && connect_calls == calls_before) {
        return CONNECTION_DENIED;
    }
    return CONNECTION_UNEXPECTED;
}

/* Writes an IPv4 or IPv6 destination into the storage, choosing the family from whether
 * the address text holds a colon, and returns its length. */
static socklen_t fill_destination(struct sockaddr_storage *destination, const char *address,
                                  uint16_t port) {
    memset(destination, 0, sizeof(*destination));
    if (strchr(address, ':') != nullptr) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)destination;
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(port);
        inet_pton(AF_INET6, address, &ipv6->sin6_addr);
        return sizeof(*ipv6);
    }
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)destination;
    ipv4->sin_family = AF_INET;
    ipv4->sin_port = htons(port);
    inet_pton(AF_INET, address, &ipv4->sin_addr);
    return sizeof(*ipv4);
}

/* What a datagram through a UDP hook did. */
enum datagram_outcome {
    DATAGRAM_SENT,      /* it reached the send the hook guards */
    DATAGRAM_DENIED,    /* it was refused with EACCES without reaching it */
    DATAGRAM_UNEXPECTED /* anything else, which no check accepts */
};

/* Sends through the sendto hook to an IPv4 or IPv6 address and reports what happened. */
static enum datagram_outcome sendto_outcome(const char *address, uint16_t port) {
    struct sockaddr_storage destination;
    socklen_t length = fill_destination(&destination, address, port);
    int calls_before = sendto_calls;
    errno = 0;
    ssize_t status = sendto(3, "x", 1, 0, (struct sockaddr *)&destination, length);
    if (status == 1 && sendto_calls == calls_before + 1) {
        return DATAGRAM_SENT;
    }
    if (status == -1 && errno == EACCES && sendto_calls == calls_before) {
        return DATAGRAM_DENIED;
    }
    return DATAGRAM_UNEXPECTED;
}

/* Sends through the sendmsg hook to an IPv4 or IPv6 address and reports what happened. */
static enum datagram_outcome sendmsg_outcome(const char *address, uint16_t port) {
    struct sockaddr_storage destination;
    struct msghdr message;
    socklen_t length = fill_destination(&destination, address, port);
    int calls_before = sendmsg_calls;
    memset(&message, 0, sizeof(message));
    message.msg_name = &destination;
    message.msg_namelen = length;
    errno = 0;
    ssize_t status = sendmsg(3, &message, 0);
    if (status == 0 && sendmsg_calls == calls_before + 1) {
        return DATAGRAM_SENT;
    }
    if (status == -1 && errno == EACCES && sendmsg_calls == calls_before) {
        return DATAGRAM_DENIED;
    }
    return DATAGRAM_UNEXPECTED;
}

/* ------------------------------------------------------------------- the cases */

static void test_addresses(void) {
    struct canonical_address first;
    struct canonical_address second;
    struct canonical_address network;
    printf("\nAddresses\n");
    check("an IPv6 literal keeps its text and is not IPv4-mapped",
          canonical_address_parse("2001:db8::1", &first) && strcmp(first.text, "2001:db8::1") == 0
              && !canonical_address_is_ipv4_mapped(&first));
    check("an IPv4 literal is held mapped, with dotted text",
          canonical_address_parse("192.0.2.1", &second) && strcmp(second.text, "192.0.2.1") == 0
              && canonical_address_is_ipv4_mapped(&second));
    check("::ffff:192.0.2.1 equals 192.0.2.1",
          canonical_address_parse("::ffff:192.0.2.1", &first) && canonical_address_equals(&first, &second));
    check("two different addresses are not equal",
          canonical_address_parse("192.0.2.2", &first) && !canonical_address_equals(&first, &second));
    check("a host name is not an address", !canonical_address_parse("service.test", &first));
    check("an empty text is not an address", !canonical_address_parse("", &first));
    check("an address with a non-zero second word is not IPv4-mapped",
          canonical_address_parse("0:0:1::1", &first) && !canonical_address_is_ipv4_mapped(&first));
    check("::1 is not IPv4-mapped",
          canonical_address_parse("::1", &first) && !canonical_address_is_ipv4_mapped(&first));
    check("a dotted literal is IPv4 text", address_text_is_ipv4("192.0.2.1"));
    check("an IPv6 literal is not IPv4 text", !address_text_is_ipv4("::1"));

    canonical_address_parse("192.0.2.0", &network);
    canonical_address_parse("192.0.2.77", &first);
    canonical_address_parse("198.51.100.1", &second);
    check("a prefix of 0 bits matches nothing", !canonical_address_within(&first, &network.bytes, 0));
    check("a prefix of 129 bits matches nothing", !canonical_address_within(&first, &network.bytes, 129));
    check("a whole-byte prefix holds an address inside it", canonical_address_within(&first, &network.bytes, 120));
    check("a whole-byte prefix refuses an address outside it", !canonical_address_within(&second, &network.bytes, 120));
    check("a prefix ending inside a byte holds an address matching its bits",
          canonical_address_within(&first, &network.bytes, 121));
    check("a prefix ending inside a byte refuses an address differing in its bits",
          !canonical_address_within(&first, &network.bytes, 124));
}

static void test_rule_parsing(void) {
    struct rule *rule = nullptr;
    printf("\nReading a rule\n");
    rule = parse("service.test 443 # the web server");
    check("a host and a port, with a comment after them",
          rule != nullptr && strcmp(rule->host, "service.test") == 0 && rule->port == 443
              && !rule_is_address_range(rule));
    rule_destroy(rule);
    rule = parse("service.test");
    check("no port word grants every port", rule != nullptr && rule->port == 0);
    rule_destroy(rule);
    rule = parse("service.test *");
    check("a '*' port grants every port", rule != nullptr && rule->port == 0);
    rule_destroy(rule);
    check("a line of whitespace is no rule", parse("   \t\n") == nullptr);
    check("a comment line is no rule", parse("# only a comment\n") == nullptr);
    check("a port with trailing text drops the rule", parse("service.test 8x") == nullptr);
    check("a port above 65535 drops the rule", parse("service.test 70000") == nullptr);

    rule = parse("192.0.2.0/24 80");
    check("an IPv4 range counts its prefix from bit 96",
          rule != nullptr && strcmp(rule->host, "192.0.2.0") == 0 && rule->prefix_length == 120
              && rule->port == 80 && rule_is_address_range(rule));
    rule_destroy(rule);
    rule = parse("2001:db8::/32");
    check("an IPv6 range keeps its prefix", rule != nullptr && rule->prefix_length == 32);
    rule_destroy(rule);
    rule = parse("::ffff:192.0.2.0/120");
    check("an IPv4 range in IPv6 notation with 120 bits is kept", rule != nullptr && rule->prefix_length == 120);
    rule_destroy(rule);
    check("an IPv4-mapped range shorter than 96 bits drops the rule", parse("::ffff:192.0.2.0/64") == nullptr);
    check("an IPv4 prefix above 32 drops the rule", parse("192.0.2.0/33") == nullptr);
    check("a prefix of 0 drops the rule", parse("192.0.2.0/0") == nullptr);
    check("a prefix with trailing text drops the rule", parse("192.0.2.0/2x") == nullptr);
    check("a range on a host name drops the rule", parse("service.test/8") == nullptr);

    fail_next_calloc = true;
    check("a rule that cannot be allocated grants nothing", parse("service.test") == nullptr);
    fail_next_strdup = true;
    check("a rule whose host cannot be copied grants nothing", parse("service.test") == nullptr);
}

static void test_rule_questions(void) {
    struct rule *any = parse("*");
    struct rule *any_on_port = parse("* 80");
    struct rule *wildcard = parse("*.example.test");
    struct rule *named = parse("Service.Test 80");
    struct rule *literal = parse("192.0.2.1");
    struct rule *range = parse("192.0.2.0/24");
    struct canonical_address address;
    printf("\nWhat a rule covers\n");
    check("a range is a range", rule_is_address_range(range));
    check("'*' is any host", rule_is_any_host(any));
    check("a host name is not any host", !rule_is_any_host(named));
    check("'*.example.test' is a domain wildcard", rule_is_domain_wildcard(wildcard));
    check("'*' is not a domain wildcard", !rule_is_domain_wildcard(any));
    check("a host name is not a domain wildcard", !rule_is_domain_wildcard(named));
    check("a domain wildcard's suffix keeps its dot", strcmp(rule_domain_suffix(wildcard), ".example.test") == 0);

    check("'*' covers every name", rule_matches_host(any, "anything.test"));
    check("'*' with a port covers no name", !rule_matches_host(any_on_port, "anything.test"));
    check("a domain wildcard covers a name below it", rule_matches_host(wildcard, "a.example.test"));
    check("a domain wildcard does not cover its own domain", !rule_matches_host(wildcard, "example.test"));
    check("a domain wildcard does not cover another domain", !rule_matches_host(wildcard, "a.other.test"));
    check("a host name matches in any case", rule_matches_host(named, "service.test"));
    check("a host name does not match another name", !rule_matches_host(named, "other.test"));

    check("a lookup naming no port may use a single-port rule", rule_permits_lookup_port(named, 0));
    check("a lookup for the rule's port may use it", rule_permits_lookup_port(named, 80));
    check("a lookup for another port may not", !rule_permits_lookup_port(named, 81));
    check("an every-port rule serves a lookup for any port", rule_permits_lookup_port(any, 81));
    check("a connection to the rule's port may use it", rule_permits_port(named, 80));
    check("a connection to another port may not", !rule_permits_port(named, 81));
    check("an every-port rule serves a connection to any port", rule_permits_port(any, 81));

    canonical_address_parse("192.0.2.1", &address);
    check("an address rule names its address", rule_names_address(literal, &address));
    check("a range holds an address inside it", rule_range_contains(range, &address));
    check("a host name rule names no address", !rule_names_address(named, &address));
    canonical_address_parse("192.0.2.2", &address);
    check("an address rule does not name another address", !rule_names_address(literal, &address));
    canonical_address_parse("198.51.100.1", &address);
    check("a range does not hold an address outside it", !rule_range_contains(range, &address));

    rule_destroy(any);
    rule_destroy(any_on_port);
    rule_destroy(wildcard);
    rule_destroy(named);
    rule_destroy(literal);
    rule_destroy(range);
}

static void test_address_cache(void) {
    struct address_cache cache = ADDRESS_CACHE_INITIALISER;
    char address[INET6_ADDRSTRLEN];
    printf("\nThe address cache\n");
    check("an empty cache permits nothing", !address_cache_permits(&cache, "192.0.2.1", 80));
    address_cache_record(&cache, "192.0.2.1", 80, false);
    check("a recorded port is permitted", address_cache_permits(&cache, "192.0.2.1", 80));
    check("another port is not", !address_cache_permits(&cache, "192.0.2.1", 81));
    check("another address is not", !address_cache_permits(&cache, "192.0.2.2", 80));
    address_cache_record(&cache, "2001:DB8::1", 0, true);
    check("an every-port entry permits any port, in any case", address_cache_permits(&cache, "2001:db8::1", 9));
    address_cache_record(&cache, "192.0.2.1", 80, false);
    check("recording the same authorisation again adds nothing", cache.entry_count == 2);
    address_cache_record(&cache, "192.0.2.1", 0, true);
    check("an every-port authorisation for a recorded address is its own entry", cache.entry_count == 3);
    address_cache_record(&cache, "192.0.2.1", 81, false);
    check("another single port for a recorded address is its own entry", cache.entry_count == 4);
    fail_next_calloc = true;
    address_cache_record(&cache, "192.0.2.9", 1, false);
    check("an entry that cannot be allocated is not recorded",
          cache.entry_count == 4 && !address_cache_permits(&cache, "192.0.2.9", 1));

    address_cache_clear(&cache);
    check("clearing forgets everything",
          cache.entry_count == 0 && !address_cache_permits(&cache, "192.0.2.1", 80));
    for (size_t index = 0; index <= ADDRESS_CACHE_CAPACITY; index++) {
        snprintf(address, sizeof(address), "10.0.%zu.%zu", index / 256, index % 256);
        address_cache_record(&cache, address, 1, false);
    }
    check("a full cache keeps its capacity", cache.entry_count == ADDRESS_CACHE_CAPACITY);
    check("a full cache forgets its oldest entry", !address_cache_permits(&cache, "10.0.0.0", 1));
    check("a full cache keeps its newest entry", address_cache_permits(&cache, address, 1));
    address_cache_clear(&cache);
}

static void test_loading(void) {
    printf("\nLoading the rules\n");
    policy_load(&policy, nullptr);
    check("no rules file leaves no rules", policy.first_rule == nullptr);
    load_rules("service.test 80\n# a comment\n192.0.2.0/24\n");
    check("every rule is read, the last line first",
          rule_count() == 2 && rule_is_address_range(policy.first_rule)
              && strcmp(policy.first_rule->next->host, "service.test") == 0);
    address_cache_record(&policy.cache, "192.0.2.50", 1, false);
    load_rules("service.test 80\n");
    check("loading replaces the rules and forgets every authorisation",
          rule_count() == 1 && !address_cache_permits(&policy.cache, "192.0.2.50", 1));

    policy_load(&policy, "/nonexistent/netblocker/rules");
    check("a rules file that does not exist leaves no rules", policy.first_rule == nullptr);
    policy_load(&policy, rules_directory);
    check("a directory in place of the rules file leaves no rules", policy.first_rule == nullptr);
    policy_load(&policy, link_path);
    check("a symbolic link to the rules file leaves no rules", policy.first_rule == nullptr);
    fail_next_fstat = true;
    policy_load(&policy, rules_path);
    check("a rules file that cannot be examined leaves no rules", policy.first_rule == nullptr);
    fail_next_get_flags = true;
    policy_load(&policy, rules_path);
    check("a rules file whose flags cannot be read leaves no rules", policy.first_rule == nullptr);
    fail_next_set_flags = true;
    policy_load(&policy, rules_path);
    check("a rules file that cannot be made blocking leaves no rules", policy.first_rule == nullptr);
    fail_next_fdopen = true;
    policy_load(&policy, rules_path);
    check("a rules file that cannot be read as a stream leaves no rules", policy.first_rule == nullptr);
}

static const char POLICY_RULES[] = "service.test 443\n"
                                   "mixed.test\n"
                                   "*.example.test\n"
                                   "192.0.2.1 80\n"
                                   "198.51.100.0/24\n"
                                   "* 25\n"
                                   "*.wild.test 8080\n"
                                   "*.none.test\n";

static void test_policy(void) {
    printf("\nWhat the policy answers\n");
    load_rules(POLICY_RULES);
    check("a host may be looked up for its port", policy_permits_lookup(&policy, "service.test", 443));
    check("a host may be looked up for no port", policy_permits_lookup(&policy, "service.test", 0));
    check("a host may not be looked up for another port", !policy_permits_lookup(&policy, "service.test", 80));
    check("a name below a domain wildcard may be looked up", policy_permits_lookup(&policy, "a.example.test", 22));
    check("a range lets no name be looked up", !policy_permits_lookup(&policy, "198.51.100.0", 0));

    policy_record_resolution(&policy, "service.test", "192.0.2.10");
    check("a resolved address may be reached on the host's port", policy_permits_connection(&policy, "192.0.2.10", 443));
    check("a resolved address may not be reached on another port",
          !policy_permits_connection(&policy, "192.0.2.10", 444));
    check("an address rule permits its port", policy_permits_connection(&policy, "192.0.2.1", 80));
    check("an address rule refuses another port", !policy_permits_connection(&policy, "192.0.2.1", 81));
    check("a range permits an address inside it", policy_permits_connection(&policy, "198.51.100.9", 1));
    check("'*' with a port permits any address on it", policy_permits_connection(&policy, "203.0.113.5", 25));
    check("a host name is not an address to connect to", !policy_permits_connection(&policy, "service.test", 443));
    check("the empty text of another family is refused", !policy_permits_connection(&policy, "", 0));
    check("a domain wildcard permits an address its suffix resolves to",
          policy_permits_connection(&policy, "203.0.113.7", 8080));
    check("that lookup recorded the rest of its answer", address_cache_permits(&policy.cache, "203.0.113.8", 8080));
    check("a domain wildcard refuses an address its suffix does not resolve to",
          !policy_permits_connection(&policy, "203.0.113.9", 8080));
    check("a domain wildcard refuses a port it does not grant",
          !policy_permits_connection(&policy, "203.0.113.9", 9));
}

static void test_hooks(void) {
    int resolver_calls_before = 0;
    struct sockaddr unix_destination;
    printf("\nThe hooks\n");
    check("no service is no port", service_port(nullptr) == 0);
    check("a numeric service is its port", service_port("443") == 443);
    check("a service name is no port", service_port("http") == 0);
    check("a service above 65535 is no port", service_port("70000") == 0);

    load_rules(POLICY_RULES);
    real_getaddrinfo = nullptr;
    resolver_calls_before = resolver_calls;
    check("a lookup of a host no rule covers fails with EAI_FAIL",
          lookup("blocked.test", nullptr) == EAI_FAIL && resolver_calls == resolver_calls_before);
    check("the hook finds the resolver on first use", real_getaddrinfo == fake_getaddrinfo);
    check("a lookup without a node goes to the resolver", lookup(nullptr, "80") == 0);
    check("a permitted lookup the resolver fails keeps the resolver's answer",
          lookup("unknown.example.test", nullptr) == EAI_NONAME);
    check("a permitted lookup succeeds", lookup("service.test", "443") == 0);
    check("its IPv6 address may then be reached on the port",
          connection_outcome("2001:db8::10", 443) == CONNECTION_ALLOWED);
    check("but not on another port", connection_outcome("2001:db8::10", 22) == CONNECTION_DENIED);
    check("a lookup with an unprintable answer succeeds", lookup("mixed.test", nullptr) == 0);
    check("its printable address may then be reached", connection_outcome("192.0.2.20", 9) == CONNECTION_ALLOWED);

    reload_during_lookup = true;
    check("a lookup whose rules are replaced while it resolves succeeds", lookup("service.test", "443") == 0);
    check("but records nothing under rules that no longer exist",
          connection_outcome("192.0.2.10", 443) == CONNECTION_DENIED);
    load_rules(POLICY_RULES);

    real_connect = nullptr;
    check("a connection an address rule covers goes through", connection_outcome("192.0.2.1", 80) == CONNECTION_ALLOWED);
    check("the hook finds connect on first use", real_connect == fake_connect);
    check("a connection no rule covers is refused", connection_outcome("192.0.2.1", 81) == CONNECTION_DENIED);

    memset(&unix_destination, 0, sizeof(unix_destination));
    unix_destination.sa_family = AF_UNIX;
    errno = 0;
    check("a connection of another family is refused with EACCES",
          connect(3, &unix_destination, sizeof(sa_family_t)) == -1 && errno == EACCES);

    /* The UDP hooks. sendto and sendmsg filter a datagram named for an unconnected
     * socket, which connect never sees. They share destination_permitted with connect,
     * so the family branches are exercised through them here. */
    int sendto_before = 0;
    int sendmsg_before = 0;
    struct msghdr connected_message;
    real_sendto = nullptr;
    check("a datagram an address rule covers is sent", sendto_outcome("192.0.2.1", 80) == DATAGRAM_SENT);
    check("the hook finds sendto on first use", real_sendto == fake_sendto);
    check("a datagram no rule covers is refused", sendto_outcome("192.0.2.1", 81) == DATAGRAM_DENIED);
    check("an IPv6 datagram a rule covers is sent", sendto_outcome("2001:db8::99", 25) == DATAGRAM_SENT);

    sendto_before = sendto_calls;
    check("a datagram with no destination is on a connected socket and passes",
          sendto(3, "x", 1, 0, nullptr, 0) == 1 && sendto_calls == sendto_before + 1);
    sendto_before = sendto_calls;
    check("a datagram to a non-INET family is left to other layers and passes",
          sendto(3, "x", 1, 0, &unix_destination, sizeof(sa_family_t)) == 1
              && sendto_calls == sendto_before + 1);

    real_sendmsg = nullptr;
    check("a message an address rule covers is sent", sendmsg_outcome("192.0.2.1", 80) == DATAGRAM_SENT);
    check("the hook finds sendmsg on first use", real_sendmsg == fake_sendmsg);
    check("a message no rule covers is refused", sendmsg_outcome("192.0.2.1", 81) == DATAGRAM_DENIED);

    memset(&connected_message, 0, sizeof(connected_message));
    sendmsg_before = sendmsg_calls;
    check("a message with no destination is on a connected socket and passes",
          sendmsg(3, &connected_message, 0) == 0 && sendmsg_calls == sendmsg_before + 1);
}

/* What a bind through the hook did. */
enum bind_result { BIND_BOUND, BIND_DENIED, BIND_UNEXPECTED };

/* Binds a socket of the given type to a local address through the hook and reports whether
 * it reached the real bind or was refused with EACCES. A real socket is created so the
 * hook's SO_TYPE check reads a true type; the real bind is faked, so nothing is bound. */
static enum bind_result bind_outcome(int socket_type, const char *address, uint16_t port) {
    struct sockaddr_storage local;
    socklen_t length = fill_destination(&local, address, port);
    int family = (strchr(address, ':') != nullptr) ? AF_INET6 : AF_INET;
    int descriptor = socket(family, socket_type, 0);
    int calls_before = bind_calls;
    errno = 0;
    int status = bind(descriptor, (struct sockaddr *)&local, length);
    enum bind_result result = BIND_UNEXPECTED;
    if (status == 0 && bind_calls == calls_before + 1) {
        result = BIND_BOUND;
    }
    else if (status == -1 && errno == EACCES && bind_calls == calls_before) {
        result = BIND_DENIED;
    }
    if (descriptor >= 0) {
        close(descriptor);
    }
    return result;
}

static void test_bind(void) {
    struct sockaddr_storage local;
    struct sockaddr unix_local;
    socklen_t length;
    int closed_descriptor;
    int calls_before;
    printf("\nThe bind hook\n");

    /* With no [bind] rule the hook passes every bind, matching Landlock leaving bind
     * unrestricted when no bind port is named. */
    policy_load(&bind_policy, nullptr);
    real_bind = nullptr;
    check("with no bind rule a bind passes", bind_outcome(SOCK_STREAM, "127.0.0.1", 8080) == BIND_BOUND);
    check("the hook finds bind on first use", real_bind == fake_bind);

    /* With a bind rule, a TCP bind to an allowed local address passes, and to a disallowed
     * address or port is refused. */
    load_bind_rules("127.0.0.1 8080\n");
    check("a TCP bind to an allowed local address passes", bind_outcome(SOCK_STREAM, "127.0.0.1", 8080) == BIND_BOUND);
    check("a TCP bind to a disallowed local address is refused", bind_outcome(SOCK_STREAM, "0.0.0.0", 8080) == BIND_DENIED);
    check("a TCP bind to a disallowed port is refused", bind_outcome(SOCK_STREAM, "127.0.0.1", 9090) == BIND_DENIED);
    check("an IPv6 TCP bind is filtered too", bind_outcome(SOCK_STREAM, "::1", 8080) == BIND_DENIED);

    /* Only TCP is filtered, matching Landlock's TCP-only bind right: a datagram bind passes
     * even where the address is not listed. */
    check("a UDP bind is not filtered and passes", bind_outcome(SOCK_DGRAM, "0.0.0.0", 8080) == BIND_BOUND);

    /* A non-INET family is left to other layers. */
    memset(&unix_local, 0, sizeof(unix_local));
    unix_local.sa_family = AF_UNIX;
    calls_before = bind_calls;
    check("a bind of another family passes to other layers",
          bind(3, &unix_local, sizeof(sa_family_t)) == 0 && bind_calls == calls_before + 1);

    /* A descriptor whose type cannot be read passes, since the hook cannot tell it is TCP;
     * a closed descriptor makes getsockopt fail. */
    closed_descriptor = socket(AF_INET, SOCK_STREAM, 0);
    close(closed_descriptor);
    length = fill_destination(&local, "0.0.0.0", 8080);
    calls_before = bind_calls;
    check("a bind whose socket type cannot be read passes",
          bind(closed_descriptor, (struct sockaddr *)&local, length) == 0 && bind_calls == calls_before + 1);

    policy_load(&bind_policy, nullptr);
}

int main(void) {
    if (mkdtemp(rules_directory) == nullptr) {
        perror("mkdtemp");
        return 2;
    }
    snprintf(rules_path, sizeof(rules_path), "%s/rules", rules_directory);
    snprintf(link_path, sizeof(link_path), "%s/link", rules_directory);
    write_rules(POLICY_RULES);
    if (symlink(rules_path, link_path) != 0) {
        perror("symlink");
        return 2;
    }

    setenv("NETBLOCKER_CONF", rules_path, 1);
    netblocker_initialise();
    printf("Loading the library\n");
    check("the rules NETBLOCKER_CONF names are loaded", rule_count() == 8);
    check("the functions the hooks hand calls to are found",
          real_getaddrinfo == fake_getaddrinfo && real_connect == fake_connect
              && real_bind == fake_bind && real_sendto == fake_sendto
              && real_sendmsg == fake_sendmsg);

    test_addresses();
    test_rule_parsing();
    test_rule_questions();
    test_address_cache();
    test_loading();
    test_policy();
    test_hooks();
    test_bind();

    policy_load(&policy, nullptr);
    policy_load(&bind_policy, nullptr);
    unlink(link_path);
    unlink(rules_path);
    rmdir(rules_directory);
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
