/* Probe client for the network interposer's address cache.
 *
 * The first phase binds listening sockets on ephemeral loopback ports, writes
 * the rule file naming those ports, and re-executes itself with the interposer
 * preloaded. Listening descriptors survive the exec, so the ports stay
 * reserved and every probe below talks only to this process: no external
 * service is contacted and no port number is hard-coded.
 *
 * The second phase runs one scenario and prints a "key=value" line per probe.
 * A connection prints "allowed" when it completes, "denied" when the
 * interposer refuses it with EACCES, and "errno:<n>" for anything else, so a
 * refusal can never be confused with an unrelated failure.
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORTS_V4 3
#define PORTS_V6 2

struct listener {
  int fd;
  unsigned short port;
};

static int listen_ephemeral(int family, struct listener *out) {
  int fd = socket(family, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  struct sockaddr_storage addr;
  socklen_t len;
  memset(&addr, 0, sizeof addr);

  if (family == AF_INET) {
    struct sockaddr_in *v4 = (struct sockaddr_in *) &addr;
    v4->sin_family = AF_INET;
    v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    len = sizeof *v4;
  } else {
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *) &addr;
    v6->sin6_family = AF_INET6;
    v6->sin6_addr = in6addr_loopback;
    len = sizeof *v6;
  }

  if (bind(fd, (struct sockaddr *) &addr, len) != 0 || listen(fd, 16) != 0) {
    close(fd);
    return -1;
  }

  len = sizeof addr;
  if (getsockname(fd, (struct sockaddr *) &addr, &len) != 0) {
    close(fd);
    return -1;
  }

  out->fd = fd;
  out->port = (family == AF_INET)
      ? ntohs(((struct sockaddr_in *) &addr)->sin_port)
      : ntohs(((struct sockaddr_in6 *) &addr)->sin6_port);
  return 0;
}

static const char *connect_result(int family, const char *ip, unsigned short port) {
  static char buf[32];
  int fd = socket(family, SOCK_STREAM, 0);
  if (fd < 0) return "socket-failed";

  struct sockaddr_storage addr;
  socklen_t len;
  memset(&addr, 0, sizeof addr);

  if (family == AF_INET) {
    struct sockaddr_in *v4 = (struct sockaddr_in *) &addr;
    v4->sin_family = AF_INET;
    v4->sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &v4->sin_addr) != 1) { close(fd); return "bad-address"; }
    len = sizeof *v4;
  } else {
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *) &addr;
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htons(port);
    if (inet_pton(AF_INET6, ip, &v6->sin6_addr) != 1) { close(fd); return "bad-address"; }
    len = sizeof *v6;
  }

  errno = 0;
  int rc = connect(fd, (struct sockaddr *) &addr, len);
  int err = errno;
  close(fd);

  if (rc == 0) return "allowed";
  if (err == EACCES) return "denied";
  snprintf(buf, sizeof buf, "errno:%d", err);
  return buf;
}

/* Resolves a host without naming a service, which is the lookup an ordinary
   client performs before it decides which port to use. */
static int resolve_without_service(const char *host, int family) {
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = family;
  hints.ai_socktype = SOCK_STREAM;
  int rc = getaddrinfo(host, NULL, &hints, &res);
  if (rc == 0) freeaddrinfo(res);
  return rc;
}

static void write_rules(const char *path, const char *body) {
  FILE *f = fopen(path, "w");
  if (!f) { perror("rules"); exit(2); }
  fputs(body, f);
  fclose(f);
}

/* ------------------------- phase one ------------------------- */

static int phase_one(const char *self, const char *scenario) {
  const char *rules = getenv("PROBE_RULES");
  const char *lib = getenv("PROBE_LIB");
  if (!rules || !lib) {
    fprintf(stderr, "PROBE_RULES and PROBE_LIB must be set\n");
    return 2;
  }

  struct listener v4[PORTS_V4];
  for (int i = 0; i < PORTS_V4; i++) {
    if (listen_ephemeral(AF_INET, &v4[i]) != 0) {
      fprintf(stderr, "cannot bind an IPv4 loopback listener\n");
      return 3;
    }
  }

  struct listener v6[PORTS_V6];
  int have_v6 = 1;
  for (int i = 0; i < PORTS_V6; i++) {
    if (listen_ephemeral(AF_INET6, &v6[i]) != 0) { have_v6 = 0; break; }
  }

  char body[512];
  if (!strcmp(scenario, "port_specific") || !strcmp(scenario, "no_lookup")) {
    snprintf(body, sizeof body, "localhost %u\n", v4[0].port);
  } else if (!strcmp(scenario, "multi_port")) {
    snprintf(body, sizeof body, "localhost %u\nlocalhost %u\n", v4[0].port, v4[1].port);
  } else if (!strcmp(scenario, "any_port")) {
    snprintf(body, sizeof body, "localhost\n");
  } else if (!strcmp(scenario, "literal_ip")) {
    snprintf(body, sizeof body, "127.0.0.1 %u\n", v4[0].port);
  } else if (!strcmp(scenario, "literal_ip_any")) {
    snprintf(body, sizeof body, "127.0.0.1 *\n");
  } else if (!strcmp(scenario, "ipv6")) {
    if (!have_v6) { printf("ipv6=unavailable\n"); return 0; }
    snprintf(body, sizeof body, "localhost %u\n", v6[0].port);
  } else {
    fprintf(stderr, "unknown scenario: %s\n", scenario);
    return 2;
  }
  write_rules(rules, body);

  char args[1 + PORTS_V4 + PORTS_V6][16];
  char *argv[4 + PORTS_V4 + PORTS_V6];
  int n = 0;
  argv[n++] = (char *) self;
  argv[n++] = "child";
  argv[n++] = (char *) scenario;
  for (int i = 0; i < PORTS_V4; i++) {
    snprintf(args[i], sizeof args[i], "%u", v4[i].port);
    argv[n++] = args[i];
  }
  for (int i = 0; i < PORTS_V6; i++) {
    snprintf(args[PORTS_V4 + i], sizeof args[PORTS_V4 + i], "%u", have_v6 ? v6[i].port : 0);
    argv[n++] = args[PORTS_V4 + i];
  }
  argv[n] = NULL;

  setenv("NETBLOCKER_CONF", rules, 1);
  setenv("LD_PRELOAD", lib, 1);
  execv(self, argv);
  perror("execv");
  return 4;
}

/* ------------------------- phase two ------------------------- */

static int phase_two(int argc, char **argv) {
  if (argc < 3 + PORTS_V4 + PORTS_V6) {
    fprintf(stderr, "child invoked without the expected ports\n");
    return 2;
  }
  const char *scenario = argv[2];
  unsigned short v4[PORTS_V4];
  unsigned short v6[PORTS_V6];
  for (int i = 0; i < PORTS_V4; i++) v4[i] = (unsigned short) atoi(argv[3 + i]);
  for (int i = 0; i < PORTS_V6; i++) v6[i] = (unsigned short) atoi(argv[3 + PORTS_V4 + i]);

  if (!strcmp(scenario, "port_specific")) {
    printf("resolve=%s\n", resolve_without_service("localhost", AF_INET) == 0 ? "ok" : "failed");
    printf("permitted_port=%s\n", connect_result(AF_INET, "127.0.0.1", v4[0]));
    printf("other_port=%s\n", connect_result(AF_INET, "127.0.0.1", v4[1]));
  } else if (!strcmp(scenario, "no_lookup")) {
    /* No lookup happens first, so nothing may authorise this address. */
    printf("without_lookup=%s\n", connect_result(AF_INET, "127.0.0.1", v4[0]));
  } else if (!strcmp(scenario, "multi_port")) {
    printf("resolve=%s\n", resolve_without_service("localhost", AF_INET) == 0 ? "ok" : "failed");
    printf("first_port=%s\n", connect_result(AF_INET, "127.0.0.1", v4[0]));
    printf("second_port=%s\n", connect_result(AF_INET, "127.0.0.1", v4[1]));
    printf("third_port=%s\n", connect_result(AF_INET, "127.0.0.1", v4[2]));
  } else if (!strcmp(scenario, "any_port")) {
    printf("resolve=%s\n", resolve_without_service("localhost", AF_INET) == 0 ? "ok" : "failed");
    printf("first_port=%s\n", connect_result(AF_INET, "127.0.0.1", v4[0]));
    printf("second_port=%s\n", connect_result(AF_INET, "127.0.0.1", v4[1]));
    printf("third_port=%s\n", connect_result(AF_INET, "127.0.0.1", v4[2]));
  } else if (!strcmp(scenario, "literal_ip")) {
    printf("permitted_port=%s\n", connect_result(AF_INET, "127.0.0.1", v4[0]));
    printf("other_port=%s\n", connect_result(AF_INET, "127.0.0.1", v4[1]));
  } else if (!strcmp(scenario, "literal_ip_any")) {
    printf("first_port=%s\n", connect_result(AF_INET, "127.0.0.1", v4[0]));
    printf("second_port=%s\n", connect_result(AF_INET, "127.0.0.1", v4[1]));
  } else if (!strcmp(scenario, "ipv6")) {
    printf("resolve=%s\n", resolve_without_service("localhost", AF_INET6) == 0 ? "ok" : "failed");
    printf("permitted_port=%s\n", connect_result(AF_INET6, "::1", v6[0]));
    printf("other_port=%s\n", connect_result(AF_INET6, "::1", v6[1]));
  } else {
    fprintf(stderr, "unknown scenario: %s\n", scenario);
    return 2;
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <scenario>\n", argv[0]);
    return 2;
  }
  if (!strcmp(argv[1], "child")) return phase_two(argc, argv);
  return phase_one(argv[0], argv[1]);
}
