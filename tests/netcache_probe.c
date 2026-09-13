/* Probe client for the network interposer's address cache and rules file.
 *
 * The first phase binds listening sockets on ephemeral loopback ports, writes
 * the rule file naming those ports into a directory of its own, and re-executes
 * itself with the interposer preloaded. Listening descriptors survive the exec,
 * so the ports stay reserved and every probe below talks only to this process:
 * no external service is contacted and no port number is hard-coded.
 *
 * The rules directory is created with mkdtemp and the rules file inside it
 * exclusively and readable by its owner only, so nothing else can place or read
 * a file there. Its path goes to the second phase as an argument, and the second
 * phase removes the directory once its scenario has run.
 *
 * The second phase runs one scenario and prints a "key=value" line per probe.
 * A connection prints "allowed" when it completes, "denied" when the
 * interposer refuses it with EACCES, and "errno:<n>" for anything else, so a
 * refusal can never be confused with an unrelated failure.
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define PORTS_V4 3
#define PORTS_V6 2

/* The fixed part of the rules directory's name; mkdtemp fills in the rest. */
static const char RULES_DIRECTORY_TEMPLATE[] = "/tmp/phobos-netcache-probe.XXXXXX";

/* The names a scenario may create inside the rules directory. */
static const char RULES_NAME[] = "rules";
static const char LINK_NAME[] = "link";
static const char FIFO_NAME[] = "fifo";
static const char DIRECTORY_NAME[] = "directory";

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
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = family;
  hints.ai_socktype = SOCK_STREAM;
  int rc = getaddrinfo(host, NULL, &hints, &res);
  if (rc == 0) freeaddrinfo(res);
  return rc;
}

/* Reports how SIGHUP is handled in this process: left at the default, ignored,
   or caught by a handler somebody installed. */
static const char *hangup_disposition(void) {
  struct sigaction current;
  if (sigaction(SIGHUP, NULL, &current) != 0) return "unknown";
  if (current.sa_handler == SIG_DFL) return "default";
  if (current.sa_handler == SIG_IGN) return "ignored";
  return "handled";
}

/* Writes the rules into the file of that name inside the rules directory. The
   file is created exclusively, readable by its owner only, and a link planted in
   its place is not followed. With keep_writable, a second descriptor stays open
   across the exec, so that a scenario can rewrite the rules without opening a
   path; it is stored in write_fd, which is -1 otherwise. */
static int write_rules(const char *directory, const char *body, int keep_writable, int *write_fd) {
  char path[PATH_MAX];
  *write_fd = -1;
  snprintf(path, sizeof path, "%s/%s", directory, RULES_NAME);
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) { perror("rules"); return -1; }
  FILE *f = fdopen(fd, "w");
  if (!f) { perror("rules"); close(fd); return -1; }
  int written = fputs(body, f) != EOF;
  int closed = fclose(f) == 0;
  if (!written || !closed) { perror("rules"); return -1; }
  if (keep_writable) {
    *write_fd = open(path, O_WRONLY | O_NOFOLLOW);
    if (*write_fd < 0) { perror("rules"); return -1; }
  }
  return 0;
}

/* Puts in place the name NETBLOCKER_CONF points at when a scenario wants
   something other than the rules file itself: a symbolic link to it, a
   directory, or a FIFO that nothing ever writes to. */
static int create_entry(const char *directory, const char *entry) {
  char path[PATH_MAX];
  snprintf(path, sizeof path, "%s/%s", directory, entry);
  if (!strcmp(entry, LINK_NAME)) return symlink(RULES_NAME, path);
  if (!strcmp(entry, DIRECTORY_NAME)) return mkdir(path, 0700);
  if (!strcmp(entry, FIFO_NAME)) return mkfifo(path, 0600);
  return 0;
}

/* Removes everything a scenario may have created, then the rules directory.
   Any of the names may be absent, since a scenario creates at most one besides
   the rules file. */
static void remove_rules_directory(const char *directory) {
  static const char *const files[] = { RULES_NAME, LINK_NAME, FIFO_NAME };
  char path[PATH_MAX];
  for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
    snprintf(path, sizeof path, "%s/%s", directory, files[i]);
    unlink(path);
  }
  snprintf(path, sizeof path, "%s/%s", directory, DIRECTORY_NAME);
  rmdir(path);
  rmdir(directory);
}

/* Replaces the rules through a descriptor the first phase left open. */
static const char *rewrite_rules(int fd, const char *body) {
  size_t length = strlen(body);
  if (fd < 0) return "no-descriptor";
  if (ftruncate(fd, 0) != 0) return "failed";
  if (pwrite(fd, body, length, 0) != (ssize_t) length) return "failed";
  return "ok";
}

/* ------------------------- phase one ------------------------- */

static int phase_one(const char *self, const char *scenario) {
  const char *lib = getenv("PROBE_LIB");
  if (!lib) {
    fprintf(stderr, "PROBE_LIB must be set\n");
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
  const char *entry = RULES_NAME;
  int ignore_hangup = 0;
  int keep_writable = 0;
  if (!strcmp(scenario, "port_specific") || !strcmp(scenario, "no_lookup")) {
    snprintf(body, sizeof body, "localhost %u\n", v4[0].port);
  } else if (!strcmp(scenario, "multi_port")) {
    snprintf(body, sizeof body, "localhost %u\nlocalhost %u\n", v4[0].port, v4[1].port);
  } else if (!strcmp(scenario, "any_port")) {
    snprintf(body, sizeof body, "localhost\n");
  } else if (!strcmp(scenario, "literal_ip") || !strcmp(scenario, "sighup_default")) {
    snprintf(body, sizeof body, "127.0.0.1 %u\n", v4[0].port);
  } else if (!strcmp(scenario, "literal_ip_any")) {
    snprintf(body, sizeof body, "127.0.0.1 *\n");
  } else if (!strcmp(scenario, "ipv6")) {
    if (!have_v6) { printf("ipv6=unavailable\n"); return 0; }
    snprintf(body, sizeof body, "localhost %u\n", v6[0].port);
  } else if (!strcmp(scenario, "rules_symlink")) {
    snprintf(body, sizeof body, "127.0.0.1 %u\n", v4[0].port);
    entry = LINK_NAME;
  } else if (!strcmp(scenario, "rules_directory")) {
    snprintf(body, sizeof body, "127.0.0.1 %u\n", v4[0].port);
    entry = DIRECTORY_NAME;
  } else if (!strcmp(scenario, "rules_fifo")) {
    snprintf(body, sizeof body, "127.0.0.1 %u\n", v4[0].port);
    entry = FIFO_NAME;
  } else if (!strcmp(scenario, "sighup_ignored")) {
    snprintf(body, sizeof body, "127.0.0.1 %u\n", v4[0].port);
    ignore_hangup = 1;
  } else if (!strcmp(scenario, "sighup_no_reload")) {
    snprintf(body, sizeof body, "127.0.0.1 %u\n", v4[0].port);
    ignore_hangup = 1;
    keep_writable = 1;
  } else if (!strcmp(scenario, "range_ipv4")) {
    snprintf(body, sizeof body, "127.0.0.0/8\n");
  } else if (!strcmp(scenario, "range_other_ipv4")) {
    snprintf(body, sizeof body, "10.0.0.0/8\n");
  } else if (!strcmp(scenario, "range_single_ipv4")) {
    snprintf(body, sizeof body, "127.0.0.1/32\n");
  } else if (!strcmp(scenario, "range_ipv4_too_long")) {
    snprintf(body, sizeof body, "127.0.0.0/33\n");
  } else if (!strcmp(scenario, "range_ipv4_against_ipv6")) {
    if (!have_v6) { printf("ipv6=unavailable\n"); return 0; }
    snprintf(body, sizeof body, "127.0.0.0/8\n");
  } else if (!strcmp(scenario, "range_ipv6")) {
    if (!have_v6) { printf("ipv6=unavailable\n"); return 0; }
    snprintf(body, sizeof body, "::1/128\n");
  } else if (!strcmp(scenario, "range_mapped_ipv4")) {
    snprintf(body, sizeof body, "::ffff:127.0.0.0/104\n");
  } else if (!strcmp(scenario, "range_mapped_short")) {
    snprintf(body, sizeof body, "::ffff:127.0.0.0/8\n");
  } else {
    fprintf(stderr, "unknown scenario: %s\n", scenario);
    return 2;
  }

  char directory[sizeof RULES_DIRECTORY_TEMPLATE];
  memcpy(directory, RULES_DIRECTORY_TEMPLATE, sizeof directory);
  if (!mkdtemp(directory)) {
    perror("mkdtemp");
    return 2;
  }
  int write_fd = -1;
  if (write_rules(directory, body, keep_writable, &write_fd) != 0 || create_entry(directory, entry) != 0) {
    perror("rules directory");
    if (write_fd >= 0) close(write_fd);
    remove_rules_directory(directory);
    return 2;
  }

  char conf[PATH_MAX];
  char descriptor[16];
  char args[PORTS_V4 + PORTS_V6][16];
  char *argv[6 + PORTS_V4 + PORTS_V6];
  int n = 0;
  snprintf(conf, sizeof conf, "%s/%s", directory, entry);
  snprintf(descriptor, sizeof descriptor, "%d", write_fd);
  argv[n++] = (char *) self;
  argv[n++] = "child";
  argv[n++] = (char *) scenario;
  argv[n++] = directory;
  argv[n++] = descriptor;
  for (int i = 0; i < PORTS_V4; i++) {
    snprintf(args[i], sizeof args[i], "%u", v4[i].port);
    argv[n++] = args[i];
  }
  for (int i = 0; i < PORTS_V6; i++) {
    snprintf(args[PORTS_V4 + i], sizeof args[PORTS_V4 + i], "%u",
             (unsigned int) (have_v6 ? v6[i].port : 0));
    argv[n++] = args[PORTS_V4 + i];
  }
  argv[n] = NULL;

  if (ignore_hangup) signal(SIGHUP, SIG_IGN);
  setenv("NETBLOCKER_CONF", conf, 1);
  setenv("LD_PRELOAD", lib, 1);
  execv(self, argv);
  perror("execv");
  remove_rules_directory(directory);
  return 4;
}

/* ------------------------- phase two ------------------------- */

static int run_scenario(const char *scenario, int write_fd, const unsigned short *v4, const unsigned short *v6) {
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
  } else if (!strcmp(scenario, "rules_symlink") || !strcmp(scenario, "rules_directory")
             || !strcmp(scenario, "rules_fifo")) {
    printf("permitted_port=%s\n", connect_result(AF_INET, "127.0.0.1", v4[0]));
  } else if (!strcmp(scenario, "sighup_default") || !strcmp(scenario, "sighup_ignored")) {
    printf("sighup=%s\n", hangup_disposition());
  } else if (!strcmp(scenario, "sighup_no_reload")) {
    printf("before_rewrite=%s\n", connect_result(AF_INET, "127.0.0.1", v4[1]));
    printf("rewrite=%s\n", rewrite_rules(write_fd, "127.0.0.1 *\n"));
    raise(SIGHUP);
    printf("after_hangup=%s\n", connect_result(AF_INET, "127.0.0.1", v4[1]));
  } else if (!strcmp(scenario, "range_ipv4") || !strcmp(scenario, "range_mapped_ipv4")) {
    printf("inside=%s\n", connect_result(AF_INET, "127.0.0.1", v4[0]));
  } else if (!strcmp(scenario, "range_other_ipv4") || !strcmp(scenario, "range_ipv4_too_long")
             || !strcmp(scenario, "range_mapped_short")) {
    printf("loopback=%s\n", connect_result(AF_INET, "127.0.0.1", v4[0]));
  } else if (!strcmp(scenario, "range_single_ipv4")) {
    printf("host=%s\n", connect_result(AF_INET, "127.0.0.1", v4[0]));
    printf("neighbour=%s\n", connect_result(AF_INET, "127.0.0.2", v4[0]));
  } else if (!strcmp(scenario, "range_ipv4_against_ipv6")) {
    printf("ipv6_loopback=%s\n", connect_result(AF_INET6, "::1", v6[0]));
  } else if (!strcmp(scenario, "range_ipv6")) {
    printf("ipv6_loopback=%s\n", connect_result(AF_INET6, "::1", v6[0]));
    printf("ipv4_loopback=%s\n", connect_result(AF_INET, "127.0.0.1", v4[0]));
  } else {
    fprintf(stderr, "unknown scenario: %s\n", scenario);
    return 2;
  }
  return 0;
}

static int phase_two(int argc, char **argv) {
  if (argc < 5 + PORTS_V4 + PORTS_V6) {
    fprintf(stderr, "child invoked without the expected arguments\n");
    return 2;
  }
  const char *scenario = argv[2];
  const char *directory = argv[3];
  int write_fd = atoi(argv[4]);
  unsigned short v4[PORTS_V4];
  unsigned short v6[PORTS_V6];
  for (int i = 0; i < PORTS_V4; i++) v4[i] = (unsigned short) atoi(argv[5 + i]);
  for (int i = 0; i < PORTS_V6; i++) v6[i] = (unsigned short) atoi(argv[5 + PORTS_V4 + i]);

  int status = run_scenario(scenario, write_fd, v4, v6);
  fflush(stdout);
  remove_rules_directory(directory);
  return status;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <scenario>\n", argv[0]);
    return 2;
  }
  if (!strcmp(argv[1], "child")) return phase_two(argc, argv);
  return phase_one(argv[0], argv[1]);
}
