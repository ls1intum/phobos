/*
 * The second probe of the protection matrix: the operations the first one, probe.c, does not make. It is built
 * and used the same way: one subcommand per operation, START first, then one "OP <name> ret=<n> errno=<NAME>"
 * line for what was attempted, and the exit status 0 when it worked, 10 when it did not, 11 for a setup failure
 * and 2 for a call that was wrong. It is a test tool, never shipped, and every loop in it is capped.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

enum { STATUS_OK = 0, STATUS_USAGE = 2, STATUS_FAILED = 10, STATUS_SETUP = 11 };
enum { DUP_CAP = 20000, THREAD_CAP = 3000, CHAIN_CAP = 400, ZOMBIE_CAP = 2000, ATTEMPT_CAP = 20000, BUFFER = 4096 };

static int last_ret = 0;

static const char *errno_name(int number) {
    switch (number) {
    case 0: return "0";
    case EPERM: return "EPERM";
    case ENOENT: return "ENOENT";
    case EACCES: return "EACCES";
    case EEXIST: return "EEXIST";
    case EXDEV: return "EXDEV";
    case ENOTDIR: return "ENOTDIR";
    case EISDIR: return "EISDIR";
    case EINVAL: return "EINVAL";
    case EMFILE: return "EMFILE";
    case ENFILE: return "ENFILE";
    case EAGAIN: return "EAGAIN";
    case ENOMEM: return "ENOMEM";
    case EFBIG: return "EFBIG";
    case EBADF: return "EBADF";
    case ENOSYS: return "ENOSYS";
    case ECONNREFUSED: return "ECONNREFUSED";
    case EAFNOSUPPORT: return "EAFNOSUPPORT";
    case EPROTONOSUPPORT: return "EPROTONOSUPPORT";
    case ESOCKTNOSUPPORT: return "ESOCKTNOSUPPORT";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    case EINPROGRESS: return "EINPROGRESS";
    case ENODATA: return "ENODATA";
    case ELOOP: return "ELOOP";
    case ENOTEMPTY: return "ENOTEMPTY";
    case ENETUNREACH: return "ENETUNREACH";
    case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
    case EFAULT: return "EFAULT";
    case ESRCH: return "ESRCH";
    case ENOSPC: return "ENOSPC";
    case ERANGE: return "ERANGE";
    case EOVERFLOW: return "EOVERFLOW";
    default: return "EOTHER";
    }
}

static void op(const char *name, long ret, const char *detail) {
    int saved = errno;
    printf("OP %s ret=%ld errno=%s%s%s\n", name, ret, ret < 0 ? errno_name(saved) : "0", detail ? " " : "",
           detail ? detail : "");
    fflush(stdout);
    last_ret = ret < 0 ? -1 : 0;
    errno = saved;
}

static int finish(void) {
    return last_ret < 0 ? STATUS_FAILED : STATUS_OK;
}

static int setup_fail(const char *what) {
    printf("SETUP-FAIL %s errno=%s\n", what, errno_name(errno));
    fflush(stdout);
    return STATUS_SETUP;
}

static long arg_long(const char *text) {
    return strtol(text, NULL, 0);
}

static void address_of(struct sockaddr_in *address, const char *host, int port) {
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, host, &address->sin_addr);
}

/* ------------------------------------------------------------- sockets */

/* sock DOMAIN TYPE PROTOCOL: whether a socket of that kind can be made at all. */
static int cmd_sock(int argc, char **argv) {
    if (argc < 5) {
        return STATUS_USAGE;
    }
    int descriptor = socket((int)arg_long(argv[2]), (int)arg_long(argv[3]), (int)arg_long(argv[4]));
    op("socket", descriptor, argv[2]);
    return finish();
}

/* tcp_nb IP PORT: a non-blocking connect, then what the socket says once it is writable. */
static int cmd_tcp_nb(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (descriptor < 0) {
        return setup_fail("socket");
    }
    struct sockaddr_in address;
    address_of(&address, argv[2], (int)arg_long(argv[3]));
    int result = connect(descriptor, (struct sockaddr *)&address, sizeof(address));
    op("connect_nb", result, NULL);
    if (result < 0 && errno != EINPROGRESS) {
        return finish();
    }
    struct pollfd waiting = { .fd = descriptor, .events = POLLOUT };
    int ready = poll(&waiting, 1, 3000);
    int error = -1;
    socklen_t length = sizeof(error);
    getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &length);
    printf("NB ready=%d so_error=%s\n", ready, errno_name(error));
    fflush(stdout);
    last_ret = (ready > 0 && error == 0) ? 0 : -1;
    return finish();
}

/* connect_unspec: a connect whose address family is AF_UNSPEC, which disconnects a datagram socket. */
static int cmd_connect_unspec(void) {
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr address;
    memset(&address, 0, sizeof(address));
    address.sa_family = AF_UNSPEC;
    int result = connect(descriptor, &address, sizeof(address));
    op("connect_unspec", result, NULL);
    return finish();
}

/* connect_len IP PORT LENGTH: a connect handed an address length other than the structure's own. */
static int cmd_connect_len(int argc, char **argv) {
    if (argc < 5) {
        return STATUS_USAGE;
    }
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    union {
        struct sockaddr_in inet;
        unsigned char bytes[64];
    } storage;
    memset(&storage, 0, sizeof(storage));
    address_of(&storage.inet, argv[2], (int)arg_long(argv[3]));
    int result = connect(descriptor, (struct sockaddr *)&storage, (socklen_t)arg_long(argv[4]));
    op("connect_len", result, NULL);
    return finish();
}

static atomic_int race_over;
static struct sockaddr_in race_destination;
static in_addr_t race_allowed;
static in_addr_t race_forbidden;

static void *race_flip(void *unused) {
    (void)unused;
    while (!atomic_load(&race_over)) {
        *(volatile in_addr_t *)&race_destination.sin_addr.s_addr = race_forbidden;
        *(volatile in_addr_t *)&race_destination.sin_addr.s_addr = race_allowed;
    }
    return NULL;
}

/* tcp_race ALLOWED FORBIDDEN PORT ATTEMPTS: connects while a second thread rewrites the destination address in
 * memory, and sends a tag on every connection that is made. Prints how many connects were refused and how many
 * went through; the servers outside count who received the tag. */
static int cmd_tcp_race(int argc, char **argv) {
    if (argc < 6) {
        return STATUS_USAGE;
    }
    race_allowed = inet_addr(argv[2]);
    race_forbidden = inet_addr(argv[3]);
    int port = (int)arg_long(argv[4]);
    int attempts = (int)arg_long(argv[5]);
    if (attempts > ATTEMPT_CAP) {
        attempts = ATTEMPT_CAP;
    }
    memset(&race_destination, 0, sizeof(race_destination));
    race_destination.sin_family = AF_INET;
    race_destination.sin_port = htons((unsigned short)port);
    race_destination.sin_addr.s_addr = race_allowed;
    pthread_t thread;
    if (pthread_create(&thread, NULL, race_flip, NULL) != 0) {
        return setup_fail("thread");
    }
    int refused = 0;
    int connected = 0;
    for (int attempt = 0; attempt < attempts; attempt++) {
        int descriptor = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(descriptor, (struct sockaddr *)&race_destination, sizeof(race_destination)) == 0) {
            connected++;
            if (send(descriptor, "RACE", 4, MSG_NOSIGNAL) < 0) {
                refused++;
            }
        } else {
            refused++;
        }
        close(descriptor);
    }
    atomic_store(&race_over, 1);
    pthread_join(thread, NULL);
    printf("RACE attempts=%d refused=%d connected=%d\n", attempts, refused, connected);
    return STATUS_OK;
}

/* ---------------------------------------------------------------- files */

static int open_flags_for(const char *mode) {
    if (strcmp(mode, "w") == 0) {
        return O_WRONLY;
    }
    if (strcmp(mode, "rw") == 0) {
        return O_RDWR;
    }
    if (strcmp(mode, "path") == 0) {
        return O_PATH;
    }
    return O_RDONLY;
}

/* openat2 PATH MODE RESOLVE: the newer open call, with the RESOLVE_* flags given in hexadecimal. */
static int cmd_openat2(int argc, char **argv) {
    if (argc < 5) {
        return STATUS_USAGE;
    }
    struct open_how how;
    memset(&how, 0, sizeof(how));
    how.flags = (unsigned long long)open_flags_for(argv[3]);
    how.resolve = (unsigned long long)arg_long(argv[4]);
    long descriptor = syscall(SYS_openat2, AT_FDCWD, argv[2], &how, sizeof(how));
    op("openat2", descriptor, argv[2]);
    if (descriptor >= 0) {
        char buffer[BUFFER];
        ssize_t got = read((int)descriptor, buffer, sizeof(buffer) - 1);
        if (got > 0) {
            buffer[got] = '\0';
            printf("CONTENT %s", buffer);
        }
    }
    return finish();
}

/* otmpfile DIR: an unnamed file in a directory, which counts as creating a regular file there. */
static int cmd_otmpfile(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    int descriptor = open(argv[2], O_TMPFILE | O_WRONLY, 0600);
    op("otmpfile", descriptor, argv[2]);
    return finish();
}

static int cmd_getxattr(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    char buffer[BUFFER];
    ssize_t got = getxattr(argv[2], "user.phobos", buffer, sizeof(buffer));
    op("getxattr", got < 0 && errno == ENODATA ? 0 : got, argv[2]);
    return finish();
}

static int cmd_listxattr(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    char buffer[BUFFER];
    ssize_t got = listxattr(argv[2], buffer, sizeof(buffer));
    op("listxattr", got, argv[2]);
    return finish();
}

static int cmd_readlink(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    char buffer[BUFFER];
    ssize_t got = readlink(argv[2], buffer, sizeof(buffer) - 1);
    op("readlink", got, argv[2]);
    if (got >= 0) {
        buffer[got] = '\0';
        printf("TARGET %s\n", buffer);
    }
    return finish();
}

static int cmd_lstat(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    struct stat information;
    int result = lstat(argv[2], &information);
    op("lstat", result, argv[2]);
    return finish();
}

static int cmd_statx(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    struct statx information;
    long result = syscall(SYS_statx, AT_FDCWD, argv[2], 0, STATX_BASIC_STATS, &information);
    op("statx", result, argv[2]);
    return finish();
}

/* inotify PATH: a watch on a path, which reports changes to it without opening it. */
static int cmd_inotify(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    int instance = inotify_init1(IN_NONBLOCK);
    if (instance < 0) {
        return setup_fail("inotify_init");
    }
    int watch = inotify_add_watch(instance, argv[2], IN_ALL_EVENTS);
    op("inotify_add_watch", watch, argv[2]);
    return finish();
}

/* fdcopy MODE FD DESTINATION: copies a descriptor the process already holds. MODE is sendfile, splice,
 * copy_file_range or mmap; the first three write to the destination, which must be a path the policy lets the
 * command create, and mmap prints what it mapped. */
static int cmd_fdcopy(int argc, char **argv) {
    if (argc < 5) {
        return STATUS_USAGE;
    }
    int source = (int)arg_long(argv[3]);
    const char *mode = argv[2];
    if (strcmp(mode, "mmap") == 0) {
        void *mapped = mmap(NULL, 16, PROT_READ, MAP_PRIVATE, source, 0);
        op("mmap_fd", mapped == MAP_FAILED ? -1 : 0, NULL);
        if (mapped != MAP_FAILED) {
            printf("MAPPED %.10s\n", (const char *)mapped);
        }
        return finish();
    }
    int destination = open(argv[4], O_WRONLY | O_CREAT | O_TRUNC, 0600);
    op("open_destination", destination, argv[4]);
    if (destination < 0) {
        return finish();
    }
    long copied;
    if (strcmp(mode, "sendfile") == 0) {
        copied = sendfile(destination, source, NULL, 16);
    } else if (strcmp(mode, "copy_file_range") == 0) {
        copied = copy_file_range(source, NULL, destination, NULL, 16, 0);
    } else {
        int channel[2];
        if (pipe(channel) != 0) {
            return setup_fail("pipe");
        }
        copied = splice(source, NULL, channel[1], NULL, 16, 0);
        if (copied > 0) {
            copied = splice(channel[0], NULL, destination, NULL, (size_t)copied, 0);
        }
    }
    op(mode, copied, NULL);
    return finish();
}

/* fallocate PATH MEGABYTES */
static int cmd_fallocate(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int descriptor = open(argv[2], O_WRONLY | O_CREAT, 0600);
    op("open", descriptor, argv[2]);
    if (descriptor < 0) {
        return finish();
    }
    signal(SIGXFSZ, SIG_IGN);
    int result = posix_fallocate(descriptor, 0, (off_t)arg_long(argv[3]) * 1024 * 1024);
    errno = result;
    op("fallocate", result == 0 ? 0 : -1, NULL);
    return finish();
}

/* ftruncate_size PATH MEGABYTES [ignore]: growing a file past the file-size limit. Without "ignore" the signal
 * the kernel sends ends the process, which is what a command meets. */
static int cmd_ftruncate_size(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int descriptor = open(argv[2], O_WRONLY | O_CREAT, 0600);
    op("open", descriptor, argv[2]);
    if (descriptor < 0) {
        return finish();
    }
    if (argc > 4 && strcmp(argv[4], "ignore") == 0) {
        signal(SIGXFSZ, SIG_IGN);
    }
    int result = ftruncate(descriptor, (off_t)arg_long(argv[3]) * 1024 * 1024);
    op("ftruncate_size", result, NULL);
    return finish();
}

/* dirfd_open DIRECTORY NAME: a directory opened as a path descriptor, then a file opened relative to it. */
static int cmd_dirfd_open(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int directory = open(argv[2], O_PATH | O_DIRECTORY);
    op("open_dir", directory, argv[2]);
    if (directory < 0) {
        return finish();
    }
    int descriptor = openat(directory, argv[3], O_RDONLY);
    op("openat_relative", descriptor, argv[3]);
    if (descriptor >= 0) {
        char buffer[BUFFER];
        ssize_t got = read(descriptor, buffer, sizeof(buffer) - 1);
        if (got > 0) {
            buffer[got] = '\0';
            printf("CONTENT %s", buffer);
        }
    }
    return finish();
}

/* chdir_open DIRECTORY NAME: the same through the working directory. */
static int cmd_chdir_open(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int moved = chdir(argv[2]);
    op("chdir", moved, argv[2]);
    if (moved < 0) {
        return finish();
    }
    int descriptor = open(argv[3], O_RDONLY);
    op("open_relative", descriptor, argv[3]);
    return finish();
}

static const char *race_link;
static const char *race_first;
static const char *race_second;
static char race_temporary[BUFFER];

static atomic_int installed_first;
static atomic_int installed_second;

static void point_link_at(const char *target, atomic_int *counter) {
    unlink(race_temporary);
    if (symlink(target, race_temporary) == 0 && rename(race_temporary, race_link) == 0) {
        atomic_fetch_add(counter, 1);
    }
}

static void *swap_links(void *unused) {
    (void)unused;
    while (!atomic_load(&race_over)) {
        point_link_at(race_first, &installed_first);
        point_link_at(race_second, &installed_second);
    }
    return NULL;
}

/* open_race LINK ALLOWED FORBIDDEN ATTEMPTS: a second thread points the symbolic link LINK at ALLOWED and at
 * FORBIDDEN in turn, by making a new link beside it and renaming that over it, while the first thread opens LINK
 * and reads it. Prints how many reads returned the forbidden file's content, which starts with TOP-SECRET. */
static int cmd_open_race(int argc, char **argv) {
    if (argc < 6) {
        return STATUS_USAGE;
    }
    race_link = argv[2];
    race_first = argv[3];
    race_second = argv[4];
    snprintf(race_temporary, sizeof(race_temporary), "%s.tmp", argv[2]);
    int attempts = (int)arg_long(argv[5]);
    if (attempts > ATTEMPT_CAP) {
        attempts = ATTEMPT_CAP;
    }
    point_link_at(race_first, &installed_first);
    pthread_t thread;
    if (pthread_create(&thread, NULL, swap_links, NULL) != 0) {
        return setup_fail("thread");
    }
    int denied = 0;
    int read_allowed = 0;
    int read_secret = 0;
    for (int attempt = 0; attempt < attempts; attempt++) {
        int descriptor = open(race_link, O_RDONLY);
        if (descriptor < 0) {
            denied++;
            continue;
        }
        char buffer[32];
        ssize_t got = read(descriptor, buffer, sizeof(buffer) - 1);
        if (got > 0) {
            buffer[got] = '\0';
            if (strncmp(buffer, "TOP-SECRET", 10) == 0) {
                read_secret++;
            } else {
                read_allowed++;
            }
        }
        close(descriptor);
    }
    atomic_store(&race_over, 1);
    pthread_join(thread, NULL);
    printf("OPENRACE attempts=%d denied=%d allowed=%d secret=%d installed_first=%d installed_second=%d\n", attempts, denied,
           read_allowed, read_secret, atomic_load(&installed_first), atomic_load(&installed_second));
    return STATUS_OK;
}

/* ------------------------------------------------------------ resources */

static int cmd_dup_until(void) {
    int count = 0;
    int last = -1;
    while (count < DUP_CAP) {
        last = dup(0);
        if (last < 0) {
            break;
        }
        count++;
    }
    int saved = errno;
    printf("DUPS %d of cap errno=%s\n", count, last < 0 ? errno_name(saved) : "0");
    fflush(stdout);
    return STATUS_OK;
}

static int cmd_pipe_until(void) {
    int count = 0;
    int channel[2];
    int result = 0;
    while (count < DUP_CAP / 2) {
        result = pipe(channel);
        if (result < 0) {
            break;
        }
        count++;
    }
    int saved = errno;
    printf("PIPES %d errno=%s\n", count, result < 0 ? errno_name(saved) : "0");
    fflush(stdout);
    return STATUS_OK;
}

static int cmd_socket_until(void) {
    int count = 0;
    int descriptor = 0;
    while (count < DUP_CAP) {
        descriptor = socket(AF_INET, SOCK_DGRAM, 0);
        if (descriptor < 0) {
            break;
        }
        count++;
    }
    int saved = errno;
    printf("SOCKETS %d errno=%s\n", count, descriptor < 0 ? errno_name(saved) : "0");
    fflush(stdout);
    return STATUS_OK;
}

static void *idle_thread(void *unused) {
    (void)unused;
    sleep(30);
    return NULL;
}

/* threads_until: starts threads that sleep until the system says no, and reports how many it made. */
static int cmd_threads_until(void) {
    int count = 0;
    int result = 0;
    pthread_attr_t attributes;
    pthread_attr_init(&attributes);
    pthread_attr_setstacksize(&attributes, 64 * 1024);
    pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    while (count < THREAD_CAP) {
        pthread_t thread;
        result = pthread_create(&thread, &attributes, idle_thread, NULL);
        if (result != 0) {
            break;
        }
        count++;
    }
    printf("THREADS %d errno=%s\n", count, result != 0 ? errno_name(result) : "0");
    fflush(stdout);
    _exit(STATUS_OK);
}

/* mmap_file PATH MEGABYTES: a file-backed mapping, which the address space limit counts as well. */
static int cmd_mmap_file(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int descriptor = open(argv[2], O_RDONLY);
    op("open", descriptor, argv[2]);
    if (descriptor < 0) {
        return finish();
    }
    size_t length = (size_t)arg_long(argv[3]) * 1024 * 1024;
    void *mapped = mmap(NULL, length, PROT_READ, MAP_PRIVATE, descriptor, 0);
    op("mmap_file", mapped == MAP_FAILED ? -1 : 0, NULL);
    return finish();
}

/* brk_grow MEGABYTES: moves the end of the data segment, which the address space limit counts too. */
static int cmd_brk_grow(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    void *result = sbrk((intptr_t)arg_long(argv[2]) * 1024 * 1024);
    op("brk", result == (void *)-1 ? -1 : 0, NULL);
    return finish();
}

static int cmd_getrlimit_all(void) {
    static const struct {
        int resource;
        const char *name;
    } limits[] = {
        { RLIMIT_CORE, "core" },
        { RLIMIT_DATA, "data" },
        { RLIMIT_STACK, "stack" },
        { RLIMIT_RSS, "rss" },
        { RLIMIT_MEMLOCK, "memlock" },
        { RLIMIT_SIGPENDING, "sigpending" },
        { RLIMIT_MSGQUEUE, "msgqueue" },
        { RLIMIT_LOCKS, "locks" },
        { RLIMIT_NICE, "nice" },
        { RLIMIT_RTPRIO, "rtprio" },
    };
    for (size_t index = 0; index < sizeof(limits) / sizeof(limits[0]); index++) {
        struct rlimit limit;
        getrlimit(limits[index].resource, &limit);
        printf("RLIMIT %s soft=%llu hard=%llu\n", limits[index].name,
               limit.rlim_cur == RLIM_INFINITY ? 0ULL : (unsigned long long)limit.rlim_cur,
               limit.rlim_max == RLIM_INFINITY ? 0ULL : (unsigned long long)limit.rlim_max);
    }
    return STATUS_OK;
}

/* ------------------------------------------------------------- processes */

/* chain DEPTH SECONDS: each process forks the next until DEPTH is reached, and the last one sleeps. The first
 * prints CHAIN-UP once the last has started. */
static int cmd_chain(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int depth = (int)arg_long(argv[2]);
    if (depth > CHAIN_CAP) {
        depth = CHAIN_CAP;
    }
    int channel[2];
    if (pipe(channel) != 0) {
        return setup_fail("pipe");
    }
    pid_t child = fork();
    if (child == 0) {
        for (int level = 1; level < depth; level++) {
            pid_t next = fork();
            if (next < 0) {
                _exit(1);
            }
            if (next > 0) {
                int status;
                waitpid(next, &status, 0);
                _exit(0);
            }
        }
        if (write(channel[1], "x", 1) < 0) {
            _exit(1);
        }
        sleep((unsigned)arg_long(argv[3]));
        _exit(0);
    }
    close(channel[1]);
    char byte;
    if (read(channel[0], &byte, 1) == 1) {
        puts("CHAIN-UP");
        fflush(stdout);
    }
    int status;
    waitpid(child, &status, 0);
    return STATUS_OK;
}

/* zombies COUNT SECONDS: children that exit at once and are never waited for, then a sleep. */
static int cmd_zombies(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int count = (int)arg_long(argv[2]);
    if (count > ZOMBIE_CAP) {
        count = ZOMBIE_CAP;
    }
    int made = 0;
    for (; made < count; made++) {
        pid_t child = fork();
        if (child < 0) {
            break;
        }
        if (child == 0) {
            _exit(0);
        }
    }
    printf("ZOMBIES %d\n", made);
    fflush(stdout);
    sleep((unsigned)arg_long(argv[3]));
    puts("ZOMBIES-DONE");
    return STATUS_OK;
}

static int cmd_ids(void) {
    printf("IDS pid=%d ppid=%d pgid=%d sid=%d uid=%d gid=%d\n", getpid(), getppid(), getpgrp(), getsid(0), getuid(),
           getgid());
    return STATUS_OK;
}

static int cmd_umask(void) {
    mode_t current = umask(0);
    umask(current);
    printf("UMASK %04o\n", (unsigned)current);
    return STATUS_OK;
}

static int cmd_fdstat(void) {
    for (int descriptor = 0; descriptor < 3; descriptor++) {
        struct stat information;
        if (fstat(descriptor, &information) != 0) {
            printf("FD %d closed\n", descriptor);
        } else {
            const char *kind = S_ISREG(information.st_mode)    ? "file"
                               : S_ISFIFO(information.st_mode) ? "pipe"
                               : S_ISCHR(information.st_mode)  ? "char"
                               : S_ISSOCK(information.st_mode) ? "socket"
                                                               : "other";
            printf("FD %d open %s\n", descriptor, kind);
        }
    }
    return STATUS_OK;
}

static int cmd_sigdisp(void) {
    sigset_t blocked;
    sigprocmask(SIG_BLOCK, NULL, &blocked);
    for (int number = 1; number < 32; number++) {
        struct sigaction action;
        if (sigaction(number, NULL, &action) != 0) {
            continue;
        }
        printf("SIG %d %s%s\n", number, action.sa_handler == SIG_IGN ? "ign" : "dfl",
               sigismember(&blocked, number) == 1 ? " blocked" : "");
    }
    return STATUS_OK;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: pedge <subcommand> ...\n");
        return STATUS_USAGE;
    }
    const char *name = argv[1];
    puts("START");
    fflush(stdout);
    struct {
        const char *name;
        int (*run)(int, char **);
    } with_arguments[] = {
        { "sock", cmd_sock },
        { "tcp_nb", cmd_tcp_nb },
        { "connect_len", cmd_connect_len },
        { "tcp_race", cmd_tcp_race },
        { "openat2", cmd_openat2 },
        { "otmpfile", cmd_otmpfile },
        { "getxattr", cmd_getxattr },
        { "listxattr", cmd_listxattr },
        { "readlink", cmd_readlink },
        { "lstat", cmd_lstat },
        { "statx", cmd_statx },
        { "inotify", cmd_inotify },
        { "fdcopy", cmd_fdcopy },
        { "fallocate", cmd_fallocate },
        { "ftruncate_size", cmd_ftruncate_size },
        { "dirfd_open", cmd_dirfd_open },
        { "chdir_open", cmd_chdir_open },
        { "open_race", cmd_open_race },
        { "mmap_file", cmd_mmap_file },
        { "brk_grow", cmd_brk_grow },
        { "chain", cmd_chain },
        { "zombies", cmd_zombies },
    };
    for (size_t index = 0; index < sizeof(with_arguments) / sizeof(with_arguments[0]); index++) {
        if (strcmp(name, with_arguments[index].name) == 0) {
            return with_arguments[index].run(argc, argv);
        }
    }
    if (strcmp(name, "connect_unspec") == 0) return cmd_connect_unspec();
    if (strcmp(name, "dup_until") == 0) return cmd_dup_until();
    if (strcmp(name, "pipe_until") == 0) return cmd_pipe_until();
    if (strcmp(name, "socket_until") == 0) return cmd_socket_until();
    if (strcmp(name, "threads_until") == 0) return cmd_threads_until();
    if (strcmp(name, "getrlimit_all") == 0) return cmd_getrlimit_all();
    if (strcmp(name, "ids") == 0) return cmd_ids();
    if (strcmp(name, "umask") == 0) return cmd_umask();
    if (strcmp(name, "fdstat") == 0) return cmd_fdstat();
    if (strcmp(name, "sigdisp") == 0) return cmd_sigdisp();
    fprintf(stderr, "unknown subcommand %s\n", name);
    return STATUS_USAGE;
}
