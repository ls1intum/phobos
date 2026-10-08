/*
 * pprobe: one small static program the protection matrix runs under phobos.sh, one subcommand per
 * attempted operation.
 *
 * Every subcommand prints START first, then one line per operation it attempted:
 *
 *   OP <name> ret=<return value> errno=<NAME or 0> [detail]
 *
 * and ends with the status 0 when its last operation succeeded and 10 when it failed. A subcommand
 * that cannot even set up what it needs prints SETUP-FAIL <what> and ends with 11, so the suites can
 * tell a refused operation from a probe that never reached it. The probe never decides what is right:
 * the suites read the OP lines.
 *
 * Every loop is capped inside the probe, so no case can exhaust the container whatever Phobos does.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

/* The statuses the probe ends with. */
enum { STATUS_OK = 0, STATUS_USAGE = 2, STATUS_FAILED = 10, STATUS_SETUP = 11 };
/* The caps that keep every loop bounded whatever the sandbox does. */
enum {
    FORK_CAP = 600,
    OPEN_CAP = 4000,
    ALLOC_CAP_MB = 20000,
    WRITE_CAP_MB = 600,
    SLEEP_CAP = 120,
    ATTEMPT_CAP = 50000,
    BUFFER = 65536
};

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
    case ENOSPC: return "ENOSPC";
    case EMFILE: return "EMFILE";
    case ENFILE: return "ENFILE";
    case EAGAIN: return "EAGAIN";
    case ENOMEM: return "ENOMEM";
    case EFBIG: return "EFBIG";
    case EBADF: return "EBADF";
    case ENOSYS: return "ENOSYS";
    case ECONNREFUSED: return "ECONNREFUSED";
    case ECONNRESET: return "ECONNRESET";
    case ECONNABORTED: return "ECONNABORTED";
    case EADDRINUSE: return "EADDRINUSE";
    case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
    case ENETUNREACH: return "ENETUNREACH";
    case EMSGSIZE: return "EMSGSIZE";
    case EDESTADDRREQ: return "EDESTADDRREQ";
    case EAFNOSUPPORT: return "EAFNOSUPPORT";
    case EPROTONOSUPPORT: return "EPROTONOSUPPORT";
    case ESOCKTNOSUPPORT: return "ESOCKTNOSUPPORT";
    case ENOTCONN: return "ENOTCONN";
    case EFAULT: return "EFAULT";
    case ESRCH: return "ESRCH";
    case ENOEXEC: return "ENOEXEC";
    case ELOOP: return "ELOOP";
    case ENOTEMPTY: return "ENOTEMPTY";
    case EROFS: return "EROFS";
    case EBUSY: return "EBUSY";
    case ENODEV: return "ENODEV";
    case ENOTTY: return "ENOTTY";
    case ETIMEDOUT: return "ETIMEDOUT";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    default: return "EOTHER";
    }
}

static int last_ret = 0;

/* Prints one OP line and remembers whether the operation worked. */
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
    return strtol(text, NULL, 10);
}

static void loopback_address(struct sockaddr_in *address, const char *host, int port) {
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, host, &address->sin_addr);
}

/* ---------------------------------------------------------------- files */

static int cmd_open(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    const char *mode = argv[3];
    int flags = O_RDONLY;
    if (strcmp(mode, "w") == 0) {
        flags = O_WRONLY;
    } else if (strcmp(mode, "a") == 0) {
        flags = O_WRONLY | O_APPEND;
    } else if (strcmp(mode, "rw") == 0) {
        flags = O_RDWR;
    } else if (strcmp(mode, "trunc") == 0) {
        flags = O_WRONLY | O_TRUNC;
    } else if (strcmp(mode, "excl") == 0) {
        flags = O_WRONLY | O_CREAT | O_EXCL;
    } else if (strcmp(mode, "creat") == 0) {
        flags = O_WRONLY | O_CREAT;
    } else if (strcmp(mode, "dir") == 0) {
        flags = O_RDONLY | O_DIRECTORY;
    }
    int descriptor = open(argv[2], flags, 0644);
    op("open", descriptor, argv[2]);
    if (descriptor >= 0) {
        close(descriptor);
    }
    return finish();
}

static int cmd_read(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    int descriptor = open(argv[2], O_RDONLY);
    op("open", descriptor, argv[2]);
    if (descriptor < 0) {
        return finish();
    }
    char buffer[256];
    ssize_t got = read(descriptor, buffer, sizeof(buffer) - 1);
    op("read", got, NULL);
    if (got >= 0) {
        buffer[got] = '\0';
        for (ssize_t index = 0; index < got; index++) {
            if (buffer[index] == '\n') {
                buffer[index] = '\0';
                break;
            }
        }
        printf("CONTENT %s\n", buffer);
    }
    close(descriptor);
    return finish();
}

static int cmd_write(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int descriptor = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    op("open", descriptor, argv[2]);
    if (descriptor < 0) {
        return finish();
    }
    ssize_t put = write(descriptor, argv[3], strlen(argv[3]));
    op("write", put, NULL);
    close(descriptor);
    return finish();
}

static int cmd_readdir(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    DIR *directory = opendir(argv[2]);
    op("opendir", directory ? 0 : -1, argv[2]);
    if (directory == NULL) {
        return finish();
    }
    int count = 0;
    while (readdir(directory) != NULL) {
        count++;
    }
    printf("ENTRIES %d\n", count);
    closedir(directory);
    return finish();
}

static int cmd_stat(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    struct stat information;
    int result = stat(argv[2], &information);
    op("stat", result, argv[2]);
    return finish();
}

static int cmd_truncate(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int result = truncate(argv[2], arg_long(argv[3]));
    op("truncate", result, argv[2]);
    return finish();
}

static int cmd_ftruncate(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int descriptor = open(argv[2], O_WRONLY);
    op("open", descriptor, argv[2]);
    if (descriptor < 0) {
        return finish();
    }
    int result = ftruncate(descriptor, arg_long(argv[3]));
    op("ftruncate", result, NULL);
    close(descriptor);
    return finish();
}

static int cmd_simple_path(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    const char *name = argv[1];
    const char *path = argv[2];
    int result;
    if (strcmp(name, "mkdir") == 0) {
        result = mkdir(path, 0755);
    } else if (strcmp(name, "rmdir") == 0) {
        result = rmdir(path);
    } else if (strcmp(name, "unlink") == 0) {
        result = unlink(path);
    } else if (strcmp(name, "mkfifo") == 0) {
        result = mkfifo(path, 0644);
    } else if (strcmp(name, "mknod_char") == 0) {
        result = mknod(path, S_IFCHR | 0600, makedev(1, 3));
    } else if (strcmp(name, "mknod_block") == 0) {
        result = mknod(path, S_IFBLK | 0600, makedev(7, 0));
    } else if (strcmp(name, "mknod_reg") == 0) {
        result = mknod(path, S_IFREG | 0600, 0);
    } else if (strcmp(name, "chmod") == 0) {
        result = chmod(path, argc > 3 ? (mode_t)strtol(argv[3], NULL, 8) : 0600);
    } else if (strcmp(name, "chown") == 0) {
        result = chown(path, getuid(), getgid());
    } else if (strcmp(name, "utime") == 0) {
        result = utime(path, NULL);
    } else if (strcmp(name, "setxattr") == 0) {
        result = setxattr(path, "user.pm", "x", 1, 0);
    } else if (strcmp(name, "access") == 0) {
        result = access(path, R_OK);
    } else if (strcmp(name, "chdir") == 0) {
        result = chdir(path);
    } else {
        return STATUS_USAGE;
    }
    op(name, result, path);
    return finish();
}

static int cmd_mksock(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0) {
        return setup_fail("socket");
    }
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", argv[2]);
    int result = bind(descriptor, (struct sockaddr *)&address, sizeof(address));
    op("bind_unix", result, argv[2]);
    close(descriptor);
    return finish();
}

static int cmd_two_paths(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    const char *name = argv[1];
    int result;
    if (strcmp(name, "symlink") == 0) {
        result = symlink(argv[2], argv[3]);
    } else if (strcmp(name, "link") == 0) {
        result = link(argv[2], argv[3]);
    } else if (strcmp(name, "rename") == 0) {
        result = rename(argv[2], argv[3]);
    } else if (strcmp(name, "renameat2_noreplace") == 0) {
        result = (int)syscall(SYS_renameat2, AT_FDCWD, argv[2], AT_FDCWD, argv[3], 1);
    } else if (strcmp(name, "renameat2_exchange") == 0) {
        result = (int)syscall(SYS_renameat2, AT_FDCWD, argv[2], AT_FDCWD, argv[3], 2);
    } else {
        return STATUS_USAGE;
    }
    op(name, result, argv[3]);
    return finish();
}

/* Runs an exec attempt in a child, so the probe survives to report it: the child execs, and if that fails it
 * sends its errno up a pipe that closes on a successful exec. Prints OP <name> ret=0 and the child's output when
 * it ran, OP <name> ret=-1 errno=... when it did not. */
static int spawn_attempt(const char *name, const char *detail, int (*attempt)(void *), void *context) {
    int channel[2];
    if (pipe2(channel, O_CLOEXEC) != 0) {
        return setup_fail("pipe");
    }
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) {
        return setup_fail("fork");
    }
    if (child == 0) {
        close(channel[0]);
        attempt(context);
        int failure = errno;
        if (write(channel[1], &failure, sizeof(failure)) < 0) {
            _exit(126);
        }
        _exit(127);
    }
    close(channel[1]);
    int failure = 0;
    ssize_t got = read(channel[0], &failure, sizeof(failure));
    int status = 0;
    waitpid(child, &status, 0);
    if (got == (ssize_t)sizeof(failure)) {
        errno = failure;
        op(name, -1, detail);
    } else if (got == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        op(name, 0, detail);
    } else if (got == 0) {
        errno = ECANCELED;
        op(name, -1, detail);
    } else {
        return setup_fail("exec channel");
    }
    return finish();
}

struct exec_target {
    char **argv;
    int descriptor;
};

static int attempt_execv(void *context) {
    struct exec_target *target = context;
    return execv(target->argv[0], target->argv);
}

static int attempt_fexecve(void *context) {
    struct exec_target *target = context;
    char *const arguments[] = { "pm", "execd", NULL };
    char *const environment[] = { NULL };
    return fexecve(target->descriptor, arguments, environment);
}

/* tryexec PATH [ARGS...]: execv of the path. */
static int cmd_exec(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    struct exec_target target = { .argv = &argv[2], .descriptor = -1 };
    return spawn_attempt("exec", argv[2], attempt_execv, &target);
}

/* tryfexec PATH: open the file first, then fexecve the descriptor. */
static int cmd_fexec(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    int descriptor = open(argv[2], O_RDONLY | O_CLOEXEC);
    op("open", descriptor, argv[2]);
    if (descriptor < 0) {
        return finish();
    }
    struct exec_target target = { .argv = NULL, .descriptor = descriptor };
    return spawn_attempt("fexec", argv[2], attempt_fexecve, &target);
}

/* execld LOADER FILE: the program run through the dynamic loader, so the loader is executed and FILE is only read. */
static int cmd_execld(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    struct exec_target target = { .argv = &argv[2], .descriptor = -1 };
    return spawn_attempt("execld", argv[3], attempt_execv, &target);
}

/* Copies a readable program into an anonymous memory file and executes that. */
static int cmd_memfdexec(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    int source = open(argv[2], O_RDONLY);
    op("open", source, argv[2]);
    if (source < 0) {
        return finish();
    }
    int memory = (int)syscall(SYS_memfd_create, "pm", MFD_CLOEXEC);
    op("memfd_create", memory, NULL);
    if (memory < 0) {
        return finish();
    }
    char buffer[BUFFER];
    ssize_t got;
    while ((got = read(source, buffer, sizeof(buffer))) > 0) {
        if (write(memory, buffer, (size_t)got) != got) {
            return setup_fail("memfd write");
        }
    }
    struct exec_target target = { .argv = NULL, .descriptor = memory };
    return spawn_attempt("memfdexec", argv[2], attempt_fexecve, &target);
}

static int cmd_execd(void) {
    puts("EXECD");
    return STATUS_OK;
}

static int cmd_readfd(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    char buffer[256];
    ssize_t got = read((int)arg_long(argv[2]), buffer, sizeof(buffer) - 1);
    op("read_fd", got, NULL);
    if (got >= 0) {
        buffer[got] = '\0';
        for (ssize_t index = 0; index < got; index++) {
            if (buffer[index] == '\n') {
                buffer[index] = '\0';
                break;
            }
        }
        printf("CONTENT %s\n", buffer);
    }
    return finish();
}

static int cmd_writefd(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    ssize_t put = write((int)arg_long(argv[2]), argv[3], strlen(argv[3]));
    op("write_fd", put, NULL);
    return finish();
}

/* Opens a directory, then opens a name relative to it, as a path walk that starts from a descriptor. */
static int cmd_openat(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int directory = open(argv[2], O_RDONLY | O_DIRECTORY);
    op("open_dir", directory, argv[2]);
    if (directory < 0) {
        return finish();
    }
    int descriptor = openat(directory, argv[3], O_RDONLY);
    op("openat", descriptor, argv[3]);
    return finish();
}

/* ------------------------------------------------------------ landlock */

struct ll_attr {
    unsigned long long handled_access_fs;
    unsigned long long handled_access_net;
    unsigned long long scoped;
};
struct ll_beneath {
    unsigned long long allowed_access;
    int parent_fd;
};

/* A new ruleset that grants everything on /, restricted onto the process: it can only intersect. */
static int cmd_landlock_widen(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    struct ll_attr attribute = { .handled_access_fs = 0x3fff };
    int ruleset = (int)syscall(444, &attribute, 16, 0);
    op("landlock_create_ruleset", ruleset, NULL);
    if (ruleset < 0) {
        return finish();
    }
    int root = open("/", O_PATH | O_DIRECTORY);
    struct ll_beneath rule = { .allowed_access = 0x3fff, .parent_fd = root };
    long added = syscall(445, ruleset, 1, &rule, 0);
    op("landlock_add_rule", added, NULL);
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    long restricted = syscall(446, ruleset, 0);
    op("landlock_restrict_self", restricted, NULL);
    int descriptor = open(argv[2], O_RDONLY);
    op("open_after_widen", descriptor, argv[2]);
    return finish();
}

static int cmd_nnp_get(void) {
    int value = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    op("nnp_get", value, NULL);
    return STATUS_OK;
}

static int cmd_nnp_clear(void) {
    int result = prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0);
    op("prctl_clear_no_new_privs", result, NULL);
    return finish();
}

/* ------------------------------------------------------------- escapes */

static int cmd_mount(void) {
    int result = mount("tmpfs", "/mnt", "tmpfs", 0, "");
    op("mount", result, NULL);
    return finish();
}

static int cmd_chroot(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    int result = chroot(argv[2]);
    op("chroot", result, argv[2]);
    return finish();
}

static int cmd_unshare_user(void) {
    int result = unshare(CLONE_NEWUSER);
    op("unshare_user", result, NULL);
    return finish();
}

static int cmd_unshare_mount(void) {
    int result = unshare(CLONE_NEWNS);
    op("unshare_mount", result, NULL);
    return finish();
}

static int cmd_ptrace(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    long result = ptrace(PTRACE_ATTACH, (pid_t)arg_long(argv[2]), 0, 0);
    op("ptrace_attach", result, NULL);
    return finish();
}

static int cmd_kill(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    pid_t target = (pid_t)arg_long(argv[2]);
    if (target == 0) {
        target = getppid();
    }
    int result = kill(target, (int)arg_long(argv[3]));
    op("kill", result, NULL);
    return finish();
}

static int cmd_abstract_connect(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0) {
        return setup_fail("socket");
    }
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    address.sun_path[0] = '\0';
    snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1, "%s", argv[2]);
    socklen_t length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(argv[2]));
    int result = connect(descriptor, (struct sockaddr *)&address, length);
    op("connect_abstract", result, argv[2]);
    return finish();
}

static int cmd_abstract_server(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1, "%s", argv[2]);
    socklen_t length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(argv[2]));
    if (bind(descriptor, (struct sockaddr *)&address, length) != 0 || listen(descriptor, 4) != 0) {
        return setup_fail("abstract bind");
    }
    puts("LISTENING");
    fflush(stdout);
    int accepted = 0;
    for (long tenth = 0; tenth < arg_long(argv[3]) * 10; tenth++) {
        struct pollfd waiting = { .fd = descriptor, .events = POLLIN };
        if (poll(&waiting, 1, 100) > 0 && accept(descriptor, NULL, NULL) >= 0) {
            accepted++;
        }
    }
    printf("ACCEPTED %d\n", accepted);
    return STATUS_OK;
}

/* ------------------------------------------------------------- network */

static int cmd_tcp(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (descriptor < 0) {
        return setup_fail("socket");
    }
    struct sockaddr_in address;
    loopback_address(&address, argv[2], (int)arg_long(argv[3]));
    int result = connect(descriptor, (struct sockaddr *)&address, sizeof(address));
    op("connect", result, NULL);
    if (result < 0) {
        return finish();
    }
    ssize_t put = send(descriptor, "ping", 4, MSG_NOSIGNAL);
    op("send", put, NULL);
    char reply[16] = { 0 };
    struct pollfd waiting = { .fd = descriptor, .events = POLLIN };
    if (poll(&waiting, 1, 3000) > 0) {
        ssize_t got = read(descriptor, reply, sizeof(reply) - 1);
        op("read", got, NULL);
        if (got > 0) {
            printf("REPLY %s\n", reply);
        }
    } else {
        puts("REPLY none");
    }
    return finish();
}

/* A connected TCP socket, then sendmsg on it: the guard makes datagram sends itself and refuses this one. */
static int cmd_tcp_sendmsg(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    loopback_address(&address, argv[2], (int)arg_long(argv[3]));
    int result = connect(descriptor, (struct sockaddr *)&address, sizeof(address));
    op("connect", result, NULL);
    if (result < 0) {
        return finish();
    }
    struct iovec vector = { .iov_base = "ping", .iov_len = 4 };
    struct msghdr header;
    memset(&header, 0, sizeof(header));
    header.msg_iov = &vector;
    header.msg_iovlen = 1;
    ssize_t sent = sendmsg(descriptor, &header, MSG_NOSIGNAL);
    op("sendmsg_tcp", sent, NULL);
    return finish();
}

static int cmd_tcp6(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int descriptor = socket(AF_INET6, SOCK_STREAM, 0);
    if (descriptor < 0) {
        return setup_fail("socket6");
    }
    struct sockaddr_in6 address;
    memset(&address, 0, sizeof(address));
    address.sin6_family = AF_INET6;
    address.sin6_port = htons((unsigned short)arg_long(argv[3]));
    inet_pton(AF_INET6, argv[2], &address.sin6_addr);
    int result = connect(descriptor, (struct sockaddr *)&address, sizeof(address));
    op("connect6", result, NULL);
    return finish();
}

static int cmd_unixconnect(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", argv[2]);
    int result = connect(descriptor, (struct sockaddr *)&address, sizeof(address));
    op("connect_unix", result, argv[2]);
    return finish();
}

static int cmd_socket_kind(const char *name) {
    int descriptor = -1;
    if (strcmp(name, "raw") == 0) {
        descriptor = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    } else if (strcmp(name, "icmp") == 0) {
        descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    } else if (strcmp(name, "packet") == 0) {
        descriptor = socket(AF_PACKET, SOCK_RAW, 0);
    } else if (strcmp(name, "sctp") == 0) {
        descriptor = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
    } else if (strcmp(name, "netlink") == 0) {
        descriptor = socket(AF_NETLINK, SOCK_RAW, 0);
    }
    op(name, descriptor, NULL);
    return finish();
}

static int cmd_io_uring(void) {
    unsigned char parameters[120];
    memset(parameters, 0, sizeof(parameters));
    long result = syscall(425, 4, parameters);
    op("io_uring_setup", result, NULL);
    return finish();
}

static int cmd_tfo(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    loopback_address(&address, argv[2], (int)arg_long(argv[3]));
    ssize_t put = sendto(descriptor, "x", 1, MSG_FASTOPEN | MSG_NOSIGNAL, (struct sockaddr *)&address, sizeof(address));
    op("sendto_fastopen", put, NULL);
    return finish();
}

/* One datagram by the named call. A fresh unbound socket unless a descriptor is given in FD. */
static int send_datagram(const char *mode, int descriptor, const struct sockaddr_in *address, const char *payload) {
    size_t length = strlen(payload);
    struct iovec vector = { .iov_base = (void *)payload, .iov_len = length };
    struct msghdr header;
    memset(&header, 0, sizeof(header));
    header.msg_name = (void *)address;
    header.msg_namelen = sizeof(*address);
    header.msg_iov = &vector;
    header.msg_iovlen = 1;
    if (strcmp(mode, "sendto") == 0) {
        return (int)sendto(descriptor, payload, length, 0, (const struct sockaddr *)address, sizeof(*address));
    }
    if (strcmp(mode, "sendmsg") == 0) {
        return (int)sendmsg(descriptor, &header, 0);
    }
    if (strcmp(mode, "sendmmsg") == 0) {
        struct mmsghdr entry;
        memset(&entry, 0, sizeof(entry));
        entry.msg_hdr = header;
        return sendmmsg(descriptor, &entry, 1, 0);
    }
    if (strcmp(mode, "connect_send") == 0) {
        int connected = connect(descriptor, (const struct sockaddr *)address, sizeof(*address));
        op("connect_udp", connected, NULL);
        if (connected < 0) {
            return -1;
        }
        return (int)send(descriptor, payload, length, 0);
    }
    errno = EINVAL;
    return -1;
}

static int cmd_udp_send(int argc, char **argv) {
    if (argc < 5) {
        return STATUS_USAGE;
    }
    int descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    if (descriptor < 0) {
        return setup_fail("socket");
    }
    struct sockaddr_in address;
    loopback_address(&address, argv[3], (int)arg_long(argv[4]));
    int result = send_datagram(argv[2], descriptor, &address, argc > 5 ? argv[5] : "datagram");
    op(argv[2], result, NULL);
    return finish();
}

/* A socket bound to an explicit local port first, then one datagram: a bound sender needs no ephemeral grant. */
static int cmd_udp_bound_send(int argc, char **argv) {
    if (argc < 6) {
        return STATUS_USAGE;
    }
    int descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local;
    loopback_address(&local, "127.0.0.1", (int)arg_long(argv[5]));
    int bound = bind(descriptor, (struct sockaddr *)&local, sizeof(local));
    op("bind_udp", bound, NULL);
    if (bound < 0) {
        return finish();
    }
    struct sockaddr_in address;
    loopback_address(&address, argv[3], (int)arg_long(argv[4]));
    int result = send_datagram(argv[2], descriptor, &address, "bound");
    op(argv[2], result, NULL);
    return finish();
}

/* A datagram sendmsg with ancillary data, which can steer where it goes. */
static int cmd_udp_ancillary(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in address;
    loopback_address(&address, argv[2], (int)arg_long(argv[3]));
    char payload = 'x';
    struct iovec vector = { .iov_base = &payload, .iov_len = 1 };
    union {
        char buffer[CMSG_SPACE(sizeof(int))];
        struct cmsghdr alignment;
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr header;
    memset(&header, 0, sizeof(header));
    header.msg_name = &address;
    header.msg_namelen = sizeof(address);
    header.msg_iov = &vector;
    header.msg_iovlen = 1;
    header.msg_control = control.buffer;
    header.msg_controllen = sizeof(control.buffer);
    struct cmsghdr *entry = CMSG_FIRSTHDR(&header);
    entry->cmsg_level = IPPROTO_IP;
    entry->cmsg_type = IP_TOS;
    entry->cmsg_len = CMSG_LEN(sizeof(int));
    int tos = 0;
    memcpy(CMSG_DATA(entry), &tos, sizeof(tos));
    ssize_t result = sendmsg(descriptor, &header, 0);
    op("sendmsg_ancillary", result, NULL);
    return finish();
}

/* Sends on an inherited descriptor: FD, then the destination, or none for an address-less send. */
static int cmd_inherited_send(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    int descriptor = (int)arg_long(argv[2]);
    ssize_t result;
    if (argc >= 5) {
        struct sockaddr_in address;
        loopback_address(&address, argv[3], (int)arg_long(argv[4]));
        result = sendto(descriptor, "inherited", 9, 0, (struct sockaddr *)&address, sizeof(address));
        op("sendto_inherited", result, NULL);
    } else {
        result = send(descriptor, "inherited", 9, MSG_NOSIGNAL);
        op("send_inherited", result, NULL);
    }
    return finish();
}

/* connect() on a descriptor inherited, as a stream, to the destination given. */
static int cmd_inherited_connect(int argc, char **argv) {
    if (argc < 5) {
        return STATUS_USAGE;
    }
    struct sockaddr_in address;
    loopback_address(&address, argv[3], (int)arg_long(argv[4]));
    int result = connect((int)arg_long(argv[2]), (struct sockaddr *)&address, sizeof(address));
    op("connect_inherited", result, NULL);
    return finish();
}

/* Writes on an inherited stream descriptor that is already connected. */
static int cmd_inherited_write(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    ssize_t result = send((int)arg_long(argv[2]), "inherited", 9, MSG_NOSIGNAL);
    op("send_inherited_stream", result, NULL);
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

static int race_receiver(in_addr_t host, int port) {
    int descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    int buffer_bytes = 4 * 1024 * 1024;
    setsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &buffer_bytes, sizeof(buffer_bytes));
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons((unsigned short)port);
    local.sin_addr.s_addr = host;
    if (bind(descriptor, (struct sockaddr *)&local, sizeof(local)) != 0) {
        return -1;
    }
    return descriptor;
}

static int race_drain(int descriptor) {
    int count = 0;
    char buffer[32];
    while (recv(descriptor, buffer, sizeof(buffer), 0) > 0) {
        count++;
    }
    return count;
}

/* The destination race: two receivers share a port, one allowed and one forbidden, and a second thread
 * rewrites the address while the first sends. Prints how many reached each. With "outside" as the fifth argument
 * the receivers are the caller's, so the probe binds nothing and only sends. */
static int cmd_udp_race(int argc, char **argv) {
    if (argc < 5) {
        return STATUS_USAGE;
    }
    int attempts = (int)arg_long(argv[4]);
    if (attempts > ATTEMPT_CAP) {
        attempts = ATTEMPT_CAP;
    }
    int port = (int)arg_long(argv[3]);
    race_allowed = inet_addr("127.0.0.1");
    race_forbidden = inet_addr("127.0.0.2");
    int outside = argc > 5 && strcmp(argv[5], "outside") == 0;
    int allowed = -1;
    int forbidden = -1;
    if (!outside) {
        allowed = race_receiver(race_allowed, port);
        forbidden = race_receiver(race_forbidden, port);
        if (allowed < 0 || forbidden < 0) {
            return setup_fail("receivers");
        }
    }
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&race_destination, 0, sizeof(race_destination));
    race_destination.sin_family = AF_INET;
    race_destination.sin_port = htons((unsigned short)port);
    race_destination.sin_addr.s_addr = race_allowed;
    pthread_t thread;
    pthread_create(&thread, NULL, race_flip, NULL);
    int refused = 0;
    int to_allowed = 0;
    int to_forbidden = 0;
    const char *mode = argv[2];
    for (int attempt = 0; attempt < attempts; attempt++) {
        if (!outside && attempt % 20 == 0) {
            to_allowed += race_drain(allowed);
            to_forbidden += race_drain(forbidden);
        }
        int result;
        if (strcmp(mode, "connect") == 0) {
            result = connect(sender, (struct sockaddr *)&race_destination, sizeof(race_destination)) == 0
                         ? (int)send(sender, "x", 1, 0)
                         : -1;
        } else {
            result = send_datagram(mode, sender, &race_destination, "x");
        }
        if (result < 0) {
            refused++;
        }
    }
    atomic_store(&race_over, 1);
    pthread_join(thread, NULL);
    usleep(100000);
    if (!outside) {
        to_allowed += race_drain(allowed);
        to_forbidden += race_drain(forbidden);
    }
    printf("RACE mode=%s attempts=%d refused=%d allowed=%d forbidden=%d\n", mode, attempts, refused, to_allowed,
           to_forbidden);
    return STATUS_OK;
}

static int cmd_bind(int argc, char **argv) {
    if (argc < 5) {
        return STATUS_USAGE;
    }
    int udp = strcmp(argv[4], "udp") == 0;
    int descriptor = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (descriptor < 0) {
        return setup_fail("socket");
    }
    int one = 1;
    setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in address;
    loopback_address(&address, argv[2], (int)arg_long(argv[3]));
    int result = bind(descriptor, (struct sockaddr *)&address, sizeof(address));
    op(udp ? "bind_udp" : "bind_tcp", result, NULL);
    if (result == 0) {
        struct sockaddr_in bound;
        socklen_t length = sizeof(bound);
        getsockname(descriptor, (struct sockaddr *)&bound, &length);
        printf("BOUND %d\n", ntohs(bound.sin_port));
    }
    return finish();
}

/* socket, optionally bind, listen, then a client of its own connects and the listener accepts: a whole server. */
static int cmd_serve(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in address;
    loopback_address(&address, "127.0.0.1", (int)arg_long(argv[2]));
    if (arg_long(argv[2]) >= 0) {
        int bound = bind(descriptor, (struct sockaddr *)&address, sizeof(address));
        op("bind", bound, NULL);
        if (bound < 0) {
            return finish();
        }
    }
    int listening = listen(descriptor, 4);
    op("listen", listening, NULL);
    if (listening < 0) {
        return finish();
    }
    struct sockaddr_in bound;
    socklen_t length = sizeof(bound);
    getsockname(descriptor, (struct sockaddr *)&bound, &length);
    struct sockaddr_in target;
    loopback_address(&target, "127.0.0.1", ntohs(bound.sin_port));
    int client = socket(AF_INET, SOCK_STREAM, 0);
    int connected = connect(client, (struct sockaddr *)&target, sizeof(target));
    op("connect_self", connected, NULL);
    struct pollfd waiting = { .fd = descriptor, .events = POLLIN };
    int accepted = poll(&waiting, 1, 2000) > 0 ? accept(descriptor, NULL, NULL) : -1;
    op("accept", accepted, NULL);
    printf("PORT %d\n", ntohs(bound.sin_port));
    return finish();
}

/* A listen() on a socket that was never bound: the kernel would give it a port of its own choosing. */
static int cmd_listen_unbound(void) {
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    int result = listen(descriptor, 4);
    op("listen_unbound", result, NULL);
    if (result == 0) {
        struct sockaddr_in bound;
        socklen_t length = sizeof(bound);
        getsockname(descriptor, (struct sockaddr *)&bound, &length);
        printf("PORT %d\n", ntohs(bound.sin_port));
    }
    return finish();
}

static atomic_int swap_over;
static int swap_bound;
static int swap_unbound;

static void *swap_flip(void *unused) {
    (void)unused;
    while (!atomic_load(&swap_over)) {
        dup2(swap_unbound, 50);
        dup2(swap_bound, 50);
    }
    return NULL;
}

/* The listen race: another thread swaps a never-bound socket under the descriptor being listened on. */
static int cmd_listen_race(int argc, char **argv) {
    swap_bound = socket(AF_INET, SOCK_STREAM, 0);
    swap_unbound = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    setsockopt(swap_bound, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in address;
    loopback_address(&address, "127.0.0.1", argc > 2 ? (int)arg_long(argv[2]) : 0);
    if (bind(swap_bound, (struct sockaddr *)&address, sizeof(address)) != 0) {
        return setup_fail("bind");
    }
    dup2(swap_bound, 50);
    pthread_t thread;
    pthread_create(&thread, NULL, swap_flip, NULL);
    for (int attempt = 0; attempt < 20000; attempt++) {
        (void)listen(50, 4);
    }
    atomic_store(&swap_over, 1);
    pthread_join(thread, NULL);
    struct sockaddr_in bound;
    socklen_t length = sizeof(bound);
    getsockname(swap_unbound, (struct sockaddr *)&bound, &length);
    printf("LISTEN-RACE port=%d\n", ntohs(bound.sin_port));
    return STATUS_OK;
}

static int cmd_resolve(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    struct addrinfo hints;
    struct addrinfo *found = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int result = getaddrinfo(argv[2], NULL, &hints, &found);
    op("getaddrinfo", result == 0 ? 0 : -1, NULL);
    if (result == 0 && found != NULL) {
        char text[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &((struct sockaddr_in *)found->ai_addr)->sin_addr, text, sizeof(text));
        printf("ADDRESS %s\n", text);
    }
    return finish();
}

/* ---------------------------------------------- servers run outside the sandbox */

static int cmd_tcpserver(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int server = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in address;
    loopback_address(&address, argv[2], (int)arg_long(argv[3]));
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(server, 8) != 0) {
        return setup_fail("tcpserver bind");
    }
    puts("LISTENING");
    fflush(stdout);
    int rounds = argc > 4 ? (int)arg_long(argv[4]) : 1;
    int idle_milliseconds = argc > 5 ? (int)arg_long(argv[5]) * 1000 : 8000;
    for (int round = 0; round < rounds; round++) {
        struct pollfd waiting = { .fd = server, .events = POLLIN };
        if (poll(&waiting, 1, idle_milliseconds) <= 0) {
            break;
        }
        int client = accept(server, NULL, NULL);
        char buffer[32] = { 0 };
        struct pollfd data = { .fd = client, .events = POLLIN };
        if (poll(&data, 1, 2000) > 0 && read(client, buffer, sizeof(buffer) - 1) > 0) {
            printf("SERVER-GOT %s\n", buffer);
            fflush(stdout);
            if (write(client, "pong", 4) < 0) {
                break;
            }
        } else {
            puts("SERVER-GOT nothing");
            fflush(stdout);
        }
        close(client);
    }
    return STATUS_OK;
}

static int cmd_udp_arrivals(int argc, char **argv) {
    if (argc < 5) {
        return STATUS_USAGE;
    }
    int descriptor = race_receiver(inet_addr(argv[2]), (int)arg_long(argv[3]));
    if (descriptor < 0) {
        return setup_fail("udp receiver");
    }
    puts("RECEIVER-UP");
    fflush(stdout);
    int total = 0;
    long seconds = arg_long(argv[4]);
    for (long idle = 0; idle < seconds * 10;) {
        struct pollfd waiting = { .fd = descriptor, .events = POLLIN };
        if (poll(&waiting, 1, 100) <= 0) {
            idle++;
            continue;
        }
        char buffer[128];
        ssize_t got;
        while ((got = recv(descriptor, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[got] = '\0';
            printf("ARRIVED %s\n", buffer);
            total++;
        }
        fflush(stdout);
    }
    printf("ARRIVALS %d\n", total);
    return STATUS_OK;
}

/* A connected stream socket opened here and left for a child to inherit: prints nothing, execs the command. */
static int cmd_holder(int argc, char **argv) {
    if (argc < 5) {
        return STATUS_USAGE;
    }
    int udp = strcmp(argv[2], "udp") == 0;
    int descriptor = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    struct sockaddr_in address;
    loopback_address(&address, argv[3], (int)arg_long(argv[4]));
    if (argc > 5 && strcmp(argv[5], "connect") == 0) {
        if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) {
            return setup_fail("holder connect");
        }
    }
    dup2(descriptor, 7);
    return STATUS_OK;
}

/* ----------------------------------------------------- time and resources */

static int cmd_sleep(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    long seconds = arg_long(argv[2]);
    if (seconds > SLEEP_CAP) {
        seconds = SLEEP_CAP;
    }
    printf("SLEEPING %ld\n", seconds);
    fflush(stdout);
    sleep((unsigned)seconds);
    puts("SLEPT");
    return STATUS_OK;
}

static int cmd_spin(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    long seconds = arg_long(argv[2]);
    if (seconds > SLEEP_CAP) {
        seconds = SLEEP_CAP;
    }
    puts("SPINNING");
    fflush(stdout);
    time_t end = time(NULL) + seconds;
    volatile unsigned long counter = 0;
    while (time(NULL) < end) {
        counter++;
    }
    puts("SPUN");
    return STATUS_OK;
}

static void *spin_thread(void *seconds) {
    time_t end = time(NULL) + (long)(intptr_t)seconds;
    volatile unsigned long counter = 0;
    while (time(NULL) < end) {
        counter++;
    }
    return NULL;
}

/* Several threads spin together, to show CPU time is added up across them. */
static int cmd_spin_threads(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    int count = (int)arg_long(argv[2]);
    long seconds = arg_long(argv[3]);
    if (count > 8) {
        count = 8;
    }
    pthread_t threads[8];
    puts("SPINNING");
    fflush(stdout);
    for (int index = 0; index < count; index++) {
        pthread_create(&threads[index], NULL, spin_thread, (void *)(intptr_t)seconds);
    }
    for (int index = 0; index < count; index++) {
        pthread_join(threads[index], NULL);
    }
    puts("SPUN");
    return STATUS_OK;
}

static volatile sig_atomic_t term_seen;

static void on_term(int signal_number) {
    (void)signal_number;
    term_seen = 1;
}

/* Ignores or traps SIGTERM and sleeps, so only a SIGKILL ends it. */
static int cmd_trapterm(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_term;
    sigaction(SIGTERM, &action, NULL);
    puts("TRAPPING");
    fflush(stdout);
    long seconds = arg_long(argv[2]);
    for (long tick = 0; tick < seconds * 10 && tick < SLEEP_CAP * 10; tick++) {
        usleep(100000);
    }
    printf("TRAPPED-DONE term_seen=%d\n", term_seen);
    return STATUS_OK;
}

/* Calls getpid through the 32-bit interface, int 0x80, which a Phobos filter refuses and a kernel with that
 * interface otherwise answers. Only x86-64 has it; elsewhere the call is reported as not implemented. */
static int cmd_int80(void) {
#if defined(__x86_64__)
    int result;
    __asm__ volatile("int $0x80" : "=a"(result) : "a"(20) : "memory");
    long returned = result;
    if (result < 0 && result > -4096) {
        errno = -result;
        returned = -1;
    }
    op("int80", returned, NULL);
#else
    errno = ENOSYS;
    op("int80", -1, NULL);
#endif
    return finish();
}

static int cmd_setsid(void) {
    pid_t result = setsid();
    op("setsid", result, NULL);
    return finish();
}

static int cmd_setpgid(void) {
    int result = setpgid(0, 0);
    op("setpgid", result, NULL);
    return finish();
}

/* Detaches a descendant that outlives the command: it sleeps, then creates a marker file. With "orphan" the
 * original command exits at once, without it the command waits for the end of the sleep. */
static int cmd_daemonize(int argc, char **argv) {
    if (argc < 5) {
        return STATUS_USAGE;
    }
    long seconds = arg_long(argv[2]);
    const char *marker = argv[3];
    int orphan = strcmp(argv[4], "orphan") == 0;
    pid_t first = fork();
    if (first == 0) {
        pid_t second = fork();
        if (second == 0) {
            for (long tick = 0; tick < seconds * 10 && tick < SLEEP_CAP * 10; tick++) {
                usleep(100000);
            }
            int descriptor = open(marker, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (descriptor >= 0) {
                if (write(descriptor, "alive", 5) < 0) {
                    _exit(1);
                }
                close(descriptor);
            }
            _exit(0);
        }
        _exit(0);
    }
    waitpid(first, NULL, 0);
    printf("DAEMONISED pid=%d\n", first);
    fflush(stdout);
    if (!orphan) {
        sleep((unsigned)(seconds < SLEEP_CAP ? seconds : SLEEP_CAP));
    }
    return STATUS_OK;
}

/* Forks up to N children that each sleep a second and counts how many could be made. */
static int cmd_fork_n(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    int wanted = (int)arg_long(argv[2]);
    if (wanted > FORK_CAP) {
        wanted = FORK_CAP;
    }
    int made = 0;
    int first_errno = 0;
    for (int index = 0; index < wanted; index++) {
        pid_t child = fork();
        if (child == 0) {
            sleep(3);
            _exit(0);
        }
        if (child < 0) {
            first_errno = errno;
            break;
        }
        made++;
    }
    printf("FORKED %d of %d errno=%s\n", made, wanted, errno_name(first_errno));
    fflush(stdout);
    for (int index = 0; index < made; index++) {
        wait(NULL);
    }
    return made == wanted ? STATUS_OK : STATUS_FAILED;
}

static int cmd_alloc(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    long megabytes = arg_long(argv[2]);
    if (megabytes > ALLOC_CAP_MB) {
        megabytes = ALLOC_CAP_MB;
    }
    void *block = mmap(NULL, (size_t)megabytes << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    op("mmap", block == MAP_FAILED ? -1 : 0, NULL);
    if (block == MAP_FAILED) {
        return finish();
    }
    long touch = megabytes < 64 ? megabytes : 64;
    for (long page = 0; page < touch << 8; page++) {
        ((volatile char *)block)[page << 12] = 1;
    }
    return finish();
}

static int cmd_openfiles(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    int wanted = (int)arg_long(argv[2]);
    if (wanted > OPEN_CAP) {
        wanted = OPEN_CAP;
    }
    int opened = 0;
    int failure = 0;
    for (int index = 0; index < wanted; index++) {
        if (open("/dev/null", O_RDONLY) < 0) {
            failure = errno;
            break;
        }
        opened++;
    }
    printf("OPENED %d of %d errno=%s\n", opened, wanted, errno_name(failure));
    return opened == wanted ? STATUS_OK : STATUS_FAILED;
}

static void ignore_signal(int signal_number) {
    (void)signal_number;
}

static int cmd_writebig(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    long megabytes = arg_long(argv[3]);
    if (megabytes > WRITE_CAP_MB) {
        megabytes = WRITE_CAP_MB;
    }
    signal(SIGXFSZ, ignore_signal);
    int descriptor = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    op("open", descriptor, argv[2]);
    if (descriptor < 0) {
        return finish();
    }
    static char block[1 << 20];
    memset(block, 'x', sizeof(block));
    long written = 0;
    int failure = 0;
    for (long index = 0; index < megabytes; index++) {
        ssize_t put = write(descriptor, block, sizeof(block));
        if (put != (ssize_t)sizeof(block)) {
            failure = put < 0 ? errno : EFBIG;
            break;
        }
        written++;
    }
    printf("WROTE %ld of %ld MB errno=%s\n", written, megabytes, errno_name(failure));
    close(descriptor);
    return written == megabytes ? STATUS_OK : STATUS_FAILED;
}

static int cmd_getrlimit(void) {
    static const struct {
        int resource;
        const char *name;
    } limits[] = {
        { RLIMIT_AS, "as" },
        { RLIMIT_CPU, "cpu" },
        { RLIMIT_NOFILE, "nofile" },
        { RLIMIT_NPROC, "nproc" },
        { RLIMIT_FSIZE, "fsize" },
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

/* Raises RLIMIT_NOFILE above the current hard limit: an unprivileged process cannot. */
static int cmd_setrlimit_raise(void) {
    struct rlimit limit;
    getrlimit(RLIMIT_NOFILE, &limit);
    limit.rlim_max = limit.rlim_max == RLIM_INFINITY ? RLIM_INFINITY : limit.rlim_max + 1000;
    limit.rlim_cur = limit.rlim_max;
    int result = setrlimit(RLIMIT_NOFILE, &limit);
    op("setrlimit_raise", result, NULL);
    return finish();
}

static int cmd_env(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    const char *value = getenv(argv[2]);
    printf("ENV %s=%s\n", argv[2], value ? value : "<unset>");
    return STATUS_OK;
}

static int cmd_exitwith(int argc, char **argv) {
    return argc < 3 ? STATUS_USAGE : (int)arg_long(argv[2]);
}

static int cmd_selfsignal(int argc, char **argv) {
    if (argc < 3) {
        return STATUS_USAGE;
    }
    signal((int)arg_long(argv[2]), SIG_DFL);
    raise((int)arg_long(argv[2]));
    return STATUS_OK;
}

/* Writes N bytes to a stream, to check output passes through whole: 'o' stdout, 'e' stderr. */
static int cmd_emit(int argc, char **argv) {
    if (argc < 4) {
        return STATUS_USAGE;
    }
    FILE *stream = argv[2][0] == 'e' ? stderr : stdout;
    long count = arg_long(argv[3]);
    for (long index = 0; index < count; index++) {
        fputc((int)('a' + index % 26), stream);
    }
    fputc('\n', stream);
    fflush(stream);
    return STATUS_OK;
}

static int cmd_argv(int argc, char **argv) {
    for (int index = 2; index < argc; index++) {
        printf("ARG[%d]=<%s>\n", index - 2, argv[index]);
    }
    return STATUS_OK;
}

static int cmd_cat(void) {
    char buffer[BUFFER];
    ssize_t got;
    while ((got = read(0, buffer, sizeof(buffer))) > 0) {
        if (write(1, buffer, (size_t)got) < 0) {
            return STATUS_FAILED;
        }
    }
    return STATUS_OK;
}

static int cmd_whoami(void) {
    printf("UID %d GID %d PID %d PPID %d PGID %d SID %d\n", getuid(), getgid(), getpid(), getppid(), getpgid(0), getsid(0));
    return STATUS_OK;
}

/* Connects from a chosen source address to a loopback destination, sends a tag and reports what came back:
 * REPLY <text> when the peer answered, CLOSED when it closed or reset without an answer, SILENT on a timeout. */
static int cmd_tcpfrom(int argc, char **argv) {
    if (argc < 6) {
        return STATUS_USAGE;
    }
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (descriptor < 0) {
        return setup_fail("socket");
    }
    struct sockaddr_in source;
    loopback_address(&source, argv[2], 0);
    if (bind(descriptor, (struct sockaddr *)&source, sizeof(source)) != 0) {
        return setup_fail("bind source");
    }
    struct sockaddr_in destination;
    loopback_address(&destination, argv[3], (int)arg_long(argv[4]));
    int connected = connect(descriptor, (struct sockaddr *)&destination, sizeof(destination));
    op("connect", connected, NULL);
    if (connected < 0) {
        return finish();
    }
    ssize_t sent = send(descriptor, argv[5], strlen(argv[5]), MSG_NOSIGNAL);
    op("send", sent, NULL);
    struct pollfd waiting = { .fd = descriptor, .events = POLLIN };
    if (poll(&waiting, 1, 4000) <= 0) {
        puts("SILENT");
        return finish();
    }
    char buffer[64] = { 0 };
    ssize_t got = read(descriptor, buffer, sizeof(buffer) - 1);
    if (got > 0) {
        printf("REPLY %s\n", buffer);
    } else {
        puts("CLOSED");
    }
    return finish();
}

/* Prints every descriptor above standard error that is open in this process, one per line. */
static int cmd_openfds(void) {
    int count = 0;
    for (int descriptor = 3; descriptor < 1024; descriptor++) {
        if (fcntl(descriptor, F_GETFD) >= 0) {
            printf("OPENFD %d\n", descriptor);
            count++;
        }
    }
    printf("OPENFDS %d\n", count);
    return STATUS_OK;
}

static int cmd_cwd(void) {
    char buffer[4096];
    printf("CWD %s\n", getcwd(buffer, sizeof(buffer)) ? buffer : "<none>");
    return STATUS_OK;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: pprobe <subcommand> ...\n");
        return STATUS_USAGE;
    }
    const char *name = argv[1];
    if (strcmp(name, "execd") != 0) {
        puts("START");
        fflush(stdout);
    }
    struct {
        const char *name;
        int (*run)(int, char **);
    } with_arguments[] = {
        { "open", cmd_open },
        { "read", cmd_read },
        { "write", cmd_write },
        { "readdir", cmd_readdir },
        { "stat", cmd_stat },
        { "truncate", cmd_truncate },
        { "ftruncate", cmd_ftruncate },
        { "mkdir", cmd_simple_path },
        { "rmdir", cmd_simple_path },
        { "unlink", cmd_simple_path },
        { "mkfifo", cmd_simple_path },
        { "mknod_char", cmd_simple_path },
        { "mknod_block", cmd_simple_path },
        { "mknod_reg", cmd_simple_path },
        { "chmod", cmd_simple_path },
        { "chown", cmd_simple_path },
        { "utime", cmd_simple_path },
        { "setxattr", cmd_simple_path },
        { "access", cmd_simple_path },
        { "chdir", cmd_simple_path },
        { "mksock", cmd_mksock },
        { "symlink", cmd_two_paths },
        { "link", cmd_two_paths },
        { "rename", cmd_two_paths },
        { "renameat2_noreplace", cmd_two_paths },
        { "renameat2_exchange", cmd_two_paths },
        { "exec", cmd_exec },
        { "fexec", cmd_fexec },
        { "execld", cmd_execld },
        { "memfdexec", cmd_memfdexec },
        { "readfd", cmd_readfd },
        { "writefd", cmd_writefd },
        { "openat", cmd_openat },
        { "landlock_widen", cmd_landlock_widen },
        { "chroot", cmd_chroot },
        { "ptrace", cmd_ptrace },
        { "kill", cmd_kill },
        { "abstract_connect", cmd_abstract_connect },
        { "abstract_server", cmd_abstract_server },
        { "tcp", cmd_tcp },
        { "tcp6", cmd_tcp6 },
        { "unixconnect", cmd_unixconnect },
        { "tfo", cmd_tfo },
        { "udp_send", cmd_udp_send },
        { "udp_bound_send", cmd_udp_bound_send },
        { "udp_ancillary", cmd_udp_ancillary },
        { "inherited_send", cmd_inherited_send },
        { "inherited_connect", cmd_inherited_connect },
        { "inherited_write", cmd_inherited_write },
        { "udp_race", cmd_udp_race },
        { "bind", cmd_bind },
        { "serve", cmd_serve },
        { "resolve", cmd_resolve },
        { "tcpserver", cmd_tcpserver },
        { "udp_arrivals", cmd_udp_arrivals },
        { "holder", cmd_holder },
        { "sleep", cmd_sleep },
        { "spin", cmd_spin },
        { "spin_threads", cmd_spin_threads },
        { "trapterm", cmd_trapterm },
        { "daemonize", cmd_daemonize },
        { "fork_n", cmd_fork_n },
        { "alloc", cmd_alloc },
        { "openfiles", cmd_openfiles },
        { "writebig", cmd_writebig },
        { "env", cmd_env },
        { "exitwith", cmd_exitwith },
        { "selfsignal", cmd_selfsignal },
        { "emit", cmd_emit },
        { "argv", cmd_argv },
        { "listen_race", cmd_listen_race },
        { "tcp_sendmsg", cmd_tcp_sendmsg },
        { "tcpfrom", cmd_tcpfrom },
    };
    for (size_t index = 0; index < sizeof(with_arguments) / sizeof(with_arguments[0]); index++) {
        if (strcmp(name, with_arguments[index].name) == 0) {
            return with_arguments[index].run(argc, argv);
        }
    }
    if (strcmp(name, "execd") == 0) return cmd_execd();
    if (strcmp(name, "nnp_clear") == 0) return cmd_nnp_clear();
    if (strcmp(name, "nnp_get") == 0) return cmd_nnp_get();
    if (strcmp(name, "mount") == 0) return cmd_mount();
    if (strcmp(name, "unshare_user") == 0) return cmd_unshare_user();
    if (strcmp(name, "unshare_mount") == 0) return cmd_unshare_mount();
    if (strcmp(name, "raw") == 0 || strcmp(name, "icmp") == 0 || strcmp(name, "packet") == 0 ||
        strcmp(name, "sctp") == 0 || strcmp(name, "netlink") == 0) return cmd_socket_kind(name);
    if (strcmp(name, "io_uring") == 0) return cmd_io_uring();
    if (strcmp(name, "listen_unbound") == 0) return cmd_listen_unbound();
    if (strcmp(name, "int80") == 0) return cmd_int80();
    if (strcmp(name, "setsid") == 0) return cmd_setsid();
    if (strcmp(name, "setpgid") == 0) return cmd_setpgid();
    if (strcmp(name, "getrlimit") == 0) return cmd_getrlimit();
    if (strcmp(name, "setrlimit_raise") == 0) return cmd_setrlimit_raise();
    if (strcmp(name, "cat") == 0) return cmd_cat();
    if (strcmp(name, "whoami") == 0) return cmd_whoami();
    if (strcmp(name, "cwd") == 0) return cmd_cwd();
    if (strcmp(name, "openfds") == 0) return cmd_openfds();
    fprintf(stderr, "unknown subcommand %s\n", name);
    return STATUS_USAGE;
}
