#define _GNU_SOURCE
#include "phobos-seccomp-filesystem-path.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/uio.h>
#include <unistd.h>

#include <linux/seccomp.h>

/* A name is read out of the command in pieces that never cross a boundary of this size, so a name
 * that ends right before an unmapped page is still read whole. Every page size Linux uses is a
 * multiple of it. */
static constexpr size_t READ_PIECE_ALIGNMENT = 4096;

/* Room for /proc/<pid>/cwd and /proc/<pid>/fd/<descriptor>. */
static constexpr size_t PROC_LINK_LENGTH = 64;

/* What the kernel appends to the link of a directory that was removed. */
static const char DELETED_SUFFIX[] = " (deleted)";

/* The magic number of procfs, and the inode of its root. self and thread-self, the two links there
 * that read differently for every process, live in that root. */
static constexpr unsigned long PROC_FILESYSTEM_MAGIC = 0x9fa0;
static constexpr ino_t PROC_ROOT_INODE = 1;

/* As many symbolic links as the kernel follows on one walk before it answers ELOOP. */
static constexpr int SYMBOLIC_LINKS_MAXIMUM = 40;

/* The status lines that number the task's thread group and the task itself, as procfs counts them. */
static const char THREAD_GROUP_KEY[] = "\nTgid:";
static const char THREAD_KEY[] = "\nPid:";
static constexpr int DECIMAL = 10;

bool notification_still_valid(const struct task_view *task) {
    uint64_t id = task->id;
    return ioctl(task->notify_descriptor, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0;
}

bool read_command_bytes(const struct task_view *task, uint64_t address, void *out, size_t size) {
    struct iovec local = {.iov_base = out, .iov_len = size};
    struct iovec remote = {.iov_base = (void *)(uintptr_t)address, .iov_len = size};
    ssize_t got = process_vm_readv(task->pid, &local, 1, &remote, 1, 0);
    return got == (ssize_t)size && notification_still_valid(task);
}

/* Reads a NUL-terminated string of fewer than size bytes, piece by piece, so the read never
 * reaches past the page the string ends on. */
static bool read_command_string(const struct task_view *task, uint64_t address, char *out,
                                size_t size) {
    size_t done = 0;
    while (done < size - 1) {
        uint64_t here = address + done;
        size_t piece_left = READ_PIECE_ALIGNMENT - (size_t)(here % READ_PIECE_ALIGNMENT);
        size_t room = size - 1 - done;
        size_t want = piece_left < room ? piece_left : room;
        struct iovec local = {.iov_base = out + done, .iov_len = want};
        struct iovec remote = {.iov_base = (void *)(uintptr_t)here, .iov_len = want};
        ssize_t got = process_vm_readv(task->pid, &local, 1, &remote, 1, 0);
        if (got <= 0) {
            return false;
        }
        if (memchr(out + done, '\0', (size_t)got) != NULL) {
            return true;
        }
        done += (size_t)got;
    }
    return false;
}

/* Whether a link the kernel wrote names a directory still reachable from the root: an absolute
 * path, not one marked as deleted. A socket, a pipe or an unreachable directory is none of that. */
static bool reachable_directory_link(const char *link) {
    size_t length = strlen(link);
    size_t suffix = sizeof(DELETED_SUFFIX) - 1;
    if (link[0] != '/') {
        return false;
    }
    return length < suffix || strcmp(link + length - suffix, DELETED_SUFFIX) != 0;
}

bool make_absolute(const struct task_view *task, int directory, const char *name, char *out,
                   size_t size) {
    if (name[0] == '/') {
        return (size_t)snprintf(out, size, "%s", name) < size;
    }
    char link[PROC_LINK_LENGTH];
    char base[PATH_MAX];
    if (directory == AT_FDCWD) {
        snprintf(link, sizeof(link), "/proc/%d/cwd", (int)task->pid);
    } else if (directory >= 0) {
        snprintf(link, sizeof(link), "/proc/%d/fd/%d", (int)task->pid, directory);
    } else {
        return false;
    }
    ssize_t length = readlink(link, base, sizeof(base) - 1);
    if (length <= 0) {
        return false;
    }
    base[length] = '\0';
    if (!reachable_directory_link(base)) {
        return false;
    }
    const char *separator = strcmp(base, "/") == 0 ? "" : "/";
    return (size_t)snprintf(out, size, "%s%s%s", base, separator, name) < size;
}

bool read_absolute_name(const struct task_view *task, const struct named_object *object, char *out,
                        size_t size) {
    char name[PATH_MAX];
    if (!read_command_string(task, object->name_address, name, sizeof(name)) || name[0] == '\0') {
        return false;
    }
    return make_absolute(task, object->directory, name, out, size)
           && notification_still_valid(task);
}

/* Whether a last name is one a call can create or remove: neither empty nor a dot entry. */
static bool creatable_name(const char *last) {
    return last[0] != '\0' && strcmp(last, ".") != 0 && strcmp(last, "..") != 0;
}

/* Whether a directory is the root of a procfs, where self and thread-self live. An empty name is
 * the root of the filesystem. */
static bool is_proc_root(const char *directory) {
    const char *path = directory[0] == '\0' ? "/" : directory;
    struct statfs filesystem;
    struct stat status;
    return statfs(path, &filesystem) == 0
           && (unsigned long)filesystem.f_type == PROC_FILESYSTEM_MAGIC
           && stat(path, &status) == 0 && status.st_ino == PROC_ROOT_INODE;
}

/* The number a status line gives after key, or -1 when the status has no such line. */
static long status_number(const char *status, const char *key) {
    const char *line = strstr(status, key);
    if (line == NULL) {
        return -1;
    }
    const char *number = line + strlen(key);
    char *end = NULL;
    long value = strtol(number, &end, DECIMAL);
    return end == number || value <= 0 ? -1 : value;
}

/* What self (thread == false) or thread-self (thread == true) reads as for the task whose status
 * this is: its thread group, or its thread within that group, relative to the procfs root. */
static bool task_link_target(const char *status, bool thread, char *out, size_t size) {
    long group = status_number(status, THREAD_GROUP_KEY);
    long task = status_number(status, THREAD_KEY);
    if (group < 0 || task < 0) {
        return false;
    }
    int written = thread ? snprintf(out, size, "%ld/task/%ld", group, task)
                         : snprintf(out, size, "%ld", group);
    return (size_t)written < size;
}

/* Reads the target of the symbolic link at path, whose last name is name in directory. self and
 * thread-self of a procfs root read as they read for the task whose status is given; with no
 * status, meeting one of them ends the walk. Either way the meeting is recorded in
 * met_reader_link. */
static bool link_target(const char *directory, const char *name, const char *path,
                        const char *task_status, bool *met_reader_link, char *out, size_t size) {
    bool self = strcmp(name, "self") == 0;
    bool thread_self = strcmp(name, "thread-self") == 0;
    if ((self || thread_self) && is_proc_root(directory)) {
        *met_reader_link = true;
        return task_status != NULL && task_link_target(task_status, thread_self, out, size);
    }
    ssize_t length = readlink(path, out, size - 1);
    if (length <= 0 || (size_t)length >= size - 1) {
        return false;
    }
    out[length] = '\0';
    return true;
}

/* Whether the task may search a resolved directory, in which an empty string stands for the root,
 * the supervisor's credentials standing in for the task's. The kernel asks this before every name
 * it looks up there, "." and ".." included. */
static bool searchable(const char *done) {
    return faccessat(AT_FDCWD, done[0] == '\0' ? "/" : done, X_OK, AT_EACCESS) == 0;
}

/* Whether the kernel's protection of symbolic links may refuse the task to follow this one before
 * Landlock is asked: a link in a sticky directory that others may write, owned by neither the
 * task nor that directory's owner. The protected_symlinks setting is not read, so this errs
 * towards silence. */
static bool link_protected(const char *done, const struct stat *link) {
    struct stat directory;
    return stat(done[0] == '\0' ? "/" : done, &directory) != 0
           || ((directory.st_mode & S_ISVTX) != 0 && (directory.st_mode & S_IWOTH) != 0
               && link->st_uid != geteuid() && link->st_uid != directory.st_uid);
}

/* Whether nothing but slashes is left of a name. */
static bool only_slashes(const char *rest) {
    return rest[strspn(rest, "/")] == '\0';
}

/* Removes the last name of a resolved path, in which an empty string stands for the root. */
static void drop_last_name(char *done) {
    char *slash = strrchr(done, '/');
    if (slash != NULL) {
        *slash = '\0';
    }
}

/* Whether one name of a walk is "." (dots == 1) or ".." (dots == 2). */
static bool is_dot_name(const char *name, size_t length, size_t dots) {
    return length == dots && strncmp(name, "..", dots) == 0;
}

/* Joins a resolved directory, in which an empty string stands for the root, and the first length
 * bytes of a name into out, which holds PATH_MAX bytes. Answers false when the result does not
 * fit. */
static bool join_name(const char *done, const char *name, size_t length, char *out) {
    return (size_t)snprintf(out, PATH_MAX, "%s/%.*s", done, (int)length, name) < PATH_MAX;
}

/* Walks an absolute name name by name, the way the kernel walks it: "." stays, ".." leaves the
 * directory resolved so far, a symbolic link is read and walked in place of its name, and a name
 * with a slash after it must be a directory and is followed. The last name is followed only with
 * follow_last or a slash after it; otherwise it is joined unresolved and not examined. Answers false
 * for a name that does not exist on the way, a file used as a directory, a "." or ".." in a
 * directory the task may not search, a link the protection of symbolic links may refuse to follow,
 * too many links, or a result that does not fit: the kernel ends each of those before Landlock.
 * The supervisor's credentials stand in for the task's, as the judge's caller has checked. */
static bool walk_name(const char *absolute, bool follow_last, const char *task_status,
                      bool *met_reader_link, char *out, size_t size) {
    char done[PATH_MAX];
    char pending[PATH_MAX];
    char candidate[PATH_MAX];
    char name[PATH_MAX];
    char target[PATH_MAX];
    char joined[PATH_MAX];
    int links = 0;
    if (absolute[0] != '/'
        || (size_t)snprintf(pending, sizeof(pending), "%s", absolute) >= sizeof(pending)) {
        return false;
    }
    done[0] = '\0';
    char *cursor = pending;
    while (*(cursor += strspn(cursor, "/")) != '\0') {
        size_t length = strcspn(cursor, "/");
        char *rest = cursor + length;
        bool slash_after = *rest == '/';
        bool last = only_slashes(rest);
        struct stat status;
        if (is_dot_name(cursor, length, 1) || is_dot_name(cursor, length, 2)) {
            if (!searchable(done)) {
                return false;
            }
            if (length == 2) {
                drop_last_name(done);
            }
            cursor = rest;
            continue;
        }
        if (last && !follow_last && !slash_after) {
            return join_name(done, cursor, length, candidate)
                   && (size_t)snprintf(out, size, "%s", candidate) < size;
        }
        if (!join_name(done, cursor, length, candidate) || lstat(candidate, &status) != 0) {
            return false;
        }
        if (!S_ISLNK(status.st_mode)) {
            if ((!last || slash_after) && !S_ISDIR(status.st_mode)) {
                return false;
            }
            memcpy(done, candidate, sizeof(done));
            cursor = rest;
            continue;
        }
        snprintf(name, sizeof(name), "%.*s", (int)length, cursor);
        if (++links > SYMBOLIC_LINKS_MAXIMUM || link_protected(done, &status)
            || !link_target(done, name, candidate, task_status, met_reader_link, target,
                            sizeof(target))
            || (size_t)snprintf(joined, sizeof(joined), "%s%s", target, rest) >= sizeof(joined)) {
            return false;
        }
        if (target[0] == '/') {
            done[0] = '\0';
        }
        memcpy(pending, joined, sizeof(pending));
        cursor = pending;
    }
    return (size_t)snprintf(out, size, "%s", done[0] == '\0' ? "/" : done) < size;
}

bool resolve_as_task(const struct task_view *task, const char *absolute, bool follow_last,
                     char *out, size_t size) {
    bool met_reader_link = false;
    return walk_name(absolute, follow_last, task->status, &met_reader_link, out, size);
}

bool reads_alike_for_every_process(const char *absolute) {
    char resolved[PATH_MAX];
    bool met_reader_link = false;
    (void)walk_name(absolute, true, NULL, &met_reader_link, resolved, sizeof(resolved));
    return absolute[0] == '/' && !met_reader_link;
}

bool command_string_present(const struct task_view *task, uint64_t address) {
    char text[PATH_MAX];
    return read_command_string(task, address, text, sizeof(text)) && text[0] != '\0'
           && notification_still_valid(task);
}

bool resolve_for_landlock(const struct task_view *task, const char *absolute, bool parent,
                          char *anchor, size_t anchor_size, char *shown, size_t shown_size) {
    char resolved[PATH_MAX];
    char copy[PATH_MAX];
    if ((size_t)snprintf(copy, sizeof(copy), "%s", absolute) >= sizeof(copy) || copy[0] != '/') {
        return false;
    }
    if (!parent) {
        return resolve_as_task(task, copy, true, resolved, sizeof(resolved))
               && (size_t)snprintf(anchor, anchor_size, "%s", resolved) < anchor_size
               && (size_t)snprintf(shown, shown_size, "%s", resolved) < shown_size;
    }
    char *slash = strrchr(copy, '/');
    const char *last = slash + 1;
    if (!creatable_name(last)) {
        return false;
    }
    if (slash == copy) {
        snprintf(resolved, sizeof(resolved), "/");
    } else {
        *slash = '\0';
        if (!resolve_as_task(task, copy, true, resolved, sizeof(resolved))) {
            return false;
        }
    }
    const char *separator = strcmp(resolved, "/") == 0 ? "" : "/";
    return (size_t)snprintf(anchor, anchor_size, "%s", resolved) < anchor_size
           && (size_t)snprintf(shown, shown_size, "%s%s%s", resolved, separator, last) < shown_size;
}

bool read_small_file(const char *path, char *out, size_t size, size_t *length) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        return false;
    }
    size_t used = 0;
    ssize_t got = 0;
    do {
        got = read(descriptor, out + used, size - 1 - used);
        if (got > 0) {
            used += (size_t)got;
        }
    } while (got > 0 && used < size - 1);
    close(descriptor);
    out[used] = '\0';
    if (length != NULL) {
        *length = used;
    }
    return got == 0;
}
