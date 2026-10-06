#define _GNU_SOURCE
#include "phobos-seccomp-filesystem-path.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
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

bool resolve_for_landlock(const char *absolute, bool parent, char *anchor, size_t anchor_size,
                          char *shown, size_t shown_size) {
    char resolved[PATH_MAX];
    char copy[PATH_MAX];
    if ((size_t)snprintf(copy, sizeof(copy), "%s", absolute) >= sizeof(copy) || copy[0] != '/') {
        return false;
    }
    if (!parent) {
        return realpath(copy, resolved) != NULL
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
        if (realpath(copy, resolved) == NULL) {
            return false;
        }
    }
    const char *separator = strcmp(resolved, "/") == 0 ? "" : "/";
    return (size_t)snprintf(anchor, anchor_size, "%s", resolved) < anchor_size
           && (size_t)snprintf(shown, shown_size, "%s%s%s", resolved, separator, last) < shown_size;
}

bool read_small_file(const char *path, char *out, size_t size) {
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
    return got == 0;
}
