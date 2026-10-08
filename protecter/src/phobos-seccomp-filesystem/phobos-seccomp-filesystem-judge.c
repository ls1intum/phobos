#define _GNU_SOURCE
#include "phobos-seccomp-filesystem-judge.h"

#include "phobos-seccomp-filesystem-message.h"

#include "../phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-ruleset.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/openat2.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/un.h>
#include <unistd.h>

/* The mount identifier statx answers since Linux 5.8, named here for an older header. */
#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x00001000U
#endif

/* The kernel's own O_LARGEFILE, which a 64-bit C library leaves out of its header but another
 * library or a raw call may still pass. The value differs between the two architectures. */
#if defined(__x86_64__)
static constexpr int KERNEL_O_LARGEFILE = 0100000;
#else
static constexpr int KERNEL_O_LARGEFILE = 0400000;
#endif

/* The open flags a judged open may carry (A.6.4 of the plan). Anything else, O_PATH, O_TMPFILE and
 * O_NOATIME among them, leaves the call unjudged. */
static constexpr int JUDGED_OPEN_FLAGS = O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC | O_APPEND
                                         | O_CLOEXEC | O_NONBLOCK | O_NOCTTY | O_DIRECTORY
                                         | O_NOFOLLOW | O_SYNC | O_DSYNC | KERNEL_O_LARGEFILE
                                         | O_DIRECT | O_ASYNC;

/* The open_how layout an openat2 is judged with: the first version, whose size is fixed. */
static constexpr uint64_t OPEN_HOW_FIRST_SIZE = sizeof(struct open_how);

/* The mode bits an openat2 accepts; any other bit is refused with EINVAL before the walk. */
static constexpr uint64_t OPEN_HOW_MODE_BITS = 07777;

/* The rename flags a judged rename may carry, each on its own. */
static constexpr unsigned int JUDGED_RENAME_FLAGS = RENAME_NOREPLACE | RENAME_EXCHANGE;

/* The capability that lets a task hard-link a file it does not own, and the status lines that
 * hold credentials. */
static constexpr unsigned int CAPABILITY_FOWNER = 3;
static const char *const CREDENTIAL_KEYS[] = {"Uid:", "Gid:", "Groups:", "CapEff:"};

/* Room for a socket link and /proc/<pid>/net/unix. */
static constexpr size_t SOCKET_LINK_LENGTH = 64;
static constexpr size_t UNIX_TABLE_LENGTH = 1 << 20;
static constexpr size_t PROC_PATH_LENGTH = 64;

/* An object of two quoted paths: "'from' to 'to'". */
static constexpr size_t TWO_PATH_OBJECT_LENGTH = 2 * REPORT_QUOTED_MAXIMUM + 8;

static char own_status[PROC_STATUS_LENGTH];
static bool own_status_read = false;
static bool own_status_known = false;
static char unix_table[UNIX_TABLE_LENGTH];

/* The supervisor's own /proc/self/status, read once, and only tried once: its credentials do not
 * change, and a status that could not be read then will not be read later. */
static const char *supervisor_status(void) {
    if (!own_status_read) {
        own_status_read = true;
        own_status_known = read_small_file("/proc/self/status", own_status, sizeof(own_status), NULL);
    }
    return own_status_known ? own_status : "";
}

/* The line of a status text that starts with key, up to its newline, or NULL. */
static const char *status_line(const char *status, const char *key, size_t *length) {
    size_t key_length = strlen(key);
    for (const char *line = status; *line != '\0';) {
        const char *end = strchr(line, '\n');
        size_t line_length = end == NULL ? strlen(line) : (size_t)(end - line);
        if (line_length >= key_length && strncmp(line, key, key_length) == 0) {
            *length = line_length;
            return line;
        }
        if (end == NULL) {
            break;
        }
        line = end + 1;
    }
    return NULL;
}

/* Whether the task holds exactly the supervisor's user and group ids, groups and effective
 * capabilities, so that the supervisor's own access check speaks for the task. */
static bool credentials_match(const char *task_status) {
    const char *own = supervisor_status();
    for (size_t index = 0; index < sizeof(CREDENTIAL_KEYS) / sizeof(CREDENTIAL_KEYS[0]); index++) {
        size_t own_length = 0;
        size_t task_length = 0;
        const char *own_line = status_line(own, CREDENTIAL_KEYS[index], &own_length);
        const char *task_line = status_line(task_status, CREDENTIAL_KEYS[index], &task_length);
        if (own_line == NULL || task_line == NULL || own_length != task_length
            || strncmp(own_line, task_line, own_length) != 0) {
            return false;
        }
    }
    return true;
}

/* Whether the task resolves paths from the same root as the supervisor. */
static bool root_is_ours(const struct task_view *task) {
    char link[PROC_PATH_LENGTH];
    char root[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/%d/root", (int)task->pid);
    ssize_t length = readlink(link, root, sizeof(root) - 1);
    if (length <= 0) {
        return false;
    }
    root[length] = '\0';
    return strcmp(root, "/") == 0 && notification_still_valid(task);
}

/* The hexadecimal value of a status line, or 0 when the status has no such line. */
static unsigned long long status_hexadecimal(const char *status, const char *key) {
    size_t length = 0;
    const char *line = status_line(status, key, &length);
    return line == NULL ? 0 : strtoull(line + strlen(key), NULL, 16);
}

/* Whether the supervisor holds a capability in its effective set. */
static bool supervisor_capable(unsigned int capability) {
    return (status_hexadecimal(supervisor_status(), "CapEff:") >> capability) & 1ULL;
}

/* Whether the mount a path lies on lets it be changed, executed from, or opened as a device. */
static bool mount_allows(const char *path, unsigned long refused_flag) {
    struct statvfs status;
    return statvfs(path, &status) == 0 && (status.f_flag & refused_flag) == 0;
}

/* Whether the file mode lets the task do what the call asks, the supervisor's credentials
 * standing in for the task's. */
static bool mode_allows(const char *path, int access) {
    return faccessat(AT_FDCWD, path, access, AT_EACCESS) == 0;
}

/* The mount a path lies on, by its identifier, or 0 when it cannot be told. With
 * AT_SYMLINK_NOFOLLOW a final symbolic link is not followed, though a mount on the last name is
 * still crossed, as a lookup crosses it. */
static uint64_t mount_of(const char *path, int flags) {
    struct statx status;
    if (statx(AT_FDCWD, path, flags, STATX_MNT_ID, &status) != 0
        || (status.stx_mask & STATX_MNT_ID) == 0) {
        return 0;
    }
    return status.stx_mnt_id;
}

/* Whether a file is append-only, or cannot be told not to be. An append-only file is refused a
 * write that does not append, and any truncation, before Landlock is asked. */
static bool append_only_or_unknown(const char *path) {
    struct statx status;
    return statx(AT_FDCWD, path, 0, STATX_TYPE, &status) != 0
           || (status.stx_attributes & STATX_ATTR_APPEND) != 0;
}

/* Whether the kernel's protection of files in sticky directories may refuse an O_CREAT open of
 * this existing file before Landlock is asked: a regular file or named pipe in a sticky directory
 * that others may write, owned by neither that directory's owner nor the task. The
 * protected_regular and protected_fifos settings are not read, so this errs towards silence.
 * target is a resolved absolute path. */
static bool sticky_protected(const char *target, const struct stat *status) {
    char parent[PATH_MAX];
    struct stat directory;
    if (!S_ISREG(status->st_mode) && !S_ISFIFO(status->st_mode)) {
        return false;
    }
    snprintf(parent, sizeof(parent), "%s", target);
    char *slash = strrchr(parent, '/');
    slash[slash == parent ? 1 : 0] = '\0';
    return stat(parent, &directory) != 0
           || ((directory.st_mode & S_ISVTX) != 0 && (directory.st_mode & (S_IWOTH | S_IWGRP)) != 0
               && status->st_uid != directory.st_uid && status->st_uid != geteuid());
}

/* Removes the slashes a path ends with, keeping a lone "/". Answers whether there were any. */
static bool strip_trailing_slashes(char *path) {
    size_t length = strlen(path);
    bool stripped = false;
    while (length > 1 && path[length - 1] == '/') {
        path[--length] = '\0';
        stripped = true;
    }
    return stripped;
}

/* Whether Landlock refuses a right this ruleset handles and the rules along the path do not grant. */
static bool refused(const struct policy_model *model, uint64_t granted, uint64_t wanted) {
    return (wanted & model->handled_filesystem & ~granted) != 0;
}

/* The noun a line gives an object of this type. */
static const char *noun_for(mode_t mode) {
    switch (mode & S_IFMT) {
    case S_IFDIR: return "Directory";
    case S_IFLNK: return "Symbolic Link";
    case S_IFIFO: return "Named Pipe";
    case S_IFSOCK: return "Socket File";
    case S_IFCHR: return "Device";
    case S_IFBLK: return "Device";
    default: return "File";
    }
}

/* The noun a line gives an object it reads, deletes, moves or links: the vocabulary has only the
 * Directory and the File there, one per right (READ_DIR and READ_FILE, REMOVE_DIR and
 * REMOVE_FILE), so a device or a named pipe that is read is a File. */
static const char *whole_object_noun_for(mode_t mode) {
    return S_ISDIR(mode) ? "Directory" : "File";
}

/* The right that creating an object of this type takes. */
static uint64_t make_right_for(mode_t mode) {
    switch (mode & S_IFMT) {
    case S_IFDIR: return LANDLOCK_ACCESS_FILESYSTEM_MAKE_DIRECTORY;
    case S_IFLNK: return LANDLOCK_ACCESS_FILESYSTEM_MAKE_SYMBOLIC_LINK;
    case S_IFIFO: return LANDLOCK_ACCESS_FILESYSTEM_MAKE_NAMED_PIPE;
    case S_IFSOCK: return LANDLOCK_ACCESS_FILESYSTEM_MAKE_SOCKET;
    case S_IFCHR: return LANDLOCK_ACCESS_FILESYSTEM_MAKE_CHARACTER_DEVICE;
    case S_IFBLK: return LANDLOCK_ACCESS_FILESYSTEM_MAKE_BLOCK_DEVICE;
    default: return LANDLOCK_ACCESS_FILESYSTEM_MAKE_REGULAR_FILE;
    }
}

/* The right that removing an object of this type takes. */
static uint64_t remove_right_for(mode_t mode) {
    return S_ISDIR(mode) ? LANDLOCK_ACCESS_FILESYSTEM_REMOVE_DIRECTORY
                         : LANDLOCK_ACCESS_FILESYSTEM_REMOVE_FILE;
}

/* Reports one refusal of a path, naming the path the program gave beside it when it differs. */
static void report_path(const char *verb, const char *noun, const char *shown,
                        const char *absolute) {
    report_blocked(REPORT_LAYER_FILESYSTEM, verb, noun, shown, true,
                   strcmp(shown, absolute) != 0 ? absolute : NULL);
}

/* Reports one refusal of a move or a link, whose object is two paths. */
static void report_two_paths(const char *verb, const char *noun, const char *from, const char *to) {
    static char quoted_from[REPORT_QUOTED_MAXIMUM];
    static char quoted_to[REPORT_QUOTED_MAXIMUM];
    static char object[TWO_PATH_OBJECT_LENGTH];
    quote_like_bash(from, quoted_from, sizeof(quoted_from));
    quote_like_bash(to, quoted_to, sizeof(quoted_to));
    snprintf(object, sizeof(object), "%s to %s", quoted_from, quoted_to);
    report_blocked(REPORT_LAYER_FILESYSTEM, verb, noun, object, false, NULL);
}

/* Whether a name the call creates is absent as the kernel looks it up for the task: entry, the
 * name with its directories resolved, does not exist. Any other failure to look, a last name
 * longer than a name may be among them, is refused before Landlock and answers false. */
static bool name_absent(const char *entry) {
    struct stat status;
    return lstat(entry, &status) != 0 && errno == ENOENT;
}

/* Resolves the parent a call creates or removes a name in, and answers whether the kernel would
 * reach Landlock at all: the parent is a directory on a writable mount that the file mode lets the
 * task search. Write permission on the parent is checked only after Landlock's hook, so it is not
 * asked here. */
static bool parent_accepts_change(const struct task_view *task, const char *absolute, char *anchor,
                                  char *shown) {
    if (!resolve_for_landlock(task, absolute, true, anchor, PATH_MAX, shown, PATH_MAX)) {
        return false;
    }
    struct stat status;
    return stat(anchor, &status) == 0 && S_ISDIR(status.st_mode)
           && mount_allows(anchor, ST_RDONLY) && mode_allows(anchor, X_OK);
}

/* Whether an open of an existing object reaches Landlock: its type takes the access mode and the
 * flags, the file mode lets the task read or write it as asked, a write or truncation is not on a
 * read-only mount, a device is not on a nodev mount, and an append-only file is opened to append
 * and not truncated. */
static bool open_reaches_landlock(const char *target, const struct stat *status, int flags) {
    int access = flags & O_ACCMODE;
    bool directory = S_ISDIR(status->st_mode);
    bool device = S_ISCHR(status->st_mode) || S_ISBLK(status->st_mode);
    bool writes = access == O_WRONLY || access == O_RDWR;
    bool reads = access == O_RDONLY || access == O_RDWR;
    bool truncating = (flags & O_TRUNC) != 0;
    bool changes_contents = writes || (truncating && S_ISREG(status->st_mode));
    int mode_access = (reads ? R_OK : 0) | (writes || truncating ? W_OK : 0);
    if (access == O_ACCMODE || S_ISSOCK(status->st_mode)
        || (directory && (writes || truncating || (flags & O_CREAT) != 0))
        || ((flags & O_DIRECTORY) != 0 && !directory)) {
        return false;
    }
    return !(changes_contents && !mount_allows(target, ST_RDONLY))
           && !(device && !mount_allows(target, ST_NODEV)) && mode_allows(target, mode_access)
           && !(((writes && (flags & O_APPEND) == 0) || truncating)
                && append_only_or_unknown(target));
}

/* An open of a name that exists; target is the object the open lands on. Landlock checks the write
 * and the read the open asks for, and only after that a truncation. */
static void judge_open_existing(const char *target, const struct stat *status, int flags,
                                const char *absolute, const struct policy_model *model) {
    int access = flags & O_ACCMODE;
    bool writes = access == O_WRONLY || access == O_RDWR;
    bool reads = access == O_RDONLY || access == O_RDWR;
    bool truncates = (flags & O_TRUNC) != 0 && S_ISREG(status->st_mode);
    if (!open_reaches_landlock(target, status, flags)) {
        return;
    }
    uint64_t granted = model_rights_along(model, target);
    uint64_t read_right = S_ISDIR(status->st_mode) ? LANDLOCK_ACCESS_FILESYSTEM_READ_DIRECTORY
                                                   : LANDLOCK_ACCESS_FILESYSTEM_READ_FILE;
    if (writes && refused(model, granted, LANDLOCK_ACCESS_FILESYSTEM_WRITE_FILE)) {
        report_path("write", "File", target, absolute);
    } else if (reads && refused(model, granted, read_right)) {
        report_path("read", whole_object_noun_for(status->st_mode), target, absolute);
    } else if (truncates && refused(model, granted, LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE)) {
        report_path("write", "File", target, absolute);
    }
}

/* An open that creates its name. Landlock checks the creation in the parent first, and then, on
 * the new file, the write and read the open asks for. */
static void judge_open_create(const struct task_view *task, const char *absolute, int flags,
                              const struct policy_model *model) {
    char anchor[PATH_MAX];
    char shown[PATH_MAX];
    if ((flags & O_DIRECTORY) != 0 || !parent_accepts_change(task, absolute, anchor, shown)) {
        return;
    }
    int access = flags & O_ACCMODE;
    uint64_t granted = model_rights_along(model, anchor);
    if (refused(model, granted, LANDLOCK_ACCESS_FILESYSTEM_MAKE_REGULAR_FILE)) {
        report_path("create", "File", shown, absolute);
    } else if ((access == O_WRONLY || access == O_RDWR)
               && refused(model, granted, LANDLOCK_ACCESS_FILESYSTEM_WRITE_FILE)) {
        report_path("write", "File", shown, absolute);
    } else if ((access == O_RDONLY || access == O_RDWR)
               && refused(model, granted, LANDLOCK_ACCESS_FILESYSTEM_READ_FILE)) {
        report_path("read", "File", shown, absolute);
    }
}

/* An open, with flags from the call or from an openat2's open_how. A name with a slash after it is
 * followed by the walk, so a missing one ends the walk and is never created. */
static void judge_open(const struct task_view *task, const struct named_object *object, int flags,
                       const struct policy_model *model) {
    char absolute[PATH_MAX];
    char entry[PATH_MAX];
    char target[PATH_MAX];
    struct stat status;
    if ((flags & ~JUDGED_OPEN_FLAGS) != 0
        || !read_absolute_name(task, object, absolute, sizeof(absolute))
        || !resolve_as_task(task, absolute, false, entry, sizeof(entry))) {
        return;
    }
    if (lstat(entry, &status) != 0) {
        if (errno == ENOENT && (flags & O_CREAT) != 0) {
            judge_open_create(task, absolute, flags, model);
        }
        return;
    }
    bool exclusive = (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL);
    if (exclusive || (S_ISLNK(status.st_mode) && (flags & O_NOFOLLOW) != 0)
        || !resolve_as_task(task, absolute, true, target, sizeof(target))
        || stat(target, &status) != 0
        || ((flags & O_CREAT) != 0 && sticky_protected(target, &status))) {
        return;
    }
    judge_open_existing(target, &status, flags, absolute, model);
}

/* An openat2: judged as an open only for the first open_how layout with no resolve flag, since
 * the resolve flags change the walk in ways the mirror does not reproduce, and only with a mode
 * openat2 accepts: bits within 07777, and none at all unless the open creates. */
static void judge_open_how(const struct task_view *task, const struct access_request *request,
                           const struct policy_model *model) {
    struct open_how how;
    if (request->open_how_size != OPEN_HOW_FIRST_SIZE
        || !read_command_bytes(task, request->open_how_address, &how, sizeof(how))
        || how.resolve != 0 || how.flags > (uint64_t)INT_MAX
        || (how.mode & ~OPEN_HOW_MODE_BITS) != 0
        || ((how.flags & O_CREAT) == 0 && how.mode != 0)) {
        return;
    }
    judge_open(task, &request->objects[0], (int)how.flags, model);
}

/* An execve or execveat. Landlock checks execute and read on the file; the file must be a regular
 * file the mode lets the task execute, on a mount that allows it. */
static void judge_execute(const struct task_view *task, const struct access_request *request,
                          const struct policy_model *model) {
    char absolute[PATH_MAX];
    char entry[PATH_MAX];
    char target[PATH_MAX];
    struct stat status;
    bool no_follow = (request->execute_flags & AT_SYMLINK_NOFOLLOW) != 0;
    if ((request->execute_flags & ~AT_SYMLINK_NOFOLLOW) != 0
        || !read_absolute_name(task, &request->objects[0], absolute, sizeof(absolute))
        || !resolve_as_task(task, absolute, false, entry, sizeof(entry))
        || lstat(entry, &status) != 0 || (S_ISLNK(status.st_mode) && no_follow)
        || !resolve_as_task(task, absolute, true, target, sizeof(target))
        || stat(target, &status) != 0 || !S_ISREG(status.st_mode)
        || !mount_allows(target, ST_NOEXEC) || !mode_allows(target, X_OK)) {
        return;
    }
    if (refused(model, model_rights_along(model, target),
                LANDLOCK_ACCESS_FILESYSTEM_EXECUTE | LANDLOCK_ACCESS_FILESYSTEM_READ_FILE)) {
        report_path("execute", "File", target, absolute);
    }
}

/* A call that creates one name of the given type in a parent: mkdir, mknod and symlink. Only a
 * directory may be named with a trailing slash. */
static void judge_create_name(const struct task_view *task, const struct named_object *object,
                              mode_t type, const struct policy_model *model) {
    char absolute[PATH_MAX];
    char entry[PATH_MAX];
    char anchor[PATH_MAX];
    char shown[PATH_MAX];
    if (!read_absolute_name(task, object, absolute, sizeof(absolute))
        || (strip_trailing_slashes(absolute) && !S_ISDIR(type))
        || !resolve_as_task(task, absolute, false, entry, sizeof(entry)) || !name_absent(entry)
        || !parent_accepts_change(task, absolute, anchor, shown)) {
        return;
    }
    if (refused(model, model_rights_along(model, anchor), make_right_for(type))) {
        report_path("create", noun_for(type), shown, absolute);
    }
}

/* A mknod, judged by the type its mode names; a type mknod cannot create is refused before
 * Landlock and left alone. */
static void judge_make_node(const struct task_view *task, const struct access_request *request,
                            const struct policy_model *model) {
    mode_t type = request->mode & S_IFMT;
    switch (type) {
    case 0:
        type = S_IFREG;
        break;
    case S_IFREG:
    case S_IFIFO:
    case S_IFSOCK:
    case S_IFCHR:
    case S_IFBLK:
        break;
    default:
        return;
    }
    judge_create_name(task, &request->objects[0], type, model);
}

/* A symlink, judged only when its target is a name the kernel accepts, since the target is read
 * before the new name is looked at. */
static void judge_make_symbolic_link(const struct task_view *task,
                                     const struct access_request *request,
                                     const struct policy_model *model) {
    if (command_string_present(task, request->link_target_address)) {
        judge_create_name(task, &request->objects[0], S_IFLNK, model);
    }
}

/* An unlink or rmdir: the name must exist with the type the call expects, and Landlock checks the
 * removal in the parent. */
static void judge_remove(const struct task_view *task, const struct access_request *request,
                         const struct policy_model *model) {
    char absolute[PATH_MAX];
    char entry[PATH_MAX];
    char anchor[PATH_MAX];
    char shown[PATH_MAX];
    struct stat status;
    bool directory = (request->unlink_flags & AT_REMOVEDIR) != 0;
    if ((request->unlink_flags & ~AT_REMOVEDIR) != 0
        || !read_absolute_name(task, &request->objects[0], absolute, sizeof(absolute))
        || (strip_trailing_slashes(absolute) && !directory)
        || !resolve_as_task(task, absolute, false, entry, sizeof(entry))
        || lstat(entry, &status) != 0 || S_ISDIR(status.st_mode) != directory
        || !parent_accepts_change(task, absolute, anchor, shown)) {
        return;
    }
    if (refused(model, model_rights_along(model, anchor), remove_right_for(status.st_mode))) {
        report_path("delete", whole_object_noun_for(status.st_mode), shown, absolute);
    }
}

/* Both names of a rename or a link, made absolute, their directories resolved, and resolved to
 * their parents. */
struct two_names {
    char from[PATH_MAX];
    char to[PATH_MAX];
    char from_entry[PATH_MAX];
    char to_entry[PATH_MAX];
    char from_anchor[PATH_MAX];
    char to_anchor[PATH_MAX];
    char from_shown[PATH_MAX];
    char to_shown[PATH_MAX];
    struct stat from_status;
    struct stat to_status;
    bool to_exists;
};

/* Reads both names and strips their trailing slashes before either is looked up, and answers
 * whether the kernel would reach Landlock: the source exists, the destination exists or is absent
 * (not unreadable), a trailing slash names a directory, the destination's parent accepts a change,
 * the source's parent accepts one too when the call removes the source (a rename, not a link) and
 * otherwise resolves, and the call stays on one mount, since a call across mounts ends with EXDEV
 * first. A rename compares the two parents' mounts, a link the source object's own mount with the
 * destination parent's, as the kernel does. */
static bool read_two_names(const struct task_view *task, const struct access_request *request,
                           bool source_removed, struct two_names *names) {
    if (!read_absolute_name(task, &request->objects[0], names->from, sizeof(names->from))
        || !read_absolute_name(task, &request->objects[1], names->to, sizeof(names->to))) {
        return false;
    }
    bool from_slashes = strip_trailing_slashes(names->from);
    bool to_slashes = strip_trailing_slashes(names->to);
    if (!resolve_as_task(task, names->from, false, names->from_entry, PATH_MAX)
        || !resolve_as_task(task, names->to, false, names->to_entry, PATH_MAX)
        || lstat(names->from_entry, &names->from_status) != 0) {
        return false;
    }
    names->to_exists = lstat(names->to_entry, &names->to_status) == 0;
    if ((!names->to_exists && errno != ENOENT)
        || ((from_slashes || to_slashes) && !S_ISDIR(names->from_status.st_mode))) {
        return false;
    }
    bool source_ready = source_removed
                            ? parent_accepts_change(task, names->from, names->from_anchor,
                                                    names->from_shown)
                            : resolve_for_landlock(task, names->from, true, names->from_anchor,
                                                   PATH_MAX, names->from_shown, PATH_MAX);
    if (!source_ready
        || !parent_accepts_change(task, names->to, names->to_anchor, names->to_shown)) {
        return false;
    }
    uint64_t source_mount = source_removed ? mount_of(names->from_anchor, 0)
                                           : mount_of(names->from_entry, AT_SYMLINK_NOFOLLOW);
    return source_mount != 0 && source_mount == mount_of(names->to_anchor, 0);
}

/* Whether path lies strictly beneath ancestor. */
static bool lies_beneath(const char *path, const char *ancestor) {
    size_t length = strlen(ancestor);
    return strncmp(path, ancestor, length) == 0 && path[length] == '/';
}

/* Whether a rename moves a name into its own subtree, or onto one of its own ancestors, which the
 * kernel refuses with EINVAL or ENOTEMPTY before Landlock is asked. */
static bool renames_into_itself(const struct two_names *names) {
    return lies_beneath(names->to_shown, names->from_shown)
           || lies_beneath(names->from_shown, names->to_shown);
}

/* Whether a move or a link crosses directories, which takes REFER on both parents. */
static bool reparents(const struct two_names *names) {
    return strcmp(names->from_anchor, names->to_anchor) != 0;
}

/* A rename. Landlock checks the removal in the source's parent, the creation (and, over an
 * existing name, its removal) in the destination's, the same the other way round for an exchange,
 * and REFER on both parents when they differ. The first refusal in that order is the line. */
static void judge_rename(const struct task_view *task, const struct access_request *request,
                         const struct policy_model *model) {
    static struct two_names names;
    unsigned int flags = request->rename_flags;
    bool exchange = flags == RENAME_EXCHANGE;
    if ((flags & ~JUDGED_RENAME_FLAGS) != 0 || flags == JUDGED_RENAME_FLAGS
        || !read_two_names(task, request, true, &names) || renames_into_itself(&names)
        || (flags == RENAME_NOREPLACE && names.to_exists) || (exchange && !names.to_exists)
        || (names.to_exists && !exchange
            && S_ISDIR(names.from_status.st_mode) != S_ISDIR(names.to_status.st_mode))) {
        return;
    }
    mode_t from_mode = names.from_status.st_mode;
    mode_t to_mode = names.to_status.st_mode;
    uint64_t from_granted = model_rights_along(model, names.from_anchor);
    uint64_t to_granted = model_rights_along(model, names.to_anchor);
    if (refused(model, from_granted, remove_right_for(from_mode))) {
        report_path("delete", whole_object_noun_for(from_mode), names.from_shown, names.from);
    } else if (refused(model, to_granted, make_right_for(from_mode))) {
        report_path("create", noun_for(from_mode), names.to_shown, names.to);
    } else if (names.to_exists && refused(model, to_granted, remove_right_for(to_mode))) {
        report_path("delete", whole_object_noun_for(to_mode), names.to_shown, names.to);
    } else if (exchange && refused(model, from_granted, make_right_for(to_mode))) {
        report_path("create", noun_for(to_mode), names.from_shown, names.from);
    } else if (reparents(&names)
               && (refused(model, from_granted, LANDLOCK_ACCESS_FILESYSTEM_REFER)
                   || refused(model, to_granted, LANDLOCK_ACCESS_FILESYSTEM_REFER))) {
        report_two_paths("move", whole_object_noun_for(from_mode), names.from_shown, names.to_shown);
    }
}

/* Whether the kernel's protection of hard links lets the task link a file it may not own: the
 * owner and a task with CAP_FOWNER may, and so may anyone who may read and write a regular file
 * that is neither set-user-id nor executable set-group-id. */
static bool hard_link_allowed(const char *path, const struct stat *status) {
    bool safe_source = S_ISREG(status->st_mode) && (status->st_mode & S_ISUID) == 0
                       && (status->st_mode & (S_ISGID | S_IXGRP)) != (S_ISGID | S_IXGRP);
    return status->st_uid == geteuid() || supervisor_capable(CAPABILITY_FOWNER)
           || (safe_source && mode_allows(path, R_OK | W_OK));
}

/* A hard link. Landlock checks the creation in the destination's parent, and REFER on both parents
 * when they differ. */
static void judge_link(const struct task_view *task, const struct access_request *request,
                       const struct policy_model *model) {
    static struct two_names names;
    if (request->link_flags != 0 || !read_two_names(task, request, false, &names) || names.to_exists
        || S_ISDIR(names.from_status.st_mode)
        || !hard_link_allowed(names.from_entry, &names.from_status)) {
        return;
    }
    mode_t from_mode = names.from_status.st_mode;
    uint64_t from_granted = model_rights_along(model, names.from_anchor);
    uint64_t to_granted = model_rights_along(model, names.to_anchor);
    if (refused(model, to_granted, make_right_for(from_mode))) {
        report_path("create", noun_for(from_mode), names.to_shown, names.to);
    } else if (reparents(&names)
               && (refused(model, from_granted, LANDLOCK_ACCESS_FILESYSTEM_REFER)
                   || refused(model, to_granted, LANDLOCK_ACCESS_FILESYSTEM_REFER))) {
        report_two_paths("link", whole_object_noun_for(from_mode), names.from_shown, names.to_shown);
    }
}

/* A truncate: a regular file the mode lets the task write, on a writable mount, that is not
 * append-only, of a length that is not negative. Landlock checks TRUNCATE on the file. */
static void judge_truncate(const struct task_view *task, const struct access_request *request,
                           const struct policy_model *model) {
    char absolute[PATH_MAX];
    char target[PATH_MAX];
    struct stat status;
    if (request->truncate_length < 0
        || !read_absolute_name(task, &request->objects[0], absolute, sizeof(absolute))
        || !resolve_as_task(task, absolute, true, target, sizeof(target))
        || stat(target, &status) != 0 || !S_ISREG(status.st_mode)
        || !mount_allows(target, ST_RDONLY) || !mode_allows(target, W_OK)
        || append_only_or_unknown(target)) {
        return;
    }
    if (refused(model, model_rights_along(model, target), LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE)) {
        report_path("write", "File", target, absolute);
    }
}

/* The inode of the socket behind one of the task's descriptors, or 0. */
static unsigned long socket_inode(const struct task_view *task, int descriptor) {
    char link[PROC_PATH_LENGTH];
    char target[SOCKET_LINK_LENGTH];
    unsigned long inode = 0;
    snprintf(link, sizeof(link), "/proc/%d/fd/%d", (int)task->pid, descriptor);
    ssize_t length = readlink(link, target, sizeof(target) - 1);
    if (length <= 0) {
        return 0;
    }
    target[length] = '\0';
    if (sscanf(target, "socket:[%lu]", &inode) != 1) {
        return 0;
    }
    return inode;
}

/* Whether one of the task's descriptors is a UNIX socket, found by its inode among the UNIX
 * sockets of the task's network namespace. A bind of a UNIX name on any other socket is refused
 * by its own family before Landlock. */
static bool socket_is_unix(const struct task_view *task, int descriptor) {
    char path[PROC_PATH_LENGTH];
    unsigned long inode = socket_inode(task, descriptor);
    snprintf(path, sizeof(path), "/proc/%d/net/unix", (int)task->pid);
    if (inode == 0 || !read_small_file(path, unix_table, sizeof(unix_table), NULL)
        || !notification_still_valid(task)) {
        return false;
    }
    char *state = NULL;
    for (char *line = strtok_r(unix_table, "\n", &state); line != NULL;
         line = strtok_r(NULL, "\n", &state)) {
        unsigned long row_inode = 0;
        if (sscanf(line, "%*s %*s %*s %*s %*s %*s %lu", &row_inode) == 1 && row_inode == inode) {
            return true;
        }
    }
    return false;
}

/* A bind of a UNIX socket to a path name, which creates a socket file in a parent. An abstract
 * name and an automatic one create no file and are left alone. */
static void judge_bind_unix(const struct task_view *task, const struct access_request *request,
                            const struct sockaddr_un *address, const struct policy_model *model) {
    size_t length = request->socket_address_length;
    size_t path_room = length - offsetof(struct sockaddr_un, sun_path);
    char name[sizeof(address->sun_path) + 1];
    char absolute[PATH_MAX];
    char entry[PATH_MAX];
    char anchor[PATH_MAX];
    char shown[PATH_MAX];
    if (length <= offsetof(struct sockaddr_un, sun_path) || address->sun_path[0] == '\0') {
        return;
    }
    snprintf(name, sizeof(name), "%.*s", (int)path_room, address->sun_path);
    if (!socket_is_unix(task, request->socket_descriptor)
        || !make_absolute(task, AT_FDCWD, name, absolute, sizeof(absolute))
        || !notification_still_valid(task) || strip_trailing_slashes(absolute)
        || !resolve_as_task(task, absolute, false, entry, sizeof(entry)) || !name_absent(entry)
        || !parent_accepts_change(task, absolute, anchor, shown)) {
        return;
    }
    if (refused(model, model_rights_along(model, anchor), LANDLOCK_ACCESS_FILESYSTEM_MAKE_SOCKET)) {
        report_path("create", "Socket File", shown, absolute);
    }
}

/* Reads a bind's address out of the command, of a length the kernel accepts. */
static bool read_bind_address(const struct task_view *task, const struct access_request *request,
                              struct sockaddr_storage *address) {
    size_t length = request->socket_address_length;
    memset(address, 0, sizeof(*address));
    return length >= sizeof(sa_family_t) && length <= sizeof(*address)
           && read_command_bytes(task, request->objects[0].name_address, address, length);
}

/* A bind, judged here only when it names a UNIX path; a port is the network model's. */
static void judge_bind(const struct task_view *task, const struct access_request *request,
                       const struct policy_model *model) {
    struct sockaddr_storage address;
    if (read_bind_address(task, request, &address) && address.ss_family == AF_UNIX
        && request->socket_address_length <= sizeof(struct sockaddr_un)) {
        judge_bind_unix(task, request, (const struct sockaddr_un *)&address, model);
    }
}

void judge_bind_port(const struct task_view *task, const struct access_request *request,
                     const struct policy_model *network, socket_type_lookup socket_type_of) {
    struct sockaddr_storage address;
    uint16_t port = 0;
    if (request->kind != ACCESS_BIND || socket_type_of == NULL
        || !read_bind_address(task, request, &address)) {
        return;
    }
    if (address.ss_family == AF_INET
        && request->socket_address_length >= sizeof(struct sockaddr_in)) {
        port = ntohs(((const struct sockaddr_in *)&address)->sin_port);
    } else if (address.ss_family == AF_INET6
               && request->socket_address_length >= sizeof(struct sockaddr_in6)) {
        port = ntohs(((const struct sockaddr_in6 *)&address)->sin6_port);
    } else {
        return;
    }
    int type = socket_type_of(task->pid, request->socket_descriptor);
    if (type != SOCK_STREAM && type != SOCK_DGRAM) {
        return;
    }
    bool datagram = type == SOCK_DGRAM;
    if (!model_bind_permitted(network, datagram, port)) {
        char object[PROC_PATH_LENGTH];
        snprintf(object, sizeof(object), "%u over %s", (unsigned int)port, datagram ? "UDP" : "TCP");
        report_blocked(REPORT_LAYER_NETWORK, "bind", "Port", object, false, NULL);
    }
}

void judge_and_report(const struct task_view *task, const struct access_request *request,
                      const struct policy_model *filesystem) {
    if (!credentials_match(task->status) || !root_is_ours(task)) {
        return;
    }
    switch (request->kind) {
    case ACCESS_OPEN:
        judge_open(task, &request->objects[0], request->open_flags, filesystem);
        return;
    case ACCESS_OPEN_HOW:
        judge_open_how(task, request, filesystem);
        return;
    case ACCESS_EXECUTE:
        judge_execute(task, request, filesystem);
        return;
    case ACCESS_MAKE_DIRECTORY:
        judge_create_name(task, &request->objects[0], S_IFDIR, filesystem);
        return;
    case ACCESS_MAKE_NODE:
        judge_make_node(task, request, filesystem);
        return;
    case ACCESS_MAKE_SYMBOLIC_LINK:
        judge_make_symbolic_link(task, request, filesystem);
        return;
    case ACCESS_REMOVE:
        judge_remove(task, request, filesystem);
        return;
    case ACCESS_RENAME:
        judge_rename(task, request, filesystem);
        return;
    case ACCESS_LINK:
        judge_link(task, request, filesystem);
        return;
    case ACCESS_TRUNCATE:
        judge_truncate(task, request, filesystem);
        return;
    case ACCESS_BIND:
        judge_bind(task, request, filesystem);
        return;
    case ACCESS_ARMING:
        return;
    }
}

#ifdef PHOBOS_REPORTER_UNIT_TEST
void reset_judge_for_tests(void) {
    own_status_read = false;
    own_status_known = false;
}
#endif
