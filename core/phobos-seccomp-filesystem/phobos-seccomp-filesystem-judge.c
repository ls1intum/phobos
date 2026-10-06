#define _GNU_SOURCE
#include "phobos-seccomp-filesystem-judge.h"

#include "phobos-seccomp-filesystem-message.h"

#include "../phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-ruleset.h"

#include <arpa/inet.h>
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

/* The rename flags a judged rename may carry, each on its own. */
static constexpr unsigned int JUDGED_RENAME_FLAGS = RENAME_NOREPLACE | RENAME_EXCHANGE;

/* The capability that lets a task hard-link a file it does not own, and the status lines that
 * hold credentials. */
static constexpr unsigned int CAPABILITY_FOWNER = 3;
static const char *const CREDENTIAL_KEYS[] = {"Uid:", "Gid:", "Groups:", "CapEff:"};

/* Room for the supervisor's own /proc/self/status, a socket link and /proc/<pid>/net/unix. */
static constexpr size_t STATUS_LENGTH = 4096;
static constexpr size_t SOCKET_LINK_LENGTH = 64;
static constexpr size_t UNIX_TABLE_LENGTH = 1 << 20;
static constexpr size_t PROC_PATH_LENGTH = 64;

/* An object of two quoted paths: "'from' to 'to'". */
static constexpr size_t TWO_PATH_OBJECT_LENGTH = 2 * REPORT_QUOTED_MAXIMUM + 8;

static char own_status[STATUS_LENGTH];
static bool own_status_known = false;
static char unix_table[UNIX_TABLE_LENGTH];

/* The supervisor's own /proc/self/status, read once: its credentials do not change. */
static const char *supervisor_status(void) {
    if (!own_status_known) {
        own_status_known = read_small_file("/proc/self/status", own_status, sizeof(own_status));
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

/* Whether the mount a path lies on lets it be changed, or executed from. */
static bool mount_allows(const char *path, unsigned long refused_flag) {
    struct statvfs status;
    return statvfs(path, &status) == 0 && (status.f_flag & refused_flag) == 0;
}

/* Whether the file mode lets the task do what the call asks, the supervisor's credentials
 * standing in for the task's. */
static bool mode_allows(const char *path, int access) {
    return faccessat(AT_FDCWD, path, access, AT_EACCESS) == 0;
}

/* The mount a path lies on, by its identifier, or 0 when it cannot be told. */
static uint64_t mount_of(const char *path) {
    struct statx status;
    if (statx(AT_FDCWD, path, 0, STATX_MNT_ID, &status) != 0
        || (status.stx_mask & STATX_MNT_ID) == 0) {
        return 0;
    }
    return status.stx_mnt_id;
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

/* The noun a line gives an object it deletes, moves or links: the vocabulary has only the
 * Directory and the File there, one per right (REMOVE_DIR, REMOVE_FILE). */
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

/* Resolves the parent a call creates or removes a name in, and answers whether the kernel would
 * reach Landlock at all: the parent is a directory on a writable mount that the file mode lets
 * the task write and search. */
static bool parent_accepts_change(const char *absolute, char *anchor, char *shown) {
    if (!resolve_for_landlock(absolute, true, anchor, PATH_MAX, shown, PATH_MAX)) {
        return false;
    }
    struct stat status;
    return stat(anchor, &status) == 0 && S_ISDIR(status.st_mode)
           && mount_allows(anchor, ST_RDONLY) && mode_allows(anchor, W_OK | X_OK);
}

/* An open of a name that exists. The file mode, the mount and the type must let the open reach
 * Landlock, and then Landlock checks write (and truncate) before read. */
static void judge_open_existing(const char *absolute, const struct stat *status, int flags,
                                const struct policy_model *model) {
    int access = flags & O_ACCMODE;
    bool directory = S_ISDIR(status->st_mode);
    bool writes = access == O_WRONLY || access == O_RDWR;
    bool reads = access == O_RDONLY || access == O_RDWR;
    bool truncates = (flags & O_TRUNC) != 0 && S_ISREG(status->st_mode);
    if (access == O_ACCMODE || S_ISSOCK(status->st_mode)
        || (directory && (writes || (flags & O_CREAT) != 0))
        || ((flags & O_DIRECTORY) != 0 && !directory)) {
        return;
    }
    int mode_access = (reads ? R_OK : 0) | (writes || truncates ? W_OK : 0);
    if (((writes || truncates) && !mount_allows(absolute, ST_RDONLY))
        || !mode_allows(absolute, mode_access)) {
        return;
    }
    char anchor[PATH_MAX];
    char shown[PATH_MAX];
    if (!resolve_for_landlock(absolute, false, anchor, sizeof(anchor), shown, sizeof(shown))) {
        return;
    }
    uint64_t granted = model_rights_along(model, anchor);
    uint64_t write_rights = (writes ? LANDLOCK_ACCESS_FILESYSTEM_WRITE_FILE : 0)
                            | (truncates ? LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE : 0);
    uint64_t read_right = directory ? LANDLOCK_ACCESS_FILESYSTEM_READ_DIRECTORY
                                    : LANDLOCK_ACCESS_FILESYSTEM_READ_FILE;
    if (refused(model, granted, write_rights)) {
        report_path("write", "File", shown, absolute);
    } else if (reads && refused(model, granted, read_right)) {
        report_path("read", noun_for(status->st_mode), shown, absolute);
    }
}

/* An open that creates its name. Landlock checks the creation in the parent first, and then, on
 * the new file, the write and read the open asks for. */
static void judge_open_create(char *absolute, int flags, const struct policy_model *model) {
    char anchor[PATH_MAX];
    char shown[PATH_MAX];
    if ((flags & O_DIRECTORY) != 0 || strip_trailing_slashes(absolute)
        || !parent_accepts_change(absolute, anchor, shown)) {
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

/* An open, with flags from the call or from an openat2's open_how. */
static void judge_open(const struct task_view *task, const struct named_object *object, int flags,
                       const struct policy_model *model) {
    char absolute[PATH_MAX];
    if ((flags & ~JUDGED_OPEN_FLAGS) != 0
        || !read_absolute_name(task, object, absolute, sizeof(absolute))) {
        return;
    }
    bool exclusive = (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL);
    struct stat status;
    if (lstat(absolute, &status) != 0) {
        if ((flags & O_CREAT) != 0) {
            judge_open_create(absolute, flags, model);
        }
        return;
    }
    if (exclusive || (S_ISLNK(status.st_mode) && (flags & O_NOFOLLOW) != 0)
        || stat(absolute, &status) != 0) {
        return;
    }
    judge_open_existing(absolute, &status, flags, model);
}

/* An openat2: judged as an open only for the first open_how layout with no resolve flag, since
 * the resolve flags change the walk in ways the mirror does not reproduce. */
static void judge_open_how(const struct task_view *task, const struct access_request *request,
                           const struct policy_model *model) {
    struct open_how how;
    if (request->open_how_size != OPEN_HOW_FIRST_SIZE
        || !read_command_bytes(task, request->open_how_address, &how, sizeof(how))
        || how.resolve != 0 || how.flags > (uint64_t)INT_MAX) {
        return;
    }
    judge_open(task, &request->objects[0], (int)how.flags, model);
}

/* An execve or execveat. Landlock checks execute and read on the file; the file must be a regular
 * file the mode lets the task execute, on a mount that allows it. */
static void judge_execute(const struct task_view *task, const struct access_request *request,
                          const struct policy_model *model) {
    char absolute[PATH_MAX];
    char anchor[PATH_MAX];
    char shown[PATH_MAX];
    struct stat status;
    bool no_follow = (request->execute_flags & AT_SYMLINK_NOFOLLOW) != 0;
    if ((request->execute_flags & ~AT_SYMLINK_NOFOLLOW) != 0
        || !read_absolute_name(task, &request->objects[0], absolute, sizeof(absolute))
        || lstat(absolute, &status) != 0 || (S_ISLNK(status.st_mode) && no_follow)
        || stat(absolute, &status) != 0 || !S_ISREG(status.st_mode)
        || !mount_allows(absolute, ST_NOEXEC) || !mode_allows(absolute, X_OK)
        || !resolve_for_landlock(absolute, false, anchor, sizeof(anchor), shown, sizeof(shown))) {
        return;
    }
    if (refused(model, model_rights_along(model, anchor),
                LANDLOCK_ACCESS_FILESYSTEM_EXECUTE | LANDLOCK_ACCESS_FILESYSTEM_READ_FILE)) {
        report_path("execute", "File", shown, absolute);
    }
}

/* A call that creates one name of the given type in a parent: mkdir, mknod and symlink. Only a
 * directory may be named with a trailing slash. */
static void judge_create_name(const struct task_view *task, const struct named_object *object,
                              mode_t type, const struct policy_model *model) {
    char absolute[PATH_MAX];
    char anchor[PATH_MAX];
    char shown[PATH_MAX];
    struct stat status;
    if (!read_absolute_name(task, object, absolute, sizeof(absolute))
        || (strip_trailing_slashes(absolute) && !S_ISDIR(type)) || lstat(absolute, &status) == 0
        || !parent_accepts_change(absolute, anchor, shown)) {
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

/* An unlink or rmdir: the name must exist with the type the call expects, and Landlock checks the
 * removal in the parent. */
static void judge_remove(const struct task_view *task, const struct access_request *request,
                         const struct policy_model *model) {
    char absolute[PATH_MAX];
    char anchor[PATH_MAX];
    char shown[PATH_MAX];
    struct stat status;
    bool directory = (request->unlink_flags & AT_REMOVEDIR) != 0;
    if ((request->unlink_flags & ~AT_REMOVEDIR) != 0
        || !read_absolute_name(task, &request->objects[0], absolute, sizeof(absolute))
        || (strip_trailing_slashes(absolute) && !directory) || lstat(absolute, &status) != 0
        || S_ISDIR(status.st_mode) != directory || !parent_accepts_change(absolute, anchor, shown)) {
        return;
    }
    if (refused(model, model_rights_along(model, anchor), remove_right_for(status.st_mode))) {
        report_path("delete", whole_object_noun_for(status.st_mode), shown, absolute);
    }
}

/* Both names of a rename or a link, made absolute and resolved to their parents. */
struct two_names {
    char from[PATH_MAX];
    char to[PATH_MAX];
    char from_anchor[PATH_MAX];
    char to_anchor[PATH_MAX];
    char from_shown[PATH_MAX];
    char to_shown[PATH_MAX];
    struct stat from_status;
    struct stat to_status;
    bool to_exists;
};

/* Reads both names, and answers whether the kernel would reach Landlock: the source exists, a
 * trailing slash names a directory, the destination's parent accepts a change, the source's parent
 * accepts one too when the call removes the source (a rename, not a link) and otherwise resolves,
 * and both parents lie on one mount, since a call across mounts ends with EXDEV first. */
static bool read_two_names(const struct task_view *task, const struct access_request *request,
                           bool source_removed, struct two_names *names) {
    if (!read_absolute_name(task, &request->objects[0], names->from, sizeof(names->from))
        || !read_absolute_name(task, &request->objects[1], names->to, sizeof(names->to))
        || lstat(names->from, &names->from_status) != 0) {
        return false;
    }
    bool from_slashes = strip_trailing_slashes(names->from);
    bool to_slashes = strip_trailing_slashes(names->to);
    names->to_exists = lstat(names->to, &names->to_status) == 0;
    if ((from_slashes || to_slashes) && !S_ISDIR(names->from_status.st_mode)) {
        return false;
    }
    bool source_ready =
        source_removed ? parent_accepts_change(names->from, names->from_anchor, names->from_shown)
                       : resolve_for_landlock(names->from, true, names->from_anchor, PATH_MAX,
                                              names->from_shown, PATH_MAX);
    if (!source_ready || !parent_accepts_change(names->to, names->to_anchor, names->to_shown)) {
        return false;
    }
    uint64_t from_mount = mount_of(names->from_anchor);
    return from_mount != 0 && from_mount == mount_of(names->to_anchor);
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
        || !hard_link_allowed(names.from, &names.from_status)) {
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

/* A truncate: a regular file the mode lets the task write, on a writable mount, of a length that
 * is not negative. Landlock checks TRUNCATE on the file. */
static void judge_truncate(const struct task_view *task, const struct access_request *request,
                           const struct policy_model *model) {
    char absolute[PATH_MAX];
    char anchor[PATH_MAX];
    char shown[PATH_MAX];
    struct stat status;
    if (request->truncate_length < 0
        || !read_absolute_name(task, &request->objects[0], absolute, sizeof(absolute))
        || stat(absolute, &status) != 0 || !S_ISREG(status.st_mode)
        || !mount_allows(absolute, ST_RDONLY) || !mode_allows(absolute, W_OK)
        || !resolve_for_landlock(absolute, false, anchor, sizeof(anchor), shown, sizeof(shown))) {
        return;
    }
    if (refused(model, model_rights_along(model, anchor), LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE)) {
        report_path("write", "File", shown, absolute);
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
    if (inode == 0 || !read_small_file(path, unix_table, sizeof(unix_table))
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
    char anchor[PATH_MAX];
    char shown[PATH_MAX];
    struct stat status;
    if (length <= offsetof(struct sockaddr_un, sun_path) || address->sun_path[0] == '\0') {
        return;
    }
    snprintf(name, sizeof(name), "%.*s", (int)path_room, address->sun_path);
    if (!socket_is_unix(task, request->socket_descriptor)
        || !make_absolute(task, AT_FDCWD, name, absolute, sizeof(absolute))
        || !notification_still_valid(task) || strip_trailing_slashes(absolute)
        || lstat(absolute, &status) == 0 || !parent_accepts_change(absolute, anchor, shown)) {
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
        judge_create_name(task, &request->objects[0], S_IFLNK, filesystem);
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
    own_status_known = false;
}
#endif
