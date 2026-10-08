/*
 * Reading what a trapped call names out of the command, and resolving it the way Landlock sees it.
 *
 * Every read from the command is followed by SECCOMP_IOCTL_NOTIF_ID_VALID, so a process number the
 * kernel has recycled since the notification can never make the supervisor read a stranger's
 * memory or working directory into a line. A read that fails, or a notification that has
 * vanished, answers false, and the caller then reports nothing: this module errs towards a
 * missing line, never a wrong one.
 */
#ifndef PHOBOS_SECCOMP_FILESYSTEM_PATH_H
#define PHOBOS_SECCOMP_FILESYSTEM_PATH_H

#include "phobos-seccomp-filesystem-access.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* The task a notification came from, and how to ask whether that notification is still live. */
struct task_view {
    pid_t pid;
    int notify_descriptor;
    uint64_t id;
    const char *status;  /* /proc/<pid>/status, read once for the notification */
};

/* Whether the notification is still pending, so what was read for it belongs to its task. */
bool notification_still_valid(const struct task_view *task);

/* Reads exactly size bytes at address out of the command. */
bool read_command_bytes(const struct task_view *task, uint64_t address, void *out, size_t size);

/* Reads a NUL-terminated name of fewer than size bytes out of the command, page by page, and
 * makes it absolute against /proc/<pid>/cwd or /proc/<pid>/fd/<directory>. Answers false for an
 * empty name, a name too long, a directory that reads back as deleted or as not reachable from
 * the root, and a vanished notification. */
bool read_absolute_name(const struct task_view *task, const struct named_object *object, char *out,
                        size_t size);

/* Makes a name absolute against the task's working directory or the directory a descriptor of
 * the task names, with the same refusals as read_absolute_name. */
bool make_absolute(const struct task_view *task, int directory, const char *name, char *out,
                   size_t size);

/* The room a /proc/<pid>/status is read into, the supervisor's own and the task's alike. */
static constexpr size_t PROC_STATUS_LENGTH = 8192;

/* Resolves an absolute name as the kernel resolves it for the task, into a path that names the
 * same object for the supervisor: every directory on the way is resolved, and the last name too
 * with follow_last or a slash after it. The links of procfs that read differently for every
 * process, self and thread-self, are read as the task's from the Tgid and Pid lines of its status;
 * a status without them refuses such a walk. Answers false for a name that does not resolve, or a
 * result that does not fit. */
bool resolve_as_task(const struct task_view *task, const char *absolute, bool follow_last,
                     char *out, size_t size);

/* Whether an absolute name reaches the same object for every process: no procfs self or
 * thread-self lies on its way. A relative name answers false. */
bool reads_alike_for_every_process(const char *absolute);

/* Whether the command holds a readable, non-empty, NUL-terminated string at address, as the kernel
 * requires of a name before it looks at anything else. */
bool command_string_present(const struct task_view *task, uint64_t address);

/* Resolves a name the way Landlock sees it for the task. anchor receives the path whose ancestors
 * are walked: the object itself (parent == false), or its resolved parent directory (parent ==
 * true). shown receives the path the line names: the resolved object, or the resolved parent
 * joined with the last name as the program gave it. The two differ only for a call that creates or
 * removes a name. Answers false when the path or its parent does not resolve, and, with parent,
 * when the last name is empty, "." or "..". */
bool resolve_for_landlock(const struct task_view *task, const char *absolute, bool parent,
                          char *anchor, size_t anchor_size, char *shown, size_t shown_size);

/* Reads a whole small file, such as one under /proc, NUL-terminated, and its length in bytes into
 * length unless that is NULL; the length counts NUL bytes inside the file, as /proc/<pid>/cmdline
 * holds them. Answers false when it cannot be opened or read, or does not fit. */
bool read_small_file(const char *path, char *out, size_t size, size_t *length);

#endif
